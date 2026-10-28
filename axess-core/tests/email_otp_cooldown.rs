#![cfg(feature = "testing")]
//! The email-OTP cooldown is claimed atomically before the hash is computed,
//! so parallel requests send one code, not one each.

mod common;

use axess_core::authn::AuditContext;
use axess_core::authn::{
    factor::{EmailOtpConfig, FactorConfig, FactorKind},
    service::{AuthnService, PrepareOutcome, RequestAuthnService},
    store::{AuthMethod, FactorStore},
    types::AuthnScope,
};
use axess_core::blocking::KdfExecutor;
use axess_core::testing::{
    MockRng,
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use common::{test_tenant, test_user, tid, uid, user_scope};
use std::sync::Arc;

type Svc = RequestAuthnService<MockIdentityStore, MockFactorStore>;

fn world(ttl_secs: u32, kdf: Arc<KdfExecutor>) -> (Svc, MockFactorStore) {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(
            user_scope(),
            FactorConfig::EmailOtp(EmailOtpConfig {
                email: "alice@example.com".into(),
                ttl_secs,
                ..EmailOtpConfig::default()
            }),
        )
        .with_method(
            &uid("u1"),
            AuthMethod::sequential("email_otp", vec![FactorKind::EmailOtp], user_scope()),
        );
    let svc = AuthnService::builder(identity, factors.clone())
        .with_rng(MockRng::new(7))
        .with_kdf_executor(kdf)
        .build()
        .with_audit_context(AuditContext::default());
    (svc, factors)
}

async fn stored(factors: &MockFactorStore) -> EmailOtpConfig {
    let scope = AuthnScope::User {
        tenant_id: tid("t1"),
        user_id: uid("u1"),
    };
    match factors
        .load_factor(&scope, FactorKind::EmailOtp)
        .await
        .unwrap()
    {
        Some(FactorConfig::EmailOtp(cfg)) => cfg,
        other => panic!("email otp config missing: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_requests_send_one_code() {
    let kdf = Arc::new(KdfExecutor::pool());
    let (svc, factors) = world(300, kdf.clone());
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let svc = svc.clone();
        tasks.push(tokio::spawn(async move {
            let session = test_session();
            svc.begin_login("alice", "default", &session).await.unwrap();
            svc.prepare_factor(&session).await.unwrap()
        }))
    }
    let mut sent = 0;
    let mut cooling = 0;
    for t in tasks {
        match t.await.unwrap() {
            PrepareOutcome::SendOtp { .. } => sent += 1,
            PrepareOutcome::AlreadySent { .. } => cooling += 1,
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!((sent, cooling), (1, 9));
    assert_eq!(kdf.jobs_started(), 1, "only the winner hashes a code");
    assert!(stored(&factors).await.pending_hash.is_some());
}

#[tokio::test]
async fn the_largest_ttl_issues_a_code_without_overflow() {
    let (svc, factors) = world(u32::MAX, Arc::new(KdfExecutor::inline()));
    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    let outcome = svc.prepare_factor(&session).await.unwrap();
    assert!(
        matches!(outcome, PrepareOutcome::SendOtp { .. }),
        "got {outcome:?}"
    );
    assert!(stored(&factors).await.pending_until.is_some());
}

#[tokio::test]
async fn a_lost_claim_sends_nothing_and_hashes_nothing() {
    let kdf = Arc::new(KdfExecutor::inline());
    let (svc, factors) = world(300, kdf.clone());
    factors.arm_cas_failures(1);
    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();

    let outcome = svc.prepare_factor(&session).await.unwrap();

    assert!(
        matches!(outcome, PrepareOutcome::AlreadySent { .. }),
        "got {outcome:?}"
    );
    assert_eq!(kdf.jobs_started(), 0);
    assert!(stored(&factors).await.pending_hash.is_none());
}
