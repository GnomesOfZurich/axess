#![cfg(feature = "testing")]
//! Email one-time codes: a burned code keeps its cooldown, a new code starts
//! with a fresh allowance, a lost swap is retried, and an unfinished claim is
//! a short lease.

mod common;

use axess_clock::{Clock, testing::MockClock};
use axess_core::authn::AuditContext;
use axess_core::authn::{
    factor::{EmailOtpConfig, FactorConfig, FactorCredential, FactorKind},
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

fn world(cfg: EmailOtpConfig) -> (Svc, MockFactorStore, MockClock) {
    let clock = MockClock::now();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), FactorConfig::EmailOtp(cfg))
        .with_method(
            &uid("u1"),
            AuthMethod::sequential("email_otp", vec![FactorKind::EmailOtp], user_scope()),
        );
    let svc = AuthnService::builder(identity, factors.clone())
        .with_rng(MockRng::new(7))
        .with_clock(clock.clone())
        .with_kdf_executor(Arc::new(KdfExecutor::inline()))
        .build()
        .with_audit_context(AuditContext::default());
    (svc, factors, clock)
}

fn base() -> EmailOtpConfig {
    EmailOtpConfig {
        email: "alice@example.com".into(),
        ttl_secs: 300,
        ..EmailOtpConfig::default()
    }
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

#[tokio::test]
async fn a_burned_code_keeps_the_cooldown_until_its_original_expiry() {
    let (svc, factors, clock) = world(EmailOtpConfig {
        max_attempts: 2,
        ..base()
    });
    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    let issued = svc.prepare_factor(&session).await.unwrap();
    assert!(matches!(issued, PrepareOutcome::SendOtp { .. }));

    // Three wrong codes: the allowance of two is spent and the third burns it.
    for _ in 0..3 {
        let _ = svc
            .verify_factor(&FactorCredential::OtpCode("000000".into()), &session)
            .await;
    }
    let after_burn = stored(&factors).await;
    assert!(after_burn.pending_hash.is_none(), "the code is burned");
    assert!(
        after_burn.pending_until.is_some(),
        "the cooldown outlives the burn"
    );

    clock.advance(chrono::Duration::seconds(1));
    let again = svc.prepare_factor(&session).await.unwrap();
    assert!(
        matches!(again, PrepareOutcome::AlreadySent { .. }),
        "no fresh code (and so no fresh guesses) straight after a burn: {again:?}"
    );

    clock.advance(chrono::Duration::seconds(301));
    let later = svc.prepare_factor(&session).await.unwrap();
    assert!(matches!(later, PrepareOutcome::SendOtp { .. }), "{later:?}");
}

#[tokio::test]
async fn a_new_code_starts_with_a_fresh_attempt_count() {
    let (svc, factors, _clock) = world(EmailOtpConfig {
        attempt_count: 4,
        ..base()
    });
    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    let issued = svc.prepare_factor(&session).await.unwrap();
    assert!(matches!(issued, PrepareOutcome::SendOtp { .. }));
    assert_eq!(stored(&factors).await.attempt_count, 0);
}

#[tokio::test]
async fn a_lost_second_swap_is_retried_against_the_claim_that_is_still_ours() {
    let (svc, factors, _clock) = world(base());
    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    // The claim swap goes through; the store swap is lost once.
    factors.arm_cas_failures_after(1, 1);
    let issued = svc.prepare_factor(&session).await.unwrap();
    assert!(
        matches!(issued, PrepareOutcome::SendOtp { .. }),
        "{issued:?}"
    );
    assert!(stored(&factors).await.pending_hash.is_some());
}

#[tokio::test]
async fn an_unfinished_claim_is_a_short_lease_not_the_full_ttl() {
    let (svc, factors, clock) = world(base());
    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    // The store swap never lands, as if the request died after claiming.
    factors.arm_cas_failures_after(1, 100);
    let res = svc.prepare_factor(&session).await;
    assert!(res.is_err(), "nothing was delivered");
    let claim = stored(&factors).await;
    let until = claim.pending_until.expect("the claim holds the slot");
    assert!(
        until <= clock.now() + chrono::Duration::seconds(31),
        "a claim blocks for a lease, not the 300 s TTL: {until}"
    );
}

#[tokio::test]
async fn the_address_in_an_already_sent_answer_is_masked() {
    let (svc, _factors, _clock) = world(base());
    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    let issued = svc.prepare_factor(&session).await.unwrap();
    assert_eq!(
        issued.masked_destination().as_deref(),
        Some("a***@example.com")
    );
    let again = svc.prepare_factor(&session).await.unwrap();
    match again {
        PrepareOutcome::AlreadySent { destination } => {
            assert_eq!(&*destination, "a***@example.com");
        }
        other => panic!("{other:?}"),
    }
}
