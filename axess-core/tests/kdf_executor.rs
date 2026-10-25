#![cfg(feature = "testing")]
//! Password hashing runs on the service's KDF executor, never on the
//! runtime's worker; the salt comes from the injected RNG; a recovery-code
//! check costs no hash when its rows are keyed.

mod common;

use axess_core::authn::AuditContext;
use axess_core::authn::{
    factor::{EmailOtpConfig, FactorConfig, FactorCredential, FactorKind, ZeroizedString},
    service::{AuthnService, FactorOutcome, PrepareOutcome},
    store::{AuthMethod, FactorStore},
    types::AuthnScope,
};
use axess_core::blocking::KdfExecutor;
use axess_core::testing::{
    MockRng,
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use common::{password_config, password_method, test_tenant, test_user, tid, uid, user_scope};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

fn password_world(
    kdf: Arc<KdfExecutor>,
) -> axess_core::authn::service::RequestAuthnService<MockIdentityStore, MockFactorStore> {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Gnomes2+"))
        .with_method(&uid("u1"), password_method());
    AuthnService::builder(identity, factors)
        .with_kdf_executor(kdf)
        .build()
        .with_audit_context(AuditContext::default())
}

fn password(p: &str) -> FactorCredential {
    FactorCredential::Password(ZeroizedString::new(p))
}

/// The reason the executor exists. On a one-worker runtime, a ticker task can
/// only run while the login task is suspended; the mock stores never suspend,
/// so the only suspension in `verify_factor` is the wait for the hash. If the
/// hash ran inline the ticker would run zero times.
#[tokio::test(flavor = "current_thread")]
async fn a_password_check_leaves_the_runtime_free() {
    let svc = password_world(Arc::new(KdfExecutor::pool()));
    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();

    let ticks = Arc::new(AtomicUsize::new(0));
    let counter = ticks.clone();
    let ticker = tokio::spawn(async move {
        loop {
            tokio::task::yield_now().await;
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });
    let out = svc
        .verify_factor(&password("Gnomes2+"), &session)
        .await
        .unwrap();
    ticker.abort();

    assert!(matches!(out, FactorOutcome::Authenticated), "got {out:?}");
    assert!(
        ticks.load(Ordering::SeqCst) > 0,
        "the runtime was blocked for the whole Argon2 verification"
    );
}

#[tokio::test]
async fn a_right_and_a_wrong_password_each_cost_one_job() {
    let kdf = Arc::new(KdfExecutor::inline());
    let svc = password_world(kdf.clone());
    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    assert_eq!(kdf.jobs_started(), 0, "begin_login runs no hash");

    let out = svc
        .verify_factor(&password("wrong"), &session)
        .await
        .unwrap();
    assert!(matches!(out, FactorOutcome::InvalidCredential), "{out:?}");
    assert_eq!(kdf.jobs_started(), 1);

    let out = svc
        .verify_factor(&password("Gnomes2+"), &session)
        .await
        .unwrap();
    assert!(matches!(out, FactorOutcome::Authenticated), "{out:?}");
    assert_eq!(kdf.jobs_started(), 2);
}

fn email_otp_world(
    seed: u64,
    kdf: Arc<KdfExecutor>,
) -> (
    axess_core::authn::service::RequestAuthnService<MockIdentityStore, MockFactorStore>,
    MockFactorStore,
) {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(
            user_scope(),
            FactorConfig::EmailOtp(EmailOtpConfig {
                email: "alice@example.com".into(),
                ttl_secs: 300,
                ..EmailOtpConfig::default()
            }),
        )
        .with_method(
            &uid("u1"),
            AuthMethod::sequential("email_otp", vec![FactorKind::EmailOtp], user_scope()),
        );
    let svc = AuthnService::builder(identity, factors.clone())
        .with_rng(MockRng::new(seed))
        .with_kdf_executor(kdf)
        .build()
        .with_audit_context(AuditContext::default());
    (svc, factors)
}

async fn issue_otp(
    svc: &axess_core::authn::service::RequestAuthnService<MockIdentityStore, MockFactorStore>,
    factors: &MockFactorStore,
) -> (String, String) {
    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    let PrepareOutcome::SendOtp { code, .. } = svc.prepare_factor(&session).await.unwrap() else {
        panic!("expected a code to send");
    };
    let scope = AuthnScope::User {
        tenant_id: tid("t1"),
        user_id: uid("u1"),
    };
    let Some(FactorConfig::EmailOtp(cfg)) = factors
        .load_factor(&scope, FactorKind::EmailOtp)
        .await
        .unwrap()
    else {
        panic!("email otp config missing");
    };
    (
        code.to_string(),
        cfg.pending_hash.expect("a pending hash").to_string(),
    )
}

/// The stored hash is a function of the injected RNG alone: same seed, same
/// code, same salt, same bytes. With the salt from the operating system it
/// differs on every run.
#[tokio::test]
async fn the_email_otp_hash_is_reproducible_under_a_seeded_rng() {
    let kdf = Arc::new(KdfExecutor::inline());
    let (a, fa) = email_otp_world(11, kdf.clone());
    let (b, fb) = email_otp_world(11, kdf.clone());
    let (c, fc) = email_otp_world(12, kdf.clone());
    let (code_a, hash_a) = issue_otp(&a, &fa).await;
    let (code_b, hash_b) = issue_otp(&b, &fb).await;
    let (code_c, hash_c) = issue_otp(&c, &fc).await;
    assert_eq!(code_a, code_b);
    assert_eq!(hash_a, hash_b, "same seed gives the same stored hash");
    assert_ne!(code_a, code_c);
    assert_ne!(hash_a, hash_c);
    assert!(axess_factors::verify_password(&code_a, &hash_a).is_ok());
    assert_eq!(kdf.jobs_started(), 3, "one hash per issued code");
}

/// A password reset with a three-entry history and a fresh password verifies
/// the history and hashes the new password in a single job.
#[tokio::test]
async fn a_reset_checks_history_and_hashes_in_one_job() {
    use axess_core::authn::factor::PasswordRules;
    use axess_core::authn::store::IdentityPasswordHistory;

    let user = test_user("u1", "alice");
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(user.clone())
        .with_password_rules(
            &user.tenant_id,
            PasswordRules {
                history_count: 3,
                ..PasswordRules::default()
            },
        );
    for old in ["Old-password-1", "Old-password-2", "Old-password-3"] {
        identity
            .record_password_hash(&user.id, &axess_factors::generate_password_hash(old))
            .await
            .unwrap();
    }
    let kdf = Arc::new(KdfExecutor::inline());
    let svc = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_rng(MockRng::new(5))
        .with_kdf_executor(kdf.clone())
        .build()
        .with_audit_context(AuditContext::default());
    let token = svc
        .begin_password_reset("alice", "default", std::time::Duration::from_secs(60))
        .await
        .unwrap()
        .expect("token");
    assert_eq!(kdf.jobs_started(), 0);

    let ok = svc
        .complete_password_reset(&user.id, &token, "Brand-new-pass-9")
        .await
        .unwrap();
    assert!(ok);
    assert_eq!(
        kdf.jobs_started(),
        1,
        "three verifications and one hash share one blocking task"
    );
    let newest = identity.password_history(&user.id, 1).await.unwrap();
    assert!(axess_factors::verify_password("Brand-new-pass-9", &newest[0]).is_ok());
}

// ── Recovery codes ──────────────────────────────────────────────────────────

fn recovery_world(
    set: axess_factors::GeneratedRecoveryCodes,
    pepper: Option<axess_factors::RecoveryCodePepper>,
    kdf: Arc<KdfExecutor>,
) -> (
    axess_core::authn::service::RequestAuthnService<MockIdentityStore, MockFactorStore>,
    Vec<String>,
) {
    let shown: Vec<String> = set.display.iter().map(|c| c.to_string()).collect();
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), FactorConfig::RecoveryCodes(set.config))
        .with_method(
            &uid("u1"),
            AuthMethod::sequential("rc", vec![FactorKind::RecoveryCode], user_scope()),
        );
    let mut builder = AuthnService::builder(identity, factors).with_kdf_executor(kdf);
    if let Some(p) = pepper {
        builder = builder.with_recovery_code_pepper(p);
    }
    (
        builder.build().with_audit_context(AuditContext::default()),
        shown,
    )
}

fn pepper() -> axess_factors::RecoveryCodePepper {
    axess_factors::RecoveryCodePepper::new(vec![9u8; 32]).unwrap()
}

async fn spend(
    svc: &axess_core::authn::service::RequestAuthnService<MockIdentityStore, MockFactorStore>,
    code: &str,
) -> FactorOutcome {
    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    svc.verify_factor(&FactorCredential::RecoveryCode(code.into()), &session)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_keyed_recovery_set_verifies_with_no_hash_at_all() {
    let kdf = Arc::new(KdfExecutor::inline());
    let set = axess_factors::generate_recovery_codes_peppered(&MockRng::new(3), 10, &pepper());
    let (svc, shown) = recovery_world(set, Some(pepper()), kdf.clone());
    let out = spend(&svc, &shown[9]).await;
    assert!(matches!(out, FactorOutcome::Authenticated), "{out:?}");
    assert_eq!(kdf.jobs_started(), 0, "ten keyed rows, zero Argon2 runs");
    let out = spend(&svc, &shown[9]).await;
    assert!(
        matches!(out, FactorOutcome::InvalidCredential),
        "spent: {out:?}"
    );
}

#[tokio::test]
async fn a_keyed_row_fails_closed_when_the_service_has_no_pepper() {
    let kdf = Arc::new(KdfExecutor::inline());
    let set = axess_factors::generate_recovery_codes_peppered(&MockRng::new(3), 2, &pepper());
    let (svc, shown) = recovery_world(set, None, kdf);
    let out = spend(&svc, &shown[0]).await;
    assert!(matches!(out, FactorOutcome::InvalidCredential), "{out:?}");
}

#[tokio::test]
async fn an_argon2_recovery_set_still_verifies_and_runs_as_one_job() {
    let kdf = Arc::new(KdfExecutor::inline());
    let set = axess_factors::generate_recovery_codes(&MockRng::new(3), 3);
    let (svc, shown) = recovery_world(set, Some(pepper()), kdf.clone());
    let out = spend(&svc, &shown[2]).await;
    assert!(matches!(out, FactorOutcome::Authenticated), "{out:?}");
    assert_eq!(
        kdf.jobs_started(),
        1,
        "the whole set is one blocking task, not three"
    );
}
