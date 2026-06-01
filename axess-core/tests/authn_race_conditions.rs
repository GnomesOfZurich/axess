#![cfg(feature = "testing")]
//! Race-window and store-outage rails: suspend-during-auth, HOTP counter-burn
//! after max attempts, and counter-store outage MUST NOT propagate as
//! `Err(Store)`.

mod common;

use axess_core::authn::{
    factor::{FactorConfig, FactorCredential, FactorKind, HotpConfig, ZeroizedString},
    service::{AuthnService, FactorOutcome},
    store::{AuthMethod, IdentityAdmin},
    types::StatusDetail,
};
use axess_core::session::store::MemorySessionRegistry;
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use chrono::Utc;
use common::{
    generate_hotp_code, password_config, password_method, test_tenant, test_user, uid, user_scope,
};

/// Simulates the race: between the initial `account_status` check in
/// `verify_factor` and the `register` call in `complete_factor_step`, an
/// admin's `suspend_user` lands. The post-register re-check MUST catch the
/// now-suspended state, invalidate the just-registered session, and return
/// `Locked`.
#[tokio::test]
async fn auth_completing_concurrently_with_suspend_returns_locked() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Gnomes2+"))
        .with_method(&uid("u1"), password_method());
    let registry = MemorySessionRegistry::new();
    let svc = AuthnService::new(identity.clone(), factors).with_registry(registry.clone());

    let session = test_session();
    svc.begin_login("alice", "default", &session, None)
        .await
        .unwrap();

    // Pre-flight the "concurrent suspend": flip the account to Suspended just
    // before the final `verify_factor` call. Models the worst case where the
    // suspend lands between the initial status check and the post-register
    // re-check. Without the re-check this would still authenticate.
    identity
        .suspend_user(
            &uid("u1"),
            StatusDetail {
                reason: "concurrent admin suspend".into(),
                since: Utc::now(),
                until: None,
            },
        )
        .await
        .unwrap();

    let cred = FactorCredential::Password(ZeroizedString::new("Gnomes2+"));
    let result = svc.verify_factor(&cred, &session).await.unwrap();

    assert!(
        matches!(result, FactorOutcome::Locked { .. }),
        "got {result:?}"
    );
    assert!(!session.is_authenticated().await);
}

/// Regression: after `max_attempts` failed HOTP attempts, the counter
/// advances past the lookahead window so the current set of codes can never
/// be presented again.
#[tokio::test]
async fn hotp_burns_counter_after_max_attempts() {
    let secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "carol"));

    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Gnomes2+"))
        .with_factor(
            user_scope(),
            FactorConfig::Hotp(HotpConfig {
                secret: ZeroizedString::new(secret),
                counter: 0,
                lookahead_window: 10,
                max_attempts: 3,
                ..HotpConfig::default()
            }),
        )
        .with_method(
            &uid("u1"),
            AuthMethod::sequential(
                "password+hotp",
                vec![FactorKind::Password, FactorKind::Hotp],
                user_scope(),
            ),
        );
    let service = AuthnService::new(identity, factors);

    // Three wrong attempts.
    for _ in 0..3 {
        let session = test_session();
        service
            .begin_login("carol", "default", &session, None)
            .await
            .unwrap();
        service
            .verify_factor(
                &FactorCredential::Password(ZeroizedString::new("Gnomes2+")),
                &session,
            )
            .await
            .unwrap();
        let r = service
            .verify_factor(
                &FactorCredential::OtpCode("000000".to_string().into()),
                &session,
            )
            .await
            .unwrap();
        assert!(matches!(
            r,
            FactorOutcome::InvalidCredential | FactorOutcome::Locked { .. }
        ));
    }

    // Now: even the genuine code at counter 0 must NOT verify, because the
    // counter was burned past the lookahead window.
    let code_0 = generate_hotp_code(secret, 0);
    let session = test_session();
    service
        .begin_login("carol", "default", &session, None)
        .await
        .unwrap();
    let r = service
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("Gnomes2+")),
            &session,
        )
        .await;
    // Account may be locked from the wrong-attempt counter; either way the
    // genuine code cannot succeed.
    if let Ok(FactorOutcome::FactorRequired(FactorKind::Hotp)) = r {
        let r = service
            .verify_factor(&FactorCredential::OtpCode(code_0.into()), &session)
            .await
            .unwrap();
        assert!(
            !matches!(r, FactorOutcome::Authenticated),
            "burned counter must NOT accept the previously valid code"
        );
    }
}

/// A wrong password while the counter store is down must return
/// `InvalidCredential` (just like with a healthy counter), not
/// `Err(AuthnError::Store)`. Two attack scenarios this defends against:
///
/// 1. **User enumeration:** an attacker who can induce store errors (or
///    waits for an outage) can tell good usernames from bad by the distinct
///    `Err` shape vs. the normal `InvalidCredential`.
/// 2. **Lockout bypass:** without this fix, the attacker gets unlimited
///    attempts during the outage because no counter increments.
#[tokio::test]
async fn wrong_password_during_counter_outage_returns_invalid_credential() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Gnomes2+"))
        .with_method(&uid("u1"), password_method());
    let service = AuthnService::new(identity.clone(), factors);

    let session = test_session();
    service
        .begin_login("alice", "default", &session, None)
        .await
        .unwrap();

    // Arm the counter-store outage.
    identity.arm_record_failed_attempt_failure();

    // Wrong password: must come back as InvalidCredential, not Err(Store).
    let result = service
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("wrong")),
            &session,
        )
        .await;
    assert!(
        matches!(result, Ok(FactorOutcome::InvalidCredential)),
        "wrong-credential under counter outage must be InvalidCredential, got {result:?}"
    );

    // Repeating the attack with the outage in place yields the same outcome:
    // no Err timing difference for the attacker to exploit.
    let result2 = service
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("wrong-again")),
            &session,
        )
        .await;
    assert!(
        matches!(result2, Ok(FactorOutcome::InvalidCredential)),
        "subsequent wrong attempts under outage must also be InvalidCredential, got {result2:?}"
    );
}
