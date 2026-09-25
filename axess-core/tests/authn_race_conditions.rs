#![cfg(feature = "testing")]
//! Race-window and store-outage rails: suspend-during-auth, HOTP counter-burn
//! after max attempts, and counter-store outage MUST NOT propagate as
//! `Err(Store)`.

mod common;

use axess_core::authn::AuditContext;
use axess_core::authn::event::AuthFailureReason;
use axess_core::authn::{
    factor::{FactorConfig, FactorCredential, FactorKind, HotpConfig, ZeroizedString},
    service::{AuthnService, FactorOutcome, LoginOutcome},
    store::{AuthMethod, IdentityAdmin},
    types::{CounterUnavailable, LockoutPolicy, StatusDetail},
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
    let svc = AuthnService::builder(identity.clone(), factors)
        .with_registry(registry.clone())
        .build()
        .with_audit_context(AuditContext::default());

    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();

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
    let service = AuthnService::new(identity, factors).with_audit_context(AuditContext::default());

    // Three wrong attempts.
    for _ in 0..3 {
        let session = test_session();
        service
            .begin_login("carol", "default", &session)
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
        .begin_login("carol", "default", &session)
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

/// A wrong password while the counter store is down must never come back as
/// `Err(AuthnError::Store)`. An attacker who can induce store errors, or who
/// simply waits for an outage, would otherwise tell good usernames from bad
/// by the distinct `Err` shape against the normal credential rejection.
///
/// What it *does* come back as is the deployment's choice, because the
/// counter being dead means lockout cannot be enforced from the count.
/// Both arms are pinned below.
#[tokio::test]
async fn wrong_password_during_counter_outage_never_returns_err() {
    // Default policy: CounterUnavailable::Lock. The attempt is treated as
    // locked, so the outage cannot be used for unlimited attempts.
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Gnomes2+"))
        .with_method(&uid("u1"), password_method());
    let service =
        AuthnService::new(identity.clone(), factors).with_audit_context(AuditContext::default());

    let session = test_session();
    service
        .begin_login("alice", "default", &session)
        .await
        .unwrap();

    identity.arm_record_failed_attempt_failure();

    let result = service
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("wrong")),
            &session,
        )
        .await;
    assert!(
        matches!(result, Ok(FactorOutcome::Locked { .. })),
        "default policy must fail closed under counter outage, got {result:?}"
    );

    // Repeating yields the same outcome: no Err timing difference to exploit.
    let result2 = service
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("wrong-again")),
            &session,
        )
        .await;
    assert!(
        matches!(result2, Ok(FactorOutcome::Locked { .. })),
        "repeat attempts under outage must stay Locked, got {result2:?}"
    );
}

#[tokio::test]
async fn wrong_password_during_counter_outage_allows_when_configured() {
    // CounterUnavailable::Allow keeps logins working and disables lockout
    // for the duration. Still never `Err`, for the enumeration reason above.
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"))
        .with_lockout_policy(LockoutPolicy {
            on_counter_unavailable: CounterUnavailable::Allow,
            ..LockoutPolicy::default()
        });
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Gnomes2+"))
        .with_method(&uid("u1"), password_method());
    let service =
        AuthnService::new(identity.clone(), factors).with_audit_context(AuditContext::default());

    let session = test_session();
    service
        .begin_login("alice", "default", &session)
        .await
        .unwrap();

    identity.arm_record_failed_attempt_failure();

    let result = service
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("wrong")),
            &session,
        )
        .await;
    assert!(
        matches!(result, Ok(FactorOutcome::InvalidCredential)),
        "Allow must surface the outage as InvalidCredential, got {result:?}"
    );
}

/// An audit-store outage must fail the login rather than let it proceed
/// unrecorded, and it must fail **identically** for a known and an unknown
/// identifier.
///
/// The second half is the part that is easy to get wrong. Before the
/// unknown-identifier path emitted an audit event, an outage produced
/// `Err(Store)` for a real user and `Ok(InvalidCredentials)` for a
/// nonexistent one, which is a user-enumeration oracle an attacker can open
/// at will by degrading the audit store. Both paths emit now, so both fail.
#[tokio::test]
async fn audit_outage_fails_closed_identically_for_known_and_unknown_users() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Gnomes2+"))
        .with_method(&uid("u1"), password_method());
    let service =
        AuthnService::new(identity.clone(), factors).with_audit_context(AuditContext::default());

    identity.arm_record_event_failure();

    let known = service
        .begin_login("alice", "default", &test_session())
        .await;
    let unknown = service
        .begin_login("nobody", "default", &test_session())
        .await;

    assert!(
        known.is_err(),
        "a login that cannot be recorded must not proceed, got {known:?}"
    );
    assert!(
        unknown.is_err(),
        "the unknown-identifier path must fail the same way, or an audit \
         outage becomes a user-enumeration oracle, got {unknown:?}"
    );
    assert_eq!(
        format!("{known:?}"),
        format!("{unknown:?}"),
        "known and unknown identifiers must be indistinguishable under an audit outage"
    );
}

/// With the audit store healthy, a login attempt against an identifier that
/// does not exist still lands in the trail. A credential-stuffing run over a
/// list of addresses, none of which are registered, used to leave nothing
/// behind but a metric counter.
#[tokio::test]
async fn unknown_identifier_attempts_reach_the_audit_trail() {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let service = AuthnService::new(identity.clone(), MockFactorStore::new())
        .with_audit_context(AuditContext::default());

    let outcome = service
        .begin_login("nobody", "default", &test_session())
        .await
        .expect("healthy audit store: the attempt is recorded and rejected");
    assert!(matches!(outcome, LoginOutcome::InvalidCredentials));

    let events = identity.events();
    assert!(
        events
            .iter()
            .any(|e| e.error == Some(AuthFailureReason::UnknownIdentifier)),
        "an attempt against an unknown identifier must leave an audit row, got {events:?}"
    );
}
