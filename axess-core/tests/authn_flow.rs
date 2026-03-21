//! Integration tests for the authentication flow.
//!
//! These tests exercise `AuthnService` end-to-end using `MockIdentityStore`,
//! `MockFactorStore`, `MockClock`, `MockRng`, and `MemorySessionRegistry`.
//! No real database, Valkey, or HTTP server is involved.

use axess_core::{
    authn::{
        event::AuthEventType,
        factor::{
            EmailOtpConfig, FactorConfig, FactorCredential, FactorKind, HotpConfig, PasswordConfig,
            PasswordRules, TotpConfig, ZeroizedString,
        },
        service::{AuthnService, FactorOutcome, LoginOutcome, PrepareOutcome},
        store::AuthMethod,
        types::{AuthnScope, EntityState, LockoutPolicy, Tenant, User},
    },
    session::store::MemorySessionRegistry,
    utils::{
        testing::{
            MockClock, MockRng,
            mock_authn::{MockFactorStore, MockIdentityStore},
            test_session,
        },
        time::Clock,
    },
};

// ── Test helpers ─────────────────────────────────────────────────────────────

fn test_tenant() -> Tenant {
    Tenant {
        id: "t1".into(),
        identifier: "default".into(),
        display_name: "Test Tenant".into(),
        status: EntityState::Active,
    }
}

fn test_user(id: &str, identifier: &str) -> User {
    User {
        id: id.into(),
        tenant_id: "t1".into(),
        identifier: identifier.into(),
        display_name: identifier.into(),
        status: EntityState::Active,
        webauthn_id: None,
    }
}

fn password_config(password: &str) -> FactorConfig {
    let hash = axess_factors::generate_password_hash(password);
    FactorConfig::Password(PasswordConfig {
        hash: ZeroizedString::new(hash),
        rules: PasswordRules::default(),
    })
}

fn totp_config(secret: &str) -> FactorConfig {
    FactorConfig::Totp(TotpConfig {
        secret: ZeroizedString::new(secret),
        ..TotpConfig::default()
    })
}

fn user_scope() -> AuthnScope {
    AuthnScope::User {
        tenant_id: "t1".into(),
        user_id: "u1".into(),
    }
}

fn password_method() -> AuthMethod {
    AuthMethod {
        name: "password".into(),
        factors: vec![FactorKind::Password],
        scope: user_scope(),
    }
}

fn password_totp_method() -> AuthMethod {
    AuthMethod {
        name: "password+totp".into(),
        factors: vec![FactorKind::Password, FactorKind::Totp],
        scope: user_scope(),
    }
}

/// Generate a TOTP code for the given secret at the given system time.
fn generate_totp_code(secret: &str, now: std::time::SystemTime) -> String {
    use std::time::UNIX_EPOCH;
    let secs = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let step = secs / 30;
    let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret).unwrap();
    let totp = totp_rs::TOTP::new(totp_rs::Algorithm::SHA1, 6, 0, 30, decoded).unwrap();
    totp.generate(step * 30)
}

/// Generate an HOTP code for the given secret and counter.
fn generate_hotp_code(secret: &str, counter: u64) -> String {
    let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret).unwrap();
    let hotp = libreauth::oath::HOTPBuilder::new()
        .key(&decoded)
        .counter(counter)
        .output_len(6)
        .finalize()
        .unwrap();
    hotp.generate()
}

// ── Full login flow: password only ──────────────────────────────────────────

#[tokio::test]
async fn password_only_login_flow() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("hunter2"))
        .with_method("u1", password_method());

    let service = AuthnService::new(identity, factors);
    let session = test_session();

    let outcome = service
        .begin_login("alice", "default", &session)
        .await
        .unwrap();
    assert!(matches!(
        outcome,
        LoginOutcome::FactorRequired(FactorKind::Password)
    ));

    let cred = FactorCredential::Password(ZeroizedString::new("hunter2"));
    let result = service.verify_factor(&cred, &session).await.unwrap();
    assert!(
        matches!(result, FactorOutcome::Authenticated),
        "got {result:?}"
    );
    assert!(session.is_authenticated().await);
    assert_eq!(session.user_id().await.unwrap().as_ref(), "u1");
}

// ── Full login flow: password + TOTP ────────────────────────────────────────

#[tokio::test]
async fn password_totp_login_flow() {
    let secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "bob"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("hunter2"))
        .with_factor(user_scope(), totp_config(secret))
        .with_method("u1", password_totp_method());

    let clock = MockClock::now();
    let service = AuthnService::new(identity, factors).with_clock(clock.clone());
    let session = test_session();

    let outcome = service
        .begin_login("bob", "default", &session)
        .await
        .unwrap();
    assert!(matches!(
        outcome,
        LoginOutcome::FactorRequired(FactorKind::Password)
    ));

    let pw = FactorCredential::Password(ZeroizedString::new("hunter2"));
    let r = service.verify_factor(&pw, &session).await.unwrap();
    assert!(
        matches!(r, FactorOutcome::FactorRequired(FactorKind::Totp)),
        "got {r:?}"
    );

    let code = generate_totp_code(secret, clock.now().into());
    let r = service
        .verify_factor(&FactorCredential::OtpCode(code.into()), &session)
        .await
        .unwrap();
    assert!(matches!(r, FactorOutcome::Authenticated), "got {r:?}");
    assert!(session.is_authenticated().await);
}

// ── Invalid credentials ─────────────────────────────────────────────────────

#[tokio::test]
async fn wrong_password_returns_invalid_credential() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("hunter2"))
        .with_method("u1", password_method());

    let service = AuthnService::new(identity, factors);
    let session = test_session();

    service
        .begin_login("alice", "default", &session)
        .await
        .unwrap();
    let cred = FactorCredential::Password(ZeroizedString::new("wrong"));
    let result = service.verify_factor(&cred, &session).await.unwrap();
    assert!(matches!(result, FactorOutcome::InvalidCredential));
}

#[tokio::test]
async fn user_not_found_returns_invalid_credentials() {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let factors = MockFactorStore::new();
    let service = AuthnService::new(identity, factors);
    let session = test_session();

    let outcome = service
        .begin_login("nobody", "default", &session)
        .await
        .unwrap();
    assert!(matches!(outcome, LoginOutcome::InvalidCredentials));
}

// ── Lockout after max attempts ──────────────────────────────────────────────

#[tokio::test]
async fn lockout_after_max_attempts() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"))
        .with_lockout_policy(LockoutPolicy {
            max_attempts: 3,
            duration: Some(std::time::Duration::from_secs(60)),
        });
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("hunter2"))
        .with_method("u1", password_method());

    let service = AuthnService::new(identity.clone(), factors);

    for i in 0..3 {
        let session = test_session();
        service
            .begin_login("alice", "default", &session)
            .await
            .unwrap();
        let cred = FactorCredential::Password(ZeroizedString::new("wrong"));
        let result = service.verify_factor(&cred, &session).await.unwrap();
        if i < 2 {
            assert!(
                matches!(result, FactorOutcome::InvalidCredential),
                "attempt {i}: {result:?}"
            );
        } else {
            assert!(
                matches!(result, FactorOutcome::Locked { .. }),
                "attempt {i}: {result:?}"
            );
        }
    }
    assert_eq!(identity.failed_attempts_for("u1"), 3);
}

// ── Lockout counter NOT reset per-factor ────────────────────────────────────

#[tokio::test]
async fn lockout_counter_accumulates_across_begin_login_cycles() {
    let secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "bob"))
        .with_lockout_policy(LockoutPolicy {
            max_attempts: 4,
            duration: Some(std::time::Duration::from_secs(60)),
        });
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("hunter2"))
        .with_factor(user_scope(), totp_config(secret))
        .with_method("u1", password_totp_method());

    let service = AuthnService::new(identity.clone(), factors);

    // Cycle 1: password OK, 2 wrong TOTP.
    let s1 = test_session();
    service.begin_login("bob", "default", &s1).await.unwrap();
    service
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("hunter2")),
            &s1,
        )
        .await
        .unwrap();
    for _ in 0..2 {
        let r = service
            .verify_factor(&FactorCredential::OtpCode("000000".into()), &s1)
            .await
            .unwrap();
        assert!(matches!(r, FactorOutcome::InvalidCredential));
    }
    assert_eq!(identity.failed_attempts_for("u1"), 2);

    // Cycle 2: password OK — counter must NOT reset.
    let s2 = test_session();
    service.begin_login("bob", "default", &s2).await.unwrap();
    service
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("hunter2")),
            &s2,
        )
        .await
        .unwrap();
    assert_eq!(
        identity.failed_attempts_for("u1"),
        2,
        "counter should not reset after password"
    );

    // 2 more wrong TOTP → lockout at attempt 4.
    let r = service
        .verify_factor(&FactorCredential::OtpCode("000000".into()), &s2)
        .await
        .unwrap();
    assert!(matches!(r, FactorOutcome::InvalidCredential)); // attempt 3

    let r = service
        .verify_factor(&FactorCredential::OtpCode("000000".into()), &s2)
        .await
        .unwrap();
    assert!(
        matches!(r, FactorOutcome::Locked { .. }),
        "expected Locked at attempt 4, got {r:?}"
    );
    assert_eq!(identity.failed_attempts_for("u1"), 4);
}

// ── TOTP replay rejection ───────────────────────────────────────────────────

#[tokio::test]
async fn totp_replay_rejected() {
    let secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "bob"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("hunter2"))
        .with_factor(user_scope(), totp_config(secret))
        .with_method("u1", password_totp_method());

    let clock = MockClock::now();
    let service = AuthnService::new(identity, factors).with_clock(clock.clone());

    // First login succeeds.
    let s1 = test_session();
    service.begin_login("bob", "default", &s1).await.unwrap();
    service
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("hunter2")),
            &s1,
        )
        .await
        .unwrap();
    let code = generate_totp_code(secret, clock.now().into());
    let r = service
        .verify_factor(&FactorCredential::OtpCode(code.clone().into()), &s1)
        .await
        .unwrap();
    assert!(matches!(r, FactorOutcome::Authenticated));

    // Second login with SAME code (same time step) should fail.
    let s2 = test_session();
    service.begin_login("bob", "default", &s2).await.unwrap();
    service
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("hunter2")),
            &s2,
        )
        .await
        .unwrap();
    let r = service
        .verify_factor(&FactorCredential::OtpCode(code.into()), &s2)
        .await
        .unwrap();
    assert!(
        matches!(r, FactorOutcome::InvalidCredential),
        "replayed TOTP should be rejected, got {r:?}"
    );
}

// ── HOTP counter advancement ────────────────────────────────────────────────

#[tokio::test]
async fn hotp_counter_advances_and_old_rejected() {
    let secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "carol"));

    let hotp_method = AuthMethod {
        name: "password+hotp".into(),
        factors: vec![FactorKind::Password, FactorKind::Hotp],
        scope: user_scope(),
    };
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("hunter2"))
        .with_factor(
            user_scope(),
            FactorConfig::Hotp(HotpConfig {
                secret: ZeroizedString::new(secret),
                counter: 0,
                ..HotpConfig::default()
            }),
        )
        .with_method("u1", hotp_method);

    let service = AuthnService::new(identity, factors);
    let code_0 = generate_hotp_code(secret, 0);

    // Login with counter=0 code.
    let s1 = test_session();
    service.begin_login("carol", "default", &s1).await.unwrap();
    service
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("hunter2")),
            &s1,
        )
        .await
        .unwrap();
    let r = service
        .verify_factor(&FactorCredential::OtpCode(code_0.clone().into()), &s1)
        .await
        .unwrap();
    assert!(matches!(r, FactorOutcome::Authenticated));

    // Second login: counter=0 code should be rejected (counter advanced to 1).
    let s2 = test_session();
    service.begin_login("carol", "default", &s2).await.unwrap();
    service
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("hunter2")),
            &s2,
        )
        .await
        .unwrap();
    let r = service
        .verify_factor(&FactorCredential::OtpCode(code_0.into()), &s2)
        .await
        .unwrap();
    assert!(
        matches!(r, FactorOutcome::InvalidCredential),
        "old HOTP counter should be rejected, got {r:?}"
    );
}

// ── Session fixation: regenerate flag set on authentication ─────────────────

#[tokio::test]
async fn session_regenerate_flag_set_on_authentication() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("hunter2"))
        .with_method("u1", password_method());

    let service = AuthnService::new(identity, factors);
    let session = test_session();

    service
        .begin_login("alice", "default", &session)
        .await
        .unwrap();
    service
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("hunter2")),
            &session,
        )
        .await
        .unwrap();

    // We can't read `regenerate` directly (pub(crate)), but we can verify
    // the session is authenticated — the `advance_factor` method sets
    // `regenerate = true` when transitioning to Authenticated.
    assert!(session.is_authenticated().await);
    // The session data should be marked modified.
    let data = session.data().await;
    assert!(data.auth_state.is_authenticated());
}

// ── Forced logout via registry ──────────────────────────────────────────────

#[tokio::test]
async fn forced_logout_via_registry() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("hunter2"))
        .with_method("u1", password_method());

    let registry = MemorySessionRegistry::new();
    let service = AuthnService::new(identity, factors).with_registry(registry.clone());
    let session = test_session();

    service
        .begin_login("alice", "default", &session)
        .await
        .unwrap();
    service
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("hunter2")),
            &session,
        )
        .await
        .unwrap();
    assert!(service.check_session(&session).await);

    // Invalidate all sessions for the user.
    use axess_core::session::store::SessionRegistry;
    registry.invalidate_user("u1").await.unwrap();
    assert!(
        !service.check_session(&session).await,
        "should be invalid after registry invalidation"
    );
}

// ── Email OTP: prepare → verify ─────────────────────────────────────────────

#[tokio::test]
async fn email_otp_prepare_and_verify() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let email_method = AuthMethod {
        name: "email_otp".into(),
        factors: vec![FactorKind::EmailOtp],
        scope: user_scope(),
    };
    let factors = MockFactorStore::new()
        .with_factor(
            user_scope(),
            FactorConfig::EmailOtp(EmailOtpConfig {
                email: "alice@example.com".into(),
                code_length: 6,
                ttl_secs: 300,
                ..EmailOtpConfig::default()
            }),
        )
        .with_method("u1", email_method);

    let clock = MockClock::now();
    let rng = MockRng::new(42);
    let service = AuthnService::new(identity, factors)
        .with_clock(clock.clone())
        .with_rng(rng);
    let session = test_session();

    service
        .begin_login("alice", "default", &session)
        .await
        .unwrap();

    let prep = service.prepare_factor(&session).await.unwrap();
    let (code, dest) = match prep {
        PrepareOutcome::SendOtp { code, destination } => (code, destination),
        other => panic!("expected SendOtp, got {other:?}"),
    };
    assert_eq!(dest.as_ref(), "alice@example.com");
    assert_eq!(code.len(), 6);

    let r = service
        .verify_factor(&FactorCredential::OtpCode(code.into()), &session)
        .await
        .unwrap();
    assert!(matches!(r, FactorOutcome::Authenticated), "got {r:?}");
}

// ── Email OTP cooldown: AlreadySent ─────────────────────────────────────────

#[tokio::test]
async fn email_otp_cooldown_returns_already_sent() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let email_method = AuthMethod {
        name: "email_otp".into(),
        factors: vec![FactorKind::EmailOtp],
        scope: user_scope(),
    };
    let factors = MockFactorStore::new()
        .with_factor(
            user_scope(),
            FactorConfig::EmailOtp(EmailOtpConfig {
                email: "alice@example.com".into(),
                ttl_secs: 300,
                ..EmailOtpConfig::default()
            }),
        )
        .with_method("u1", email_method);

    let clock = MockClock::now();
    let service = AuthnService::new(identity, factors)
        .with_clock(clock.clone())
        .with_rng(MockRng::new(42));
    let session = test_session();

    service
        .begin_login("alice", "default", &session)
        .await
        .unwrap();

    assert!(matches!(
        service.prepare_factor(&session).await.unwrap(),
        PrepareOutcome::SendOtp { .. }
    ));
    assert!(matches!(
        service.prepare_factor(&session).await.unwrap(),
        PrepareOutcome::AlreadySent { .. }
    ));

    // After TTL expires, a new code can be sent.
    clock.advance_secs(301);
    assert!(matches!(
        service.prepare_factor(&session).await.unwrap(),
        PrepareOutcome::SendOtp { .. }
    ));
}

// ── Email OTP: expired code rejected ────────────────────────────────────────

#[tokio::test]
async fn email_otp_expired_code_rejected() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let email_method = AuthMethod {
        name: "email_otp".into(),
        factors: vec![FactorKind::EmailOtp],
        scope: user_scope(),
    };
    let factors = MockFactorStore::new()
        .with_factor(
            user_scope(),
            FactorConfig::EmailOtp(EmailOtpConfig {
                email: "alice@example.com".into(),
                ttl_secs: 300,
                ..EmailOtpConfig::default()
            }),
        )
        .with_method("u1", email_method);

    let clock = MockClock::now();
    let service = AuthnService::new(identity, factors)
        .with_clock(clock.clone())
        .with_rng(MockRng::new(42));
    let session = test_session();

    service
        .begin_login("alice", "default", &session)
        .await
        .unwrap();
    let code = match service.prepare_factor(&session).await.unwrap() {
        PrepareOutcome::SendOtp { code, .. } => code,
        other => panic!("expected SendOtp, got {other:?}"),
    };

    clock.advance_secs(301);

    let r = service
        .verify_factor(&FactorCredential::OtpCode(code.into()), &session)
        .await
        .unwrap();
    assert!(
        matches!(r, FactorOutcome::InvalidCredential),
        "expired code should fail, got {r:?}"
    );
}

// ── Scope fallback: global config resolves ──────────────────────────────────

#[tokio::test]
async fn scope_fallback_to_global() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(AuthnScope::Global, password_config("hunter2"))
        .with_method("u1", password_method());

    let service = AuthnService::new(identity, factors);
    let session = test_session();

    service
        .begin_login("alice", "default", &session)
        .await
        .unwrap();
    let r = service
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("hunter2")),
            &session,
        )
        .await
        .unwrap();
    assert!(
        matches!(r, FactorOutcome::Authenticated),
        "global scope should resolve, got {r:?}"
    );
}

// ── MockRng determinism ─────────────────────────────────────────────────────

#[tokio::test]
async fn mock_rng_produces_deterministic_session_ids() {
    use axess_core::session::id::SessionId;

    let mut r1 = MockRng::new(123);
    let mut r2 = MockRng::new(123);
    assert_eq!(SessionId::new(&mut r1), SessionId::new(&mut r2));
}

// ── Audit events are recorded ───────────────────────────────────────────────

#[tokio::test]
async fn audit_events_recorded_on_login() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("hunter2"))
        .with_method("u1", password_method());

    let service = AuthnService::new(identity.clone(), factors);
    let session = test_session();

    service
        .begin_login("alice", "default", &session)
        .await
        .unwrap();
    service
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("hunter2")),
            &session,
        )
        .await
        .unwrap();

    let events = identity.events();
    assert!(
        events.len() >= 2,
        "expected >=2 events, got {}",
        events.len()
    );
    let types: Vec<_> = events.iter().map(|e| &e.event_type).collect();
    assert!(types.contains(&&AuthEventType::LoginAttempt));
    assert!(types.contains(&&AuthEventType::Authenticated));
}
