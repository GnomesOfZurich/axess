#![cfg(feature = "testing")]
//! Input-boundary validation, validated-constructor surface, session-config
//! builder rejections, and the `MemorySessionStore` auto-purge trigger.

mod common;

use axess_core::authn::{
    factor::{FactorCredential, FactorKind, ZeroizedString},
    ids::{TenantId, UserId},
    service::{AuthnService, LoginOutcome},
    store::AuthMethod,
    types::{EntityState, Tenant, User},
};
use axess_core::testing::mock_authn::make_password_service;
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use chrono::Utc;
use common::{password_config, test_tenant, test_user, tid, totp_config, uid, user_scope};

// ── Input boundaries ────────────────────────────────────────────────────────

#[tokio::test]
async fn oversized_identifier_returns_invalid_credentials() {
    let service = make_password_service("u1", "alice", "secret");
    let session = test_session();

    // 300-byte identifier should be rejected (limit is 256).
    let huge_identifier = "a".repeat(300);
    let outcome = service
        .begin_login(&huge_identifier, "default", &session, None)
        .await
        .unwrap();
    assert!(matches!(outcome, LoginOutcome::InvalidCredentials));
}

#[tokio::test]
async fn empty_identifier_returns_invalid_credentials() {
    let service = make_password_service("u1", "alice", "secret");
    let session = test_session();

    let outcome = service.begin_login("", "t1", &session, None).await.unwrap();
    assert!(matches!(outcome, LoginOutcome::InvalidCredentials));
}

#[tokio::test]
async fn oversized_password_rejected_before_argon2() {
    let service = make_password_service("u1", "alice", "secret");
    let session = test_session();

    service
        .begin_login("alice", "t1", &session, None)
        .await
        .unwrap();

    // 2000-byte password should be rejected before reaching Argon2.
    let huge_password = "a".repeat(2000);
    let result = service
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new(huge_password)),
            &session,
        )
        .await
        .unwrap();
    assert!(matches!(
        result,
        axess_core::authn::service::FactorOutcome::InvalidCredential
    ));
}

#[tokio::test]
async fn oversized_otp_code_rejected() {
    // Start a password+TOTP flow to get into Authenticating state with TOTP pending.
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("secret"))
        .with_factor(user_scope(), totp_config("JBSWY3DPEHPK3PXP"))
        .with_method(
            &uid("u1"),
            AuthMethod::sequential(
                "pw+totp",
                vec![FactorKind::Password, FactorKind::Totp],
                user_scope(),
            ),
        );
    let service = AuthnService::new(identity, factors);
    let session = test_session();

    service
        .begin_login("alice", "default", &session, None)
        .await
        .unwrap();
    service
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("secret")),
            &session,
        )
        .await
        .unwrap();

    // Now try a 200-byte OTP code (limit is 64).
    let huge_otp = "1".repeat(200);
    let result = service
        .verify_factor(&FactorCredential::OtpCode(huge_otp.into()), &session)
        .await
        .unwrap();
    assert!(matches!(
        result,
        axess_core::authn::service::FactorOutcome::InvalidCredential
    ));
}

// ── Newtype invariants ──────────────────────────────────────────────────────

/// UserId type-system rejects empty id at construction time.
#[test]
fn user_id_rejects_empty() {
    assert!(UserId::try_new("").is_err());
}

/// User::validate rejects control characters in identifier.
#[test]
fn user_validate_rejects_control_chars() {
    let now = Utc::now();
    let user = User {
        id: uid("u1"),
        tenant_id: tid("t1"),
        identifier: "alice\x00admin".into(),
        display_name: "Alice".into(),
        status: EntityState::Active,
        webauthn_id: None,
        created_by: UserId::system(),
        created_at: now,
        updated_by: UserId::system(),
        updated_at: now,
    };
    assert!(user.validate().is_err());
}

/// TenantId type-system rejects empty id at construction time.
#[test]
fn tenant_id_rejects_empty() {
    assert!(TenantId::try_new("").is_err());
}

/// Valid User passes validation.
#[test]
fn user_validate_accepts_valid() {
    let user = test_user("u1", "alice");
    assert!(user.validate().is_ok());
}

// ── Validated constructors ──────────────────────────────────────────────────

#[test]
fn user_new_validates_and_returns_ok() {
    // UUID-shaped ids are required since `UserId`/`TenantId` are Uuid newtypes;
    // use v5-derived stable test fixtures from `axess_core::authn::ids::testing`.
    let uid = axess_core::authn::ids::testing::user("u1").to_string();
    let tid = axess_core::authn::ids::testing::tenant("t1").to_string();
    let user = User::new(
        uid,
        tid,
        "alice",
        "Alice",
        EntityState::Active,
        UserId::system(),
        Utc::now(),
    );
    assert!(user.is_ok());
    assert_eq!(user.unwrap().identifier.as_ref(), "alice");
}

#[test]
fn user_new_rejects_empty_id() {
    let tid = axess_core::authn::ids::testing::tenant("t1").to_string();
    let result = User::new(
        "",
        tid,
        "alice",
        "Alice",
        EntityState::Active,
        UserId::system(),
        Utc::now(),
    );
    assert!(result.is_err());
}

#[test]
fn user_new_rejects_control_chars_in_identifier() {
    let uid = axess_core::authn::ids::testing::user("u1").to_string();
    let tid = axess_core::authn::ids::testing::tenant("t1").to_string();
    let result = User::new(
        uid,
        tid,
        "alice\x00admin",
        "Alice",
        EntityState::Active,
        UserId::system(),
        Utc::now(),
    );
    assert!(result.is_err());
}

#[test]
fn tenant_new_validates_and_returns_ok() {
    let tid = axess_core::authn::ids::testing::tenant("t1").to_string();
    let tenant = Tenant::new(
        tid,
        "default",
        "Test Tenant",
        EntityState::Active,
        UserId::system(),
        Utc::now(),
    );
    assert!(tenant.is_ok());
}

#[test]
fn tenant_new_rejects_empty_identifier() {
    let tid = axess_core::authn::ids::testing::tenant("t1").to_string();
    let result = Tenant::new(
        tid,
        "",
        "Test",
        EntityState::Active,
        UserId::system(),
        Utc::now(),
    );
    assert!(result.is_err());
}

// ── SessionConfig builder ──────────────────────────────────────────────────

/// SessionConfig builder rejects zero TTL.
#[test]
#[should_panic(expected = "ttl must be > 0")]
fn session_config_rejects_zero_ttl() {
    use axess_core::session::config::SessionConfig;
    SessionConfig::builder()
        .ttl(std::time::Duration::ZERO)
        .build();
}

/// SessionConfig builder rejects empty cookie name.
#[test]
#[should_panic(expected = "cookie_name must not be empty")]
fn session_config_rejects_empty_cookie_name() {
    use axess_core::session::config::SessionConfig;
    SessionConfig::builder().cookie_name("").build();
}

/// SessionConfig builder accepts valid configuration.
#[test]
fn session_config_accepts_valid() {
    use axess_core::session::config::SessionConfig;
    let config = SessionConfig::builder()
        .ttl(std::time::Duration::from_secs(3600))
        .build();
    assert_eq!(config.ttl, std::time::Duration::from_secs(3600));
}

// ── MemorySessionStore auto-purge ──────────────────────────────────────────

/// MemorySessionStore auto-purges expired sessions after many writes.
#[tokio::test]
async fn memory_store_auto_purges_expired_sessions() {
    use axess_clock::testing::MockClock;
    use axess_core::session::data::SessionData;
    use axess_core::session::id::SessionId;
    use axess_core::session::store::{MemorySessionStore, SessionStore};
    use axess_core::testing::MockRng;
    use std::sync::Arc;

    // DST shape: anchor the clock, save with a short finite TTL, then
    // advance past expiry before the auto-purge trigger fires.
    let clock = Arc::new(MockClock::at(Utc::now()));
    let store = MemorySessionStore::new().with_clock(clock.clone());
    let rng = MockRng::new(1);

    let expired_id = SessionId::new(&rng);
    store
        .save(
            &expired_id,
            &SessionData::default(),
            std::time::Duration::from_secs(10),
        )
        .await
        .unwrap();

    // Advance past `expires_at` so the next 1024 saves see this row
    // as expired during auto-purge.
    clock.advance_secs(11);

    // Write 1024+ sessions to trigger auto-purge.
    for i in 0..1025 {
        let rng_i = MockRng::new(1000 + i);
        let id = SessionId::new(&rng_i);
        store
            .save(
                &id,
                &SessionData::default(),
                std::time::Duration::from_secs(3600),
            )
            .await
            .unwrap();
    }

    let loaded = store.load(&expired_id).await.unwrap();
    assert!(loaded.is_none(), "expired session should have been purged");
}
