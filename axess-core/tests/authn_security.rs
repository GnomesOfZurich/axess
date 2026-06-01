#![cfg(feature = "testing")]
//! Penetration-style security tests: session-fixation rotation, partial-auth
//! isolation, registry-gated session validity, refresh-token reuse rejection,
//! and `set_custom` size enforcement.

mod common;

use axess_core::authn::{
    factor::{FactorCredential, ZeroizedString},
    service::AuthnService,
    types::StatusDetail,
};
use axess_core::session::store::MemorySessionRegistry;
use axess_core::testing::mock_authn::make_password_service;
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use chrono::Utc;
use common::{password_config, password_method, test_tenant, test_user, uid, user_scope};

/// Verify that the session id rotates synchronously as part of the auth-state
/// transition (session-fixation prevention). Handler-side code that calls
/// `reg.register(user, session.session_id())` must key the registry against
/// the same id the cookie will carry on the next request.
#[tokio::test]
async fn session_id_changes_after_authentication() {
    let service = make_password_service("u1", "alice", "pass");
    let session = test_session();

    let id_before = session.session_id().await;

    service
        .begin_login("alice", "t1", &session, None)
        .await
        .unwrap();
    service
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("pass")),
            &session,
        )
        .await
        .unwrap();

    assert!(session.is_authenticated().await);
    let id_after = session.session_id().await;
    assert_ne!(
        id_before, id_after,
        "session id MUST rotate synchronously on auth completion \
         so handler-side `reg.register(user, session_id())` keys the \
         registry against the same id the cookie carries"
    );
}

/// A session in the `Authenticating` state (mid-MFA) must NOT be treated as
/// fully authenticated. Prevents privilege escalation via partial auth.
#[tokio::test]
async fn partial_auth_is_not_authenticated() {
    let service = make_password_service("u1", "alice", "pass");
    let session = test_session();

    let outcome = service
        .begin_login("alice", "t1", &session, None)
        .await
        .unwrap();
    assert!(matches!(
        outcome,
        axess_core::authn::service::LoginOutcome::FactorRequired(_)
    ));

    assert!(!session.is_authenticated().await);
    let state = session.auth_state().await;
    assert!(state.is_authenticating());
    assert!(!state.is_authenticated());
}

/// `check_session` returns false for unauthenticated sessions, preventing
/// access to registry-protected routes.
#[tokio::test]
async fn check_session_rejects_unauthenticated() {
    let service = make_password_service("u1", "alice", "pass");
    let session = test_session();

    // Not logged in at all.
    assert!(!service.check_session(&session).await);

    // Partially logged in (mid-MFA).
    service
        .begin_login("alice", "t1", &session, None)
        .await
        .unwrap();
    assert!(!service.check_session(&session).await);
}

/// Suspended users are force-logged-out when using a session registry.
#[tokio::test]
async fn suspend_invalidates_registry_sessions() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("pass"))
        .with_method(&uid("u1"), password_method());
    let registry = MemorySessionRegistry::new();
    let service = AuthnService::new(identity, factors).with_registry(registry.clone());
    let session = test_session();

    service
        .begin_login("alice", "default", &session, None)
        .await
        .unwrap();
    service
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("pass")),
            &session,
        )
        .await
        .unwrap();
    assert!(service.check_session(&session).await);

    // Suspend the user: session should be invalidated via registry.
    service
        .suspend_user(
            &uid("u1"),
            StatusDetail {
                reason: "admin action".into(),
                since: Utc::now(),
                until: None,
            },
        )
        .await
        .unwrap();

    assert!(!service.check_session(&session).await);
}

/// Refresh token rotation: using the old plaintext after rotation fails.
#[tokio::test]
async fn refresh_token_reuse_after_rotation_rejected() {
    use axess_clock::{Clock, testing::MockClock};
    use axess_core::session::refresh::*;
    use axess_core::testing::{MemoryRefreshTokenStore, MockRng};

    let store = MemoryRefreshTokenStore::new();
    let config = RefreshTokenConfig {
        rotation: true,
        ..Default::default()
    };
    let rng = MockRng::new(99);
    let clock = MockClock::now();
    let now = clock.now();

    let user = axess_core::authn::ids::testing::user("u1");
    let tenant = axess_core::authn::ids::testing::tenant("t1");
    let (plaintext, _record) = issue_refresh_token(
        IssueRequest {
            user_id: &user,
            tenant_id: &tenant,
            device_info: None,
            family_id: None,
            device_id: None,
        },
        &config,
        &store,
        &rng,
        now,
    )
    .await
    .unwrap();

    // First refresh: should succeed and rotate.
    let (_, new_token) = refresh_session(&plaintext, &store, &config, &rng, now, None)
        .await
        .unwrap();
    assert!(new_token.is_some(), "rotation should issue a new token");

    // Reuse the OLD plaintext: should be rejected (revoked by rotation).
    let err = refresh_session(&plaintext, &store, &config, &rng, now, None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, RefreshError::Revoked),
        "reused token should be Revoked, got {err:?}"
    );
}

/// `set_custom` eagerly enforces `max_custom_bytes`: oversized writes are rejected.
#[tokio::test]
async fn session_custom_data_size_enforced() {
    let session = test_session();

    // Attempt to store 100 KB of custom data (default limit is 64 KiB).
    let big_value = serde_json::Value::String("x".repeat(100_000));
    let accepted = session.set_custom("bloat", big_value).await;
    assert!(!accepted, "oversized set_custom should be rejected");

    let val = session.get_custom("bloat").await;
    assert!(val.is_none(), "rejected data should not be stored");

    let small_value = serde_json::Value::String("hello".to_string());
    let accepted = session.set_custom("greeting", small_value).await;
    assert!(accepted, "small set_custom should be accepted");
    assert!(session.get_custom("greeting").await.is_some());
}
