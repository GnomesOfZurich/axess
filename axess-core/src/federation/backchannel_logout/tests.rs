//! Tests for the parent `backchannel_logout` module.
//!
//! Lives in a sibling sub-module so the production module stays free of the
//! 390+ lines of fixture scaffolding. Tests reach into the
//! handler's private `registry` and `sid_map` fields, so they stay inside
//! the crate rather than moving to `tests/`. Logout-token claim helpers
//! now live in `axess_factors::oidc::logout_token`
//! micro-carve).

use super::*;
use crate::session::id::SessionId;
use crate::session::store::{MemorySessionRegistry, SessionRegistry, SessionRegistryAdapter};
use crate::testing::mock_random::MockRng;
use axess_clock::SystemClock;
use axess_factors::oauth::MockOAuthProvider;
use axess_factors::oidc::logout_token::BACKCHANNEL_LOGOUT_EVENT;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

/// Helper: create a handler with a mock provider and memory registry.
fn setup() -> (
    BackChannelLogoutHandler,
    MockOAuthProvider,
    MemorySessionRegistry,
) {
    let provider = MockOAuthProvider::new("test-idp").with_user(
        "user-123",
        "alice@example.com",
        vec![],
        vec![],
    );
    let registry = MemorySessionRegistry::new();

    let providers: Vec<Arc<dyn OAuthProvider>> =
        vec![Arc::new(MockOAuthProvider::new("test-idp").with_user(
            "user-123",
            "alice@example.com",
            vec![],
            vec![],
        ))];

    let handler = BackChannelLogoutHandler::new(
        &providers,
        Arc::new(SessionRegistryAdapter(registry.clone())),
        Arc::new(DashMap::new()),
        Arc::new(SystemClock),
    )
    .expect("handler should be created");

    (handler, provider, registry)
}

#[tokio::test]
async fn valid_logout_token_invalidates_user_sessions() {
    let (handler, provider, registry) = setup();

    // Register a session for the user.
    let rng = MockRng::new(42);
    let sid = SessionId::new(&rng);
    let user = axess_identity::testing::user("user-123");
    let user_sub = user.to_string();
    registry.register(&user, &sid).await.unwrap();
    assert!(registry.is_valid(&user, &sid).await.unwrap());

    // Create a valid logout token.
    let token = provider.mock_logout_token(Some(user_sub.as_str()), None);

    // Validate and process.
    let claims = handler.validate_logout_token(&token).await.unwrap();
    assert_eq!(claims.sub.as_deref(), Some(user_sub.as_str()));
    assert!(claims.sid.is_none());

    // Simulate what the handler does.
    if let Some(ref sub) = claims.sub {
        let parsed = crate::authn::ids::UserId::try_new(sub.as_str()).expect("valid sub");
        handler.registry.invalidate_user(&parsed).await;
    }

    // Session should now be invalidated.
    assert!(!registry.is_valid(&user, &sid).await.unwrap());
}

#[tokio::test]
async fn invalid_token_returns_bad_request() {
    let (handler, _, _) = setup();

    // Malformed JWT.
    let result = handler.validate_logout_token("not-a-jwt").await;
    assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);

    // Valid JWT structure but wrong issuer.
    let wrong_issuer = MockOAuthProvider::new("wrong-idp")
        .with_issuer("https://evil.example.com")
        .mock_logout_token(Some("user-123"), None);
    let result = handler.validate_logout_token(&wrong_issuer).await;
    assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn missing_events_claim_rejected() {
    let (handler, _, _) = setup();

    // Build a JWT without the events claim.
    let header = serde_json::json!({"alg": "none", "typ": "JWT"});
    let payload = serde_json::json!({
        "iss": "https://test-idp.example.com",
        "aud": "mock-client-id",
        "iat": chrono::Utc::now().timestamp(),
        "sub": "user-123",
        "jti": "test-jti"
    });

    let token = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(header.to_string().as_bytes()),
        URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes()),
    );

    let result = handler.validate_logout_token(&token).await;
    assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn mock_generates_parseable_logout_token() {
    let provider = MockOAuthProvider::new("test-idp");

    // With sub only.
    let token = provider.mock_logout_token(Some("user-456"), None);
    let payload = decode_jwt_payload(&token).unwrap();
    assert_eq!(payload["sub"].as_str(), Some("user-456"));
    assert!(payload.get("sid").is_none());
    assert_eq!(
        payload["iss"].as_str(),
        Some("https://test-idp.example.com")
    );
    assert_eq!(payload["aud"].as_str(), Some("mock-client-id"));
    assert!(
        payload["events"]
            .as_object()
            .unwrap()
            .contains_key(BACKCHANNEL_LOGOUT_EVENT)
    );

    // With both sub and sid.
    let token = provider.mock_logout_token(Some("user-456"), Some("sess-789"));
    let payload = decode_jwt_payload(&token).unwrap();
    assert_eq!(payload["sub"].as_str(), Some("user-456"));
    assert_eq!(payload["sid"].as_str(), Some("sess-789"));

    // With sid only.
    let token = provider.mock_logout_token(None, Some("sess-only"));
    let payload = decode_jwt_payload(&token).unwrap();
    assert!(payload.get("sub").is_none());
    assert_eq!(payload["sid"].as_str(), Some("sess-only"));
}

#[tokio::test]
async fn missing_sub_and_sid_rejected() {
    let (handler, _, _) = setup();

    // Build a JWT with neither sub nor sid.
    let header = serde_json::json!({"alg": "none", "typ": "JWT"});
    let payload = serde_json::json!({
        "iss": "https://test-idp.example.com",
        "aud": "mock-client-id",
        "iat": chrono::Utc::now().timestamp(),
        "jti": "test-jti",
        "events": {
            "http://schemas.openid.net/event/backchannel-logout": {}
        }
    });

    let token = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(header.to_string().as_bytes()),
        URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes()),
    );

    let result = handler.validate_logout_token(&token).await;
    assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn nonce_in_token_rejected() {
    let (handler, _, _) = setup();

    // Build a JWT with a nonce (forbidden in logout tokens).
    let header = serde_json::json!({"alg": "none", "typ": "JWT"});
    let payload = serde_json::json!({
        "iss": "https://test-idp.example.com",
        "aud": "mock-client-id",
        "iat": chrono::Utc::now().timestamp(),
        "sub": "user-123",
        "jti": "test-jti",
        "nonce": "should-not-be-here",
        "events": {
            "http://schemas.openid.net/event/backchannel-logout": {}
        }
    });

    let token = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(header.to_string().as_bytes()),
        URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes()),
    );

    let result = handler.validate_logout_token(&token).await;
    assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
}

// ── Penetration-style tests ──────────────────────────────────────────────

/// Token with wrong `aud` (different client ID) must be rejected.
#[tokio::test]
async fn wrong_audience_rejected() {
    let (handler, _, _) = setup();

    let header = serde_json::json!({"alg": "none", "typ": "JWT"});
    let payload = serde_json::json!({
        "iss": "https://test-idp.example.com",
        "aud": "wrong-client-id",
        "iat": chrono::Utc::now().timestamp(),
        "sub": "user-123",
        "jti": "test-jti",
        "events": {
            "http://schemas.openid.net/event/backchannel-logout": {}
        }
    });

    let token = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(header.to_string().as_bytes()),
        URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes()),
    );

    let result = handler.validate_logout_token(&token).await;
    assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
}

/// Token with `iat` outside the ±5-minute window must be rejected.
#[tokio::test]
async fn stale_iat_rejected() {
    let (handler, _, _) = setup();

    // 10 minutes in the past.
    let stale_iat = chrono::Utc::now().timestamp() - 600;

    let header = serde_json::json!({"alg": "none", "typ": "JWT"});
    let payload = serde_json::json!({
        "iss": "https://test-idp.example.com",
        "aud": "mock-client-id",
        "iat": stale_iat,
        "sub": "user-123",
        "jti": "test-jti",
        "events": {
            "http://schemas.openid.net/event/backchannel-logout": {}
        }
    });

    let token = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(header.to_string().as_bytes()),
        URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes()),
    );

    let result = handler.validate_logout_token(&token).await;
    assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
}

/// Token with `iat` in the future (>5 min) must be rejected.
#[tokio::test]
async fn future_iat_rejected() {
    let (handler, _, _) = setup();

    let future_iat = chrono::Utc::now().timestamp() + 600;

    let header = serde_json::json!({"alg": "none", "typ": "JWT"});
    let payload = serde_json::json!({
        "iss": "https://test-idp.example.com",
        "aud": "mock-client-id",
        "iat": future_iat,
        "sub": "user-123",
        "jti": "test-jti",
        "events": {
            "http://schemas.openid.net/event/backchannel-logout": {}
        }
    });

    let token = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(header.to_string().as_bytes()),
        URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes()),
    );

    let result = handler.validate_logout_token(&token).await;
    assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
}

/// `sid`-only logout (no `sub`) invalidates the specific session via SidMap.
#[tokio::test]
async fn sid_only_logout_invalidates_session() {
    let registry = MemorySessionRegistry::new();
    let sid_map: SidMap = Arc::new(DashMap::new());

    let rng = MockRng::new(42);
    let session_id = SessionId::new(&rng);
    let user_id = axess_identity::testing::user("user-123");

    // Register in registry and sid map.
    registry.register(&user_id, &session_id).await.unwrap();
    let key: SidKey = (
        "https://test-idp.example.com".to_string(),
        "oidc-sid-abc".to_string(),
    );
    sid_map.insert(key.clone(), (user_id, session_id, chrono::Utc::now()));

    let providers: Vec<Arc<dyn OAuthProvider>> =
        vec![Arc::new(MockOAuthProvider::new("test-idp").with_user(
            "user-123",
            "alice@example.com",
            vec![],
            vec![],
        ))];
    let handler = BackChannelLogoutHandler::new(
        &providers,
        Arc::new(SessionRegistryAdapter(registry.clone())),
        sid_map.clone(),
        Arc::new(SystemClock),
    )
    .expect("handler should be created");

    // Create a token with sid only, no sub.
    let provider = MockOAuthProvider::new("test-idp");
    let token = provider.mock_logout_token(None, Some("oidc-sid-abc"));

    let claims = handler.validate_logout_token(&token).await.unwrap();
    assert!(claims.sub.is_none());
    assert_eq!(claims.sid.as_deref(), Some("oidc-sid-abc"));

    // Simulate the handler's sid-based invalidation.
    if let Some((_, (uid, sid, _))) = handler.sid_map.remove(&key) {
        handler.registry.invalidate_session(&uid, &sid).await;
    }

    // Session should be invalidated.
    assert!(!registry.is_valid(&user_id, &session_id).await.unwrap());
}

/// Oversized JWT is rejected before parsing (R2-4: DoS prevention).
#[tokio::test]
async fn oversized_logout_token_rejected() {
    let (handler, _, _) = setup();
    // 16 KiB token; exceeds MAX_LOGOUT_TOKEN_BYTES (8 KiB).
    let huge_token = format!("aaa.{}.bbb", "A".repeat(16 * 1024));
    let result = handler.validate_logout_token(&huge_token).await;
    assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
}

/// IAT 10 minutes in the future is rejected (R2-10: tightened tolerance).
#[tokio::test]
async fn future_iat_beyond_60s_rejected() {
    let (handler, _, _) = setup();
    // 90 seconds in the future; within old tolerance but beyond new ±60s.
    let future_iat = chrono::Utc::now().timestamp() + 90;
    let header = serde_json::json!({"alg": "none", "typ": "JWT"});
    let payload = serde_json::json!({
        "iss": "https://test-idp.example.com",
        "aud": "mock-client-id",
        "iat": future_iat,
        "sub": "user-123",
        "jti": "test-jti",
        "events": { BACKCHANNEL_LOGOUT_EVENT: {} }
    });
    let token = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(header.to_string().as_bytes()),
        URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes()),
    );
    let result = handler.validate_logout_token(&token).await;
    assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
}

/// IAT 30 seconds in the future is accepted (within ±60s clock skew).
#[tokio::test]
async fn future_iat_within_60s_accepted() {
    let (handler, _, _) = setup();
    let future_iat = chrono::Utc::now().timestamp() + 30;
    let header = serde_json::json!({"alg": "none", "typ": "JWT"});
    let payload = serde_json::json!({
        "iss": "https://test-idp.example.com",
        "aud": "mock-client-id",
        "iat": future_iat,
        "sub": "user-123",
        "jti": "test-jti",
        "events": { BACKCHANNEL_LOGOUT_EVENT: {} }
    });
    let token = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(header.to_string().as_bytes()),
        URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes()),
    );
    let result = handler.validate_logout_token(&token).await;
    assert!(result.is_ok());
}

// ── mutation-coverage tests ─────────────────────────────────────────

/// `JTI_CACHE_MAX` is exactly 16 KiB. Pins `16 * 1024` against
/// `+` (1040) and `/` (0) mutations: both would silently change the
/// replay-cache capacity ceiling.
#[test]
fn jti_cache_max_is_sixteen_kib() {
    assert_eq!(
        JTI_CACHE_MAX, 16384,
        "JTI_CACHE_MAX must be 16 * 1024 = 16384"
    );
}

/// the public `handle_backchannel_logout` entry point must
/// drive the underlying registry. A successful 200 response without
/// session invalidation is silent failure. Pins
/// `handle_backchannel_logout -> Ok(Default::default())` (which would
/// short-circuit with 200 OK) by asserting both the response code AND
/// the side effect on the registry.
///
/// Also pins replay detection (`record_jti` body, the `delete !` in
/// `&& !record_jti(...)`, the `>= → <` in retain/capacity checks, and
/// the `- → +` cutoff sign): a second call with the same `(issuer,
/// jti)` pair within the IAT window must be rejected as replay. Each
/// of those mutations breaks replay detection in a way the second call
/// would observe (either it succeeds when it must reject, or it
/// rejects when it must succeed).
#[tokio::test]
async fn handler_invalidates_session_and_rejects_jti_replay() {
    use axum::extract::{Form, State};

    let registry = MemorySessionRegistry::new();
    let providers: Vec<Arc<dyn OAuthProvider>> =
        vec![Arc::new(MockOAuthProvider::new("test-idp").with_user(
            "user-123",
            "alice@example.com",
            vec![],
            vec![],
        ))];
    let handler = BackChannelLogoutHandler::new(
        &providers,
        Arc::new(SessionRegistryAdapter(registry.clone())),
        Arc::new(DashMap::new()),
        Arc::new(SystemClock),
    )
    .expect("handler should be created");

    // Register a session that the logout must invalidate.
    let rng = MockRng::new(42);
    let session_id = SessionId::new(&rng);
    let user_id = axess_identity::testing::user("user-123");
    registry.register(&user_id, &session_id).await.unwrap();
    assert!(registry.is_valid(&user_id, &session_id).await.unwrap());

    // Build a sub-only logout token (jti embedded in the mock).
    let provider = MockOAuthProvider::new("test-idp");
    let user_sub = user_id.to_string();
    let token = provider.mock_logout_token(Some(user_sub.as_str()), None);

    // First call: must return 200 AND invalidate the registry session.
    let response = BackChannelLogoutHandler::handle_backchannel_logout(
        State(handler.clone()),
        Form(LogoutParams {
            logout_token: token.clone(),
        }),
    )
    .await
    .expect("first handler call must return Ok(StatusCode)");
    assert_eq!(
        response,
        StatusCode::OK,
        "first handler call must return 200 OK"
    );
    assert!(
        !registry.is_valid(&user_id, &session_id).await.unwrap(),
        "handle_backchannel_logout must invalidate the user's session; \
         a 200 response without registry side effect is silent failure"
    );

    // Second call with the same token (same issuer+jti): must be
    // rejected as replay. Under any of the record_jti / cutoff / retain
    // mutations this assertion flips and the mutant survives.
    let result = BackChannelLogoutHandler::handle_backchannel_logout(
        State(handler.clone()),
        Form(LogoutParams {
            logout_token: token,
        }),
    )
    .await;
    assert_eq!(
        result.unwrap_err(),
        StatusCode::BAD_REQUEST,
        "same (issuer, jti) within IAT window must be rejected as replay"
    );
}
