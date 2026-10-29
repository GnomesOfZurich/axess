//! Tests for the load and finalize decisions added around binding rotation,
//! registry liveness and the custom-data cap.

use super::*;
use crate::authn::ids::testing as ids;
use crate::session::data::{AuthState, SessionData};
use crate::session::layer::UnknownLiveness;
use crate::session::layer::handle::SessionInner;
use crate::session::store::MemorySessionStore;
use crate::testing::mock_random::MockRng;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::RwLock;

fn cookie_headers(
    keys: &SigningKeyRing,
    cfg: &SessionConfig,
    id: SessionId,
) -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        axum::http::HeaderValue::from_str(&format!(
            "{}={}",
            cfg.cookie_name.as_ref(),
            keys.sign_cookie(id)
        ))
        .unwrap(),
    );
    headers
}

fn authenticated() -> SessionData {
    let mut data = SessionData::default();
    data.auth_state
        .set_authenticated(ids::user("u"), ids::tenant("t"), chrono::Utc::now());
    data
}

/// A previous-key fingerprint match must not be accepted when this request
/// has no current-key fingerprint: it would store an empty fingerprint that
/// invalidates the session on the next request.
#[tokio::test]
async fn previous_key_match_without_a_current_fingerprint_is_a_mismatch() {
    let store = MemorySessionStore::new();
    let keys = SigningKeyRing::from_master([0xCC; 32]);
    let cfg = SessionConfig::default();
    let id = SessionId::new(&MockRng::new(5));
    let data = SessionData {
        fingerprint: Some("fp-old".to_string()),
        ..SessionData::default()
    };
    store.save(&id, &data, cfg.ttl).await.unwrap();
    let outcome = load_session(
        &store,
        &keys,
        &cfg,
        &cookie_headers(&keys, &cfg, id),
        Fingerprints {
            current: None,
            previous: Some("fp-old"),
        },
        &MockRng::new(1),
        &LoadPolicy::bare(),
    )
    .await;
    assert!(outcome.binding_invalidated);
    assert_ne!(outcome.data.fingerprint, Some(String::new()));
    assert!(outcome.existing_id.is_none());
}

#[tokio::test]
async fn previous_key_match_with_a_current_fingerprint_restores_under_the_current_key() {
    let store = MemorySessionStore::new();
    let keys = SigningKeyRing::from_master([0xCC; 32]);
    let cfg = SessionConfig::default();
    let id = SessionId::new(&MockRng::new(5));
    let data = SessionData {
        fingerprint: Some("fp-old".to_string()),
        ..SessionData::default()
    };
    store.save(&id, &data, cfg.ttl).await.unwrap();
    let outcome = load_session(
        &store,
        &keys,
        &cfg,
        &cookie_headers(&keys, &cfg, id),
        Fingerprints {
            current: Some("fp-new"),
            previous: Some("fp-old"),
        },
        &MockRng::new(1),
        &LoadPolicy::bare(),
    )
    .await;
    assert!(!outcome.binding_invalidated);
    assert!(outcome.rotation_fallback_used);
    assert_eq!(outcome.data.fingerprint.as_deref(), Some("fp-new"));
}

/// The size cap applies to a session that is saved only because it was
/// regenerated, not just to one a handler modified.
#[tokio::test]
async fn oversized_custom_data_is_cleared_on_a_regenerate_without_modification() {
    let store = MemorySessionStore::new();
    let cfg = SessionConfig::builder().max_custom_bytes(64).build();
    let id = SessionId::new(&MockRng::new(3));
    let data = SessionData {
        custom: serde_json::json!({ "blob": "x".repeat(500) }),
        ..SessionData::default()
    };
    store.save(&id, &data, cfg.ttl).await.unwrap();
    let inner = SessionInner {
        id,
        data,
        modified: false,
        needs_persist: false,
        regenerate: true,
        pre_cycle_id: None,
        pending_fingerprint: None,
        max_custom_bytes: 64,
        consume: None,
        rng: Arc::new(axess_rng::SystemRng),
    };
    let handle = SessionHandle(Arc::new(RwLock::new(inner)));
    let outcome = finalize_session(
        &store,
        &cfg,
        None,
        &axess_clock::SystemClock,
        &handle,
        Some(id),
        &MockRng::new(9),
    )
    .await;
    let stored = store.load(&outcome.final_id).await.unwrap().unwrap();
    assert_eq!(stored.custom, serde_json::Value::default());
}

/// A registry that cannot answer.
struct SilentRegistry;

impl crate::session::store::SessionRevoker for SilentRegistry {
    fn invalidate_user<'a>(
        &'a self,
        _: &'a crate::authn::ids::UserId,
    ) -> Pin<Box<dyn Future<Output = Result<(), crate::session::store::RevocationError>> + Send + 'a>>
    {
        Box::pin(async { Ok(()) })
    }
    fn invalidate_session<'a>(
        &'a self,
        _: &'a crate::authn::ids::UserId,
        _: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = Result<(), crate::session::store::RevocationError>> + Send + 'a>>
    {
        Box::pin(async { Ok(()) })
    }
}

impl SessionRegistryHandle for SilentRegistry {
    fn is_valid<'a>(
        &'a self,
        _: &'a crate::authn::ids::UserId,
        _: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async { false })
    }
    fn liveness<'a>(
        &'a self,
        _: &'a crate::authn::ids::UserId,
        _: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = SessionLiveness> + Send + 'a>> {
        Box::pin(async { SessionLiveness::Unknown })
    }
    fn register<'a>(
        &'a self,
        _: &'a crate::authn::ids::UserId,
        _: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async { false })
    }
    fn active_sessions<'a>(
        &'a self,
        _: &'a crate::authn::ids::UserId,
    ) -> Pin<Box<dyn Future<Output = Vec<SessionId>> + Send + 'a>> {
        Box::pin(async { Vec::new() })
    }
}

async fn load_with_silent_registry(unknown: UnknownLiveness) -> (LoadOutcome, bool, SessionId) {
    let store = MemorySessionStore::new();
    let keys = SigningKeyRing::from_master([0xCC; 32]);
    let cfg = SessionConfig::default();
    let id = SessionId::new(&MockRng::new(5));
    store.save(&id, &authenticated(), cfg.ttl).await.unwrap();
    let clock = axess_clock::SystemClock;
    let registry = SilentRegistry;
    let outcome = load_session(
        &store,
        &keys,
        &cfg,
        &cookie_headers(&keys, &cfg, id),
        Fingerprints::default(),
        &MockRng::new(1),
        &LoadPolicy {
            registry: Some(&registry),
            unknown,
            clock: &clock,
            metrics: None,
        },
    )
    .await;
    let row_kept = store.load(&id).await.unwrap().is_some();
    (outcome, row_kept, id)
}

/// A registry that cannot answer fails closed by default: the request runs
/// as a guest, but the row stays so the session works once the registry is
/// back.
#[tokio::test]
async fn an_unanswering_registry_distrusts_the_session_but_keeps_the_row() {
    let (outcome, row_kept, _) = load_with_silent_registry(UnknownLiveness::Reject).await;
    assert!(outcome.existing_id.is_none());
    assert!(!outcome.data.auth_state.is_authenticated());
    assert!(!outcome.session_ended, "the cookie is not replaced");
    assert!(row_kept);
}

#[tokio::test]
async fn an_unanswering_registry_can_be_told_to_accept() {
    let (outcome, _, id) = load_with_silent_registry(UnknownLiveness::Accept).await;
    assert_eq!(outcome.existing_id, Some(id));
    assert!(matches!(
        outcome.data.auth_state,
        AuthState::Authenticated { .. }
    ));
}
