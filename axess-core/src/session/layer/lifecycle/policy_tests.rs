//! Tests for the load and finalize decisions added around binding rotation,
//! registry liveness and the custom-data cap.

use super::*;
use crate::authn::ids::testing as ids;
use crate::session::data::{AuthState, SessionData};
use crate::session::layer::UnknownLiveness;
use crate::session::layer::handle::{SessionHandle, SessionInner};
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

/// Load `data` under `cfg` with no registry; whether the session was kept.
async fn loads_as_authenticated(cfg: &SessionConfig, data: &SessionData) -> bool {
    let store = MemorySessionStore::new();
    let keys = SigningKeyRing::from_master([0xCC; 32]);
    let id = SessionId::new(&MockRng::new(5));
    store.save(&id, data, cfg.ttl).await.unwrap();
    let outcome = load_session(
        &store,
        &keys,
        cfg,
        &cookie_headers(&keys, cfg, id),
        Fingerprints::default(),
        &MockRng::new(1),
        &LoadPolicy::bare(),
    )
    .await;
    outcome.data.auth_state.is_authenticated()
}

/// An impersonation older than the impersonation age cap ends on its next
/// request; the user's own session of the same age, and a younger
/// impersonation, stand.
#[tokio::test]
async fn an_impersonation_older_than_its_cap_is_ended() {
    let cfg = SessionConfig::builder()
        .max_impersonation_age(Some(std::time::Duration::from_secs(3600)))
        .build();
    let now = chrono::Utc::now();
    let mut old = authenticated();
    assert!(
        old.auth_state
            .set_impersonator(ids::user("admin"), now - chrono::Duration::hours(2))
    );
    let mut young = authenticated();
    assert!(
        young
            .auth_state
            .set_impersonator(ids::user("admin"), now - chrono::Duration::minutes(5))
    );

    assert!(loads_as_authenticated(&cfg, &authenticated()).await);
    assert!(loads_as_authenticated(&cfg, &young).await);
    assert!(
        !loads_as_authenticated(&cfg, &old).await,
        "the impersonation outlived the cap"
    );
    assert!(
        !loads_as_authenticated(&SessionConfig::default(), &old).await,
        "the default caps an impersonation at an hour"
    );
    let uncapped = SessionConfig::builder().max_impersonation_age(None).build();
    assert!(
        loads_as_authenticated(&uncapped, &old).await,
        "no cap, no end"
    );
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

/// The size cap applies to the idle refresh too: a read-only request past
/// half the lifetime writes the row back, and an oversized custom bag loaded
/// from the store is cleared by that write.
#[tokio::test]
async fn oversized_custom_data_is_cleared_by_the_idle_refresh_write() {
    let store = MemorySessionStore::new();
    let cfg = SessionConfig::builder().max_custom_bytes(64).build();
    let id = SessionId::new(&MockRng::new(4));
    // No refresh stamp: the row is due for a refresh at once.
    let data = SessionData {
        custom: serde_json::json!({ "blob": "x".repeat(500) }),
        touched_at: None,
        ..SessionData::default()
    };
    store.save(&id, &data, cfg.ttl).await.unwrap();
    let inner = SessionInner {
        id,
        data,
        modified: false,
        needs_persist: false,
        regenerate: false,
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
    assert!(outcome.session_changed, "the refresh writes the row");
    let stored = store.load(&outcome.final_id).await.unwrap().unwrap();
    assert_eq!(stored.custom, serde_json::Value::default());
}

/// A registry that cannot answer.
pub(super) struct SilentRegistry;

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
    fn held_sessions<'a>(
        &'a self,
        _: &'a crate::authn::ids::UserId,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Vec<SessionId>, crate::session::store::RevocationError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async {
            Err(crate::session::store::RevocationError(
                "registry unreachable".into(),
            ))
        })
    }
}

/// A registry that cannot answer reports its outage from `held_sessions`,
/// which an implementation must write, and `active_sessions` reports the same
/// outage instead of an empty list that reads as "no sessions".
#[tokio::test]
async fn an_unanswering_registry_reports_its_outage_from_both_listings() {
    let user = ids::user("u");
    assert!(
        SilentRegistry.held_sessions(&user).await.is_err(),
        "the outage reaches the caller that must refuse on it"
    );
    assert!(
        SilentRegistry.active_sessions(&user).await.is_err(),
        "an outage is not an empty list"
    );
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
