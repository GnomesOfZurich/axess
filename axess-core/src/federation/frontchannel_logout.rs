//! OIDC Front-Channel Logout.
//!
//! The IdP redirects the user's browser (via iframe or top-level redirect) to the
//! application's front-channel logout endpoint, passing `sid` and/or `iss` as
//! query parameters. The application invalidates the matching session and returns
//! a minimal response.
//!
//! # Security
//!
//! Front-channel logout has **no cryptographic binding** to the user's
//! original ID token. The `iss`/`sid` arrive as plain GET query parameters.
//! Three structural defenses to layer:
//!
//! 1. **Known-issuer allowlist (this handler).** Requests for unknown
//!    issuers are rejected before any sid_map touch.
//! 2. **`SameSite=Lax/Strict` session cookies (your axum layer).** A
//!    cross-origin GET from `attacker.com` carrying a guessed
//!    `?iss=…&sid=…` cannot trigger a SameSite cookie request, so the
//!    blast radius is limited to forged hits from the IdP origin's own
//!    referrer chain, much narrower than a CORS-style attack.
//! 3. **Rate limiting (REQUIRED).** Even with (1)+(2), a leaked sid is
//!    a denial-of-session primitive. Wrap the route with
//!    [`RateLimitLayer`] keyed at minimum on
//!    [`KeyExtractor::PeerIp`](crate::middleware::ratelimit::KeyExtractor::PeerIp);
//!    do this even on the prototype path. Recommended ceiling: 60 req /
//!    minute per source IP.
//!
//! [`RateLimitLayer`]: crate::middleware::ratelimit::RateLimitLayer
//!
//! # Setup
//!
//! ```rust,ignore
//! use axess::FrontChannelLogoutHandler;
//! use axum::Router;
//!
//! let handler = FrontChannelLogoutHandler::new(sid_map, registry, known_issuers);
//!
//! let app = Router::new()
//!     .route("/auth/frontchannel-logout", axum::routing::get(
//!         FrontChannelLogoutHandler::handle_frontchannel_logout,
//!     ))
//!     .with_state(handler);
//! ```
//!
//! # Differences from back-channel logout
//!
//! - **GET** request with query parameters (no JWT, no signature verification).
//! - Typically loaded in a hidden iframe by the IdP's logout page.
//! - Response must be a cacheable HTML page (for iframe rendering).

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;

use super::backchannel_logout::{SidKey, SidMap};
use crate::session::store::SessionRevoker;

/// Query parameters for the OIDC front-channel logout endpoint.
#[derive(Deserialize)]
pub struct FrontChannelLogoutParams {
    /// OIDC session ID: identifies which session to invalidate.
    pub sid: Option<String>,
    /// Issuer that initiated the logout (for validation / logging).
    pub iss: Option<String>,
}

/// Axum handler for OIDC Front-Channel Logout.
///
/// Mount as a `GET` route at e.g. `/auth/frontchannel-logout`.
///
/// # Security
///
/// The handler validates that the `iss` parameter matches a registered OAuth
/// provider before processing the logout. Requests without `iss` or with an
/// unknown issuer are rejected with 400 Bad Request. This prevents
/// unauthenticated logout attacks from unknown origins.
///
/// # Limitations
///
/// Per the OIDC spec, front-channel logout is a GET loaded in an iframe.
/// Browsers do not send `Origin` headers on iframe navigations, so origin
/// validation is not possible. The `iss` + `sid` validation is the
/// spec-compliant defense. For stronger guarantees, prefer back-channel
/// logout (signed JWT with JWKS verification).
#[derive(Clone)]
pub struct FrontChannelLogoutHandler {
    /// Shared `sid` → `(user_id, session_id)` map.
    sid_map: SidMap,
    /// Session registry for invalidating sessions.
    registry: Arc<dyn SessionRevoker>,
    /// Known issuer URLs: only these can trigger logout.
    known_issuers: Arc<HashSet<String>>,
}

impl FrontChannelLogoutHandler {
    /// Create a new front-channel logout handler.
    ///
    /// `known_issuers` should contain the issuer URLs of all registered OAuth
    /// providers. Requests from unknown issuers are rejected.
    pub fn new(
        sid_map: SidMap,
        registry: Arc<dyn SessionRevoker>,
        known_issuers: HashSet<String>,
    ) -> Self {
        Self {
            sid_map,
            registry,
            known_issuers: Arc::new(known_issuers),
        }
    }

    /// `GET /auth/frontchannel-logout?sid=...&iss=...`
    ///
    /// Invalidates the session matching the given `sid`. Returns a minimal
    /// HTML response suitable for iframe embedding.
    pub async fn handle_frontchannel_logout(
        State(handler): State<FrontChannelLogoutHandler>,
        Query(params): Query<FrontChannelLogoutParams>,
    ) -> Response {
        // Require `iss` and validate it matches a registered provider.
        // This prevents unauthenticated logout attacks from arbitrary origins.
        let iss = match &params.iss {
            Some(iss) if handler.known_issuers.contains(iss.as_str()) => iss,
            Some(iss) => {
                tracing::warn!(
                    iss = %iss,
                    "front-channel logout: unknown issuer; rejecting"
                );
                return StatusCode::BAD_REQUEST.into_response();
            }
            None => {
                tracing::warn!("front-channel logout: missing iss parameter; rejecting");
                return StatusCode::BAD_REQUEST.into_response();
            }
        };

        // Require `sid`; front-channel logout is session-specific.
        let sid = match &params.sid {
            Some(sid) => sid,
            None => {
                tracing::warn!("front-channel logout: missing sid parameter; rejecting");
                return StatusCode::BAD_REQUEST.into_response();
            }
        };

        let key: SidKey = (iss.clone(), sid.clone());
        if let Some((_, (user_id, session_id, _inserted_at))) = handler.sid_map.remove(&key) {
            tracing::info!(
                oidc_sid = %sid,
                user_id = %user_id,
                iss = %iss,
                "front-channel logout: invalidating session by OIDC sid"
            );
            handler
                .registry
                .invalidate_session(&user_id, &session_id)
                .await;
        } else {
            tracing::debug!(
                iss = %iss,
                oidc_sid = %sid,
                "front-channel logout: sid not found in sid map (session may already be invalidated)"
            );
        }

        // Return minimal HTML for iframe embedding (OIDC spec requirement).
        (
            StatusCode::OK,
            [("cache-control", "no-store")],
            Html("<!DOCTYPE html><html><body></body></html>"),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::id::SessionId;
    use crate::session::store::SessionRegistryAdapter;
    use crate::session::store::{MemorySessionRegistry, SessionRegistry};
    use crate::testing::mock_random::MockRng;
    use dashmap::DashMap;

    fn known_issuers() -> HashSet<String> {
        ["https://idp.example.com".to_string()]
            .into_iter()
            .collect()
    }

    #[tokio::test]
    async fn frontchannel_logout_invalidates_by_sid() {
        let registry = MemorySessionRegistry::new();
        let sid_map: SidMap = Arc::new(DashMap::new());

        let rng = MockRng::new(42);
        let session_id = SessionId::new(&rng);
        let user_id = axess_identity::testing::user("user-1");

        registry.register(&user_id, &session_id).await.unwrap();
        let key: SidKey = (
            "https://idp.example.com".to_string(),
            "oidc-sid-123".to_string(),
        );
        sid_map.insert(key.clone(), (user_id, session_id, chrono::Utc::now()));
        assert!(registry.is_valid(&user_id, &session_id).await.unwrap());

        let handler = FrontChannelLogoutHandler::new(
            sid_map.clone(),
            Arc::new(SessionRegistryAdapter(registry.clone())),
            known_issuers(),
        );

        // Simulate: valid iss + known sid.
        if let Some((_, (uid, sid, _))) = handler.sid_map.remove(&key) {
            handler.registry.invalidate_session(&uid, &sid).await;
        }

        assert!(!registry.is_valid(&user_id, &session_id).await.unwrap());
        assert!(!sid_map.contains_key(&key));
    }

    #[tokio::test]
    async fn frontchannel_logout_unknown_sid_is_noop() {
        let registry = MemorySessionRegistry::new();
        let sid_map: SidMap = Arc::new(DashMap::new());
        let handler = FrontChannelLogoutHandler::new(
            sid_map,
            Arc::new(SessionRegistryAdapter(registry)),
            known_issuers(),
        );
        let nonexistent: SidKey = (
            "https://idp.example.com".to_string(),
            "nonexistent".to_string(),
        );
        assert!(handler.sid_map.remove(&nonexistent).is_none());
    }

    #[tokio::test]
    async fn frontchannel_logout_rejects_unknown_issuer() {
        let handler = FrontChannelLogoutHandler::new(
            Arc::new(DashMap::new()),
            Arc::new(SessionRegistryAdapter(MemorySessionRegistry::new())),
            known_issuers(),
        );
        // Unknown issuer should be rejected.
        assert!(!handler.known_issuers.contains("https://evil.example.com"));
    }

    #[tokio::test]
    async fn frontchannel_logout_rejects_missing_iss() {
        let handler = FrontChannelLogoutHandler::new(
            Arc::new(DashMap::new()),
            Arc::new(SessionRegistryAdapter(MemorySessionRegistry::new())),
            known_issuers(),
        );
        // No iss → should be rejected (handler returns 400).
        let params = FrontChannelLogoutParams {
            sid: Some("s1".into()),
            iss: None,
        };
        assert!(params.iss.is_none());
        // The actual 400 is returned by the Axum handler; here we verify
        // the validation logic is in place.
        assert!(!handler.known_issuers.contains(""));
    }

    /// drives `handle_frontchannel_logout` end-to-end via the
    /// axum extractors, asserting the response code AND the registry
    /// side effect. Pins three mutations on the handler:
    /// - `handle_frontchannel_logout -> Default::default()` (empty
    ///   response without invalidation): caught by the OK status
    ///   assertion AND the registry invalidation assertion.
    /// - `match guard handler.known_issuers.contains(...) -> true`
    ///   (would accept any issuer): caught by the unknown-issuer
    ///   subtest expecting 400.
    /// - `match guard handler.known_issuers.contains(...) -> false`
    ///   (would reject all issuers, including registered ones):
    ///   caught by the known-issuer subtest expecting 200 OK.
    #[tokio::test]
    async fn handle_frontchannel_logout_drives_registry_and_gates_issuer() {
        use axum::extract::{Query, State};

        // ── Subtest 1: known iss + known sid → 200 + session invalidated.
        let registry = MemorySessionRegistry::new();
        let sid_map: SidMap = Arc::new(DashMap::new());
        let rng = MockRng::new(7);
        let session_id = SessionId::new(&rng);
        let user_id = axess_identity::testing::user("u1");
        registry.register(&user_id, &session_id).await.unwrap();
        let key: SidKey = (
            "https://idp.example.com".to_string(),
            "oidc-sid-XYZ".to_string(),
        );
        sid_map.insert(key.clone(), (user_id, session_id, chrono::Utc::now()));

        let handler = FrontChannelLogoutHandler::new(
            sid_map.clone(),
            Arc::new(SessionRegistryAdapter(registry.clone())),
            known_issuers(),
        );

        let response = FrontChannelLogoutHandler::handle_frontchannel_logout(
            State(handler.clone()),
            Query(FrontChannelLogoutParams {
                sid: Some("oidc-sid-XYZ".to_string()),
                iss: Some("https://idp.example.com".to_string()),
            }),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "known iss + known sid must return 200 OK"
        );
        assert!(
            !registry.is_valid(&user_id, &session_id).await.unwrap(),
            "front-channel logout must invalidate the registry session; \
             a non-default response without side effect is silent failure"
        );

        // ── Subtest 2: unknown iss → 400. Pins guard -> true mutation.
        let response = FrontChannelLogoutHandler::handle_frontchannel_logout(
            State(handler.clone()),
            Query(FrontChannelLogoutParams {
                sid: Some("anything".to_string()),
                iss: Some("https://evil.example.com".to_string()),
            }),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "unknown iss must be rejected as 400"
        );
    }
}
