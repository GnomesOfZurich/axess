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
//! Structural defenses to layer:
//!
//! 1. **Known-issuer allowlist (this handler).** Requests for unknown
//!    issuers are rejected before any sid_map touch.
//! 2. **`SameSite=Lax/Strict` session cookies (your axum layer).** A
//!    cross-origin GET from `attacker.com` carrying a guessed
//!    `?iss=…&sid=…` cannot trigger a SameSite cookie request, so the
//!    blast radius is limited to forged hits from the IdP origin's own
//!    referrer chain, much narrower than a CORS-style attack.
//! 3. **Session binding (optional, recommended where cookies reach the
//!    iframe).** Knowing an `(iss, sid)` pair is not proof of being the user it
//!    names. [`FrontChannelLogoutHandler::with_session_match_required`]
//!    returns a [`BoundFrontChannelLogoutHandler`], whose route takes the
//!    caller's session and ends a session only when the request carries
//!    that very session's cookie. The price: a browser that does not send the session cookie on
//!    the IdP's iframe (third-party cookie blocking, `SameSite=Lax`) ends
//!    nothing, so use back-channel logout alongside.
//! 4. **Rate limiting (REQUIRED).** Even with (1)+(2), a leaked sid is
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
//! use axess_core::federation::frontchannel_logout::FrontChannelLogoutHandler;
//! use axum::Router;
//!
//! let handler = FrontChannelLogoutHandler::new(sid_map, registry, known_issuers);
//!
//! let app = Router::new()
//!     .route("/auth/frontchannel-logout", axum::routing::get(
//!         FrontChannelLogoutHandler::handle_frontchannel_logout,
//!     ))
//!     .with_state(handler);
//!
//! // Bound to the caller's own session, on a route behind the session layer:
//! let bound = FrontChannelLogoutHandler::new(sid_map, registry, known_issuers)
//!     .with_session_match_required();
//! let app = Router::new()
//!     .route("/auth/frontchannel-logout", axum::routing::get(
//!         BoundFrontChannelLogoutHandler::handle_frontchannel_logout,
//!     ))
//!     .with_state(bound);
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
use super::log_field::loggable;
use crate::session::extractor::AuthSession;
use crate::session::id::SessionId;
use crate::session::store::{SessionRevoker, note_revocation};

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

/// A [`FrontChannelLogoutHandler`] that ends a session only when it is the
/// request's own, made by
/// [`with_session_match_required`](FrontChannelLogoutHandler::with_session_match_required).
///
/// Its only route,
/// [`handle_frontchannel_logout`](Self::handle_frontchannel_logout), takes
/// the caller's [`AuthSession`], so it must be mounted behind the session
/// layer; there is no route through which the session check could be
/// skipped.
#[derive(Clone)]
pub struct BoundFrontChannelLogoutHandler {
    handler: FrontChannelLogoutHandler,
}

/// Longest `iss` or `sid` the handler reads, in bytes. A real `sid` is a
/// UUID or a short opaque string; a longer one is refused before it is
/// looked up or logged.
const MAX_PARAM_BYTES: usize = 256;

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

    /// A handler that ends a session only when the request's own session is
    /// the one the `sid` maps to. Route
    /// [`BoundFrontChannelLogoutHandler::handle_frontchannel_logout`], behind
    /// the session layer.
    #[must_use]
    pub fn with_session_match_required(self) -> BoundFrontChannelLogoutHandler {
        BoundFrontChannelLogoutHandler { handler: self }
    }

    /// The `iss` and `sid` of a request, when both are present and within
    /// [`MAX_PARAM_BYTES`] and the issuer is one this handler knows.
    fn accepted_params<'p>(
        &self,
        params: &'p FrontChannelLogoutParams,
    ) -> Result<(&'p str, &'p str), StatusCode> {
        let Some(iss) = params.iss.as_deref() else {
            tracing::warn!("front-channel logout: missing iss parameter; rejecting");
            return Err(StatusCode::BAD_REQUEST);
        };
        let Some(sid) = params.sid.as_deref() else {
            tracing::warn!("front-channel logout: missing sid parameter; rejecting");
            return Err(StatusCode::BAD_REQUEST);
        };
        if iss.len() > MAX_PARAM_BYTES || sid.len() > MAX_PARAM_BYTES {
            tracing::debug!("front-channel logout: oversized iss or sid; rejecting");
            return Err(StatusCode::BAD_REQUEST);
        }
        if !self.known_issuers.contains(iss) {
            // Debug, not warn: the issuer is whatever the caller sent, on an
            // endpoint anyone can reach.
            tracing::debug!(
                iss = %loggable(iss),
                "front-channel logout: unknown issuer; rejecting"
            );
            return Err(StatusCode::BAD_REQUEST);
        }
        Ok((iss, sid))
    }

    /// End the session `(iss, sid)` maps to. When `caller` is `Some`, only if
    /// the mapped session is the caller's own.
    ///
    /// The session is ended in the registry first; the mapping goes only
    /// then, and only if it still names that session, so a login that
    /// re-mapped the sid in between keeps its own mapping, and a revocation
    /// the registry could not carry out is logged and leaves the mapping for
    /// a later logout. The answer is the same empty page either way.
    async fn end_by_sid(&self, iss: &str, sid: &str, caller: Option<&SessionId>) {
        let key: SidKey = (iss.to_string(), sid.to_string());
        let Some((user_id, session_id, _inserted_at)) = self.sid_map.get(&key) else {
            tracing::debug!(
                iss = %loggable(iss),
                "front-channel logout: sid not found in sid map (session may already be invalidated)"
            );
            return;
        };
        if caller.is_some_and(|caller| *caller != session_id) {
            tracing::debug!(
                iss = %loggable(iss),
                "front-channel logout: the request's session is not the one this sid maps to; \
                 ignoring"
            );
            return;
        }
        tracing::info!(
            user_id = %user_id,
            iss = %loggable(iss),
            "front-channel logout: invalidating session by OIDC sid"
        );
        let revoked = self
            .registry
            .invalidate_session(&user_id, &session_id)
            .await;
        if revoked.is_ok() {
            self.sid_map.remove_if(&key, |entry| entry.1 == session_id);
        }
        note_revocation(revoked, "front-channel logout");
    }

    /// The empty page an iframe renders.
    fn iframe_response() -> Response {
        (
            StatusCode::OK,
            [("cache-control", "no-store")],
            Html("<!DOCTYPE html><html><body></body></html>"),
        )
            .into_response()
    }

    /// `GET /auth/frontchannel-logout?sid=...&iss=...`
    ///
    /// Invalidates the session matching the given `sid`. Returns a minimal
    /// HTML response suitable for iframe embedding.
    pub async fn handle_frontchannel_logout(
        State(handler): State<FrontChannelLogoutHandler>,
        Query(params): Query<FrontChannelLogoutParams>,
    ) -> Response {
        handler.respond(&params, None).await
    }

    /// Check the parameters, end the session they name (only `caller`'s, when
    /// given), and answer with the iframe page or the refusal.
    async fn respond(
        &self,
        params: &FrontChannelLogoutParams,
        caller: Option<&SessionId>,
    ) -> Response {
        let (iss, sid) = match self.accepted_params(params) {
            Ok(pair) => pair,
            Err(status) => return status.into_response(),
        };
        self.end_by_sid(iss, sid, caller).await;
        Self::iframe_response()
    }
}

impl BoundFrontChannelLogoutHandler {
    /// `GET /auth/frontchannel-logout?sid=...&iss=...` for a route behind the
    /// session layer: ends the session the `sid` maps to only when it is the
    /// request's own session.
    ///
    /// Knowing a `sid` (it travels in browser history and referrers) is not
    /// proof of being the user it names. This route takes the caller's
    /// session from the cookie and ignores a `sid` that maps to anyone else's
    /// session, answering the same empty page either way, so the response
    /// does not say whether the `sid` exists.
    pub async fn handle_frontchannel_logout(
        State(bound): State<BoundFrontChannelLogoutHandler>,
        session: AuthSession,
        Query(params): Query<FrontChannelLogoutParams>,
    ) -> Response {
        let caller = session.session_id().await;
        bound.handler.respond(&params, Some(&caller)).await
    }
}

#[cfg(test)]
mod tests;
