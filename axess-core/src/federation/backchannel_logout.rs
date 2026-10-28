//! OIDC Back-Channel Logout (draft specification).
//!
//! When a user logs out at the IdP, the IdP sends a POST request containing a
//! `logout_token` JWT to the application's back-channel logout endpoint. This
//! module validates the token and invalidates the corresponding session(s) in
//! the [`SessionRegistry`](crate::session::store::SessionRegistry).
//!
//! # Security
//!
//! **Rate limiting is required.** This endpoint accepts POST requests from IdPs
//! and must be protected against abuse. Wrap the route with [`RateLimitLayer`]
//! (e.g. 10 requests per minute per IP) or place it behind a reverse proxy with
//! rate limiting enabled.
//!
//! [`RateLimitLayer`]: crate::middleware::ratelimit::RateLimitLayer
//!
//! # Setup
//!
//! ```text
//! use axess::BackChannelLogoutHandler;
//! use axum::Router;
//!
//! // `new` returns None when no provider advertises both an issuer and a
//! // client id, since there is then nothing a logout token could match.
//! let handler = BackChannelLogoutHandler::new(
//!     &providers,          // &[Arc<dyn OAuthProvider>]
//!     registry,            // Arc<dyn SessionRevoker>
//!     authn.sid_map(),     // the map AuthnService fills at login
//!     clock,               // Arc<dyn Clock>
//! )
//! .expect("at least one provider with an issuer and a client id");
//!
//! let app = Router::new()
//!     .route("/auth/backchannel-logout", axum::routing::post(
//!         BackChannelLogoutHandler::handle_backchannel_logout,
//!     ))
//!     .with_state(handler);
//! ```
//!
//! # Token validation
//!
//! The handler validates the logout token's structure and claims:
//! - `iss` must match a registered provider's issuer
//! - `aud` must contain the provider's client ID
//! - `iat` must be recent (within 5 minutes)
//! - `events` must contain the back-channel logout event URI
//! - At least one of `sub` or `sid` must be present
//! - `jti` must be present, and is single-use within the `iat` window
//! - A `sub` only ends the sessions that the same issuer established
//!
//! **Signature verification:** `OAuthProviderConfig` fetches and caches the
//! IdP's JWKS keys at discovery time, and `verify_logout_jwt` validates the
//! JWT signature before processing claims. `MockOAuthProvider` skips signature
//! verification for unsigned test tokens.

use crate::session::store::SessionRevoker;
use axess_clock::Clock;
use axess_factors::oauth::OAuthProvider;
use axess_factors::oidc::logout_token::{
    IatCheck, JTI_RETENTION_SECS, aud_contains, azp_satisfied, check_iat, decode_jwt_payload,
    events_contains_logout,
};
use axum::extract::{Form, State};
use axum::http::StatusCode;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

// ── Handler ──────────────────────────────────────────────────────────────────

/// Axum handler for OIDC Back-Channel Logout.
///
/// Mount as an Axum route at e.g. `/auth/backchannel-logout`. The handler
/// accepts `POST` requests with `Content-Type: application/x-www-form-urlencoded`
/// containing a `logout_token` field.
///
/// Construct with [`BackChannelLogoutHandler::new`], which returns `None`
/// unless at least one provider advertises both an issuer and a client id.
#[derive(Clone)]
pub struct BackChannelLogoutHandler {
    /// Registered providers, keyed by issuer URL for O(1) lookup.
    providers_by_issuer: Arc<HashMap<String, ProviderEntry>>,
    /// Session registry for invalidating sessions.
    registry: Arc<dyn SessionRevoker>,
    /// OIDC `(issuer, sid)` → local session mapping for `sid`-based logout,
    /// and the `(issuer, user)` index behind `sub`-based logout.
    sid_map: SidMap,
    /// Replay cache for `(issuer, jti)` pairs of recently-seen logout tokens.
    /// Within the `iat` acceptance window an attacker who captures one valid
    /// logout token must not be able to re-fire it; without this cache the
    /// 5-minute window allowed silent replay against the same `sub`/`sid`.
    /// Bounded to `JTI_CACHE_MAX` entries with TTL-based eviction.
    seen_jtis: Arc<jti_log::JtiLog>,
    /// Injected clock for the IAT-window check and the JTI replay window.
    /// Production wires `SystemClock`; tests inject `MockClock` so the
    /// 5-minute acceptance window can be exercised deterministically.
    clock: Arc<dyn Clock>,
}

/// Maximum entries kept in the per-handler `jti` replay cache. Sized so that
/// at the IAT acceptance window (300 s) and a per-second logout rate well
/// above any legitimate IdP traffic, the cache cannot itself become a
/// memory-DoS vector.
const JTI_CACHE_MAX: usize = 16 * 1024;

/// Number of entries evicted in one capacity pass. Evicting a batch rather
/// than one entry keeps a log sitting at capacity from evicting on every
/// call. Mirrors `EVICT_BATCH` in `maintain_oidc_sid_map`.
const JTI_EVICT_BATCH: usize = 128;

pub use super::sid_map::{SidEntry, SidKey, SidMap};

/// Provider entry for logout token validation: holds both metadata and the
/// provider itself for JWT signature verification.
#[derive(Clone)]
struct ProviderEntry {
    /// The provider's client ID (must appear in `aud`).
    client_id: String,
    /// Provider name for logging.
    name: Arc<str>,
    /// The full provider for `verify_logout_jwt`.
    provider: Arc<dyn OAuthProvider>,
}

/// Form body for the back-channel logout endpoint.
#[derive(Deserialize)]
pub struct LogoutParams {
    /// The logout token JWT sent by the IdP.
    pub logout_token: String,
}

/// Parsed and validated claims from a back-channel logout token.
#[derive(Debug)]
pub struct LogoutTokenClaims {
    /// OIDC subject (user ID). Present unless only `sid` was provided.
    pub sub: Option<String>,
    /// OIDC session ID. Present unless only `sub` was provided.
    pub sid: Option<String>,
    /// Issuer that sent the logout token.
    pub iss: String,
    /// Token `jti` claim (always present on a validated token). Used by the handler to detect
    /// replay of the same logout token within the IAT window.
    pub jti: Option<String>,
}

impl BackChannelLogoutHandler {
    /// Create a new handler from a set of OAuth providers and a session registry.
    ///
    /// `clock` is the injected time source used for the IAT-acceptance
    /// window check and the per-handler JTI replay cache eviction.
    /// Production wires `Arc::new(SystemClock)`; DST tests inject a
    /// `MockClock` so the 5-minute window is exercisable.
    pub fn new(
        providers: &[Arc<dyn OAuthProvider>],
        registry: Arc<dyn SessionRevoker>,
        sid_map: SidMap,
        clock: Arc<dyn Clock>,
    ) -> Option<Self> {
        let mut by_issuer = HashMap::new();

        for provider in providers {
            if let (Some(issuer), Some(client_id)) = (provider.issuer(), provider.client_id()) {
                by_issuer.insert(
                    issuer.to_string(),
                    ProviderEntry {
                        client_id: client_id.to_string(),
                        name: provider.name().clone(),
                        provider: provider.clone(),
                    },
                );
            }
        }

        if by_issuer.is_empty() {
            return None;
        }

        Some(Self {
            providers_by_issuer: Arc::new(by_issuer),
            registry,
            sid_map,
            seen_jtis: Arc::new(jti_log::JtiLog::new(JTI_CACHE_MAX, JTI_EVICT_BATCH)),
            clock,
        })
    }

    /// POST /auth/backchannel-logout
    ///
    /// Content-Type: application/x-www-form-urlencoded
    /// Body: `logout_token=<JWT>`
    ///
    /// Returns 200 on success, 400 on invalid token.
    pub async fn handle_backchannel_logout(
        State(handler): State<BackChannelLogoutHandler>,
        Form(params): Form<LogoutParams>,
    ) -> Result<StatusCode, StatusCode> {
        let claims = handler.validate_logout_token(&params.logout_token).await?;

        // Replay protection: `validate_logout_token` guarantees a `jti`, so
        // refuse to act on the same `(issuer, jti)` twice within the IAT
        // window. Without this an attacker who captures a valid logout
        // token can re-fire it for as long as its `iat` stays acceptable.
        let Some(ref jti) = claims.jti else {
            return Err(StatusCode::BAD_REQUEST);
        };
        if !handler.record_jti(&claims.iss, jti, handler.clock.now()) {
            tracing::warn!(
                iss = %claims.iss,
                jti = %jti,
                "back-channel logout: jti replay rejected"
            );
            return Err(StatusCode::BAD_REQUEST);
        }

        let provider_name = handler
            .providers_by_issuer
            .get(&claims.iss)
            .map(|p| p.name.as_ref())
            .unwrap_or("unknown");
        tracing::info!(
            provider = %provider_name,
            iss = %claims.iss,
            sub = ?claims.sub,
            sid = ?claims.sid,
            "back-channel logout: invalidating session(s)"
        );

        // If `sid` is present, invalidate the specific session mapped to this
        // OIDC session ID. Look up by `(issuer, sid)`; `sid` alone is not
        // unique across providers. This runs first so a `sub` that this
        // application cannot use never prevents the `sid` logout.
        if let Some(ref sid) = claims.sid {
            let key: SidKey = (claims.iss.clone(), sid.clone());
            if let Some((user_id, session_id, _inserted_at)) = handler.sid_map.remove(&key) {
                tracing::info!(
                    iss = %claims.iss,
                    oidc_sid = %sid,
                    user_id = %user_id,
                    "back-channel logout: invalidating session by OIDC sid"
                );
                handler
                    .registry
                    .invalidate_session(&user_id, &session_id)
                    .await;
            } else if claims.sub.is_none() {
                tracing::warn!(
                    iss = %claims.iss,
                    sid = %sid,
                    "back-channel logout: sid not found in sid map and no sub to fall back to"
                );
            }
        }

        // If `sub` is present, end the sessions of that IdP subject that THIS
        // issuer established. The sid map records `(issuer, sid)` and its
        // subject registry records `(issuer, sub) -> (local user, session)`,
        // the latter for every OAuth login including one whose ID token had
        // no `sid` or whose `sid` mapping was dropped at capacity. `sub` is
        // the IdP's own identifier and is looked up as such: after account
        // linking it differs from the local user id the session is
        // registered under, so each hit carries that id for the registry
        // call. A subject with no entry under `claims.iss` was not
        // authenticated by it, and an IdP must not be able to log out users
        // it never authenticated, nor end sessions that came from another
        // issuer or from a password or passkey login. Both lookups are by
        // exact value; `sid` handling above has already run.
        if let Some(ref sub) = claims.sub {
            let owned = handler.sid_map.take_subject_sessions(&claims.iss, sub);
            if owned.is_empty() {
                tracing::warn!(
                    iss = %claims.iss,
                    sub = %sub,
                    "back-channel logout: no session of this subject was established \
                     through this issuer; ignoring sub"
                );
            }
            for (user_id, session_id) in owned {
                handler
                    .registry
                    .invalidate_session(&user_id, &session_id)
                    .await;
            }
        }

        Ok(StatusCode::OK)
    }

    /// Validate a back-channel logout token JWT.
    ///
    /// Verifies the JWT signature (via the provider's JWKS), then checks
    /// issuer, audience, iat recency, events claim, and presence of sub/sid.
    async fn validate_logout_token(&self, token: &str) -> Result<LogoutTokenClaims, StatusCode> {
        // 0. Peek at the unverified payload to identify the issuer, so we
        //    know which provider's JWKS to verify against.
        let unverified = decode_jwt_payload(token).map_err(|e| {
            tracing::warn!(error = %e, "back-channel logout: failed to decode JWT");
            StatusCode::BAD_REQUEST
        })?;

        let iss = unverified
            .get("iss")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                tracing::warn!("back-channel logout: missing iss claim");
                StatusCode::BAD_REQUEST
            })?;

        let entry = self.providers_by_issuer.get(iss).ok_or_else(|| {
            tracing::warn!(iss = %iss, "back-channel logout: unknown issuer");
            StatusCode::BAD_REQUEST
        })?;

        // 1. Verify JWT signature using the provider's JWKS.
        //    On unknown `kid`, refresh the JWKS and retry once (key rotation).
        //    pattern-match on the typed `OAuthError::UnknownKid`
        //    variant rather than substring-matching the error message.
        let payload = match entry.provider.verify_logout_jwt(token) {
            Ok(p) => p,
            Err(
                e @ (axess_factors::oauth::OAuthError::UnknownKid(_)
                | axess_factors::oauth::OAuthError::JwksExpired),
            ) => {
                tracing::info!(iss = %iss, reason = %e, "back-channel logout: JWKS unusable; refreshing");
                if let Err(refresh_err) = entry.provider.refresh_jwks().await {
                    tracing::warn!(iss = %iss, error = %refresh_err, "JWKS refresh failed");
                }
                entry.provider.verify_logout_jwt(token).map_err(|e| {
                    tracing::warn!(iss = %iss, error = %e, "back-channel logout: JWT verification failed after JWKS refresh");
                    StatusCode::BAD_REQUEST
                })?
            }
            Err(e) => {
                tracing::warn!(iss = %iss, error = %e, "back-channel logout: JWT verification failed");
                return Err(StatusCode::BAD_REQUEST);
            }
        };

        let provider = entry;

        // 2. Check `aud` contains the client ID.
        if !aud_contains(&payload, &provider.client_id) {
            tracing::warn!(iss = %iss, "back-channel logout: aud does not contain client_id");
            return Err(StatusCode::BAD_REQUEST);
        }

        // when aud is multi-valued, OIDC §2 requires
        // `azp == client_id`. Without this, a logout token addressed to
        // [our_client_id, other_client_id] with `azp: other_client_id`
        // would be wrongly accepted.
        if !azp_satisfied(&payload, &provider.client_id) {
            tracing::warn!(
                iss = %iss,
                "back-channel logout: aud is multi-valued and azp does not match client_id"
            );
            return Err(StatusCode::BAD_REQUEST);
        }

        // 3. Check `iat` is recent.
        match check_iat(&payload, self.clock.now().timestamp()) {
            IatCheck::Ok => {}
            IatCheck::Missing => {
                tracing::warn!("back-channel logout: missing or invalid iat claim");
                return Err(StatusCode::BAD_REQUEST);
            }
            IatCheck::OutOfRange { iat, now } => {
                tracing::warn!(
                    iat = iat,
                    now = now,
                    "back-channel logout: iat too old or in the future"
                );
                return Err(StatusCode::BAD_REQUEST);
            }
        }

        // 4. Check `events` contains the back-channel logout event.
        if !events_contains_logout(&payload) {
            tracing::warn!("back-channel logout: events claim missing back-channel logout URI");
            return Err(StatusCode::BAD_REQUEST);
        }

        // 5. Extract `sub` and/or `sid`.
        let sub = payload
            .get("sub")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let sid = payload
            .get("sid")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        if sub.is_none() && sid.is_none() {
            tracing::warn!("back-channel logout: neither sub nor sid present");
            return Err(StatusCode::BAD_REQUEST);
        }

        // 6. Must NOT contain a `nonce` claim (per spec).
        if payload.get("nonce").is_some() {
            tracing::warn!("back-channel logout: logout token must not contain nonce");
            return Err(StatusCode::BAD_REQUEST);
        }

        // OIDC Back-Channel Logout 1.0 §2.4 makes `jti` REQUIRED. Without it
        // the token cannot be replay-protected, so refuse it.
        let jti = payload
            .get("jti")
            .and_then(|v| v.as_str())
            .filter(|j| !j.is_empty())
            .map(|s| s.to_string());
        if jti.is_none() {
            tracing::warn!("back-channel logout: missing jti claim");
            return Err(StatusCode::BAD_REQUEST);
        }

        Ok(LogoutTokenClaims {
            sub,
            sid,
            iss: iss.to_string(),
            jti,
        })
    }

    /// Record this `(issuer, jti)` as seen. Returns `true` if this is the
    /// first time we have seen the pair (caller may proceed). Returns
    /// `false` if the pair was already in the cache (caller should reject
    /// as a replay). Tokens without a `jti` never reach this point:
    /// `validate_logout_token` refuses them.
    ///
    /// Entries older than [`JTI_RETENTION_SECS`] (the full span over which
    /// one token's `iat` is accepted) are dropped on each call. If
    /// the log is at [`JTI_CACHE_MAX`] capacity after that, the oldest
    /// [`JTI_EVICT_BATCH`] entries are dropped to make room. Both come off
    /// the front of an arrival-ordered queue, so the work is the number of
    /// entries removed.
    fn record_jti(&self, issuer: &str, jti: &str, now: chrono::DateTime<chrono::Utc>) -> bool {
        let cutoff = now - chrono::Duration::seconds(JTI_RETENTION_SECS);
        self.seen_jtis.record(issuer, jti, now, cutoff)
    }
}

mod jti_log;

#[cfg(test)]
mod tests;
