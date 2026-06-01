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
//! use axess::{AuthnService, BackChannelLogoutHandler};
//! use axum::Router;
//!
//! let authn: Arc<AuthnService<_, _, _, _>> = /* … */;
//! let handler = authn.backchannel_logout_handler()
//!     .expect("requires both OAuth providers and a session registry");
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
//!
//! **Signature verification:** `OAuthProviderConfig` fetches and caches the
//! IdP's JWKS keys at discovery time, and `verify_logout_jwt` validates the
//! JWT signature before processing claims. `MockOAuthProvider` skips signature
//! verification for unsigned test tokens.

use crate::session::id::SessionId;
use crate::session::store::SessionRevoker;
use axess_clock::Clock;
use axess_factors::oauth::OAuthProvider;
use axess_factors::oidc::logout_token::{
    IatCheck, MAX_IAT_AGE_SECS, aud_contains, azp_satisfied, check_iat, decode_jwt_payload,
    events_contains_logout,
};
use axum::extract::{Form, State};
use axum::http::StatusCode;
use dashmap::DashMap;
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
/// Construct via `AuthnService::backchannel_logout_handler`.
#[derive(Clone)]
pub struct BackChannelLogoutHandler {
    /// Registered providers, keyed by issuer URL for O(1) lookup.
    providers_by_issuer: Arc<HashMap<String, ProviderEntry>>,
    /// Session registry for invalidating sessions.
    registry: Arc<dyn SessionRevoker>,
    /// OIDC `sid` → `(user_id, session_id)` mapping for `sid`-based logout.
    sid_map: SidMap,
    /// Replay cache for `(issuer, jti)` pairs of recently-seen logout tokens.
    /// Within the `iat` acceptance window an attacker who captures one valid
    /// logout token must not be able to re-fire it; without this cache the
    /// 5-minute window allowed silent replay against the same `sub`/`sid`.
    /// Bounded to `JTI_CACHE_MAX` entries with TTL-based eviction.
    seen_jtis: Arc<DashMap<(String, String), chrono::DateTime<chrono::Utc>>>,
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

/// number of entries evicted in one capacity-prune pass. Picked
/// to amortise the O(N log N) sort across the next BATCH inserts so the
/// per-call cost stays bounded under burst load. Mirrors `EVICT_BATCH`
/// in `oauth_service/login.rs::maintain_oidc_sid_map`.
const JTI_EVICT_BATCH: usize = 128;

/// Shared map of OIDC session IDs to local session identifiers.
///
/// Populated by `AuthnService::complete_oauth_login` when the IdP's ID token
/// contains a `sid` claim. Used by the back-channel logout handler to invalidate
/// individual sessions by OIDC session ID.
///
/// **Key shape:** `(issuer, sid)`. The `sid` is per-issuer in OIDC: two
/// providers can legitimately mint the same `sid` value for different
/// sessions, so the issuer must be part of the lookup key. Without this, a
/// malicious or buggy IdP could cause logout of sessions established via a
/// different provider by sending a logout token whose `sid` collides with
/// an existing mapping. Tuple value is
/// `(user_id, session_id, inserted_at)` enabling TTL-based eviction.
pub type SidKey = (String, String);
/// Lookup map from `(issuer, sid)` to the local session triple
/// `(user_id, session_id, inserted_at)` used for OIDC back-channel logout.
pub type SidMap = Arc<
    DashMap<
        SidKey,
        (
            crate::authn::ids::UserId,
            SessionId,
            chrono::DateTime<chrono::Utc>,
        ),
    >,
>;

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
    /// Token `jti` claim (when present). Used by the handler to detect
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
            seen_jtis: Arc::new(DashMap::new()),
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

        // Replay protection: if the IdP supplied a `jti`, refuse to act on
        // the same `(issuer, jti)` twice within the IAT window. Without this
        // an attacker who captures a valid logout token can re-fire it for
        // up to MAX_IAT_AGE_SECS, repeatedly poking the registry under the
        // victim's identity. Tokens without `jti` get the IAT window as
        // their only mitigation (RFC 7519 makes `jti` optional but the
        // OIDC back-channel logout spec recommends it).
        if let Some(ref jti) = claims.jti
            && !handler.record_jti(&claims.iss, jti, handler.clock.now())
        {
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

        // If `sub` is present, invalidate all sessions for that user.
        // The IdP-provided `sub` is a raw string, so we parse it into a
        // typed UserId. If parsing fails (e.g., the IdP issues a sub that
        // does not satisfy our UserId validation rules), reject the
        // request; better to fail visibly than to silently no-op a
        // logout.
        if let Some(ref sub) = claims.sub {
            match crate::authn::ids::UserId::try_new(sub.as_str()) {
                Ok(uid) => handler.registry.invalidate_user(&uid).await,
                Err(e) => {
                    tracing::warn!(
                        iss = %claims.iss,
                        sub = %sub,
                        error = %e,
                        "back-channel logout: provider sub is not a valid UserId; rejecting"
                    );
                    return Err(StatusCode::BAD_REQUEST);
                }
            }
        }

        // If `sid` is present, invalidate the specific session mapped to this
        // OIDC session ID. This handles the case where only `sid` (no `sub`) is
        // sent, or when the IdP wants to invalidate a single session without
        // affecting others. Look up by `(issuer, sid)`; `sid` alone is not
        // unique across providers.
        if let Some(ref sid) = claims.sid {
            let key: SidKey = (claims.iss.clone(), sid.clone());
            if let Some((_, (user_id, session_id, _inserted_at))) = handler.sid_map.remove(&key) {
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
            Err(axess_factors::oauth::OAuthError::UnknownKid(kid)) => {
                tracing::info!(iss = %iss, kid = %kid, "back-channel logout: kid miss; refreshing JWKS");
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

        let jti = payload
            .get("jti")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

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
    /// as a replay). Tokens without a `jti` claim are not replay-protected;
    /// the IAT window is the only mitigation in that case.
    ///
    /// Eviction:
    /// - Entries older than [`MAX_IAT_AGE_SECS`] are pruned on each call.
    /// - If the cache is at [`JTI_CACHE_MAX`] capacity after pruning, the
    ///   oldest [`JTI_EVICT_BATCH`] entries are evicted in a single sort,
    ///   O(N log N) once, amortised across the next BATCH inserts.
    fn record_jti(&self, issuer: &str, jti: &str, now: chrono::DateTime<chrono::Utc>) -> bool {
        let cutoff = now - chrono::Duration::seconds(MAX_IAT_AGE_SECS);
        let cache = self.seen_jtis.as_ref();
        cache.retain(|_, seen_at| *seen_at >= cutoff);

        if cache.len() >= JTI_CACHE_MAX {
            let mut oldest: Vec<(chrono::DateTime<chrono::Utc>, (String, String))> = cache
                .iter()
                .map(|e| (*e.value(), e.key().clone()))
                .collect();
            oldest.sort_by_key(|(ts, _)| *ts);
            for (_, evict_key) in oldest.into_iter().take(JTI_EVICT_BATCH) {
                cache.remove(&evict_key);
            }
        }

        let key = (issuer.to_string(), jti.to_string());
        cache.insert(key, now).is_none()
    }
}

#[cfg(test)]
mod tests;
