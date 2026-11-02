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
//! # Tenant providers
//!
//! A product where each tenant brings its own IdP builds the handler with
//! [`BackChannelLogoutHandler::with_tenant_providers`] (or
//! [`for_tenants`](BackChannelLogoutHandler::for_tenants) when every provider
//! is a tenant's). A token carries only an issuer, so the handler asks the
//! source for every tenant provider of that issuer, and the one whose client
//! id the token's `aud` names verifies it. When more than one provider (two
//! tenants, or a tenant and the global registration) has that issuer and
//! client id the token cannot be attributed to one of them, and the handler
//! refuses it with [`LogoutProviderError::Ambiguous`] instead of choosing.
//! A tenant's provider that cannot be built (its credential does not open,
//! its discovery fails) does not stop the other tenants of its issuer: a
//! token addressed to it alone is refused as retryable
//! ([`LogoutProviderError::Unavailable`], answered `503`), and one whose
//! client id it shares with another provider is still ambiguous.
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
//! - A token with a `sid` ends the one session that `sid` maps to; the
//!   sessions of its `sub` are ended only when the token has no `sid`, or the
//!   `sid` maps to no session (OIDC Back-Channel Logout 1.0 §2.4)
//! - A `sub` only ends the sessions that the same issuer established
//! - Several providers may share an issuer: the one whose client id the
//!   token's `aud` names verifies it. The `sid` map and the `jti` log are
//!   keyed by issuer, not by client: a `sid` names the session at the IdP,
//!   which is the same session whichever of its clients the token is
//!   addressed to, so a logout for one client ends the local session that
//!   IdP session established in this process whichever client logged it in
//!   (the IdP session is over for both); and a `jti` is unique per issuer,
//!   so a repeat under another client id is the same token again. See the
//!   [`sid_map`](super::sid_map) docs for the key
//! - The `typ` header, when present, must be a logout token's: `logout+jwt`
//!   (OIDC Back-Channel Logout 1.0 section 2.4 recommends explicit typing)
//!   or the `JWT` and `Logout` spellings IdPs in the field send; a token
//!   typed as another kind the same key signs (`dpop+jwt`, `at+jwt`,
//!   `id_token+jwt`) is refused. A missing `typ` is accepted, because the
//!   spec makes the type a SHOULD and IdPs omit it; the `events` and `nonce`
//!   rules above still tell a logout token from an ID token. An IdP known
//!   to send the explicit type is held to it with
//!   `OAuthProviderBuilder::with_required_logout_typ`, which refuses an
//!   untyped token too
//! - A log line carries at most a short escaped prefix of the issuer, `sub`
//!   or `sid`, since all three arrive unauthenticated
//!
//! **Signature verification:** `OAuthProviderConfig` fetches and caches the
//! IdP's JWKS keys at discovery time, and `verify_logout_jwt` validates the
//! JWT signature before processing claims. `MockOAuthProvider` skips signature
//! verification for unsigned test tokens.

mod audit;

pub use audit::{IdpSessionEnded, LogoutAudit};

use super::log_field::loggable;
use super::oauth_tenant::TenantOAuthProviders;
use crate::authn::ids::{TenantId, UserId};
use crate::session::id::SessionId;
use crate::session::store::SessionRevoker;
use axess_clock::Clock;
use axess_factors::oauth::OAuthProvider;
use axess_factors::oidc::logout_token::{
    IatCheck, JTI_RETENTION_SECS, aud_contains, azp_satisfied, check_iat, decode_jwt_payload,
    events_contains_logout,
};
use axum::extract::{Form, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
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
    /// Registered providers, keyed by issuer URL for O(1) lookup. Several
    /// providers can share an issuer (one IdP, a client per application); the
    /// token's `aud` picks the one that verifies it.
    providers_by_issuer: Arc<HashMap<String, Vec<ProviderEntry>>>,
    /// Session registry for invalidating sessions.
    registry: Arc<dyn SessionRevoker>,
    /// OIDC `(issuer, sid)` → local session mapping for `sid`-based logout,
    /// and the `(issuer, user)` index behind `sub`-based logout.
    sid_map: SidMap,
    /// Replay cache for `(issuer, jti)` pairs of recently-seen logout tokens.
    /// Within the `iat` acceptance window an attacker who captures one valid
    /// logout token must not be able to re-fire it; without this cache the
    /// 5-minute window allowed silent replay against the same `sub`/`sid`.
    /// Bounded to `JTI_CACHE_MAX` live entries per issuer, with TTL-based
    /// eviction, so one IdP's traffic cannot get another IdP's logouts
    /// refused.
    seen_jtis: Arc<jti_log::JtiLog>,
    /// Injected clock for the IAT-window check and the JTI replay window.
    /// Production wires `SystemClock`; tests inject `MockClock` so the
    /// 5-minute acceptance window can be exercised deterministically.
    clock: Arc<dyn Clock>,
    /// Told about each session the handler ends, once per session.
    audit: Option<Arc<dyn LogoutAudit>>,
    /// Per-tenant providers, searched by issuer next to the global ones.
    tenants: Option<Arc<dyn TenantOAuthProviders>>,
}

/// Why no single provider could be chosen for a logout token.
#[derive(Debug, thiserror::Error)]
pub enum LogoutProviderError {
    /// More than one provider has the token's issuer and client id, so the
    /// token cannot be attributed to one of them. The token is refused.
    #[error(
        "back-channel logout: {} providers share the issuer and client id of the token \
         (global registration: {global}, tenants: {tenants:?})",
        tenants.len() + usize::from(*global)
    )]
    Ambiguous {
        /// Whether the global registration is one of the matches.
        global: bool,
        /// The tenants whose providers match.
        tenants: Vec<TenantId>,
    },
    /// The tenant source failed while looking for providers of the issuer.
    #[error("back-channel logout: the tenant provider source failed: {0}")]
    Source(#[from] axess_factors::oauth::OAuthError),
    /// The one provider with the token's issuer and client id is a tenant's
    /// that could not be built (its configuration does not open, or its
    /// discovery failed). The token is refused as retryable: the IdP resends
    /// it, and it verifies once the configuration is fixed. Other tenants of
    /// the issuer are not affected.
    #[error(
        "back-channel logout: the provider {name} of tenant {tenant} has the token's issuer and \
         client id but could not be built: {error}"
    )]
    Unavailable {
        /// The tenant whose provider it is.
        tenant: TenantId,
        /// The provider's name within the tenant.
        name: Arc<str>,
        /// Why it could not be built.
        error: axess_factors::oauth::OAuthError,
    },
}

/// Maximum live entries the `jti` replay cache keeps per issuer. Sized so
/// that at the IAT acceptance window (300 s) and a per-second logout rate
/// well above any legitimate IdP traffic, the cache cannot itself become a
/// memory-DoS vector: the handler holds at most this many entries for each
/// issuer that sent a verified token within the replay window, since only a
/// verified token reaches the cache and an issuer's entries leave with it.
const JTI_CACHE_MAX: usize = 16 * 1024;

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
    /// The tenant the provider belongs to; `None` for a global one.
    tenant: Option<TenantId>,
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
        let mut by_issuer: HashMap<String, Vec<ProviderEntry>> = HashMap::new();

        for provider in providers {
            if let (Some(issuer), Some(client_id)) = (provider.issuer(), provider.client_id()) {
                let entries = by_issuer.entry(issuer.to_string()).or_default();
                // The same issuer AND client id twice cannot be told apart by
                // any token, so the second is ignored rather than allowed to
                // replace the first.
                if let Some(first) = entries.iter().find(|e| e.client_id == client_id) {
                    tracing::warn!(
                        first = %first.name,
                        duplicate = %provider.name(),
                        "back-channel logout: two providers share an issuer and a client id; \
                         the first one verifies, the duplicate is ignored"
                    );
                    continue;
                }
                entries.push(ProviderEntry {
                    client_id: client_id.to_string(),
                    name: provider.name().clone(),
                    provider: provider.clone(),
                    tenant: None,
                });
            }
        }

        if by_issuer.is_empty() {
            return None;
        }

        Some(Self {
            providers_by_issuer: Arc::new(by_issuer),
            registry,
            sid_map,
            seen_jtis: Arc::new(jti_log::JtiLog::new(JTI_CACHE_MAX)),
            clock,
            audit: None,
            tenants: None,
        })
    }

    /// A handler whose providers are all tenants', from `source`.
    ///
    /// [`new`](Self::new) returns `None` without a global provider that
    /// advertises an issuer and a client id; an adopter whose every provider
    /// is a tenant's has none, and builds the handler here instead. Add the
    /// global providers too with [`new`](Self::new) and
    /// [`with_tenant_providers`](Self::with_tenant_providers).
    pub fn for_tenants(
        source: Arc<dyn TenantOAuthProviders>,
        registry: Arc<dyn SessionRevoker>,
        sid_map: SidMap,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            providers_by_issuer: Arc::new(HashMap::new()),
            registry,
            sid_map,
            seen_jtis: Arc::new(jti_log::JtiLog::new(JTI_CACHE_MAX)),
            clock,
            audit: None,
            tenants: Some(source),
        }
    }

    /// Also verify tokens from the issuers of tenants' providers, found in
    /// `source` (pass
    /// [`AuthnService::tenant_oauth_providers`](crate::authn::service::AuthnService::tenant_oauth_providers)).
    /// The source is asked on every token whose issuer the global providers
    /// do not settle.
    #[must_use]
    pub fn with_tenant_providers(mut self, source: Arc<dyn TenantOAuthProviders>) -> Self {
        self.tenants = Some(source);
        self
    }

    /// The provider that verifies a token of issuer `iss` addressed to the
    /// client ids in `unverified` (its unverified payload), or `None` when no
    /// provider of the issuer has a client id the token names.
    ///
    /// Errors: [`LogoutProviderError::Ambiguous`] when more than one provider
    /// (global or a tenant's) matches; [`LogoutProviderError::Unavailable`]
    /// when the one match is a tenant's provider that could not be built;
    /// [`LogoutProviderError::Source`] when the tenant source fails.
    async fn entry_for(
        &self,
        iss: &str,
        unverified: &serde_json::Value,
    ) -> Result<Option<ProviderEntry>, LogoutProviderError> {
        // Providers can share an issuer; the one whose client id the token
        // is addressed to verifies it. The first global match stands for the
        // global registration, as before tenants existed.
        let global = self
            .providers_by_issuer
            .get(iss)
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|e| aud_contains(unverified, &e.client_id))
            })
            .cloned();
        let Some(source) = &self.tenants else {
            return Ok(global);
        };
        let found = source.providers_for_issuer(iss).await?;
        let mut tenant_matches: Vec<ProviderEntry> = Vec::new();
        for built in found.providers {
            let Some(client_id) = built.provider.client_id().map(str::to_string) else {
                continue;
            };
            if aud_contains(unverified, &client_id) {
                tenant_matches.push(ProviderEntry {
                    client_id,
                    name: built.name,
                    provider: built.provider,
                    tenant: Some(built.tenant),
                });
            }
        }
        // A provider that could not be built still counts where the token is
        // addressed to it: it may be the one the IdP meant, so it neither
        // drops out of an ambiguity nor lets a token through to another.
        // Providers of the issuer the token is not addressed to do not matter.
        let broken: Vec<_> = found
            .broken
            .into_iter()
            .filter(|b| aud_contains(unverified, &b.client_id))
            .collect();
        for b in &broken {
            tracing::warn!(
                tenant = %b.tenant,
                provider = %b.name,
                error = %b.error,
                "back-channel logout: a tenant provider the token is addressed to could not be built"
            );
        }
        if usize::from(global.is_some()) + tenant_matches.len() + broken.len() > 1 {
            return Err(LogoutProviderError::Ambiguous {
                global: global.is_some(),
                tenants: tenant_matches
                    .iter()
                    .filter_map(|e| e.tenant)
                    .chain(broken.iter().map(|b| b.tenant))
                    .collect(),
            });
        }
        if let Some(b) = broken.into_iter().next() {
            return Err(LogoutProviderError::Unavailable {
                tenant: b.tenant,
                name: b.name,
                error: b.error,
            });
        }
        Ok(global.or_else(|| tenant_matches.pop()))
    }

    /// Report every session this handler ends to `audit`.
    ///
    /// Without it an IdP-initiated logout leaves no audit row: the sessions
    /// end in the registry and nothing else hears of it. Pass
    /// [`AuthnService::backchannel_logout_audit`](crate::authn::service::AuthnService::backchannel_logout_audit)
    /// for the `SessionInvalidated` rows the rest of the audit trail uses.
    #[must_use]
    pub fn with_audit(mut self, audit: Arc<dyn LogoutAudit>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Tell the audit hook, if any, that a session ended. A failure is
    /// logged: the session is already gone and the token already spent.
    async fn report_ended(&self, iss: &str, user_id: &UserId, session_id: &SessionId) {
        let Some(audit) = &self.audit else {
            return;
        };
        let ended = IdpSessionEnded {
            iss: iss.to_string(),
            user_id: *user_id,
            session_id: *session_id,
        };
        if let Err(e) = audit.session_ended(&ended).await {
            tracing::error!(
                iss = %loggable(iss),
                error = %e,
                "back-channel logout: the audit write failed; the session is ended"
            );
        }
    }

    /// POST /auth/backchannel-logout
    ///
    /// Content-Type: application/x-www-form-urlencoded
    /// Body: `logout_token=<JWT>`
    ///
    /// Returns 200 on success, 400 on invalid token, 503 when the replay log
    /// is full or when the session registry could not end a session the
    /// token names (the token is then left unspent, its mappings stay, and
    /// the IdP's retry ends what is left). Every answer carries
    /// `Cache-Control: no-store`, as OIDC Back-Channel Logout 1.0 section 2.8
    /// asks of the logout endpoint.
    pub async fn handle_backchannel_logout(
        state: State<BackChannelLogoutHandler>,
        params: Form<LogoutParams>,
    ) -> Response {
        let status = match Self::handle_outcome(state, params).await {
            Ok(status) | Err(status) => status,
        };
        (status, [(header::CACHE_CONTROL, "no-store")]).into_response()
    }

    /// The status the endpoint answers with, `Ok` for a token acted on and
    /// `Err` for one refused.
    pub(crate) async fn handle_outcome(
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
        handler.admit_jti(&claims.iss, jti)?;

        tracing::info!(
            iss = %loggable(&claims.iss),
            has_sub = claims.sub.is_some(),
            has_sid = claims.sid.is_some(),
            "back-channel logout: invalidating session(s)"
        );

        // If `sid` is present, invalidate the specific session mapped to this
        // OIDC session ID. Look up by `(issuer, sid)`; `sid` alone is not
        // unique across providers. When the `sid` maps to a session, that
        // session alone ends: the token is a statement about one IdP
        // session, and its `sub` (OIDC Back-Channel Logout 1.0 §2.4 asks for
        // every session of the subject only when there is no `sid`) must not
        // widen it to the user's other sessions.
        //
        // Each session is ended in the registry first; its mappings are
        // dropped and its audit row written only once the registry confirmed.
        // A revocation the registry could not carry out leaves the session
        // live, so its mappings stay for the retry, the `jti` is forgotten
        // (the resend is not a replay) and the answer is retryable: OIDC
        // Back-Channel Logout 1.0 section 2.8 has the OP retry on a non-200.
        let sid_outcome = handler.end_by_sid(&claims).await;

        // End the sessions of the IdP subject that THIS issuer established
        // when the token has no `sid`, or its `sid` maps to nothing (the
        // mapping was dropped at capacity: the session may be live, and a
        // logout that ends nothing is the worse failure). The sid map records
        // `(issuer, sid)` and its subject registry records
        // `(issuer, sub) -> (local user, session)`, the latter for every OAuth
        // login including one whose ID token had no `sid`. `sub` is the IdP's
        // own identifier and is looked up as such: after account linking it
        // differs from the local user id the session is registered under, so
        // each hit carries that id for the registry call. A subject with no
        // entry under `claims.iss` was not authenticated by it, and an IdP
        // must not be able to log out users it never authenticated, nor end
        // sessions that came from another issuer or from a password or
        // passkey login.
        let failed = match sid_outcome {
            SidOutcome::Ended => false,
            SidOutcome::Failed => true,
            SidOutcome::Unmapped => handler.end_by_sub(&claims).await,
        };

        if failed {
            // The token did its work only in part. Leave it unspent so the
            // IdP's resend acts on what is left; the sessions already ended
            // are out of the map and are not ended twice.
            handler.seen_jtis.forget(&claims.iss, jti);
            return Err(StatusCode::SERVICE_UNAVAILABLE);
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

        // Read from the unverified payload only to choose whose keys to
        // verify with: the verified payload is checked for `aud` again below.
        let entry = match self.entry_for(iss, &unverified).await {
            Ok(Some(entry)) => entry,
            Ok(None) => {
                // The issuer is the sender's own claim on an endpoint anyone
                // can reach; it is not a reason to write a stranger's string
                // to the warn log.
                tracing::debug!(
                    iss = %loggable(iss),
                    "back-channel logout: no provider of this issuer has a client id the \
                     token's aud names"
                );
                return Err(StatusCode::BAD_REQUEST);
            }
            Err(e @ LogoutProviderError::Ambiguous { .. }) => {
                tracing::warn!(iss = %loggable(iss), error = %e, "back-channel logout refused");
                return Err(StatusCode::BAD_REQUEST);
            }
            Err(e @ (LogoutProviderError::Source(_) | LogoutProviderError::Unavailable { .. })) => {
                // Retryable: the IdP sends the token again.
                tracing::warn!(iss = %loggable(iss), error = %e, "back-channel logout refused");
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
        };

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
                tracing::info!(iss = %loggable(iss), reason = %e, "back-channel logout: JWKS unusable; refreshing");
                if let Err(refresh_err) = entry.provider.refresh_jwks().await {
                    tracing::warn!(iss = %loggable(iss), error = %refresh_err, "JWKS refresh failed");
                }
                entry.provider.verify_logout_jwt(token).map_err(|e| {
                    tracing::warn!(iss = %loggable(iss), error = %e, "back-channel logout: JWT verification failed after JWKS refresh");
                    StatusCode::BAD_REQUEST
                })?
            }
            Err(e) => {
                tracing::warn!(iss = %loggable(iss), error = %e, "back-channel logout: JWT verification failed");
                return Err(StatusCode::BAD_REQUEST);
            }
        };

        let provider = entry;

        // 2. Check `aud` contains the client ID.
        if !aud_contains(&payload, &provider.client_id) {
            tracing::warn!(iss = %loggable(iss), "back-channel logout: aud does not contain client_id");
            return Err(StatusCode::BAD_REQUEST);
        }

        // when aud is multi-valued, OIDC §2 requires
        // `azp == client_id`. Without this, a logout token addressed to
        // [our_client_id, other_client_id] with `azp: other_client_id`
        // would be wrongly accepted.
        if !azp_satisfied(&payload, &provider.client_id) {
            tracing::warn!(
                iss = %loggable(iss),
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

    /// Refuse a token whose `(issuer, jti)` was seen before (a replay), or
    /// that the replay log has no room to record (retryable); record it
    /// otherwise.
    fn admit_jti(&self, iss: &str, jti: &str) -> Result<(), StatusCode> {
        match self.record_jti(iss, jti, self.clock.now()) {
            Recorded::New => {}
            Recorded::Replay => {
                tracing::warn!(
                    iss = %loggable(iss),
                    "back-channel logout: jti replay rejected"
                );
                return Err(StatusCode::BAD_REQUEST);
            }
            Recorded::Full => {
                // This issuer's partition of the log is full of live entries
                // and forgets none of them. The token was not recorded, so
                // the IdP's retry is accepted once entries age out; other
                // issuers' tokens are unaffected.
                tracing::warn!(
                    iss = %loggable(iss),
                    capacity = JTI_CACHE_MAX,
                    "back-channel logout jti log is full of this issuer's live entries; \
                     refusing the token (retryable) rather than forgetting a live one"
                );
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
        }
        Ok(())
    }

    /// Record this `(issuer, jti)` as seen: [`Recorded::New`] the first time,
    /// [`Recorded::Replay`] when the log still holds the pair, and
    /// [`Recorded::Full`] when the pair is new but the issuer's partition of
    /// the log has no room. Tokens without a `jti` never reach this point:
    /// `validate_logout_token` refuses them.
    ///
    /// Entries older than [`JTI_RETENTION_SECS`] (the full span over which
    /// one token's `iat` is accepted) are dropped on each call, off the front
    /// of an arrival-ordered queue, so the work is the number of entries
    /// removed. An issuer at [`JTI_CACHE_MAX`] live entries after that
    /// refuses its new pair; the log never forgets a live one to make room,
    /// and holds the other issuers' entries apart.
    fn record_jti(&self, issuer: &str, jti: &str, now: chrono::DateTime<chrono::Utc>) -> Recorded {
        let cutoff = now - chrono::Duration::seconds(JTI_RETENTION_SECS);
        self.seen_jtis.record(issuer, jti, now, cutoff)
    }
}

mod ending;
mod jti_log;
use ending::SidOutcome;
use jti_log::Recorded;

#[cfg(test)]
mod audit_tests;
#[cfg(test)]
mod failure_tests;
#[cfg(test)]
mod scoping_tests;
#[cfg(test)]
mod tenant_tests;
#[cfg(test)]
mod tests;
