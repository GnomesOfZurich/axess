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
//! Every request is answered before it is authenticated: it reads the issuer
//! out of the unverified token, and with tenant providers each request that
//! names a configured issuer costs a read of the tenant source and may rebuild
//! or revalidate the providers it returns (discovery included) before any
//! signature is checked. The handler remembers an issuer the source has no
//! provider for for 30 seconds
//! ([`with_unknown_issuer_memory`](BackChannelLogoutHandler::with_unknown_issuer_memory)),
//! which bounds the cost of a loop of made-up issuers; it cannot bound a loop
//! that names a real one. Key the rate limit on the client address, as for the
//! front-channel route, and keep the limit low: an IdP sends a few tokens a
//! minute.
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
//! id the token's `aud` names verifies it. When two tenants' providers have
//! that issuer and client id the token cannot be attributed to one of them,
//! and the handler refuses it with [`LogoutProviderError::Ambiguous`] instead
//! of choosing. The global registration is the operator's and wins: a tenant
//! provider with its issuer and client id is ignored (and logged), never a
//! reason to refuse the token. The tenant directory refuses to register such a
//! provider in the first place.
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
use super::replay_log::{LogoutReplayLog, Recorded};
use super::sid_store::SidStore;
use crate::authn::ids::{TenantId, UserId};
use crate::metrics::SessionMetrics;
use crate::session::id::SessionId;
use crate::session::store::SessionRevoker;
use axess_clock::Clock;
use axess_factors::oauth::OAuthProvider;
use axess_factors::oidc::logout_token::{aud_contains, azp_satisfied};
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
    sid_map: Arc<dyn SidStore>,
    /// Replay cache for `(issuer, jti)` pairs of recently-seen logout tokens.
    /// Within the `iat` acceptance window an attacker who captures one valid
    /// logout token must not be able to re-fire it; without this cache the
    /// 5-minute window allowed silent replay against the same `sub`/`sid`.
    /// Bounded to `JTI_CACHE_MAX` live entries per issuer, with TTL-based
    /// eviction, so one IdP's traffic cannot get another IdP's logouts
    /// refused.
    /// The log the handler records `jti`s in: an in-process one unless replaced
    /// by [`with_replay_log`](Self::with_replay_log) with one the instances
    /// share.
    replay: Arc<dyn LogoutReplayLog>,
    /// Told when a verified token ends no session.
    metrics: Option<Arc<dyn SessionMetrics>>,
    /// Issuers the tenant source recently had no provider for, so a loop of
    /// requests naming one costs one source read per interval.
    unknown_issuers: Arc<unknown_issuers::UnknownIssuers>,
    /// Injected clock for the IAT-window check and the JTI replay window.
    /// Production wires `SystemClock`; tests inject `MockClock` so the
    /// 5-minute acceptance window can be exercised deterministically.
    clock: Arc<dyn Clock>,
    /// Told about each session the handler ends, once per session.
    audit: Option<Arc<dyn LogoutAudit>>,
    /// Per-tenant providers, searched by issuer next to the global ones.
    tenants: Option<Arc<dyn TenantOAuthProviders>>,
}

/// The pair of a token being acted on. [`finish`](Self::finish) settles it as
/// spent, or forgets it when the action failed. Dropped without finishing (the
/// request was cancelled), it forgets the pair on a task of its own, so the
/// resend is acted on.
struct ActingOn {
    log: Arc<dyn LogoutReplayLog>,
    issuer: String,
    jti: String,
    done: bool,
}

impl ActingOn {
    async fn finish(mut self, acted: bool) {
        // `done` follows the await it guards: a request cancelled while the
        // log is taking the outcome still has its pair forgotten by `Drop`.
        let result = if acted {
            self.log.settle(&self.issuer, &self.jti).await
        } else {
            self.log.forget(&self.issuer, &self.jti).await
        };
        self.done = true;
        if let Err(e) = result {
            tracing::warn!(
                iss = %loggable(&self.issuer),
                error = %e,
                "back-channel logout: the replay log did not take the outcome of a token"
            );
        }
    }
}

impl Drop for ActingOn {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let (log, issuer, jti) = (
            Arc::clone(&self.log),
            std::mem::take(&mut self.issuer),
            std::mem::take(&mut self.jti),
        );
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = log.forget(&issuer, &jti).await;
            });
        }
    }
}

/// Whether the unverified payload of a logout token is addressed to
/// `client_id`: its `aud` names the client and its `azp`, when it has one,
/// is the client. A token for two clients of one issuer names the one it is
/// for in `azp`, so the lookup must not stop at the first client in `aud`.
fn addressed_to(unverified: &serde_json::Value, client_id: &str) -> bool {
    aud_contains(unverified, client_id) && azp_satisfied(unverified, client_id)
}

/// The negative cache a handler starts with.
fn default_unknown_issuers() -> Arc<unknown_issuers::UnknownIssuers> {
    Arc::new(unknown_issuers::UnknownIssuers::new(
        chrono::Duration::seconds(unknown_issuers::DEFAULT_TTL_SECS),
    ))
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
    /// The tenant whose provider verified the token; `None` for a global
    /// provider. The sessions the token ends belong to this tenant.
    pub tenant: Option<TenantId>,
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
            sid_map: Arc::new(sid_map),
            replay: Arc::new(jti_log::JtiLog::new(JTI_CACHE_MAX)),
            metrics: None,
            unknown_issuers: default_unknown_issuers(),
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
            sid_map: Arc::new(sid_map),
            replay: Arc::new(jti_log::JtiLog::new(JTI_CACHE_MAX)),
            metrics: None,
            unknown_issuers: default_unknown_issuers(),
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

    /// Remember an issuer the tenant source has no provider for, for `ttl`
    /// (default 30 seconds), so an anonymous loop of tokens naming made-up
    /// issuers costs one source read per interval and not one per request.
    /// `Duration::ZERO` remembers nothing. A provider added through
    /// `LiveTenantOAuthProviders` or `StoredTenantOAuthProviders` is found at
    /// once (they change the source's
    /// [`generation`](TenantOAuthProviders::generation), which voids a remembered
    /// miss); a source that does not implement it, or a store another process
    /// writes, is found once the interval has passed.
    #[must_use]
    pub fn with_unknown_issuer_memory(mut self, ttl: std::time::Duration) -> Self {
        self.unknown_issuers = Arc::new(unknown_issuers::UnknownIssuers::new(
            // A TTL past chrono's range remembers for as long as chrono can
            // count, not for no time at all.
            chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::MAX),
        ));
        self
    }

    /// Read the `sid` mappings and subject records from `store` instead of
    /// the [`SidMap`] the constructor took, so a token that reaches this
    /// instance finds the session another instance established. Pass
    /// [`AuthnService::sid_store`](crate::authn::service::AuthnService::sid_store),
    /// the store the login path writes to.
    #[must_use]
    pub fn with_sid_store(mut self, store: Arc<dyn SidStore>) -> Self {
        self.sid_map = store;
        self
    }

    /// Record the `jti`s of the logout tokens in `log` instead of in this
    /// process, so a token cannot be replayed to another instance inside the
    /// `iat` window and the record survives a restart. `ValkeyReplayLog`
    /// (feature `valkey`) is the shared one. If the log fails, the token is
    /// answered with a retryable `503` and acted on when the IdP resends it.
    #[must_use]
    pub fn with_replay_log(mut self, log: Arc<dyn LogoutReplayLog>) -> Self {
        self.replay = log;
        self
    }

    /// Count, through `metrics`, the logout tokens that verified but ended no
    /// session ([`SessionMetrics::back_channel_logout_unmatched`]). The IdP
    /// is answered `200` either way, as OpenID Connect Back-Channel Logout
    /// 1.0 has it; the count is how an operator sees the rate. A rate that
    /// does not fall is instances that do not share a `sid` store.
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<dyn SessionMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
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
        handler.admit_jti(&claims.iss, jti).await?;
        // Until the token has been acted on, its pair is in flight (recording
        // it set that): a resend meanwhile is told to come again, and a
        // delivery that ends any other way than done (a failure, a dropped
        // request) leaves the pair forgotten so the resend is acted on.
        let acting = ActingOn {
            log: Arc::clone(&handler.replay),
            issuer: claims.iss.clone(),
            jti: jti.clone(),
            done: false,
        };
        let outcome = handler.act_on(&claims).await;
        acting.finish(outcome.is_ok()).await;
        outcome
    }

    /// End the sessions a verified, admitted token names.
    async fn act_on(&self, claims: &LogoutTokenClaims) -> Result<StatusCode, StatusCode> {
        let handler = self;
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
        let sid_outcome = handler.end_by_sid(claims).await;

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
        let (failed, matched) = match sid_outcome {
            SidOutcome::Ended => (false, true),
            SidOutcome::Failed => (true, true),
            SidOutcome::Unmapped => {
                let by_sub = handler.end_by_sub(claims).await;
                (by_sub.failed, by_sub.found > 0)
            }
        };

        if failed {
            // The token did its work only in part. Leave it unspent so the
            // IdP's resend acts on what is left; the sessions already ended
            // are out of the map and are not ended twice.
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }

        if !matched {
            // The token verified and named nothing this instance can find.
            // The answer stays `200`, as the OIDC specification has it for a
            // session the endpoint does not know; the count is how an
            // operator sees instances that do not share a `sid` store.
            tracing::warn!(
                iss = %loggable(&claims.iss),
                "back-channel logout: the token verified but no session was found"
            );
            if let Some(metrics) = &handler.metrics {
                metrics.back_channel_logout_unmatched();
            }
        }

        Ok(StatusCode::OK)
    }

    /// Refuse a token whose `(issuer, jti)` was seen before (a replay), or
    /// that the replay log has no room to record or could not be asked
    /// (retryable); record it otherwise.
    ///
    /// The log forgets entries older than `JTI_RETENTION_SECS` (the full
    /// span over which one token's `iat` is accepted). The in-process log
    /// holds [`JTI_CACHE_MAX`] live entries per issuer and refuses its new
    /// pair at that bound; it never forgets a live one to make room, and
    /// holds the other issuers' entries apart.
    async fn admit_jti(&self, iss: &str, jti: &str) -> Result<(), StatusCode> {
        let recorded = match self.replay.record(iss, jti, self.clock.now()).await {
            Ok(recorded) => recorded,
            Err(e) => {
                tracing::warn!(
                    iss = %loggable(iss),
                    error = %e,
                    "back-channel logout: the replay log could not be asked; \
                     refusing the token (retryable)"
                );
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
        };
        match recorded {
            Recorded::New => {}
            Recorded::InFlight => {
                tracing::info!(
                    iss = %loggable(iss),
                    "back-channel logout: the first delivery of this token is still being \
                     acted on; asking for a resend"
                );
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
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
}

mod ending;
mod jti_log;
mod provider_lookup;
mod unknown_issuers;
mod verify;
use ending::SidOutcome;
pub use provider_lookup::LogoutProviderError;

#[cfg(test)]
mod audit_tests;
#[cfg(test)]
mod failure_tests;
#[cfg(test)]
mod in_flight_tests;
#[cfg(test)]
mod scoping_tests;
#[cfg(test)]
mod shared_tests;
#[cfg(test)]
mod tenant_tests;
#[cfg(test)]
mod tests;
#[cfg(all(test, feature = "valkey"))]
mod valkey_tests;
