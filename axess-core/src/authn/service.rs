//! Authentication service: orchestrates identity lookup, factor verification,
//! and session management.
//!
//! Hold an `Arc<AuthnService<…>>` in Axum state. The login flow is:
//!
//! 1. [`AuthnService::begin_login`]: identifies the user, starts the MFA chain.
//! 2. [`AuthnService::prepare_factor`]: for challenge-based factors (EmailOtp),
//!    generates and stores the challenge, returns data for the app to deliver.
//!    For simple factors (Password, TOTP, HOTP), returns `Ready` immediately.
//! 3. [`AuthnService::verify_factor`]: verifies the credential the user submits.
//!
//! # Enforcing session validity on protected routes
//!
//! The `login_required!` macro checks `is_authenticated()` on the session
//! state, but does **not** consult the session registry. If you use
//! [`AuthnService::with_registry`] for forced-logout support, use
//! [`require_valid_session`] middleware instead:
//!
//! ```rust,ignore
//! use axess::require_valid_session;
//!
//! let authn = AuthnService::new(identity, factors)
//!     .with_registry(registry);
//!
//! let validator = authn.session_validator();
//!
//! let app = Router::new()
//!     .route("/api/protected", get(my_handler))
//!     .layer(require_valid_session(validator));
//! ```
//!
//! [`SessionValidator`] is a lightweight, `Clone` handle that avoids threading
//! the full `AuthnService` generic type through your middleware stack.

// ── Sub-modules ──────────────────────────────────────────────────────────────

mod account;
mod factor_pipeline;
mod login;
pub mod outcomes;
#[cfg(feature = "device")]
pub mod step_up;
mod verification;

#[cfg(feature = "fido2")]
pub(crate) mod fido2_service;

#[cfg(feature = "ldap")]
mod ldap_service;

#[cfg(feature = "oauth")]
pub(crate) mod oauth_service;

pub mod session_validator;

pub use outcomes::{FactorOutcome, LoginOutcome, PrepareOutcome, SignupOutcome};
pub use session_validator::{NoSessionRegistryError, SessionValidator, require_valid_session};
#[cfg(feature = "device")]
pub use step_up::{StepUpPolicy, StepUpPolicyBuilder, decide_step_up};

// ── Imports ──────────────────────────────────────────────────────────────────

use crate::{
    authn::store::{FactorStore, IdentityStore},
    session::store::{SessionRegistry, SessionRegistryAdapter, SessionRegistryHandle},
};
use axess_clock::{Clock, SystemClock};
use axess_rng::{SecureRng, SystemRng};
use std::sync::Arc;

// ── AuthnService ──────────────────────────────────────────────────────────────

/// Authentication service: orchestrates identity lookup, factor verification,
/// and session management.
///
/// Generic over:
/// - `I`: [`IdentityStore`]
/// - `F`: [`FactorStore`] (same error type as `I`)
///
/// RNG and Clock are held as `Arc<dyn SecureRng>` / `Arc<dyn Clock>` so
/// the service shape is `AuthnService<I, F>` regardless of which
/// concrete RNG / clock the adopter wires in. Swap clocks for DST via
/// [`AuthnService::with_clock`] without changing the type; adopters
/// can store the service in `Arc<AppState>` and inject a `MockClock`
/// for tests against the same `<I, F>` shape.
pub struct AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore,
{
    pub(crate) identity: Arc<I>,
    pub(crate) factors: Arc<F>,
    pub(crate) registry: Option<Arc<dyn SessionRegistryHandle>>,
    pub(crate) metrics: Arc<dyn crate::metrics::AuthnMetrics>,
    /// Maximum concurrent sessions per user. `None` means unlimited.
    pub(crate) max_sessions_per_user: Option<usize>,
    pub(crate) rng: Arc<dyn SecureRng>,
    pub(crate) clock: Arc<dyn Clock>,
    #[cfg(feature = "fido2")]
    pub(crate) fido2: Option<Arc<dyn axess_factors::fido2::Fido2Provider>>,
    #[cfg(feature = "fido2")]
    pub(crate) fido2_options: crate::authn::factor::Fido2Options,
    #[cfg(feature = "ldap")]
    pub(crate) ldap: Option<Arc<dyn axess_factors::ldap::LdapProvider>>,
    #[cfg(feature = "oauth")]
    pub(crate) oauth_providers: crate::federation::oauth::OAuthProviderRegistry,
    /// Shared OIDC `sid` → `(user_id, session_id, inserted_at)` map for back-channel logout.
    /// The timestamp enables TTL-based eviction of stale entries.
    #[cfg(feature = "oauth")]
    pub(crate) sid_map: crate::federation::backchannel_logout::SidMap,
}

// ── Constructors and builders ────────────────────────────────────────────────

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Create a new service with OS RNG and system clock.
    pub fn new(identity: I, factors: F) -> Self {
        Self {
            identity: Arc::new(identity),
            factors: Arc::new(factors),
            registry: None,
            metrics: Arc::new(crate::metrics::NoopMetrics),
            max_sessions_per_user: None,
            rng: Arc::new(SystemRng),
            clock: Arc::new(SystemClock),
            #[cfg(feature = "fido2")]
            fido2: None,
            #[cfg(feature = "fido2")]
            fido2_options: Default::default(),
            #[cfg(feature = "ldap")]
            ldap: None,
            #[cfg(feature = "oauth")]
            oauth_providers: Default::default(),
            #[cfg(feature = "oauth")]
            sid_map: Default::default(),
        }
    }
}

impl<B> AuthnService<B, B>
where
    B: crate::authn::store::AuthnBackend + Clone,
{
    /// Create a new service from a backend that implements both
    /// [`IdentityStore`] and [`FactorStore`] (typical SQL pattern).
    /// Equivalent to `AuthnService::new(backend.clone(), backend)`:
    /// removes the universal `(b.clone(), b)` ceremony at every example.
    pub fn from_backend(backend: B) -> Self {
        Self::new(backend.clone(), backend)
    }
}

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Stamp the builder with `self.clock.now()` and dispatch the
    /// resulting [`AuthEvent`](crate::authn::event::AuthEvent) to the
    /// identity store, logging at `tracing::error!` if the store
    /// rejects the write.
    ///
    /// This is the canonical audit-emit entry point for the crate.
    /// The vast majority of audit emits share the shape
    /// `builder.build_at(self.clock.now())` followed by an identity
    /// `record_event` that must not block the request flow on store
    /// failure. Threading the clock through the builder finisher at
    /// every call site obscures intent (the timestamp is always *now*)
    /// and risks drift if the clock dependency ever changes shape
    /// (matching how the RNG threading was retrofitted). `emit_audit`
    /// centralises the `clock + record + log` pattern so call sites
    /// read as `self.emit_audit(builder.with_factor(kind)).await`:
    /// the audit content is what the reader cares about.
    ///
    /// Audit-store outages ALWAYS surface as
    /// `tracing::error!` (with `event_type` and `event_status` context),
    /// matching the same approach used in `verify_factor`. Audit-store
    /// errors must never block an auth flow (the user's request
    /// continues), but they must never be silent either (a SOC blind
    /// spot is its own incident).
    ///
    /// The underlying `record_event_or_log` is private;
    /// callers go through [`emit_audit`](Self::emit_audit) for the
    /// "now" case and [`emit_audit_at`](Self::emit_audit_at) for the
    /// captured-timestamp case. The single intentional bypass is the
    /// audit-failure-with-context emit in `factor_pipeline.rs`,
    /// which calls `self.identity.record_event(...)` directly so its
    /// `tracing::error!` can include `user_id = %user_id`: context
    /// `record_event_or_log` doesn't have. That bypass is documented
    /// at the call site.
    pub(crate) async fn emit_audit(&self, builder: crate::authn::event::AuthEventBuilder) {
        self.emit_audit_at(builder, self.clock.now()).await;
    }

    /// Stamp the builder with the given `event_time` and dispatch
    /// to the identity store (with the same fail-soft logging as
    /// [`emit_audit`](Self::emit_audit)).
    ///
    /// Use this when several events in the same flow must share a
    /// single timestamp (e.g. a successful signup and the resulting
    /// `Authenticated` row should be the same instant): capture the
    /// time once upstream and pass it to each emit. Calls that just
    /// want "now" should use [`emit_audit`](Self::emit_audit).
    pub(crate) async fn emit_audit_at(
        &self,
        builder: crate::authn::event::AuthEventBuilder,
        event_time: chrono::DateTime<chrono::Utc>,
    ) {
        let event = builder.build_at(event_time);
        let event_type = format!("{:?}", event.event_type);
        let event_status = format!("{:?}", event.event_status);
        if let Err(e) = self.identity.record_event(event).await {
            tracing::error!(
                error = %e,
                event_type = %event_type,
                event_status = %event_status,
                "identity store rejected audit event; SOC visibility lost for this attempt"
            );
        }
    }

    /// Replace the RNG (for DST). Type-erased; service shape unchanged.
    pub fn with_rng(mut self, rng: impl SecureRng) -> Self {
        self.rng = Arc::new(rng);
        self
    }

    /// Replace the clock (for DST). Type-erased; service shape unchanged.
    pub fn with_clock(mut self, clock: impl Clock) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    /// Attach a FIDO2/WebAuthn provider.
    #[cfg(feature = "fido2")]
    pub fn with_fido2(mut self, provider: impl axess_factors::fido2::Fido2Provider) -> Self {
        self.fido2 = Some(Arc::new(provider));
        self
    }

    /// Configure FIDO2 ceremony timeout and other options stored on the service.
    #[cfg(feature = "fido2")]
    pub fn with_fido2_options(mut self, options: crate::authn::factor::Fido2Options) -> Self {
        self.fido2_options = options;
        self
    }

    /// Attach an LDAP provider for directory-based password verification.
    ///
    /// When a user's factor chain includes [`FactorKind::LdapBind`](crate::authn::factor::FactorKind::LdapBind), the
    /// service will verify their password via an LDAP simple bind against
    /// this provider instead of checking a local password hash.
    ///
    /// ```rust,ignore
    /// let ldap = LdapProviderConfig::new(
    ///     "ldaps://ad.corp.example.com",
    ///     "{user}@corp.example.com",
    /// );
    /// let authn = AuthnService::new(identity, factors).with_ldap(ldap);
    /// ```
    #[cfg(feature = "ldap")]
    pub fn with_ldap(mut self, provider: impl axess_factors::ldap::LdapProvider) -> Self {
        self.ldap = Some(Arc::new(provider));
        self
    }

    /// Register an OAuth/OIDC identity provider.
    ///
    /// Call once per provider at startup. Multiple providers can be registered
    /// (e.g. Google + GitHub + corporate IdP).
    ///
    /// # Tenancy
    ///
    /// **Providers are registered globally on `AuthnService`, not per-tenant.**
    /// Two consequences operators must plan for:
    ///
    /// 1. **Same IdP, multiple tenants**: when tenant A and tenant B both
    ///    federate to the same IdP (e.g. a single Azure AD app for two
    ///    SaaS tenants), the OAuth callback alone cannot tell them apart.
    ///    The application MUST use
    ///    [`begin_oauth_login_in_tenant`](Self::begin_oauth_login_in_tenant)
    ///    to bind the ceremony to a tenant up-front, and the
    ///    claims→user resolver MUST scope its lookup to the bound tenant.
    /// 2. **Per-tenant IdP configurations**: if every tenant has its own
    ///    IdP (each with distinct `client_id`/`client_secret`), use a
    ///    distinct `name` per provider (e.g. `format!("azure-tenant-{tid}")`)
    ///    and route based on the bound tenant. The library does not
    ///    enforce a per-tenant lookup; the application owns this routing.
    ///
    /// Per-tenant provider registration is intentionally not built in:
    /// most deployments use either (a) a single platform-wide IdP or
    /// (b) one provider per IdP, and the application's claims-resolver
    /// is the right place to enforce tenant binding (it already needs
    /// tenant context to look up the local user).
    #[cfg(feature = "oauth")]
    pub fn with_oauth_provider(
        mut self,
        provider: impl axess_factors::oauth::OAuthProvider,
    ) -> Self {
        self.oauth_providers.add(provider);
        self
    }

    /// Return a reference to the OAuth provider registry for introspection.
    ///
    /// Use `oauth_providers().provider_names()` or `oauth_providers().provider_count()`
    /// to list or count the configured providers.
    #[cfg(feature = "oauth")]
    pub fn oauth_providers(&self) -> &crate::federation::oauth::OAuthProviderRegistry {
        &self.oauth_providers
    }

    /// Attach a session registry for forced-logout support.
    pub fn with_registry(mut self, registry: impl SessionRegistry + 'static) -> Self {
        self.registry = Some(Arc::new(SessionRegistryAdapter(registry)));
        self
    }

    /// Whether a session registry is wired on this service. Adopters checking
    /// before calling the revocation methods can use this to short-circuit and
    /// return a clearer error than [`NoSessionRegistryError`] from deep
    /// inside a handler.
    pub fn has_session_registry(&self) -> bool {
        self.registry.is_some()
    }

    /// Invalidate every active session for a user. Used by admin "kick" and
    /// by credential-rotation paths that need to force a re-authentication.
    ///
    /// Returns `Err(NoSessionRegistryError)` when no registry is wired on
    /// the service: the caller cannot enforce revocation without one and
    /// should surface that as a 500 / configuration error rather than
    /// reporting a misleading 200 OK.
    ///
    /// Registry-backend errors (Valkey outage, replication lag) are logged
    /// at `warn` inside the wrapper and *swallowed*; the method returns
    /// `Ok(())` so the caller's flow continues. Backends that need
    /// fail-closed semantics should arrange them at the deployment layer
    /// (e.g. liveness probe gating on registry health).
    pub async fn invalidate_user_sessions(
        &self,
        user_id: &crate::authn::ids::UserId,
    ) -> Result<(), NoSessionRegistryError> {
        match &self.registry {
            Some(reg) => {
                reg.invalidate_user(user_id).await;
                Ok(())
            }
            None => Err(NoSessionRegistryError),
        }
    }

    /// Invalidate a single session for a user. Used by per-session "end"
    /// admin actions and by sibling-session-revocation paths (e.g. after
    /// disabling MFA, kill every other session except the current one).
    ///
    /// Same error contract as [`invalidate_user_sessions`](Self::invalidate_user_sessions).
    pub async fn invalidate_session(
        &self,
        user_id: &crate::authn::ids::UserId,
        session_id: &crate::session::id::SessionId,
    ) -> Result<(), NoSessionRegistryError> {
        match &self.registry {
            Some(reg) => {
                reg.invalidate_session(user_id, session_id).await;
                Ok(())
            }
            None => Err(NoSessionRegistryError),
        }
    }

    /// Enumerate active sessions for a user. Used by admin session lists,
    /// concurrent-session-limit enforcement, and by "kill every other
    /// session" flows that need to read the active set before filtering
    /// out the current session.
    ///
    /// Returns an empty vec when the registry's backend doesn't support
    /// enumeration. Returns `Err(NoSessionRegistryError)` when no
    /// registry is wired.
    pub async fn active_sessions(
        &self,
        user_id: &crate::authn::ids::UserId,
    ) -> Result<Vec<crate::session::id::SessionId>, NoSessionRegistryError> {
        match &self.registry {
            Some(reg) => Ok(reg.active_sessions(user_id).await),
            None => Err(NoSessionRegistryError),
        }
    }

    /// Set the maximum number of concurrent sessions per user.
    ///
    /// When a user authenticates and already has this many active sessions,
    /// the oldest session is evicted. `None` (default) means unlimited.
    pub fn with_max_sessions_per_user(mut self, max: usize) -> Self {
        self.max_sessions_per_user = Some(max);
        self
    }

    /// Attach a metrics hook for observability.
    ///
    /// The [`AuthnMetrics`](crate::metrics::AuthnMetrics) trait has no-op
    /// defaults; implement only the counters you need.
    pub fn with_metrics(mut self, metrics: impl crate::metrics::AuthnMetrics) -> Self {
        self.metrics = Arc::new(metrics);
        self
    }

    /// Create a [`SessionValidator`] that checks registry validity.
    ///
    /// Use this with [`require_valid_session`] middleware to enforce
    /// registry-based session checks on protected routes without threading
    /// the full `AuthnService` type through your middleware:
    pub fn session_validator(&self) -> SessionValidator {
        SessionValidator {
            registry: self.registry.clone(),
            identity: None,
        }
    }

    /// Create a [`SessionValidator`] that **also** cross-checks the session's
    /// stated `tenant_id` against the user's actual tenant on every call.
    ///
    /// Adds one `IdentityStore::get_user` lookup per `is_valid` call: wire
    /// this when your threat model includes session-store tampering or
    /// cross-environment session bleed (shared keys across dev/prod, backup
    /// restored after compromise, etc.). For deployments where the session
    /// store sits inside the same trust boundary as the identity store,
    /// the lookup overhead is wasted; use [`session_validator`](Self::session_validator)
    /// in that case.
    pub fn session_validator_with_identity_check(&self) -> SessionValidator {
        SessionValidator {
            registry: self.registry.clone(),
            identity: Some(Arc::new(session_validator::IdentityWrapper(
                self.identity.clone(),
            ))),
        }
    }
}
