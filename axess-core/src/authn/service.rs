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
//! [`AuthnServiceBuilder::with_registry`] for forced-logout support, use
//! [`require_valid_session`] middleware instead:
//!
//! ```rust,ignore
//! use axess::require_valid_session;
//!
//! let authn = AuthnService::builder(identity, factors)
//!     .with_registry(registry)
//!     .build();
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
/// [`AuthnServiceBuilder::with_clock`] without changing the type; adopters
/// can store the service in `Arc<AppState>` and inject a `MockClock`
/// for tests against the same `<I, F>` shape.
/// A cheap handle over one `Arc` of shared collaborators, plus the
/// per-request audit context.
///
/// Cloning is a refcount bump, which is what makes
/// [`with_audit_context`](Self::with_audit_context) affordable once per
/// request. Construction goes through [`AuthnService::builder`], because
/// the collaborators must be settled before they are shared.
pub struct AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore,
{
    pub(crate) inner: Arc<AuthnServiceBuilder<I, F>>,
    /// Client metadata stamped onto every event this handle emits.
    /// `None` straight from the builder.
    pub(crate) audit: Option<Arc<crate::authn::event::AuditContext>>,
}

// Cloneable whatever `I` and `F` are, because both sit behind the `Arc`.
// `#[derive(Clone)]` would emit `I: Clone, F: Clone` bounds and so refuse
// the stores adopters actually have.
impl<I, F> Clone for AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore,
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            audit: self.audit.clone(),
        }
    }
}

/// What axess does when about to write an audit event carrying no client
/// metadata.
///
/// The seam this governs was unwired for a whole release: the context
/// type, the extractor and the builder method all existed, nothing joined
/// them, and every audit row carried a null IP while the documentation
/// offered the catalogue as SOC 2 and PCI-DSS evidence. Nothing failed,
/// which is why nobody noticed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuditContextPolicy {
    /// Write the event with whatever metadata is present, including none.
    /// Correct where there is genuinely no trustworthy address: a null IP
    /// is honest where an invented one is not.
    #[default]
    Optional,
    /// Refuse to write an event on a route that attached no context,
    /// turning a silent omission into a loud one.
    ///
    /// The test is whether a context was **attached**, not how much it
    /// contains. A context carrying no address still satisfies this:
    /// `extract_audit_context(.., None, ..)` is the documented choice
    /// where nothing is trustworthy, and refusing it would punish the
    /// deployments that were honest about having no address.
    ///
    /// **This is a fail-closed path.** An adopter who sets it and forgets
    /// [`AuthnService::with_audit_context`] on one route fails that
    /// route's logins rather than under-recording them. Wire every route
    /// before turning it on, and watch
    /// [`AuthnMetrics::audit_context_missing`](crate::metrics::AuthnMetrics::audit_context_missing).
    ///
    /// **It does not guarantee the event was recorded**, despite the
    /// name. A sink that returns
    /// [`AuditOutcome::Shed`](crate::authn::store::AuditOutcome::Shed)
    /// still drops it, and the login still succeeds. `Required` fixes the
    /// wiring; durability is the sink's contract, and
    /// [`AuthnMetrics::audit_event_shed`](crate::metrics::AuthnMetrics::audit_event_shed)
    /// is where a gap shows up.
    Required,
}

/// Configures an [`AuthnService`], and is what the built handle shares.
///
/// Customisation happens here rather than on the built service because the
/// collaborators sit behind an `Arc` the moment [`build`](Self::build) is
/// called, where every copy of the handle observes them. After `build` the
/// same value is the shared collaborator set, which is why the handle's
/// field is typed as this.
pub struct AuthnServiceBuilder<I, F>
where
    I: IdentityStore,
    F: FactorStore,
{
    pub(crate) audit_policy: AuditContextPolicy,
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
    /// Capacity cap for [`sid_map`](Self::sid_map). When at/over this
    /// count, `maintain_oidc_sid_map` evicts a batch of oldest entries.
    /// High-throughput OAuth deployments raise this via
    /// [`with_sid_map_capacity`](AuthnServiceBuilder::with_sid_map_capacity); the
    /// default matches the historical hardcoded value.
    #[cfg(feature = "oauth")]
    pub(crate) sid_map_capacity: usize,
}

/// Default capacity cap for the OIDC `sid` → local-session map. High-throughput
/// OAuth deployments can override via
/// [`AuthnServiceBuilder::with_sid_map_capacity`].
#[cfg(feature = "oauth")]
pub const DEFAULT_SID_MAP_CAPACITY: usize = 10_000;

// ── Constructors and builders ────────────────────────────────────────────────

impl<I, F> AuthnServiceBuilder<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Start configuring a service. Finish with [`build`](Self::build).
    pub fn new(identity: I, factors: F) -> Self {
        Self {
            audit_policy: AuditContextPolicy::Optional,
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
            #[cfg(feature = "oauth")]
            sid_map_capacity: DEFAULT_SID_MAP_CAPACITY,
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

    /// Start configuring a service from a dual-role backend.
    pub fn builder_from_backend(backend: B) -> AuthnServiceBuilder<B, B> {
        AuthnService::builder(backend.clone(), backend)
    }
}

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Create a service with OS RNG, system clock and no customisation.
    ///
    /// Shorthand for `AuthnService::builder(identity, factors).build()`.
    /// Reach for [`builder`](Self::builder) to set a clock, registry,
    /// metrics, providers, or the audit-context policy.
    pub fn new(identity: I, factors: F) -> Self {
        Self::builder(identity, factors).build()
    }

    /// Start configuring a service.
    pub fn builder(identity: I, factors: F) -> AuthnServiceBuilder<I, F> {
        AuthnServiceBuilder::new(identity, factors)
    }

    /// Return a copy of this handle that stamps every event it emits with
    /// `ctx`.
    ///
    /// Call it once per request, from wherever the client address was
    /// resolved:
    ///
    /// ```ignore
    /// let ip = ip_from_headers_trusted(&headers, peer, &trusted);
    /// let ctx = extract_audit_context(&headers, Some(ip), Some(&session));
    /// let svc = state.authn.with_audit_context(ctx);
    /// svc.begin_login(&identifier, &tenant, &session).await?;
    /// ```
    ///
    /// The collaborators are shared, so this costs a refcount bump and one
    /// small allocation; only the context differs between copies.
    ///
    /// **Call it per request, and let the copy die with the request.**
    /// The returned handle pins that one client's address for as long as
    /// it lives, so storing it in application state would stamp a stale
    /// address onto every later event: a quieter kind of wrong than a
    /// missing one, because the rows look complete. Keep the shared
    /// service in state and derive a copy per request.
    pub fn with_audit_context(&self, ctx: crate::authn::event::AuditContext) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            audit: Some(Arc::new(ctx)),
        }
    }

    /// The audit-context policy this service was built with.
    pub fn audit_context_policy(&self) -> AuditContextPolicy {
        self.inner.audit_policy
    }

    /// Stamp the builder with `self.inner.clock.now()` and dispatch the
    /// resulting [`AuthEvent`](crate::authn::event::AuthEvent) to the
    /// identity store, logging at `tracing::error!` if the store
    /// rejects the write.
    ///
    /// This is the canonical audit-emit entry point for the crate.
    /// The vast majority of audit emits share the shape
    /// `builder.build_at(self.inner.clock.now())` followed by an identity
    /// `record_event` that must not block the request flow on store
    /// failure. Threading the clock through the builder finisher at
    /// every call site obscures intent (the timestamp is always *now*)
    /// and risks drift if the clock dependency ever changes shape
    /// (matching how the RNG threading was retrofitted). `emit_audit`
    /// centralises the `clock + record + log` pattern so call sites
    /// read as `self.emit_audit(builder.with_factor(kind)).await`:
    /// the audit content is what the reader cares about.
    ///
    /// Audit-store outages surface as `tracing::error!` (with
    /// `event_type` and `event_status` context) **and** as
    /// [`AuthnError::Store`](crate::authn::error::AuthnError::Store): the
    /// flow stops. An authentication that is not recorded has not, for
    /// evidence purposes, happened, and a deployment that offers this
    /// catalogue as SOC 2 or PCI-DSS evidence cannot have it silently
    /// develop holes. The trade is availability: logins fail while the
    /// audit store does, so the sink belongs behind something durable
    /// (a local write shipped asynchronously) rather than a remote
    /// service on the request path.
    ///
    /// Every path that can reject a login emits before it returns, which
    /// is what keeps this from becoming a user-enumeration oracle: an
    /// unknown identifier and a wrong password both attempt an audit
    /// write, so an outage fails both identically.
    ///
    /// The underlying `record_event_or_log` is private;
    /// callers go through [`emit_audit`](Self::emit_audit) for the
    /// "now" case and [`emit_audit_at`](Self::emit_audit_at) for the
    /// captured-timestamp case. The single intentional bypass is the
    /// audit-failure-with-context emit in `factor_pipeline.rs`,
    /// which calls `self.inner.identity.record_event(...)` directly so its
    /// `tracing::error!` can include `user_id = %user_id`: context
    /// `record_event_or_log` doesn't have. That bypass is documented
    /// at the call site.
    pub(crate) async fn emit_audit(
        &self,
        builder: crate::authn::event::AuthEventBuilder,
    ) -> Result<(), crate::authn::error::AuthnError<I::Error>> {
        self.emit_audit_at(builder, self.inner.clock.now()).await
    }

    /// Stamp the builder with the given `event_time` and dispatch
    /// to the identity store, failing the flow on a store error exactly
    /// as [`emit_audit`](Self::emit_audit) does.
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
    ) -> Result<(), crate::authn::error::AuthnError<I::Error>> {
        // The single point every emit site funnels through, and so the
        // one place the per-request context has to be applied. Before
        // 0.6.0 nothing applied it anywhere and every row carried a null
        // client IP.
        let builder = match &self.audit {
            Some(ctx) => builder.with_audit_context(ctx),
            None => builder,
        };
        let event = builder.build_at(event_time);

        // `Required` is about the *wiring*, not about how much the context
        // turned out to contain. A route that attached a context carrying
        // no address is the honest case: `extract_audit_context(.., None,
        // ..)` is what the docs tell you to do where nothing is
        // trustworthy, and failing it would punish exactly the deployments
        // that got this right. What must not pass silently is a route that
        // never attached one at all.
        if self.inner.audit_policy == AuditContextPolicy::Required && self.audit.is_none() {
            tracing::error!(
                event_type = ?event.event_type,
                "audit context policy is Required and this route attached no context; \
                 call AuthnService::with_audit_context on the request path"
            );
            self.inner.metrics.audit_context_missing();
            return Err(crate::authn::error::AuthnError::MissingAuditContext);
        }

        let event_type = format!("{:?}", event.event_type);
        let event_status = format!("{:?}", event.event_status);
        match self.inner.identity.record_event(event).await {
            Ok(crate::authn::store::AuditOutcome::Recorded) => Ok(()),
            Ok(crate::authn::store::AuditOutcome::Shed) => {
                // A deliberate drop, not a failure: the sink is protecting
                // its storage. Proceed, and let the metric carry it.
                self.inner.metrics.audit_event_shed();
                Ok(())
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    event_type = %event_type,
                    event_status = %event_status,
                    "identity store rejected audit event; failing the flow rather \
                     than proceeding unrecorded"
                );
                self.inner.metrics.audit_store_outage();
                Err(crate::authn::error::AuthnError::Store(e))
            }
        }
    }

    /// Return a reference to the OAuth provider registry for introspection.
    ///
    /// Use `oauth_providers().provider_names()` or `oauth_providers().provider_count()`
    /// to list or count the configured providers.
    #[cfg(feature = "oauth")]
    pub fn oauth_providers(&self) -> &crate::federation::oauth::OAuthProviderRegistry {
        &self.inner.oauth_providers
    }

    /// `true` when at least one OAuth/OIDC provider has been registered
    /// via [`with_oauth_provider`](AuthnServiceBuilder::with_oauth_provider). Sugar over
    /// [`oauth_providers`](AuthnService::oauth_providers)`.provider_count() > 0`
    /// for the common yes/no check.
    #[cfg(feature = "oauth")]
    pub fn has_oauth_providers(&self) -> bool {
        self.inner.oauth_providers.provider_count() > 0
    }

    /// `true` when a FIDO2/WebAuthn provider has been attached via
    /// [`with_fido2`](AuthnServiceBuilder::with_fido2). Adopters typically already hold
    /// a handle to the provider they wired in; this predicate exists so
    /// adopters that only need "is it configured?" don't have to keep
    /// their own bookkeeping in sync with the service.
    #[cfg(feature = "fido2")]
    pub fn has_fido2(&self) -> bool {
        self.inner.fido2.is_some()
    }

    /// `true` when an LDAP provider has been attached via
    /// [`with_ldap`](AuthnServiceBuilder::with_ldap). See [`has_fido2`](Self::has_fido2)
    /// for rationale.
    #[cfg(feature = "ldap")]
    pub fn has_ldap(&self) -> bool {
        self.inner.ldap.is_some()
    }

    /// Whether a session registry is wired on this service. Adopters checking
    /// before calling the revocation methods can use this to short-circuit and
    /// return a clearer error than [`NoSessionRegistryError`] from deep
    /// inside a handler.
    pub fn has_session_registry(&self) -> bool {
        self.inner.registry.is_some()
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
        match &self.inner.registry {
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
        match &self.inner.registry {
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
        match &self.inner.registry {
            Some(reg) => Ok(reg.active_sessions(user_id).await),
            None => Err(NoSessionRegistryError),
        }
    }

    /// Create a [`SessionValidator`] that checks registry validity.
    ///
    /// Use this with [`require_valid_session`] middleware to enforce
    /// registry-based session checks on protected routes without threading
    /// the full `AuthnService` type through your middleware:
    pub fn session_validator(&self) -> SessionValidator {
        SessionValidator {
            registry: self.inner.registry.clone(),
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
            registry: self.inner.registry.clone(),
            identity: Some(Arc::new(session_validator::IdentityWrapper(
                self.inner.identity.clone(),
            ))),
        }
    }
}

// ── Builder ──────────────────────────────────────────────────────────────────

impl<I, F> AuthnServiceBuilder<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
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
    ///
    /// **Single-instance by design.** Calling `with_fido2` twice replaces
    /// the previously attached provider silently: one deployment, one
    /// relying-party configuration is the assumption. Multi-tenant apps
    /// that need per-tenant relying-party ids (e.g. distinct RP-IDs per
    /// customer domain) must wrap dispatch in the application layer;
    /// axess-core does not maintain a per-tenant FIDO2 registry.
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
    /// **Single-instance by design.** Calling `with_ldap` twice replaces
    /// the previously attached provider silently: one deployment, one
    /// directory is the assumption. Multi-tenant apps that need
    /// per-subsidiary directories must wrap dispatch in the application
    /// layer; axess-core does not maintain a per-tenant LDAP registry.
    ///
    /// ```rust,ignore
    /// let ldap = LdapProviderConfig::new(
    ///     "ldaps://ad.corp.example.com",
    ///     "{user}@corp.example.com",
    /// );
    /// let authn = AuthnService::builder(identity, factors).with_ldap(ldap).build();
    /// ```
    #[cfg(feature = "ldap")]
    pub fn with_ldap(mut self, provider: impl axess_factors::ldap::LdapProvider) -> Self {
        self.ldap = Some(Arc::new(provider));
        self
    }

    /// Register an OAuth/OIDC identity provider.
    ///
    /// Call once per provider at startup. Multiple providers can be registered
    /// (e.g. Google + GitHub + corporate IdP), each under a distinct name.
    ///
    /// **Duplicate name safety.** Registering two providers under the same
    /// `provider.name()` is a real security-relevant misconfiguration
    /// (token exchanges for that IdP would then run against whichever
    /// credentials won the race). The registry emits `tracing::warn!` on
    /// overwrite and `debug_assert!`s in debug builds; production builds
    /// keep the new registration and continue, so operators still notice
    /// via logs.
    ///
    /// # Tenancy
    ///
    /// **Providers are registered globally on `AuthnService`, not per-tenant.**
    /// The library does not maintain a per-tenant OAuth registry; that is
    /// out of scope by design. Two supported patterns:
    ///
    /// 1. **Same IdP, multiple tenants (single shared client).** Tenant A
    ///    and tenant B both federate to the same IdP (e.g. one Azure AD
    ///    app serving two SaaS tenants). The callback alone cannot tell
    ///    them apart; the application MUST use
    ///    [`begin_oauth_login_in_tenant`](AuthnService::begin_oauth_login_in_tenant)
    ///    to bind the ceremony to a tenant up-front, and the
    ///    claims→user resolver MUST scope its lookup to the bound tenant.
    /// 2. **Distinct IdPs, one per set of tenants.** Register one provider
    ///    per IdP under a stable name (`"acme-corp-azure"`, `"beta-corp-okta"`,
    ///    etc.); the application maps a tenant → provider-name in its own
    ///    tenant record and calls [`begin_oauth_login`](AuthnService::begin_oauth_login)
    ///    with the resolved name. Provider names are stable identifiers,
    ///    NOT dynamic per-tenant strings: do not derive them from
    ///    `tenant_id` at registration time (would require re-registration
    ///    on every tenant create/delete, would collide with reserved
    ///    identifier characters, and would defeat the introspection story
    ///    on [`oauth_providers`](AuthnService::oauth_providers)).
    ///
    /// If you need genuinely dynamic per-tenant IdP configuration
    /// (each tenant admin uploads their own client_secret through a UI,
    /// changing at runtime), that requires provider hot-swap which
    /// axess-core does not yet support: see the roadmap.
    #[cfg(feature = "oauth")]
    pub fn with_oauth_provider(
        mut self,
        provider: impl axess_factors::oauth::OAuthProvider,
    ) -> Self {
        self.oauth_providers.add(provider);
        self
    }

    /// Override the capacity cap for the OIDC `sid` → local-session map that
    /// powers back-channel logout by `sid`.
    ///
    /// The map is populated per successful OAuth login that returns an
    /// `oidc_sid` claim; when at/over this cap, the maintenance path
    /// evicts a batch of oldest entries. Default:
    /// [`DEFAULT_SID_MAP_CAPACITY`] (10 000). Raise for high-throughput
    /// deployments where legitimate concurrent OIDC sessions exceed the
    /// default and back-channel logout precision degrades on eviction.
    #[cfg(feature = "oauth")]
    pub fn with_sid_map_capacity(mut self, capacity: usize) -> Self {
        self.sid_map_capacity = capacity;
        self
    }

    /// Attach a session registry for forced-logout support.
    pub fn with_registry(mut self, registry: impl SessionRegistry + 'static) -> Self {
        self.registry = Some(Arc::new(SessionRegistryAdapter(registry)));
        self
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

    /// What to do when an event would be written with no client
    /// metadata. See [`AuditContextPolicy`]; defaults to
    /// [`Optional`](AuditContextPolicy::Optional).
    pub fn with_audit_context_policy(mut self, policy: AuditContextPolicy) -> Self {
        self.audit_policy = policy;
        self
    }

    /// Share the collaborators and return the handle.
    pub fn build(self) -> AuthnService<I, F> {
        AuthnService {
            inner: Arc::new(self),
            audit: None,
        }
    }
}

#[cfg(test)]
mod audit_context_wiring_tests {
    //! The seam these cover was unwired for an entire release: the context
    //! type, the extractor and the builder method all existed, and nothing
    //! joined them, so every audit row carried a null client IP while the
    //! documentation offered the catalogue as compliance evidence. Nothing
    //! failed, which is why nothing caught it.

    use super::{AuditContextPolicy, AuthnService};
    use crate::authn::event::{AuditContext, AuthEventBuilder, AuthEventType};
    use crate::testing::{MockFactorStore, MockIdentityStore};

    fn ctx_with_ip(ip: &str) -> AuditContext {
        AuditContext {
            ip_address: Some(ip.parse().expect("test literal is a valid address")),
            user_agent: Some("probe/1.0".to_owned()),
            ..Default::default()
        }
    }

    /// The property the wiring exists for: a handle carrying a context
    /// stamps it onto the event that reaches the sink.
    #[tokio::test]
    async fn context_reaches_the_stored_event() {
        let identity = MockIdentityStore::new();
        let service = AuthnService::new(identity.clone(), MockFactorStore::new());

        service
            .with_audit_context(ctx_with_ip("203.0.113.7"))
            .emit_audit(AuthEventBuilder::success(AuthEventType::Authenticated))
            .await
            .expect("emit must succeed");

        let events = identity.events();
        let event = events.last().expect("one event recorded");
        assert_eq!(
            event.ip_address,
            Some("203.0.113.7".parse().unwrap()),
            "the context's address must reach the stored event"
        );
        assert_eq!(event.user_agent.as_deref(), Some("probe/1.0"));
    }

    /// A handle without a context records nothing about the client, which
    /// is the pre-0.6.0 behaviour, now the explicit default rather than
    /// the only possibility.
    #[tokio::test]
    async fn without_a_context_the_event_still_records() {
        let identity = MockIdentityStore::new();
        let service = AuthnService::new(identity.clone(), MockFactorStore::new());
        assert_eq!(service.audit_context_policy(), AuditContextPolicy::Optional);

        service
            .emit_audit(AuthEventBuilder::success(AuthEventType::Authenticated))
            .await
            .expect("Optional must not refuse a bare event");

        assert!(
            identity
                .events()
                .last()
                .expect("recorded")
                .ip_address
                .is_none()
        );
    }

    /// `Required` is what turns the silent omission loud.
    #[tokio::test]
    async fn required_policy_refuses_an_event_with_no_client_metadata() {
        let identity = MockIdentityStore::new();
        let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
            .with_audit_context_policy(AuditContextPolicy::Required)
            .build();

        let err = service
            .emit_audit(AuthEventBuilder::success(AuthEventType::Authenticated))
            .await
            .expect_err("Required must refuse an event with no context");
        assert!(matches!(
            err,
            crate::authn::error::AuthnError::MissingAuditContext
        ));
        assert!(
            identity.events().is_empty(),
            "a refused event must not also be written"
        );

        service
            .with_audit_context(ctx_with_ip("203.0.113.7"))
            .emit_audit(AuthEventBuilder::success(AuthEventType::Authenticated))
            .await
            .expect("Required is satisfied once a context is attached");
        assert_eq!(identity.events().len(), 1);
    }

    /// `Required` must accept a context that is legitimately empty.
    ///
    /// `extract_audit_context(.., None, ..)` is what the documentation
    /// tells an adopter to do where no address is trustworthy, and a
    /// first cut of this check tested whether the *event* carried any
    /// client metadata, which would have failed every login on exactly
    /// the deployments that were honest about having none. The policy is
    /// about whether the route wired a context, not about how much that
    /// context happened to contain.
    #[tokio::test]
    async fn required_accepts_a_context_that_is_honestly_empty() {
        let identity = MockIdentityStore::new();
        let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
            .with_audit_context_policy(AuditContextPolicy::Required)
            .build();

        // Attached, and empty: no trustworthy address was available.
        let empty = AuditContext::default();
        assert!(empty.ip_address.is_none());

        service
            .with_audit_context(empty)
            .emit_audit(AuthEventBuilder::success(AuthEventType::Authenticated))
            .await
            .expect("an attached but empty context satisfies Required");

        assert_eq!(identity.events().len(), 1);
        assert!(identity.events()[0].ip_address.is_none());
    }

    /// The handle is a view over shared collaborators, not a second
    /// service: a context-carrying copy writes to the same store.
    #[tokio::test]
    async fn copies_share_the_same_collaborators() {
        let identity = MockIdentityStore::new();
        let service = AuthnService::new(identity.clone(), MockFactorStore::new());

        service
            .with_audit_context(ctx_with_ip("203.0.113.7"))
            .emit_audit(AuthEventBuilder::success(AuthEventType::Authenticated))
            .await
            .expect("emit");
        service
            .with_audit_context(ctx_with_ip("198.51.100.4"))
            .emit_audit(AuthEventBuilder::success(AuthEventType::Authenticated))
            .await
            .expect("emit");

        let events = identity.events();
        assert_eq!(events.len(), 2, "both copies wrote to the one store");
        assert_ne!(
            events[0].ip_address, events[1].ip_address,
            "each copy carried its own context"
        );
    }
}

#[cfg(test)]
mod audit_shed_tests {
    //! `Shed` exists so a sink can protect its storage without the flow
    //! treating that as a failure. The hazard it answers: every failed
    //! login writes a row, including for identifiers that do not exist,
    //! so an unauthenticated caller can drive writes at the store, and
    //! with no way to shed, exhausting it fails every login for everyone.

    use super::AuthnService;
    use crate::authn::event::{AuthEventBuilder, AuthEventType};
    use crate::authn::store::AuditOutcome;
    use crate::testing::{MockFactorStore, MockIdentityStore};

    /// A shed event does not fail the flow. An outage does. This is the
    /// whole distinction, and the reason `Result<(), E>` was not enough.
    #[tokio::test]
    async fn shedding_continues_the_flow_where_an_outage_fails_it() {
        let identity = MockIdentityStore::new();
        let service = AuthnService::new(identity.clone(), MockFactorStore::new());

        identity.arm_record_event_shedding();
        service
            .emit_audit(AuthEventBuilder::success(AuthEventType::Authenticated))
            .await
            .expect("a deliberate drop must not fail the flow");
        assert!(
            identity.events().is_empty(),
            "shed means nothing was stored"
        );

        identity.disarm_record_event_shedding();
        identity.arm_record_event_failure();
        service
            .emit_audit(AuthEventBuilder::success(AuthEventType::Authenticated))
            .await
            .expect_err("an outage must still fail the flow");
    }

    /// The distinction the type exists for: a sink that discards events
    /// must not claim to have recorded them.
    #[tokio::test]
    async fn a_discarding_sink_reports_shed_not_recorded() {
        use crate::authn::store::IdentityAuthnLog;

        let backend = crate::authn::store::NoopAuthnLog(MockIdentityStore::new());
        let outcome = backend
            .record_event(AuthEventBuilder::success(AuthEventType::Authenticated).build())
            .await
            .expect("noop sink never errors");

        assert_eq!(
            outcome,
            AuditOutcome::Shed,
            "a sink that discards must not report Recorded: that claims a \
             write which never happened, which is what made the audit gap \
             invisible in the first place"
        );
    }

    /// A real sink records, and says so.
    #[tokio::test]
    async fn a_writing_sink_reports_recorded() {
        use crate::authn::store::IdentityAuthnLog;

        let identity = MockIdentityStore::new();
        let outcome = identity
            .record_event(AuthEventBuilder::success(AuthEventType::Authenticated).build())
            .await
            .expect("mock sink never errors");

        assert_eq!(outcome, AuditOutcome::Recorded);
        assert_eq!(identity.events().len(), 1, "and actually wrote it");
    }
}
