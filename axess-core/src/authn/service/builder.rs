//! The builder that configures an [`AuthnService`] and is the collaborator set
//! its handles share.

use super::AuthnService;
use crate::{
    authn::store::{FactorStore, IdentityStore},
    session::store::{SessionRegistry, SessionRegistryAdapter, SessionRegistryHandle},
};
use axess_clock::{Clock, SystemClock};
use axess_rng::{SecureRng, SystemRng};
use std::sync::Arc;

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
    pub(crate) identity: Arc<I>,
    pub(crate) factors: Arc<F>,
    pub(crate) registry: Option<Arc<dyn SessionRegistryHandle>>,
    pub(crate) metrics: Arc<dyn crate::metrics::AuthnMetrics>,
    /// Maximum concurrent sessions per user. `None` means unlimited.
    pub(crate) max_sessions_per_user: Option<usize>,
    pub(crate) rng: Arc<dyn SecureRng>,
    pub(crate) clock: Arc<dyn Clock>,
    /// Where password hashing and verification run.
    pub(crate) kdf: Arc<crate::blocking::KdfExecutor>,
    /// The secret keyed recovery codes are checked under, when configured.
    pub(crate) recovery_pepper: Option<Arc<axess_factors::RecoveryCodePepper>>,
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
    pub(crate) sid_map: crate::federation::sid_map::SidMap,
    /// Capacity cap for [`sid_map`](Self::sid_map). When at/over this
    /// count, `maintain_oidc_sid_map` evicts a batch of oldest entries.
    /// High-throughput OAuth deployments raise this via
    /// [`with_sid_map_capacity`](AuthnServiceBuilder::with_sid_map_capacity); the
    /// default matches the historical hardcoded value.
    #[cfg(feature = "oauth")]
    pub(crate) sid_map_capacity: usize,
    /// Interval of the JWKS refresh loop started by `build`, if requested.
    #[cfg(feature = "oauth")]
    pub(crate) jwks_refresh_interval: Option<std::time::Duration>,
    /// The running refresh loop; aborted when the last handle to the service
    /// is dropped.
    #[cfg(feature = "oauth")]
    pub(crate) jwks_refresh_task: Option<super::oauth_service::JwksRefreshTask>,
}

/// Default interval of the JWKS refresh loop the builder starts: one hour.
/// Well inside the 24 hour maximum age of a cached key set, so a few failed
/// refreshes in a row do not stop verification.
#[cfg(feature = "oauth")]
pub const DEFAULT_JWKS_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);

/// Default capacity cap for the OIDC `sid` → local-session map. High-throughput
/// OAuth deployments can override via
/// [`AuthnServiceBuilder::with_sid_map_capacity`].
#[cfg(feature = "oauth")]
pub const DEFAULT_SID_MAP_CAPACITY: usize = 10_000;

impl<I, F> AuthnServiceBuilder<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Start configuring a service. Finish with [`build`](Self::build).
    pub fn new(identity: I, factors: F) -> Self {
        Self {
            identity: Arc::new(identity),
            factors: Arc::new(factors),
            registry: None,
            metrics: Arc::new(crate::metrics::NoopMetrics),
            max_sessions_per_user: None,
            rng: Arc::new(SystemRng),
            clock: Arc::new(SystemClock),
            kdf: Arc::new(crate::blocking::KdfExecutor::pool()),
            recovery_pepper: None,
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
            #[cfg(feature = "oauth")]
            jwks_refresh_interval: None,
            #[cfg(feature = "oauth")]
            jwks_refresh_task: None,
        }
    }
}

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

    /// Replace the executor password hashing and verification run on.
    ///
    /// The default is the blocking pool, one job per CPU. Deterministic tests
    /// pass [`KdfExecutor::inline`](crate::blocking::KdfExecutor::inline),
    /// keep a clone of the `Arc`, and read
    /// [`jobs_started`](crate::blocking::KdfExecutor::jobs_started) to assert
    /// how many hashes a flow ran.
    pub fn with_kdf_executor(mut self, executor: Arc<crate::blocking::KdfExecutor>) -> Self {
        self.kdf = executor;
        self
    }

    /// Set the secret recovery codes stored in the keyed form are checked
    /// under. Without it only Argon2id recovery codes can verify; a keyed row
    /// then fails closed. See [`axess_factors::RecoveryCodePepper`].
    pub fn with_recovery_code_pepper(mut self, pepper: axess_factors::RecoveryCodePepper) -> Self {
        self.recovery_pepper = Some(Arc::new(pepper));
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

    /// Have [`build`](Self::build) start a background loop that refreshes the
    /// JWKS of every registered OAuth provider every `interval`.
    ///
    /// Cached key sets have a maximum age (24 hours by default,
    /// `JwksCache::with_max_age`), after which verification with them fails
    /// closed until a refresh succeeds. Without this loop (or an equivalent
    /// started with `AuthnService::spawn_jwks_refresh` or a scheduler calling
    /// `AuthnService::refresh_all_jwks`) the keys expire by that maximum age
    /// and logout-token verification then relies on the refresh a kid miss
    /// triggers. The loop stops when the last clone of the built service is
    /// dropped. It needs a tokio runtime at `build` time: without one it is
    /// not started and a warning is logged.
    #[cfg(feature = "oauth")]
    pub fn with_jwks_refresh(mut self, interval: std::time::Duration) -> Self {
        self.jwks_refresh_interval = Some(interval);
        self
    }

    /// [`with_jwks_refresh`](Self::with_jwks_refresh) at the default
    /// interval, [`DEFAULT_JWKS_REFRESH_INTERVAL`] (one hour).
    #[cfg(feature = "oauth")]
    pub fn with_default_jwks_refresh(self) -> Self {
        self.with_jwks_refresh(DEFAULT_JWKS_REFRESH_INTERVAL)
    }

    /// Start the refresh loop `with_jwks_refresh` asked for, if any.
    #[cfg(feature = "oauth")]
    fn with_jwks_refresh_started(mut self) -> Self {
        if let Some(interval) = self.jwks_refresh_interval {
            self.jwks_refresh_task = super::oauth_service::JwksRefreshTask::start(
                self.oauth_providers.values().cloned().collect(),
                interval,
            );
        }
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
    /// the oldest session is evicted. Not calling this (the default) means
    /// unlimited. The cap is a [`NonZeroUsize`](std::num::NonZeroUsize): a cap
    /// of 0 cannot hold a session that has just logged in, and used to behave
    /// as 1 without saying so.
    pub fn with_max_sessions_per_user(mut self, max: std::num::NonZeroUsize) -> Self {
        self.max_sessions_per_user = Some(max.get());
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

    /// Share the collaborators and return the handle.
    pub fn build(self) -> AuthnService<I, F> {
        #[cfg(feature = "oauth")]
        let this = self.with_jwks_refresh_started();
        #[cfg(not(feature = "oauth"))]
        let this = self;
        AuthnService {
            inner: Arc::new(this),
        }
    }
}
