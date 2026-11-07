//! The builder's OAuth side: global and per-tenant providers, the OIDC
//! `sid` map and its shared store, and the JWKS refresh loop.

use super::AuthnServiceBuilder;
use crate::authn::store::{FactorStore, IdentityStore};
use std::sync::Arc;

impl<I, F> AuthnServiceBuilder<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
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
    ///    [`begin_oauth_login_in_tenant`](super::AuthnService::begin_oauth_login_in_tenant)
    ///    to bind the ceremony to a tenant up-front, and the
    ///    claims→user resolver MUST scope its lookup to the bound tenant.
    /// 2. **Distinct IdPs, one per set of tenants.** Register one provider
    ///    per IdP under a stable name (`"acme-corp-azure"`, `"beta-corp-okta"`,
    ///    etc.); the application maps a tenant → provider-name in its own
    ///    tenant record and calls [`begin_oauth_login`](super::AuthnService::begin_oauth_login)
    ///    with the resolved name. Provider names are stable identifiers,
    ///    NOT dynamic per-tenant strings: do not derive them from
    ///    `tenant_id` at registration time (would require re-registration
    ///    on every tenant create/delete, would collide with reserved
    ///    identifier characters, and would defeat the introspection story
    ///    on [`oauth_providers`](super::AuthnService::oauth_providers)).
    ///
    /// If you need genuinely dynamic per-tenant IdP configuration
    /// (each tenant admin uploads their own client_secret through a UI,
    /// changing at runtime), use
    /// [`with_tenant_oauth_providers`](Self::with_tenant_oauth_providers):
    /// the provider is resolved by `(tenant, name)` from a store at request
    /// time and an update is used by the next login.
    #[cfg(feature = "oauth")]
    pub fn with_oauth_provider(
        mut self,
        provider: impl axess_factors::oauth::OAuthProvider,
    ) -> Self {
        if self.oauth_providers.add(provider) {
            self.duplicate_providers += 1;
        }
        self
    }

    /// Resolve per-tenant OAuth providers (bring your own IdP) from
    /// `providers` at request time.
    ///
    /// A login started with
    /// [`begin_oauth_login_with_tenant_provider`](super::AuthnService::begin_oauth_login_with_tenant_provider)
    /// asks `providers` for the provider named `(tenant, name)`; the
    /// callback asks again for the same tenant, taken from the session. The
    /// global registrations of
    /// [`with_oauth_provider`](Self::with_oauth_provider) are unaffected and
    /// remain the single-tenant form: a name registered there is reached by
    /// [`begin_oauth_login`](super::AuthnService::begin_oauth_login), a tenant's by
    /// the tenant method, and the two never shadow each other.
    ///
    /// [`StoredTenantOAuthProviders`](crate::federation::oauth_tenant::StoredTenantOAuthProviders)
    /// is the implementation over a store.
    #[cfg(feature = "oauth")]
    pub fn with_tenant_oauth_providers(
        mut self,
        providers: impl crate::federation::oauth_tenant::TenantOAuthProviders,
    ) -> Self {
        self.tenant_oauth_providers = Some(Arc::new(providers));
        self
    }

    /// Override the capacity cap for the OIDC `sid` → local-session map that
    /// powers back-channel logout by `sid`.
    ///
    /// The map is populated per successful OAuth login that returns an
    /// `oidc_sid` claim; when at/over this cap, the maintenance path
    /// evicts a batch of oldest entries. Default:
    /// [`DEFAULT_SID_MAP_CAPACITY`](super::DEFAULT_SID_MAP_CAPACITY) (10 000). Raise for high-throughput
    /// deployments where legitimate concurrent OIDC sessions exceed the
    /// default and back-channel logout precision degrades on eviction.
    #[cfg(feature = "oauth")]
    pub fn with_sid_map_capacity(mut self, capacity: usize) -> Self {
        self.sid_map_capacity = capacity;
        self
    }

    /// Keep the OIDC `sid` mappings and subject records in `store` instead of
    /// the in-process map, so a back-channel logout reaches the instance
    /// that holds the session: with several instances behind a load balancer
    /// the instance that receives the IdP's logout token is not the one that
    /// handled the login, and the in-process map cannot find it.
    ///
    /// `ValkeySidStore` (feature `valkey`) is the shared one. Point the
    /// logout handlers at [`AuthnService::sid_store`](super::AuthnService::sid_store) with their
    /// `with_sid_store`; `sid_map()` stays the (then unused) in-process map. A shared
    /// store ages its keys out by time, so
    /// [`with_sid_map_capacity`](Self::with_sid_map_capacity) does not apply
    /// to it. See [`sid_store`](crate::federation::sid_store).
    #[cfg(feature = "oauth")]
    #[must_use]
    pub fn with_sid_store(
        mut self,
        store: Arc<dyn crate::federation::sid_store::SidStore>,
    ) -> Self {
        self.sid_store = Some(store);
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
    /// interval, [`DEFAULT_JWKS_REFRESH_INTERVAL`](super::DEFAULT_JWKS_REFRESH_INTERVAL) (one hour).
    #[cfg(feature = "oauth")]
    pub fn with_default_jwks_refresh(self) -> Self {
        self.with_jwks_refresh(super::DEFAULT_JWKS_REFRESH_INTERVAL)
    }

    /// Start the refresh loop `with_jwks_refresh` asked for, if any.
    #[cfg(feature = "oauth")]
    pub(super) fn with_jwks_refresh_started(mut self) -> Self {
        if let Some(interval) = self.jwks_refresh_interval {
            self.jwks_refresh_task = super::super::oauth_service::JwksRefreshTask::start(
                super::super::oauth_service::live_providers(
                    self.oauth_providers.handle(),
                    self.tenant_oauth_providers.clone(),
                ),
                interval,
            );
        }
        self
    }
}
