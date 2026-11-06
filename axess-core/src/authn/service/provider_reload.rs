//! Live provider reload: replace, add and remove the OAuth, FIDO2 and LDAP
//! providers of a running [`AuthnService`].
//!
//! The design, the invariants and the failure modes are in the book chapter
//! "Live provider reload". In short: a candidate provider is built and
//! checked first (discovery and the issuer check for OAuth, the relying-party
//! parse for FIDO2, reachability for LDAP), under a deadline; only then is it
//! swapped into a lock-free slot, and a refusal leaves the previous provider
//! serving and names the step. With a coordinator, a local change is announced
//! and [`AuthnService::follow_provider_reloads`] is the receiving side.

#[cfg(feature = "fido2")]
mod fido2_options;
mod install;
mod source;

use std::sync::Arc;
use std::time::Duration;

use crate::authn::store::{FactorStore, IdentityStore};
use crate::metrics::ProviderCategory;
use crate::reload::ReloadCoordinator;

#[cfg(feature = "fido2")]
pub use fido2_options::ReloadFido2;
pub use source::{
    BuiltProvider, ProviderEntry, ProviderFollower, ProviderSource, ProviderSourceError, ReadCause,
};

use super::{AuthnService, AuthnServiceBuilder};

/// How long a candidate provider has to build and check itself before a reload
/// is refused as [`ProviderReloadError::TimedOut`]: 30 seconds, the same bound
/// as one HTTP operation of the built-in OAuth provider. Change it with
/// [`AuthnServiceBuilder::with_provider_validation_timeout`]; a very long
/// value is the opt-out.
pub const DEFAULT_PROVIDER_VALIDATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Which provider a reload, a removal or a notice is about.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProviderKey {
    /// An OAuth/OIDC provider: global when `tenant` is `None`, otherwise the
    /// one `tenant` brought, in the live tenant registry.
    #[cfg(feature = "oauth")]
    OAuth {
        /// The owning tenant, or `None` for the global registry.
        tenant: Option<crate::authn::ids::TenantId>,
        /// The provider name.
        name: Arc<str>,
    },
    /// The FIDO2/WebAuthn provider.
    #[cfg(feature = "fido2")]
    Fido2,
    /// The LDAP provider.
    #[cfg(feature = "ldap")]
    Ldap,
}

impl ProviderKey {
    /// The metrics category of this key.
    pub fn category(&self) -> ProviderCategory {
        match self {
            #[cfg(feature = "oauth")]
            Self::OAuth { .. } => ProviderCategory::OAuth,
            #[cfg(feature = "fido2")]
            Self::Fido2 => ProviderCategory::Fido2,
            #[cfg(feature = "ldap")]
            Self::Ldap => ProviderCategory::Ldap,
        }
    }

    /// A short label for logs and for the coordinator's notice. It names the
    /// provider and the tenant; a receiver never applies it.
    pub fn label(&self) -> String {
        match self {
            #[cfg(feature = "oauth")]
            Self::OAuth { tenant, name } => match tenant {
                Some(tenant) => format!("oauth:{tenant}:{name}"),
                None => format!("oauth:-:{name}"),
            },
            #[cfg(feature = "fido2")]
            Self::Fido2 => "fido2".to_string(),
            #[cfg(feature = "ldap")]
            Self::Ldap => "ldap".to_string(),
        }
    }
}

/// What a reload or removal did to the provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderChangeKind {
    /// There was none under this key; the candidate is now in force.
    Added,
    /// The candidate replaced an earlier provider.
    Replaced,
    /// The provider was taken out.
    Removed,
}

/// What a successful reload or removal did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderChange {
    /// The provider that changed.
    pub key: ProviderKey,
    /// What happened to it.
    pub kind: ProviderChangeKind,
    /// Whether the other instances were told. `false` means there is no
    /// coordinator, or announcing failed (the swap stands; followers catch up
    /// by their poll).
    pub announced: bool,
}

/// Why a provider reload or removal was refused. The previous provider stays
/// in force in every case.
#[derive(Debug, thiserror::Error)]
pub enum ProviderReloadError {
    /// The candidate did not build or did not validate: discovery failed or
    /// named another issuer, the relying party did not parse, and so on.
    #[error("the {} provider candidate did not build: {reason}", category.as_str())]
    Build {
        /// The category being reloaded.
        category: ProviderCategory,
        /// The builder's error.
        reason: String,
    },
    /// The candidate did not build, or the directory did not answer, within
    /// the validation deadline.
    #[error("the {} provider candidate did not finish within {after:?}", category.as_str())]
    TimedOut {
        /// The category being reloaded.
        category: ProviderCategory,
        /// The deadline.
        after: Duration,
    },
    /// The candidate's own name is not the name it was reloaded under.
    #[error("the candidate is named {provider:?} but was reloaded as {requested:?}")]
    NameMismatch {
        /// The name the caller gave.
        requested: String,
        /// The name the candidate reports.
        provider: String,
    },
    /// The LDAP directory could not be reached with the candidate's
    /// transport settings, or the candidate cannot check.
    #[error("the LDAP directory is not reachable: {reason}")]
    Unreachable {
        /// The check's error.
        reason: String,
    },
    /// A removal named a provider that is not registered.
    #[error("no such provider: {label}")]
    NotFound {
        /// The key's label.
        label: String,
    },
    /// A tenant provider was reloaded on a service built without
    /// [`with_live_tenant_oauth_providers`](AuthnServiceBuilder::with_live_tenant_oauth_providers).
    #[error("this service has no live tenant provider registry")]
    NoTenantRegistry,
    /// A FIDO2 reload would change the relying-party id, which orphans every
    /// registered passkey, and the caller did not acknowledge it.
    #[error(
        "the FIDO2 relying-party id would change from {current:?} to {candidate:?}, \
         which orphans every registered passkey; acknowledge it with \
         ReloadFido2::allow_rp_id_change()"
    )]
    RpIdChanged {
        /// The relying-party id in force.
        current: String,
        /// The relying-party id the candidate carries.
        candidate: String,
    },
    /// A source built a provider of another category than its key names.
    #[error("the source built a {built} provider for the key {label}")]
    WrongCategory {
        /// The key's label.
        label: String,
        /// The category the source built.
        built: &'static str,
    },
}

/// What a service keeps for provider reload.
pub(crate) struct ProviderReloadState {
    pub(crate) validation_timeout: Duration,
    pub(crate) coordinator: Option<Arc<dyn ReloadCoordinator>>,
    #[cfg(feature = "oauth")]
    pub(crate) live_tenants: Option<Arc<crate::federation::oauth_tenant::LiveTenantOAuthProviders>>,
}

impl Default for ProviderReloadState {
    fn default() -> Self {
        Self {
            validation_timeout: DEFAULT_PROVIDER_VALIDATION_TIMEOUT,
            coordinator: None,
            #[cfg(feature = "oauth")]
            live_tenants: None,
        }
    }
}

impl<I, F> AuthnServiceBuilder<I, F>
where
    I: IdentityStore,
    F: FactorStore,
{
    /// Attach a FIDO2/WebAuthn provider.
    ///
    /// **Single-instance by design.** Calling `with_fido2` twice replaces
    /// the previously attached provider silently: one deployment, one
    /// relying-party configuration is the assumption. To change the provider of a
    /// running service use [`reload_fido2`](AuthnService::reload_fido2). Multi-tenant apps
    /// that need per-tenant relying-party ids (e.g. distinct RP-IDs per
    /// customer domain) must wrap dispatch in the application layer;
    /// axess-core does not maintain a per-tenant FIDO2 registry.
    #[cfg(feature = "fido2")]
    pub fn with_fido2(mut self, provider: impl axess_factors::fido2::Fido2Provider) -> Self {
        self.fido2 = arc_swap::ArcSwapOption::from_pointee(
            Arc::new(provider) as Arc<dyn axess_factors::fido2::Fido2Provider>
        );
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
    /// directory is the assumption. To change the provider of a running service
    /// use [`reload_ldap`](AuthnService::reload_ldap). Multi-tenant apps that need
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
        self.ldap = arc_swap::ArcSwapOption::from_pointee(
            Arc::new(provider) as Arc<dyn axess_factors::ldap::LdapProvider>
        );
        self
    }

    /// Bound the time a candidate provider has to build and check itself
    /// before a reload is refused (default
    /// [`DEFAULT_PROVIDER_VALIDATION_TIMEOUT`]).
    #[must_use]
    pub fn with_provider_validation_timeout(mut self, timeout: Duration) -> Self {
        self.provider_reload.validation_timeout = timeout;
        self
    }

    /// Announce every local provider change on `coordinator`, and let
    /// [`follow_provider_reloads`](AuthnService::follow_provider_reloads)
    /// listen on it.
    ///
    /// Give the providers a coordinator of their own (a separate
    /// `InProcessCoordinator`, or `ValkeyReloadCoordinator::start_named` on
    /// `provider-reloaded`), not the one a policy reload uses.
    #[must_use]
    pub fn with_provider_coordinator(mut self, coordinator: Arc<dyn ReloadCoordinator>) -> Self {
        self.provider_reload.coordinator = Some(coordinator);
        self
    }

    /// Resolve tenant OAuth providers from `live`, and let
    /// [`reload_tenant_oauth_provider`](AuthnService::reload_tenant_oauth_provider)
    /// change them. Also installs `live` as the service's tenant provider
    /// source, as
    /// [`with_tenant_oauth_providers`](Self::with_tenant_oauth_providers)
    /// would; use one or the other.
    #[cfg(feature = "oauth")]
    #[must_use]
    pub fn with_live_tenant_oauth_providers(
        mut self,
        live: Arc<crate::federation::oauth_tenant::LiveTenantOAuthProviders>,
    ) -> Self {
        self.tenant_oauth_providers = Some(live.clone());
        self.provider_reload.live_tenants = Some(live);
        self
    }
}

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Replace or add the global OAuth provider named `name` with the one
    /// `candidate` builds.
    ///
    /// `candidate` is awaited under the validation deadline; pass the future
    /// of `OAuthProviderConfig::discover(..)` finished with `.build()`, so the
    /// discovery fetch and the issuer check run before anything is swapped.
    /// The provider's own name must equal `name`. On success the next
    /// `begin_oauth_login(name, ..)` uses the new provider; a login begun
    /// against the old one finishes only if the issuer is unchanged.
    ///
    /// # Errors
    ///
    /// [`ProviderReloadError::Build`], [`TimedOut`](ProviderReloadError::TimedOut)
    /// or [`NameMismatch`](ProviderReloadError::NameMismatch); the previous
    /// provider keeps serving.
    #[cfg(feature = "oauth")]
    pub async fn reload_oauth_provider<P, E>(
        &self,
        name: &str,
        candidate: impl std::future::Future<Output = Result<P, E>>,
    ) -> Result<ProviderChange, ProviderReloadError>
    where
        P: axess_factors::oauth::OAuthProvider,
        E: std::fmt::Display,
    {
        let key = oauth_key(None, name);
        let provider = self
            .candidate(&key, candidate)
            .await
            .map(|p| Arc::new(p) as Arc<dyn axess_factors::oauth::OAuthProvider>);
        self.settle(
            &key,
            provider.and_then(|p| self.install_oauth(&key, p)),
            true,
        )
        .await
    }

    /// Take the global OAuth provider named `name` out. Its routes refuse by
    /// name (`OAuthError::UnknownProvider`) from the next call on; a login in
    /// flight fails its callback the same way.
    ///
    /// # Errors
    ///
    /// [`ProviderReloadError::NotFound`] when no such provider is registered.
    #[cfg(feature = "oauth")]
    pub async fn remove_oauth_provider(
        &self,
        name: &str,
    ) -> Result<ProviderChange, ProviderReloadError> {
        let key = oauth_key(None, name);
        let removed = self.remove_key(&key);
        self.settle(&key, removed, true).await
    }

    /// As [`reload_oauth_provider`](Self::reload_oauth_provider), for the
    /// provider `tenant` has under `name`. Only that entry changes: another
    /// tenant's provider of the same name is not read or rebuilt.
    ///
    /// # Errors
    ///
    /// As [`reload_oauth_provider`](Self::reload_oauth_provider), and
    /// [`ProviderReloadError::NoTenantRegistry`] without
    /// [`with_live_tenant_oauth_providers`](AuthnServiceBuilder::with_live_tenant_oauth_providers).
    #[cfg(feature = "oauth")]
    pub async fn reload_tenant_oauth_provider<P, E>(
        &self,
        tenant: &crate::authn::ids::TenantId,
        name: &str,
        candidate: impl std::future::Future<Output = Result<P, E>>,
    ) -> Result<ProviderChange, ProviderReloadError>
    where
        P: axess_factors::oauth::OAuthProvider,
        E: std::fmt::Display,
    {
        let key = oauth_key(Some(*tenant), name);
        let provider = self
            .candidate(&key, candidate)
            .await
            .map(|p| Arc::new(p) as Arc<dyn axess_factors::oauth::OAuthProvider>);
        self.settle(
            &key,
            provider.and_then(|p| self.install_oauth(&key, p)),
            true,
        )
        .await
    }

    /// Take the provider `tenant` has under `name` out of the live registry.
    ///
    /// # Errors
    ///
    /// [`ProviderReloadError::NotFound`] or
    /// [`ProviderReloadError::NoTenantRegistry`].
    #[cfg(feature = "oauth")]
    pub async fn remove_tenant_oauth_provider(
        &self,
        tenant: &crate::authn::ids::TenantId,
        name: &str,
    ) -> Result<ProviderChange, ProviderReloadError> {
        let key = oauth_key(Some(*tenant), name);
        let removed = self.remove_key(&key);
        self.settle(&key, removed, true).await
    }

    /// Replace or add the FIDO2 provider with the one `candidate` builds.
    ///
    /// `candidate` parses the relying party (`WebauthnBuilder::build`), so an
    /// invalid RP id or origin is refused before the swap. Changing the RP id
    /// orphans every registered credential, so a candidate whose
    /// [`relying_party_id`](axess_factors::fido2::Fido2Provider::relying_party_id)
    /// differs from the provider in force is refused as
    /// [`RpIdChanged`](ProviderReloadError::RpIdChanged); use
    /// [`reload_fido2_with`](Self::reload_fido2_with) to acknowledge it.
    ///
    /// # Errors
    ///
    /// [`ProviderReloadError::Build`], [`TimedOut`](ProviderReloadError::TimedOut)
    /// or [`RpIdChanged`](ProviderReloadError::RpIdChanged).
    #[cfg(feature = "fido2")]
    pub async fn reload_fido2<P, E>(
        &self,
        candidate: impl std::future::Future<Output = Result<P, E>>,
    ) -> Result<ProviderChange, ProviderReloadError>
    where
        P: axess_factors::fido2::Fido2Provider,
        E: std::fmt::Display,
    {
        self.reload_fido2_with(candidate, ReloadFido2::default())
            .await
    }

    /// As [`reload_fido2`](Self::reload_fido2), with `options` stating what
    /// the caller accepts. [`ReloadFido2::allow_rp_id_change`] lets a changed
    /// relying-party id through; the change is counted
    /// (`ProviderRegistryMetrics::fido2_rp_id_changed`) and logged with both
    /// ids on `axess::authn::provider_reload`.
    ///
    /// # Errors
    ///
    /// As [`reload_fido2`](Self::reload_fido2).
    #[cfg(feature = "fido2")]
    pub async fn reload_fido2_with<P, E>(
        &self,
        candidate: impl std::future::Future<Output = Result<P, E>>,
        options: ReloadFido2,
    ) -> Result<ProviderChange, ProviderReloadError>
    where
        P: axess_factors::fido2::Fido2Provider,
        E: std::fmt::Display,
    {
        let key = ProviderKey::Fido2;
        let provider = self
            .candidate(&key, candidate)
            .await
            .map(|p| Arc::new(p) as Arc<dyn axess_factors::fido2::Fido2Provider>);
        self.settle(
            &key,
            provider.and_then(|p| self.install_fido2(&key, p, options)),
            true,
        )
        .await
    }

    /// Take the FIDO2 provider out. Its ceremony steps answer
    /// `AuthnError::NoFlow` from the next call on; credentials already
    /// registered stay in the store.
    ///
    /// # Errors
    ///
    /// [`ProviderReloadError::NotFound`] when no FIDO2 provider is attached.
    #[cfg(feature = "fido2")]
    pub async fn remove_fido2(&self) -> Result<ProviderChange, ProviderReloadError> {
        let key = ProviderKey::Fido2;
        let removed = self.remove_key(&key);
        self.settle(&key, removed, true).await
    }

    /// Take the LDAP provider out. A factor chain with
    /// [`FactorKind::LdapBind`](crate::authn::factor::FactorKind::LdapBind)
    /// answers `FactorOutcome::InvalidCredential` from the next call on.
    ///
    /// # Errors
    ///
    /// [`ProviderReloadError::NotFound`] when no LDAP provider is attached.
    #[cfg(feature = "ldap")]
    pub async fn remove_ldap(&self) -> Result<ProviderChange, ProviderReloadError> {
        let key = ProviderKey::Ldap;
        let removed = self.remove_key(&key);
        self.settle(&key, removed, true).await
    }

    /// Replace or add the LDAP provider with the one `candidate` builds,
    /// after its directory answered
    /// [`check_reachable`](axess_factors::ldap::LdapProvider::check_reachable)
    /// within the validation deadline.
    ///
    /// # Errors
    ///
    /// [`ProviderReloadError::Build`], [`TimedOut`](ProviderReloadError::TimedOut)
    /// or [`Unreachable`](ProviderReloadError::Unreachable).
    #[cfg(feature = "ldap")]
    pub async fn reload_ldap<P, E>(
        &self,
        candidate: impl std::future::Future<Output = Result<P, E>>,
    ) -> Result<ProviderChange, ProviderReloadError>
    where
        P: axess_factors::ldap::LdapProvider,
        E: std::fmt::Display,
    {
        let key = ProviderKey::Ldap;
        let provider = match self.candidate(&key, candidate).await {
            Ok(p) => Arc::new(p) as Arc<dyn axess_factors::ldap::LdapProvider>,
            Err(e) => return self.settle(&key, Err(e), true).await,
        };
        let checked = self.check_ldap(provider).await;
        self.settle(&key, checked.and_then(|p| self.install_ldap(&key, p)), true)
            .await
    }
}

#[cfg(feature = "oauth")]
fn oauth_key(tenant: Option<crate::authn::ids::TenantId>, name: &str) -> ProviderKey {
    ProviderKey::OAuth {
        tenant,
        name: Arc::from(name),
    }
}
