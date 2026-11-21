//! Live provider reload: replace, add and remove the OAuth, FIDO2 and LDAP
//! providers of a running
//! [`AuthnService`](crate::authn::service::AuthnService).
//!
//! The design, the invariants and the failure modes are in the book chapter
//! "Live provider reload". In short: a candidate provider is built and
//! checked first (discovery and the issuer check for OAuth, the relying-party
//! parse for FIDO2, reachability for LDAP), under a deadline; only then is it
//! swapped into a lock-free slot, and a refusal leaves the previous provider
//! serving and names the step. With a coordinator, a local change is announced
//! and
//! [`AuthnService::follow_provider_reloads`](crate::authn::service::AuthnService::follow_provider_reloads)
//! is the receiving side.
//!
//! A provider is changed through the `_as` methods on
//! [`RequestAuthnService`](crate::authn::service::RequestAuthnService), which
//! take the administrator and write an audit row, without which the change
//! is not made.

mod audited;
#[cfg(feature = "oauth")]
mod client_ownership;
#[cfg(feature = "fido2")]
mod fido2_options;
mod install;
mod source;

use std::sync::Arc;
use std::time::Duration;

use crate::authn::store::{FactorStore, IdentityStore};
use crate::metrics::ProviderCategory;
use crate::reload::ReloadCoordinator;

pub use audited::{PROVIDER_SOURCE_REASON, ProviderChangeError};
#[cfg(feature = "oauth")]
pub use client_ownership::{
    CLIENT_OWNERSHIP_ATTESTED_REASON, CLIENT_PAIR_HAND_OVER_REQUESTED_REASON,
    CLIENT_PAIR_HANDED_OVER_REASON,
};
#[cfg(feature = "fido2")]
pub use fido2_options::ReloadFido2;
pub use source::{
    BuiltProvider, ProviderEntry, ProviderFollower, ProviderSource, ProviderSourceError, ReadCause,
};

use super::AuthnServiceBuilder;

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

    /// The tenant and the name of an OAuth slot; `None` for a key of any
    /// other category.
    #[cfg(feature = "oauth")]
    pub(crate) fn oauth_slot(&self) -> Option<(Option<&crate::authn::ids::TenantId>, &Arc<str>)> {
        match self {
            Self::OAuth { tenant, name } => Some((tenant.as_ref(), name)),
            #[cfg(feature = "fido2")]
            Self::Fido2 => None,
            #[cfg(feature = "ldap")]
            Self::Ldap => None,
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
    /// A tenant provider's issuer and client id are held by another
    /// provider of the live registry (another tenant's, or this tenant's
    /// under another name) or by a global provider: one pair belongs to one
    /// provider, or that client's back-channel logout tokens are ambiguous.
    #[error(
        "the provider {label} was refused: its issuer and client id are already registered by {}",
        if *by_global { "the global provider" } else { "another provider" }
    )]
    PairHeld {
        /// The key's label.
        label: String,
        /// Whether a global provider holds the pair.
        by_global: bool,
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
    /// running service use
    /// [`reload_fido2_as`](crate::authn::service::RequestAuthnService::reload_fido2_as). Multi-tenant apps
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
    /// use
    /// [`reload_ldap_as`](crate::authn::service::RequestAuthnService::reload_ldap_as). Multi-tenant apps that need
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
    /// [`follow_provider_reloads`](crate::authn::service::AuthnService::follow_provider_reloads)
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
    /// [`reload_tenant_oauth_provider_as`](crate::authn::service::RequestAuthnService::reload_tenant_oauth_provider_as)
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

#[cfg(feature = "oauth")]
fn oauth_key(tenant: Option<crate::authn::ids::TenantId>, name: &str) -> ProviderKey {
    ProviderKey::OAuth {
        tenant,
        name: Arc::from(name),
    }
}
