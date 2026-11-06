//! The provider-registry concern: configuration mistakes at build time and
//! live provider reloads.

/// The category of a provider a reload touched. A closed set, so it is safe
/// as a metric label; the provider's name and tenant are not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderCategory {
    /// An OAuth/OIDC identity provider, global or a tenant's.
    OAuth,
    /// The FIDO2/WebAuthn provider.
    Fido2,
    /// The LDAP provider.
    Ldap,
}

impl ProviderCategory {
    /// The snake_case label value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OAuth => "oauth",
            Self::Fido2 => "fido2",
            Self::Ldap => "ldap",
        }
    }
}

/// Counters for the provider registries of an `AuthnService`.
pub trait ProviderRegistryMetrics: Send + Sync + 'static {
    /// A provider was registered under a name that was already taken, and
    /// replaced the earlier one. Reported when the service is built, once per
    /// duplicate. Any count above zero is a misconfiguration: the earlier
    /// provider's credentials are gone.
    fn provider_duplicate_registration(&self) {}

    /// A provider of `category` was swapped in or added on a running service,
    /// by a reload call or by a follower. The name and tenant are in the
    /// `axess::authn::provider_reload` event.
    fn provider_reloaded(&self, category: ProviderCategory) {
        let _ = category;
    }

    /// A provider of `category` was removed from a running service.
    fn provider_removed(&self, category: ProviderCategory) {
        let _ = category;
    }

    /// A reload of `category` was refused (the candidate did not build, did
    /// not answer in time, did not match its name, or the directory was
    /// unreachable); the previous provider stays in force. Any count is worth
    /// an alert: someone published a provider that does not work.
    fn provider_reload_refused(&self, category: ProviderCategory) {
        let _ = category;
    }

    /// The FIDO2 relying-party id was changed by an acknowledged reload
    /// (`ReloadFido2::allow_rp_id_change`). Every passkey registered under
    /// the old id stops verifying, so any count is an event to look at.
    fn fido2_rp_id_changed(&self) {}
}
