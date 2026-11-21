//! The redirect URI a callback arrived on, named by the registration it
//! belongs to, and its comparison with the registration a login began with.

use super::state::CeremonyTenant;
use crate::authn::ids::TenantId;

/// The route an OAuth callback arrived on: the redirect URI of a provider
/// of the global registration, or of the provider a tenant brought.
///
/// Every provider has one redirect URI, and the application mounts one
/// callback route per registration that can hold a provider:
///
/// | Registration | Redirect URI shape | Route value |
/// |---|---|---|
/// | global (`with_oauth_provider`) | `/callback/{provider}` | [`global`](Self::global) |
/// | a tenant's own (`begin_oauth_login_with_tenant_provider`) | `/callback/{tenant}/{provider}` | [`of_tenant`](Self::of_tenant) |
///
/// A provider name alone does not say which authorization server a callback
/// belongs to: two tenants may each have a provider called `sso`, and a
/// tenant's name never shadows the global one. The route does, so the tenant
/// is part of it, and it is read from the request path the server routed,
/// never from a query parameter or a body. `finish_oauth_login` compares the
/// route with the registration the login began with and refuses any other
/// before the code is exchanged: that comparison is the mix-up defence of
/// RFC 9207 for an authorization server that sends no `iss`, and without the
/// tenant in it a hostile tenant's identity provider could have another
/// tenant's code posted to its own token endpoint.
///
/// A login begun with `begin_oauth_login_in_tenant` runs against the global
/// registration's provider and returns on that provider's redirect URI, so
/// its route is [`global`](Self::global); the tenant it is bound to is
/// compared with the resolved user by `complete_oauth_login`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OAuthCallbackRoute<'a> {
    tenant: Option<&'a TenantId>,
    provider: &'a str,
}

impl<'a> OAuthCallbackRoute<'a> {
    /// The callback route of the global registration's provider `provider`.
    #[must_use]
    pub const fn global(provider: &'a str) -> Self {
        Self {
            tenant: None,
            provider,
        }
    }

    /// The callback route of the provider `tenant` has under `provider`.
    #[must_use]
    pub const fn of_tenant(tenant: &'a TenantId, provider: &'a str) -> Self {
        Self {
            tenant: Some(tenant),
            provider,
        }
    }

    /// The provider name of the route.
    #[must_use]
    pub const fn provider(&self) -> &'a str {
        self.provider
    }

    /// The tenant of the route, `None` for a route of the global
    /// registration.
    #[must_use]
    pub const fn tenant(&self) -> Option<&'a TenantId> {
        self.tenant
    }

    /// Whether this is the route of the registration a ceremony began with:
    /// the same provider name, and the same tenant when the ceremony's
    /// provider came from a tenant, no tenant when it came from the global
    /// registration. A ceremony bound to a tenant over the global provider
    /// (`provider_from_tenant` unset) began with the global registration.
    pub(super) fn is_route_of(&self, provider_name: &str, binding: Option<CeremonyTenant>) -> bool {
        let began_with_tenant = binding
            .filter(|binding| binding.provider_from_tenant)
            .map(|binding| binding.tenant);
        self.provider == provider_name && self.tenant.copied() == began_with_tenant
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authn::ids::testing::tenant;

    fn from_tenant(label: &str) -> Option<CeremonyTenant> {
        Some(CeremonyTenant {
            tenant: tenant(label),
            provider_from_tenant: true,
        })
    }

    fn railed_to(label: &str) -> Option<CeremonyTenant> {
        Some(CeremonyTenant {
            tenant: tenant(label),
            provider_from_tenant: false,
        })
    }

    /// The route is the ceremony's only when the name and the registration
    /// both match: every pairing of a global route, two tenants' routes and
    /// the three kinds of ceremony.
    #[test]
    fn a_route_matches_only_the_registration_the_ceremony_began_with() {
        let (acme, beta) = (tenant("acme"), tenant("beta"));
        let global = OAuthCallbackRoute::global("sso");
        let at_acme = OAuthCallbackRoute::of_tenant(&acme, "sso");
        let at_beta = OAuthCallbackRoute::of_tenant(&beta, "sso");

        // Begun with the global registration, with and without a tenant
        // bound for the completion.
        for binding in [None, railed_to("acme")] {
            assert!(global.is_route_of("sso", binding));
            assert!(!at_acme.is_route_of("sso", binding), "{binding:?}");
            assert!(!at_beta.is_route_of("sso", binding), "{binding:?}");
        }
        // Begun with acme's own provider.
        assert!(at_acme.is_route_of("sso", from_tenant("acme")));
        assert!(!at_beta.is_route_of("sso", from_tenant("acme")));
        assert!(!global.is_route_of("sso", from_tenant("acme")));
        // Another name is another provider, whatever the registration.
        assert!(!global.is_route_of("other", None));
        assert!(!at_acme.is_route_of("other", from_tenant("acme")));
    }
}
