//! Orchestrator-side OAuth/OIDC code: [`OAuthProviderRegistry`].
//!
//! The OAuth ceremony itself, the [`OAuthProvider`] trait, mock impls,
//! and the per-provider types live in [`axess_factors::oauth`]. This
//! file owns only the registry that [`crate::authn::AuthnService`]
//! consults when dispatching to configured providers; orchestrator
//! state, not factor-side data.
//!
//! [`OAuthProvider`]: axess_factors::oauth::OAuthProvider

use crate::authn::factor::FederatedProvider;
use axess_factors::oauth::OAuthProvider;
use std::sync::Arc;

// ── OAuthProviderRegistry ────────────────────────────────────────────────────

/// Registry of configured OAuth/OIDC providers.
///
/// Populated during `AuthnService` construction via `with_oauth_provider()`,
/// and changed afterwards only by a reload or removal on the service.
/// Provides introspection methods for listing configured providers.
///
/// A value of this type is an immutable snapshot: a running service swaps the
/// whole registry when a provider is reloaded or removed
/// ([`RequestAuthnService::reload_oauth_provider_as`](crate::authn::service::RequestAuthnService::reload_oauth_provider_as)),
/// so a snapshot taken from
/// [`AuthnService::oauth_providers`](crate::authn::service::AuthnService::oauth_providers)
/// does not change under the caller.
///
/// Each name has a kind, the [`FederatedProvider`] every login through the
/// provider records: the one its configuration named, or `Custom(name)`.
/// [`with_oauth_provider_of_kind`](crate::authn::service::AuthnServiceBuilder::with_oauth_provider_of_kind)
/// names it at construction, and a reload
/// ([`reload_oauth_provider_as`](crate::authn::service::RequestAuthnService::reload_oauth_provider_as),
/// or a [`ProviderSource`](crate::authn::service::ProviderSource) a
/// follower reads) names it again with the provider it installs, so the
/// kind is always the one the provider in force was configured with.
#[derive(Default, Clone)]
pub struct OAuthProviderRegistry {
    providers: std::collections::HashMap<Arc<str>, Arc<dyn OAuthProvider>>,
    /// The kinds the configurations named; a name not here is
    /// `Custom(name)`.
    kinds: std::collections::HashMap<Arc<str>, FederatedProvider>,
}

/// A provider as the registry held it, with the kind its configuration
/// named (`None` for `Custom(name)`): what a change takes out, and what an
/// undone change puts back.
pub(crate) type HeldProvider = (Arc<dyn OAuthProvider>, Option<FederatedProvider>);

impl OAuthProviderRegistry {
    /// Set `provider` under `name`, with the kind its configuration named
    /// (`None` for `Custom(name)`); what it replaced, if anything.
    pub(crate) fn set(
        &mut self,
        name: Arc<str>,
        provider: Arc<dyn OAuthProvider>,
        kind: Option<FederatedProvider>,
    ) -> Option<HeldProvider> {
        let was_kind = match kind {
            Some(kind) => self.kinds.insert(name.clone(), kind),
            None => self.kinds.remove(&name),
        };
        self.providers
            .insert(name, provider)
            .map(|was| (was, was_kind))
    }

    /// Drop the provider under `name` and its kind; what was there, if
    /// anything.
    pub(crate) fn remove(&mut self, name: &str) -> Option<HeldProvider> {
        let was_kind = self.kinds.remove(name);
        self.providers.remove(name).map(|was| (was, was_kind))
    }

    pub(crate) fn get(&self, name: &str) -> Option<&Arc<dyn OAuthProvider>> {
        self.providers.get(name)
    }

    pub(crate) fn values(&self) -> impl Iterator<Item = &Arc<dyn OAuthProvider>> {
        self.providers.values()
    }

    /// The kind the logins through the provider `name` record: the one its
    /// registration named, or `FederatedProvider::Custom(name)` when it named
    /// none (and for a name nothing registered).
    pub fn provider_kind(&self, name: &str) -> FederatedProvider {
        self.kinds
            .get(name)
            .cloned()
            .unwrap_or_else(|| FederatedProvider::Custom(name.to_string()))
    }

    /// Return the names of all registered providers.
    pub fn provider_names(&self) -> Vec<Arc<str>> {
        self.providers.keys().cloned().collect()
    }

    /// Return the number of registered providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }
}

/// The swap slot of the global registry: readers take a snapshot with
/// [`load`](Self::load) and never wait; writers install a changed copy.
#[derive(Default)]
pub(crate) struct OAuthRegistrySlot {
    current: Arc<arc_swap::ArcSwap<OAuthProviderRegistry>>,
}

impl OAuthRegistrySlot {
    /// The registry as of now.
    pub(crate) fn load(&self) -> Arc<OAuthProviderRegistry> {
        self.current.load_full()
    }

    /// A shared handle on the slot's current registry, for a background task
    /// that must read the live registry on every pass without holding the
    /// service that owns the slot.
    pub(crate) fn handle(&self) -> Arc<arc_swap::ArcSwap<OAuthProviderRegistry>> {
        self.current.clone()
    }

    /// Register `provider` under its own name at construction; `true` on a
    /// duplicate, which is logged: at construction a repeated name is a
    /// misconfiguration (see [`OAuthProviderRegistry::add`]).
    pub(crate) fn add(
        &self,
        provider: impl OAuthProvider,
        kind: Option<FederatedProvider>,
    ) -> bool {
        let provider: Arc<dyn OAuthProvider> = Arc::new(provider);
        let name = provider.name().clone();
        let replaced = self.set(&name, provider, kind).is_some();
        if replaced {
            tracing::warn!(
                provider_name = %name,
                "oauth: replacing existing provider registration; \
                 duplicate `with_oauth_provider` call: the previous \
                 configuration (client_id, discovery, etc.) is now lost"
            );
        }
        replaced
    }

    /// Set `provider` under `name` with the kind its configuration named
    /// (`None` for `Custom(name)`), provider and kind in one swap; what it
    /// replaced, if anything. A reload replaces on purpose and is reported
    /// by its caller.
    pub(crate) fn set(
        &self,
        name: &Arc<str>,
        provider: Arc<dyn OAuthProvider>,
        kind: Option<FederatedProvider>,
    ) -> Option<HeldProvider> {
        let replaced = std::sync::Mutex::new(None);
        self.current.rcu(|registry| {
            let mut next = OAuthProviderRegistry::clone(registry);
            *replaced.lock().unwrap_or_else(|p| p.into_inner()) =
                next.set(name.clone(), provider.clone(), kind.clone());
            next
        });
        replaced.into_inner().unwrap_or_else(|p| p.into_inner())
    }

    /// Drop the provider under `name` and its kind; what was there, if
    /// anything.
    pub(crate) fn remove(&self, name: &str) -> Option<HeldProvider> {
        let removed = std::sync::Mutex::new(None);
        self.current.rcu(|registry| {
            let mut next = OAuthProviderRegistry::clone(registry);
            *removed.lock().unwrap_or_else(|p| p.into_inner()) = next.remove(name);
            next
        });
        removed.into_inner().unwrap_or_else(|p| p.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axess_factors::oauth::MockOAuthProvider;

    impl OAuthProviderRegistry {
        fn add(&mut self, provider: impl OAuthProvider) -> bool {
            let provider: Arc<dyn OAuthProvider> = Arc::new(provider);
            self.set(provider.name().clone(), provider, None).is_some()
        }
    }

    #[test]
    fn provider_registry_get_returns_added_provider() {
        let mut registry = OAuthProviderRegistry::default();
        registry.add(MockOAuthProvider::new("google"));
        assert!(registry.get("google").is_some());
        assert!(registry.get("missing").is_none());
    }

    #[test]
    fn provider_registry_values_yields_added_providers() {
        let mut registry = OAuthProviderRegistry::default();
        registry.add(MockOAuthProvider::new("google"));
        registry.add(MockOAuthProvider::new("github"));
        let names: std::collections::HashSet<_> =
            registry.values().map(|p| p.name().to_string()).collect();
        assert!(names.contains("google"));
        assert!(names.contains("github"));
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn provider_registry_count_reflects_adds() {
        let mut registry = OAuthProviderRegistry::default();
        assert_eq!(registry.provider_count(), 0);
        registry.add(MockOAuthProvider::new("google"));
        assert_eq!(registry.provider_count(), 1);
        registry.add(MockOAuthProvider::new("github"));
        assert_eq!(registry.provider_count(), 2);
    }

    /// A name's kind is the one its registration named, `Custom(name)`
    /// otherwise; a later registration or reload of the name sets it again,
    /// and a removal takes it with the provider.
    #[test]
    fn a_names_kind_is_the_one_its_registration_named() {
        let slot = OAuthRegistrySlot::default();
        slot.add(
            MockOAuthProvider::new("google"),
            Some(FederatedProvider::Google),
        );
        slot.add(MockOAuthProvider::new("sso"), None);
        let registry = slot.load();
        assert_eq!(registry.provider_kind("google"), FederatedProvider::Google);
        assert_eq!(
            registry.provider_kind("sso"),
            FederatedProvider::Custom("sso".to_string())
        );
        assert_eq!(
            registry.provider_kind("unknown"),
            FederatedProvider::Custom("unknown".to_string())
        );
        // A reload sets the kind it names, and answers what it replaced.
        let name: Arc<str> = Arc::from("google");
        let (_, was) = slot
            .set(
                &name,
                Arc::new(MockOAuthProvider::new("google")),
                Some(FederatedProvider::Microsoft),
            )
            .expect("a provider was there");
        assert_eq!(was, Some(FederatedProvider::Google));
        assert_eq!(
            slot.load().provider_kind("google"),
            FederatedProvider::Microsoft
        );
        slot.add(MockOAuthProvider::new("google"), None);
        assert_eq!(
            slot.load().provider_kind("google"),
            FederatedProvider::Custom("google".to_string())
        );
        // A removal takes the kind with the provider.
        let sso: Arc<str> = Arc::from("sso");
        slot.set(
            &sso,
            Arc::new(MockOAuthProvider::new("sso")),
            Some(FederatedProvider::Github),
        );
        let (_, removed) = slot.remove("sso").expect("a provider was there");
        assert_eq!(removed, Some(FederatedProvider::Github));
        assert_eq!(
            slot.load().provider_kind("sso"),
            FederatedProvider::Custom("sso".to_string())
        );
    }

    /// A second registration under one name replaces the first and says so,
    /// so the builder can count it and refuse a debug build.
    #[test]
    fn provider_registry_reports_a_replaced_name() {
        let mut registry = OAuthProviderRegistry::default();
        assert!(!registry.add(MockOAuthProvider::new("google")));
        assert!(registry.add(MockOAuthProvider::new("google")));
        assert_eq!(registry.provider_count(), 1);
    }
}
