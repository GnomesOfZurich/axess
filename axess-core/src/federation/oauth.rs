//! Orchestrator-side OAuth/OIDC code: [`OAuthProviderRegistry`].
//!
//! The OAuth ceremony itself, the [`OAuthProvider`] trait, mock impls,
//! and the per-provider types live in [`axess_factors::oauth`]. This
//! file owns only the registry that [`crate::authn::AuthnService`]
//! consults when dispatching to configured providers; orchestrator
//! state, not factor-side data.
//!
//! [`OAuthProvider`]: axess_factors::oauth::OAuthProvider

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
/// ([`AuthnService::reload_oauth_provider`](crate::authn::service::AuthnService::reload_oauth_provider)),
/// so a snapshot taken from
/// [`AuthnService::oauth_providers`](crate::authn::service::AuthnService::oauth_providers)
/// does not change under the caller.
#[derive(Default, Clone)]
pub struct OAuthProviderRegistry {
    providers: std::collections::HashMap<Arc<str>, Arc<dyn OAuthProvider>>,
}

impl OAuthProviderRegistry {
    /// Set `provider` under `name`; `true` when it replaced one.
    pub(crate) fn set(&mut self, name: Arc<str>, provider: Arc<dyn OAuthProvider>) -> bool {
        self.providers.insert(name, provider).is_some()
    }

    /// Drop the provider under `name`; `true` when there was one.
    pub(crate) fn remove(&mut self, name: &str) -> bool {
        self.providers.remove(name).is_some()
    }

    pub(crate) fn get(&self, name: &str) -> Option<&Arc<dyn OAuthProvider>> {
        self.providers.get(name)
    }

    pub(crate) fn values(&self) -> impl Iterator<Item = &Arc<dyn OAuthProvider>> {
        self.providers.values()
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
    pub(crate) fn add(&self, provider: impl OAuthProvider) -> bool {
        let provider: Arc<dyn OAuthProvider> = Arc::new(provider);
        let name = provider.name().clone();
        let replaced = self.set(&name, provider);
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

    /// Set `provider` under `name`; `true` when it replaced one. A reload
    /// replaces on purpose and is reported by its caller.
    pub(crate) fn set(&self, name: &Arc<str>, provider: Arc<dyn OAuthProvider>) -> bool {
        let replaced = std::sync::atomic::AtomicBool::new(false);
        self.current.rcu(|registry| {
            let mut next = OAuthProviderRegistry::clone(registry);
            replaced.store(
                next.set(name.clone(), provider.clone()),
                std::sync::atomic::Ordering::Relaxed,
            );
            next
        });
        replaced.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Drop the provider under `name`; `true` when there was one.
    pub(crate) fn remove(&self, name: &str) -> bool {
        let removed = std::sync::atomic::AtomicBool::new(false);
        self.current.rcu(|registry| {
            let mut next = OAuthProviderRegistry::clone(registry);
            removed.store(next.remove(name), std::sync::atomic::Ordering::Relaxed);
            next
        });
        removed.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axess_factors::oauth::MockOAuthProvider;

    impl OAuthProviderRegistry {
        fn add(&mut self, provider: impl OAuthProvider) -> bool {
            let provider: Arc<dyn OAuthProvider> = Arc::new(provider);
            self.set(provider.name().clone(), provider)
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
