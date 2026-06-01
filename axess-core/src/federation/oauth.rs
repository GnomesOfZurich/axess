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
/// Populated during `AuthnService` construction via `with_oauth_provider()`.
/// Provides introspection methods for listing configured providers.
#[derive(Default)]
pub struct OAuthProviderRegistry {
    providers: std::collections::HashMap<Arc<str>, Arc<dyn OAuthProvider>>,
}

impl OAuthProviderRegistry {
    pub(crate) fn add(&mut self, provider: impl OAuthProvider) {
        let name = provider.name().clone();
        self.providers.insert(name, Arc::new(provider));
    }

    pub(crate) fn get(&self, name: &str) -> Option<&Arc<dyn OAuthProvider>> {
        self.providers.get(name)
    }

    pub(crate) fn values(&self) -> impl Iterator<Item = &Arc<dyn OAuthProvider>> {
        self.providers.values()
    }

    /// Return the names of all registered providers.
    pub fn provider_names(&self) -> Vec<&Arc<str>> {
        self.providers.keys().collect()
    }

    /// Return the number of registered providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axess_factors::oauth::MockOAuthProvider;

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
}
