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
    /// Insert a provider under its `provider.name()` key.
    ///
    /// **Duplicate-name safety:** if the key already exists, the new
    /// provider replaces the old one, a `tracing::warn!` is emitted, and
    /// in debug builds the process aborts via `debug_assert!`. Silent
    /// overwrite of a provider — especially with different `client_id`
    /// / `client_secret` — is a real security-relevant misconfiguration
    /// (token exchange would then execute against the wrong credentials
    /// for that IdP name); loud-in-dev, discoverable-in-prod is the
    /// deliberate balance chosen over an API-breaking `Result` return.
    pub(crate) fn add(&mut self, provider: impl OAuthProvider) {
        let name = provider.name().clone();
        let existing = self.providers.insert(name.clone(), Arc::new(provider));
        if existing.is_some() {
            tracing::warn!(
                provider_name = %name,
                "oauth: replacing existing provider registration; \
                 duplicate `with_oauth_provider` call — the previous \
                 configuration (client_id, discovery, etc.) is now lost"
            );
            debug_assert!(
                false,
                "duplicate OAuth provider name `{name}` registered; silent overwrite in release builds"
            );
        }
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

    /// Duplicate name registration must trip `debug_assert!` so
    /// operators discover the misconfiguration in dev / CI. Pins the
    /// silent-overwrite regression: without the assert, two
    /// `with_oauth_provider("google", ...)` calls quietly keep the
    /// second one and forget the first (which would be a real
    /// security-relevant footgun if the two carry different
    /// `client_secret`s).
    ///
    /// Cfg'd on `debug_assertions` because release builds do NOT
    /// panic — the release path emits a `tracing::warn!` and
    /// continues, and there is no straightforward way to assert on
    /// tracing output here without pulling in the mock-tracing
    /// scaffolding for a one-line check.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "duplicate OAuth provider name")]
    fn provider_registry_duplicate_name_panics_in_debug() {
        let mut registry = OAuthProviderRegistry::default();
        registry.add(MockOAuthProvider::new("google"));
        registry.add(MockOAuthProvider::new("google"));
    }
}
