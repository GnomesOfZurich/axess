//! A registry of tenant providers an adopter pushes while the service runs.

use super::{IssuerFuture, IssuerProviders, ProviderFuture, TenantOAuthProviders, TenantProvider};
use crate::authn::ids::TenantId;
use axess_factors::oauth::OAuthProvider;
use std::collections::HashMap;
use std::sync::Arc;

type Entries = HashMap<TenantId, HashMap<Arc<str>, Arc<dyn OAuthProvider>>>;

/// Tenant providers keyed by `(tenant, name)`, swapped without a lock.
///
/// Unlike [`StoredTenantOAuthProviders`](super::StoredTenantOAuthProviders),
/// which builds a provider from a stored record the first time a login needs
/// it, this holds providers the adopter built (or a
/// [`ProviderSource`](crate::authn::service::ProviderSource) built for it) and
/// installed with
/// [`AuthnService::reload_tenant_oauth_provider`](crate::authn::service::AuthnService::reload_tenant_oauth_provider).
/// The key includes the tenant, so a reload for one tenant replaces exactly
/// that tenant's entry and never reads or rebuilds another's, including one
/// of the same name.
///
/// Create one, keep an `Arc`, and hand it to
/// [`AuthnServiceBuilder::with_live_tenant_oauth_providers`](crate::authn::service::AuthnServiceBuilder::with_live_tenant_oauth_providers).
#[derive(Default)]
pub struct LiveTenantOAuthProviders {
    current: arc_swap::ArcSwap<Entries>,
    /// Bumped by every `set` and `remove`; see
    /// [`TenantOAuthProviders::generation`].
    generation: std::sync::atomic::AtomicU64,
}

impl LiveTenantOAuthProviders {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// The provider `tenant` has under `name`, as of now.
    pub fn get(&self, tenant: &TenantId, name: &str) -> Option<Arc<dyn OAuthProvider>> {
        self.current
            .load()
            .get(tenant)
            .and_then(|byname| byname.get(name))
            .cloned()
    }

    /// The names `tenant` has providers under, as of now.
    pub fn names(&self, tenant: &TenantId) -> Vec<Arc<str>> {
        self.current
            .load()
            .get(tenant)
            .map(|byname| byname.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// How many providers are registered, over all tenants.
    pub fn len(&self) -> usize {
        self.current.load().values().map(HashMap::len).sum()
    }

    /// `true` when no tenant has a provider.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Set the entry of `(tenant, name)` only; `true` when it replaced one.
    pub(crate) fn set(
        &self,
        tenant: TenantId,
        name: Arc<str>,
        provider: Arc<dyn OAuthProvider>,
    ) -> bool {
        let replaced = std::sync::atomic::AtomicBool::new(false);
        self.current.rcu(|entries| {
            let mut next = Entries::clone(entries);
            let was = next
                .entry(tenant)
                .or_default()
                .insert(name.clone(), provider.clone());
            replaced.store(was.is_some(), std::sync::atomic::Ordering::Relaxed);
            next
        });
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        replaced.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Remove the entry of `(tenant, name)` only; `true` when there was one.
    pub(crate) fn remove(&self, tenant: &TenantId, name: &str) -> bool {
        let removed = std::sync::atomic::AtomicBool::new(false);
        self.current.rcu(|entries| {
            let mut next = Entries::clone(entries);
            let was = next
                .get_mut(tenant)
                .is_some_and(|byname| byname.remove(name).is_some());
            if next.get(tenant).is_some_and(HashMap::is_empty) {
                next.remove(tenant);
            }
            removed.store(was, std::sync::atomic::Ordering::Relaxed);
            next
        });
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        removed.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl TenantOAuthProviders for LiveTenantOAuthProviders {
    fn generation(&self) -> u64 {
        self.generation.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn provider<'a>(&'a self, tenant: &'a TenantId, name: &'a str) -> ProviderFuture<'a> {
        Box::pin(async move { Ok(self.get(tenant, name)) })
    }

    fn built_providers(&self) -> Vec<Arc<dyn OAuthProvider>> {
        self.current
            .load()
            .values()
            .flat_map(|byname| byname.values().cloned())
            .collect()
    }

    fn providers_for_issuer<'a>(&'a self, issuer: &'a str) -> IssuerFuture<'a> {
        Box::pin(async move {
            let providers = self
                .current
                .load()
                .iter()
                .flat_map(|(tenant, byname)| {
                    byname
                        .iter()
                        .filter(|(_, provider)| provider.issuer() == Some(issuer))
                        .map(|(name, provider)| TenantProvider {
                            tenant: *tenant,
                            name: Arc::clone(name),
                            provider: Arc::clone(provider),
                        })
                })
                .collect();
            Ok(IssuerProviders {
                providers,
                broken: Vec::new(),
            })
        })
    }
}
