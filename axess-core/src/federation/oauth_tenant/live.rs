//! A registry of tenant providers an adopter pushes while the service runs.

use super::{
    IssuerFuture, IssuerProviders, KindFuture, ProviderFuture, TenantOAuthProviders, TenantProvider,
};
use crate::authn::factor::FederatedProvider;
use crate::authn::ids::TenantId;
use axess_factors::oauth::OAuthProvider;
use std::collections::HashMap;
use std::sync::Arc;

/// A provider as the registry holds it, with the kind every login through
/// it records.
pub(crate) type LiveEntry = (Arc<dyn OAuthProvider>, FederatedProvider);

type Entries = HashMap<TenantId, HashMap<Arc<str>, LiveEntry>>;

/// Tenant providers keyed by `(tenant, name)`, swapped without a lock.
///
/// Unlike [`StoredTenantOAuthProviders`](super::StoredTenantOAuthProviders),
/// which builds a provider from a stored record the first time a login needs
/// it, this holds providers the adopter built (or a
/// [`ProviderSource`](crate::authn::service::ProviderSource) built for it) and
/// installed with
/// [`RequestAuthnService::reload_tenant_oauth_provider_as`](crate::authn::service::RequestAuthnService::reload_tenant_oauth_provider_as).
/// The key includes the tenant, so a reload for one tenant replaces exactly
/// that tenant's entry and never reads or rebuilds another's, including one
/// of the same name.
///
/// Each entry holds the [`FederatedProvider`] the reload that installed it
/// named, which every login through it records
/// ([`TenantOAuthProviders::provider_kind`]): a kind is configured with the
/// provider, never read from its issuer URL, as for a global provider or a
/// stored record.
///
/// One `(issuer, client_id)` pair belongs to one provider, as in the stored
/// directory: a reload that would give a second `(tenant, name)` the pair
/// another one holds (another tenant's, or this tenant's under another
/// name), or a pair a global provider holds, is refused by name
/// ([`ProviderReloadError::PairHeld`](crate::authn::service::ProviderReloadError::PairHeld)),
/// whether an administrator's reload or a
/// [`ProviderSource`](crate::authn::service::ProviderSource) follower's
/// makes it. No proof of ownership is asked here: an adopter builds these
/// providers and an operator installs them through
/// [`RequestAuthnService::reload_tenant_oauth_provider_as`](crate::authn::service::RequestAuthnService::reload_tenant_oauth_provider_as),
/// which audits who did, so the operator's path is where ownership is
/// checked.
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
            .map(|(provider, _)| provider.clone())
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

    /// Set the entry of `(tenant, name)` only, with the kind its logins
    /// record; the entry it replaced, if any. Refused, and nothing set, when
    /// another entry holds the provider's issuer and client id: the check
    /// and the swap are one step.
    pub(crate) fn set(
        &self,
        tenant: TenantId,
        name: Arc<str>,
        provider: Arc<dyn OAuthProvider>,
        kind: FederatedProvider,
    ) -> Result<Option<LiveEntry>, PairHeldElsewhere> {
        let outcome = std::sync::Mutex::new(Ok(None));
        self.current.rcu(|entries| {
            if holds_pair_elsewhere(entries, &tenant, &name, &*provider) {
                *outcome.lock().unwrap_or_else(|p| p.into_inner()) = Err(PairHeldElsewhere);
                return Arc::clone(entries);
            }
            let mut next = Entries::clone(entries);
            let was = next
                .entry(tenant)
                .or_default()
                .insert(name.clone(), (provider.clone(), kind.clone()));
            *outcome.lock().unwrap_or_else(|p| p.into_inner()) = Ok(was);
            Arc::new(next)
        });
        let outcome = outcome.into_inner().unwrap_or_else(|p| p.into_inner());
        if outcome.is_ok() {
            self.generation
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        outcome
    }

    /// Remove the entry of `(tenant, name)` only; the entry there was, if
    /// any.
    pub(crate) fn remove(&self, tenant: &TenantId, name: &str) -> Option<LiveEntry> {
        let removed = std::sync::Mutex::new(None);
        self.current.rcu(|entries| {
            let mut next = Entries::clone(entries);
            let was = next.get_mut(tenant).and_then(|byname| byname.remove(name));
            if next.get(tenant).is_some_and(HashMap::is_empty) {
                next.remove(tenant);
            }
            *removed.lock().unwrap_or_else(|p| p.into_inner()) = was;
            next
        });
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        removed.into_inner().unwrap_or_else(|p| p.into_inner())
    }
}

/// A provider's issuer and client id are held by another entry of the
/// registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PairHeldElsewhere;

/// The `(issuer, client_id)` pair `provider` names, when it names both.
pub(crate) fn pair_of(provider: &dyn OAuthProvider) -> Option<(&str, &str)> {
    Some((provider.issuer()?, provider.client_id()?))
}

/// Whether an entry other than `(tenant, name)` holds `provider`'s pair.
fn holds_pair_elsewhere(
    entries: &Entries,
    tenant: &TenantId,
    name: &str,
    provider: &dyn OAuthProvider,
) -> bool {
    let Some(pair) = pair_of(provider) else {
        return false;
    };
    entries.iter().any(|(other_tenant, byname)| {
        byname.iter().any(|(other_name, (other, _))| {
            (other_tenant, other_name.as_ref()) != (tenant, name) && pair_of(&**other) == Some(pair)
        })
    })
}

impl TenantOAuthProviders for LiveTenantOAuthProviders {
    fn generation(&self) -> u64 {
        self.generation.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn provider<'a>(&'a self, tenant: &'a TenantId, name: &'a str) -> ProviderFuture<'a> {
        Box::pin(async move { Ok(self.get(tenant, name)) })
    }

    /// The kind the reload that installed the entry named, or
    /// `FederatedProvider::Custom(name)` when there is no entry.
    fn provider_kind<'a>(&'a self, tenant: &'a TenantId, name: &'a str) -> KindFuture<'a> {
        let kind = self
            .current
            .load()
            .get(tenant)
            .and_then(|byname| byname.get(name))
            .map(|(_, kind)| kind.clone())
            .unwrap_or_else(|| FederatedProvider::Custom(name.to_string()));
        Box::pin(std::future::ready(kind))
    }

    fn built_providers(&self) -> Vec<Arc<dyn OAuthProvider>> {
        self.current
            .load()
            .values()
            .flat_map(|byname| byname.values().map(|(provider, _)| provider.clone()))
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
                        .filter(|(_, (provider, _))| provider.issuer() == Some(issuer))
                        .map(|(name, (provider, _))| TenantProvider {
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
