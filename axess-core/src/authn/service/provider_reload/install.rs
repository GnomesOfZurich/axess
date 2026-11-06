//! The steps every reload shares: await the candidate under the deadline,
//! swap it into its slot, count the outcome, announce it.

use std::sync::Arc;

use tracing::{info, warn};

use super::{BuiltProvider, ProviderChange, ProviderChangeKind, ProviderKey, ProviderReloadError};
use crate::authn::service::AuthnService;
use crate::authn::store::{FactorStore, IdentityStore};

const TARGET: &str = "axess::authn::provider_reload";

fn kind(replaced: bool) -> ProviderChangeKind {
    if replaced {
        ProviderChangeKind::Replaced
    } else {
        ProviderChangeKind::Added
    }
}

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Await `candidate` under the validation deadline.
    pub(super) async fn candidate<T, E: std::fmt::Display>(
        &self,
        key: &ProviderKey,
        candidate: impl std::future::Future<Output = Result<T, E>>,
    ) -> Result<T, ProviderReloadError> {
        let category = key.category();
        let after = self.inner.provider_reload.validation_timeout;
        match tokio::time::timeout(after, candidate).await {
            Err(_) => Err(ProviderReloadError::TimedOut { category, after }),
            Ok(Err(e)) => Err(ProviderReloadError::Build {
                category,
                reason: e.to_string(),
            }),
            Ok(Ok(built)) => Ok(built),
        }
    }

    /// Count and log the outcome of a swap, and announce a local one.
    ///
    /// A refusal is counted and logged here, once, whatever step made it.
    pub(super) async fn settle(
        &self,
        key: &ProviderKey,
        result: Result<ProviderChangeKind, ProviderReloadError>,
        announce: bool,
    ) -> Result<ProviderChange, ProviderReloadError> {
        let category = key.category();
        let kind = match result {
            Ok(kind) => kind,
            Err(e) => {
                self.inner
                    .metrics
                    .registry
                    .provider_reload_refused(category);
                warn!(
                    target: TARGET,
                    provider = %key.label(),
                    error = %e,
                    "provider reload refused; the previous provider stays in force",
                );
                return Err(e);
            }
        };
        if kind == ProviderChangeKind::Removed {
            self.inner.metrics.registry.provider_removed(category);
        } else {
            self.inner.metrics.registry.provider_reloaded(category);
        }
        info!(target: TARGET, provider = %key.label(), change = ?kind, "provider changed");
        let announced = announce && self.announce_provider(key).await;
        Ok(ProviderChange {
            key: key.clone(),
            kind,
            announced,
        })
    }

    async fn announce_provider(&self, key: &ProviderKey) -> bool {
        let Some(coordinator) = &self.inner.provider_reload.coordinator else {
            return false;
        };
        match coordinator.announce(&key.label()).await {
            Ok(()) => true,
            Err(e) => {
                warn!(
                    target: TARGET,
                    provider = %key.label(),
                    error = %e,
                    "the provider change stands; announcing it failed, followers catch up by poll",
                );
                false
            }
        }
    }

    /// Swap `provider` into the OAuth slot `key` names.
    #[cfg(feature = "oauth")]
    #[allow(irrefutable_let_patterns)]
    pub(super) fn install_oauth(
        &self,
        key: &ProviderKey,
        provider: Arc<dyn axess_factors::oauth::OAuthProvider>,
    ) -> Result<ProviderChangeKind, ProviderReloadError> {
        let ProviderKey::OAuth { tenant, name } = key else {
            return Err(ProviderReloadError::WrongCategory {
                label: key.label(),
                built: "oauth",
            });
        };
        if provider.name().as_ref() != name.as_ref() {
            return Err(ProviderReloadError::NameMismatch {
                requested: name.to_string(),
                provider: provider.name().to_string(),
            });
        }
        let replaced = match tenant {
            None => self.inner.oauth_providers.set(name, provider),
            Some(tenant) => self
                .inner
                .provider_reload
                .live_tenants
                .as_ref()
                .ok_or(ProviderReloadError::NoTenantRegistry)?
                .set(*tenant, name.clone(), provider),
        };
        Ok(kind(replaced))
    }

    /// Take the provider `key` names out of its slot.
    #[cfg(any(feature = "oauth", feature = "fido2", feature = "ldap"))]
    pub(super) fn remove_key(
        &self,
        key: &ProviderKey,
    ) -> Result<ProviderChangeKind, ProviderReloadError> {
        let removed = match key {
            #[cfg(feature = "oauth")]
            ProviderKey::OAuth { tenant: None, name } => self.inner.oauth_providers.remove(name),
            #[cfg(feature = "oauth")]
            ProviderKey::OAuth {
                tenant: Some(tenant),
                name,
            } => self
                .inner
                .provider_reload
                .live_tenants
                .as_ref()
                .ok_or(ProviderReloadError::NoTenantRegistry)?
                .remove(tenant, name),
            #[cfg(feature = "fido2")]
            ProviderKey::Fido2 => self.inner.fido2.swap(None).is_some(),
            #[cfg(feature = "ldap")]
            ProviderKey::Ldap => self.inner.ldap.swap(None).is_some(),
        };
        if removed {
            Ok(ProviderChangeKind::Removed)
        } else {
            Err(ProviderReloadError::NotFound { label: key.label() })
        }
    }

    /// Swap `provider` into the FIDO2 slot.
    ///
    /// A provider whose relying-party id differs from the one it replaces is
    /// refused unless `ack` allows the change; an allowed change is counted
    /// and logged with both ids.
    #[cfg(feature = "fido2")]
    pub(super) fn install_fido2(
        &self,
        key: &ProviderKey,
        provider: Arc<dyn axess_factors::fido2::Fido2Provider>,
        ack: super::ReloadFido2,
    ) -> Result<ProviderChangeKind, ProviderReloadError> {
        if *key != ProviderKey::Fido2 {
            return Err(ProviderReloadError::WrongCategory {
                label: key.label(),
                built: "fido2",
            });
        }
        let candidate_id = provider.relying_party_id().to_string();
        let next = Arc::new(provider);
        // `rcu` may run the closure again when another reload landed first;
        // each pass decides afresh against the provider it saw.
        let mut verdict: Result<Option<String>, ProviderReloadError> = Ok(None);
        self.inner.fido2.rcu(|current| match current {
            Some(current) if current.relying_party_id() != candidate_id => {
                if ack.allows_rp_id_change() {
                    verdict = Ok(Some(current.relying_party_id().to_string()));
                    Some(next.clone())
                } else {
                    verdict = Err(ProviderReloadError::RpIdChanged {
                        current: current.relying_party_id().to_string(),
                        candidate: candidate_id.clone(),
                    });
                    current.clone().into()
                }
            }
            Some(_) => {
                verdict = Ok(Some(candidate_id.clone()));
                Some(next.clone())
            }
            None => {
                verdict = Ok(None);
                Some(next.clone())
            }
        });
        let previous = verdict?;
        if let Some(previous_id) = &previous
            && *previous_id != candidate_id
        {
            self.inner.metrics.registry.fido2_rp_id_changed();
            warn!(
                target: TARGET,
                from = %previous_id,
                to = %candidate_id,
                "the FIDO2 relying-party id changed by acknowledgement; passkeys registered under the old id no longer verify",
            );
        }
        Ok(kind(previous.is_some()))
    }

    /// Ask the candidate's directory whether it answers, under the deadline.
    #[cfg(feature = "ldap")]
    pub(super) async fn check_ldap(
        &self,
        provider: Arc<dyn axess_factors::ldap::LdapProvider>,
    ) -> Result<Arc<dyn axess_factors::ldap::LdapProvider>, ProviderReloadError> {
        let after = self.inner.provider_reload.validation_timeout;
        match tokio::time::timeout(after, provider.check_reachable()).await {
            Err(_) => Err(ProviderReloadError::TimedOut {
                category: crate::metrics::ProviderCategory::Ldap,
                after,
            }),
            Ok(Err(e)) => Err(ProviderReloadError::Unreachable {
                reason: e.to_string(),
            }),
            Ok(Ok(())) => Ok(provider),
        }
    }

    /// Swap `provider` into the LDAP slot.
    #[cfg(feature = "ldap")]
    pub(super) fn install_ldap(
        &self,
        key: &ProviderKey,
        provider: Arc<dyn axess_factors::ldap::LdapProvider>,
    ) -> Result<ProviderChangeKind, ProviderReloadError> {
        if *key != ProviderKey::Ldap {
            return Err(ProviderReloadError::WrongCategory {
                label: key.label(),
                built: "ldap",
            });
        }
        let previous = self.inner.ldap.swap(Some(Arc::new(provider)));
        Ok(kind(previous.is_some()))
    }

    /// Install what a [`ProviderSource`](super::ProviderSource) built, after
    /// the same checks a direct reload makes.
    pub(super) async fn install_built(
        &self,
        key: &ProviderKey,
        built: BuiltProvider,
    ) -> Result<ProviderChangeKind, ProviderReloadError> {
        match built {
            #[cfg(feature = "oauth")]
            BuiltProvider::OAuth(provider) => self.install_oauth(key, provider),
            #[cfg(feature = "fido2")]
            BuiltProvider::Fido2(provider) => {
                self.install_fido2(key, provider, super::ReloadFido2::default())
            }
            #[cfg(feature = "fido2")]
            BuiltProvider::Fido2AllowingRpIdChange(provider) => {
                self.install_fido2(key, provider, super::ReloadFido2::allow_rp_id_change())
            }
            #[cfg(feature = "ldap")]
            BuiltProvider::Ldap(provider) => {
                let provider = self.check_ldap(provider).await?;
                self.install_ldap(key, provider)
            }
        }
    }
}
