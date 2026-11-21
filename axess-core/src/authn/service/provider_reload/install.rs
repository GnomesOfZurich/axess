//! The steps every reload shares: await the candidate under the deadline,
//! swap it into its slot, count the outcome, announce it.

use std::sync::Arc;

use tracing::{info, warn};

use super::{BuiltProvider, ProviderChange, ProviderChangeKind, ProviderKey, ProviderReloadError};
use crate::authn::factor::FactorKind;
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

/// What a slot held before a swap, and which slot it was: enough to put it
/// back when the record of the change cannot be written, with nothing else
/// to consult.
pub(super) enum Previous {
    #[cfg(feature = "oauth")]
    OAuth {
        /// The tenant whose registry holds the slot, `None` for the global one.
        tenant: Option<crate::authn::ids::TenantId>,
        /// The provider name the slot is keyed by.
        name: Arc<str>,
        /// What the slot held: the provider, with the kind its
        /// configuration named (`None` for `Custom(name)`).
        provider: Option<crate::federation::oauth::HeldProvider>,
    },
    #[cfg(feature = "fido2")]
    Fido2(Option<Arc<Arc<dyn axess_factors::fido2::Fido2Provider>>>),
    #[cfg(feature = "ldap")]
    Ldap(Option<Arc<Arc<dyn axess_factors::ldap::LdapProvider>>>),
}

impl Previous {
    fn is_some(&self) -> bool {
        match self {
            #[cfg(feature = "oauth")]
            Self::OAuth { provider, .. } => provider.is_some(),
            #[cfg(feature = "fido2")]
            Self::Fido2(p) => p.is_some(),
            #[cfg(feature = "ldap")]
            Self::Ldap(p) => p.is_some(),
        }
    }

    /// The factor the audit row of a removal names: for an OAuth slot, the
    /// kind the removed provider's configuration named (`Custom(name)` when
    /// it named none, or when the slot was empty).
    pub(super) fn removed_factor(&self) -> FactorKind {
        match self {
            #[cfg(feature = "oauth")]
            Self::OAuth { name, provider, .. } => FactorKind::Federated(
                provider
                    .as_ref()
                    .and_then(|(_, kind)| kind.clone())
                    .unwrap_or_else(|| {
                        crate::authn::factor::FederatedProvider::Custom(name.to_string())
                    }),
            ),
            #[cfg(feature = "fido2")]
            Self::Fido2(_) => FactorKind::Fido2,
            #[cfg(feature = "ldap")]
            Self::Ldap(_) => FactorKind::LdapBind,
        }
    }
}

/// A swap that was made: what it did to the slot and what the slot held.
pub(super) struct Swapped {
    pub(super) kind: ProviderChangeKind,
    pub(super) previous: Previous,
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
                    provider = %crate::authn::service::log_text::logged_request_text(&key.label()),
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
        info!(target: TARGET, provider = %crate::authn::service::log_text::logged_request_text(&key.label()), change = ?kind, "provider changed");
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
                    provider = %crate::authn::service::log_text::logged_request_text(&key.label()),
                    error = %e,
                    "the provider change stands; announcing it failed, followers catch up by poll",
                );
                false
            }
        }
    }

    /// Build the OAuth candidate under the deadline and swap it into the
    /// slot `key` names, with the kind its logins record.
    #[cfg(feature = "oauth")]
    pub(super) async fn oauth_swap<P, E>(
        &self,
        key: &ProviderKey,
        kind: crate::authn::factor::FederatedProvider,
        candidate: impl std::future::Future<Output = Result<P, E>>,
    ) -> Result<Swapped, ProviderReloadError>
    where
        P: axess_factors::oauth::OAuthProvider,
        E: std::fmt::Display,
    {
        let provider = self
            .candidate(key, candidate)
            .await
            .map(|p| Arc::new(p) as Arc<dyn axess_factors::oauth::OAuthProvider>)?;
        self.install_oauth(key, provider, kind)
    }

    /// Build the FIDO2 candidate under the deadline and swap it in.
    #[cfg(feature = "fido2")]
    pub(super) async fn fido2_swap<P, E>(
        &self,
        key: &ProviderKey,
        candidate: impl std::future::Future<Output = Result<P, E>>,
        options: super::ReloadFido2,
    ) -> Result<Swapped, ProviderReloadError>
    where
        P: axess_factors::fido2::Fido2Provider,
        E: std::fmt::Display,
    {
        let provider = self
            .candidate(key, candidate)
            .await
            .map(|p| Arc::new(p) as Arc<dyn axess_factors::fido2::Fido2Provider>)?;
        self.install_fido2(key, provider, options)
    }

    /// Build the LDAP candidate under the deadline, ask its directory, and
    /// swap it in.
    #[cfg(feature = "ldap")]
    pub(super) async fn ldap_swap<P, E>(
        &self,
        key: &ProviderKey,
        candidate: impl std::future::Future<Output = Result<P, E>>,
    ) -> Result<Swapped, ProviderReloadError>
    where
        P: axess_factors::ldap::LdapProvider,
        E: std::fmt::Display,
    {
        let provider = self
            .candidate(key, candidate)
            .await
            .map(|p| Arc::new(p) as Arc<dyn axess_factors::ldap::LdapProvider>)?;
        let checked = self.check_ldap(provider).await?;
        self.install_ldap(key, checked)
    }

    /// Put back what a swap replaced: for a change whose audit row could not
    /// be written. A concurrent reload of the same key between the swap and
    /// this call is overwritten too, which its own audit row reports.
    pub(super) fn undo(&self, previous: Previous) {
        match previous {
            #[cfg(feature = "oauth")]
            Previous::OAuth {
                tenant,
                name,
                provider,
            } => match (tenant, provider) {
                (None, Some((p, kind))) => {
                    self.inner.oauth_providers.set(&name, p, kind);
                }
                (None, None) => {
                    self.inner.oauth_providers.remove(&name);
                }
                (Some(tenant), previous) => {
                    let Some(live) = &self.inner.provider_reload.live_tenants else {
                        return;
                    };
                    match previous {
                        Some((p, kind)) => {
                            let kind = kind.unwrap_or_else(|| {
                                crate::authn::factor::FederatedProvider::Custom(name.to_string())
                            });
                            if live.set(tenant, name.clone(), p, kind).is_err() {
                                tracing::error!(
                                    target: "axess::authn::provider_reload",
                                    %tenant,
                                    provider = %crate::authn::service::log_text::logged_request_text(&name),
                                    "the provider a change replaced could not be put back: \
                                     another provider took its issuer and client id meanwhile"
                                );
                            }
                        }
                        None => {
                            live.remove(&tenant, &name);
                        }
                    }
                }
            },
            #[cfg(feature = "fido2")]
            Previous::Fido2(previous) => {
                self.inner.fido2.swap(previous);
            }
            #[cfg(feature = "ldap")]
            Previous::Ldap(previous) => {
                self.inner.ldap.swap(previous);
            }
        }
    }

    /// Swap `provider` into the OAuth slot `key` names, with `federated`,
    /// the kind every login through it records from then on.
    #[cfg(feature = "oauth")]
    pub(super) fn install_oauth(
        &self,
        key: &ProviderKey,
        provider: Arc<dyn axess_factors::oauth::OAuthProvider>,
        federated: crate::authn::factor::FederatedProvider,
    ) -> Result<Swapped, ProviderReloadError> {
        let Some((tenant, name)) = key.oauth_slot() else {
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
        let previous = match tenant {
            None => self
                .inner
                .oauth_providers
                .set(name, provider, Some(federated)),
            Some(tenant) => {
                let live = self
                    .inner
                    .provider_reload
                    .live_tenants
                    .as_ref()
                    .ok_or(ProviderReloadError::NoTenantRegistry)?;
                self.refuse_a_global_pair(key, &*provider)?;
                live.set(*tenant, name.clone(), provider, federated)
                    .map_err(|_| ProviderReloadError::PairHeld {
                        label: key.label(),
                        by_global: false,
                    })?
                    .map(|(was, was_kind)| (was, Some(was_kind)))
            }
        };
        Ok(Swapped {
            kind: kind(previous.is_some()),
            previous: Previous::OAuth {
                tenant: tenant.copied(),
                name: name.clone(),
                provider: previous,
            },
        })
    }

    /// Refuse a tenant provider whose issuer and client id a global provider
    /// holds: the global registration decides that client's logout tokens,
    /// and a tenant's provider never shadows it.
    #[cfg(feature = "oauth")]
    fn refuse_a_global_pair(
        &self,
        key: &ProviderKey,
        provider: &dyn axess_factors::oauth::OAuthProvider,
    ) -> Result<(), ProviderReloadError> {
        let Some(pair) = crate::federation::oauth_tenant::pair_of(provider) else {
            return Ok(());
        };
        let globals = self.inner.oauth_providers.load();
        if globals
            .values()
            .any(|global| crate::federation::oauth_tenant::pair_of(&**global) == Some(pair))
        {
            return Err(ProviderReloadError::PairHeld {
                label: key.label(),
                by_global: true,
            });
        }
        Ok(())
    }

    /// Take the provider `key` names out of its slot.
    #[cfg(any(feature = "oauth", feature = "fido2", feature = "ldap"))]
    pub(super) fn remove_key(&self, key: &ProviderKey) -> Result<Swapped, ProviderReloadError> {
        let previous = match key {
            #[cfg(feature = "oauth")]
            ProviderKey::OAuth { tenant: None, name } => Previous::OAuth {
                tenant: None,
                name: name.clone(),
                provider: self.inner.oauth_providers.remove(name),
            },
            #[cfg(feature = "oauth")]
            ProviderKey::OAuth {
                tenant: Some(tenant),
                name,
            } => Previous::OAuth {
                tenant: Some(*tenant),
                name: name.clone(),
                provider: self
                    .inner
                    .provider_reload
                    .live_tenants
                    .as_ref()
                    .ok_or(ProviderReloadError::NoTenantRegistry)?
                    .remove(tenant, name)
                    .map(|(was, kind)| (was, Some(kind))),
            },
            #[cfg(feature = "fido2")]
            ProviderKey::Fido2 => Previous::Fido2(self.inner.fido2.swap(None)),
            #[cfg(feature = "ldap")]
            ProviderKey::Ldap => Previous::Ldap(self.inner.ldap.swap(None)),
        };
        if previous.is_some() {
            Ok(Swapped {
                kind: ProviderChangeKind::Removed,
                previous,
            })
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
    ) -> Result<Swapped, ProviderReloadError> {
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
        type Held = Option<Arc<Arc<dyn axess_factors::fido2::Fido2Provider>>>;
        let mut verdict: Result<Held, ProviderReloadError> = Ok(None);
        self.inner.fido2.rcu(|current| match current {
            Some(current) if current.relying_party_id() != candidate_id => {
                if ack.allows_rp_id_change() {
                    verdict = Ok(Some(current.clone()));
                    Some(next.clone())
                } else {
                    verdict = Err(ProviderReloadError::RpIdChanged {
                        current: current.relying_party_id().to_string(),
                        candidate: candidate_id.clone(),
                    });
                    current.clone().into()
                }
            }
            Some(current) => {
                verdict = Ok(Some(current.clone()));
                Some(next.clone())
            }
            None => {
                verdict = Ok(None);
                Some(next.clone())
            }
        });
        let previous = verdict?;
        if let Some(previous_provider) = &previous
            && previous_provider.relying_party_id() != candidate_id
        {
            self.inner.metrics.registry.fido2_rp_id_changed();
            warn!(
                target: TARGET,
                from = %previous_provider.relying_party_id(),
                to = %candidate_id,
                "the FIDO2 relying-party id changed by acknowledgement; passkeys registered under the old id no longer verify",
            );
        }
        Ok(Swapped {
            kind: kind(previous.is_some()),
            previous: Previous::Fido2(previous),
        })
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
    ) -> Result<Swapped, ProviderReloadError> {
        if *key != ProviderKey::Ldap {
            return Err(ProviderReloadError::WrongCategory {
                label: key.label(),
                built: "ldap",
            });
        }
        let previous = self.inner.ldap.swap(Some(Arc::new(provider)));
        Ok(Swapped {
            kind: kind(previous.is_some()),
            previous: Previous::Ldap(previous),
        })
    }

    /// Install what a [`ProviderSource`](super::ProviderSource) built, after
    /// the same checks a direct reload makes.
    pub(super) async fn install_built(
        &self,
        key: &ProviderKey,
        built: BuiltProvider,
    ) -> Result<Swapped, ProviderReloadError> {
        match built {
            #[cfg(feature = "oauth")]
            BuiltProvider::OAuth { provider, kind } => self.install_oauth(key, provider, kind),
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
