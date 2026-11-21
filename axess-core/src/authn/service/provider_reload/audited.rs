//! Provider changes made by a named administrator, each recorded as an audit
//! row before it stands.
//!
//! Changing an identity provider is the most powerful administrative act in a
//! multi-tenant deployment: a tenant's logins go wherever the new provider
//! points. Each method here takes the administrator who made the change and
//! writes a `MethodEnabled` (reload) or `MethodDisabled` (removal) row naming
//! them, the provider and, for a tenant's provider, the tenant. A refused
//! change writes a failure row with the refusal. When the row of a change
//! that was made cannot be written, the change is undone and refused as
//! [`ProviderChangeError::Audit`]: a provider change nobody can account for
//! does not stand.
//!
//! A change a follower applies from its
//! [`ProviderSource`](super::ProviderSource) has no administrator: its row
//! names none and carries the reason [`PROVIDER_SOURCE_REASON`], and the
//! same rule holds, so a change whose row cannot be written is undone and
//! tried again at the follower's next read.

use super::install::Swapped;
use super::{ProviderChange, ProviderKey, ProviderReloadError};
use crate::authn::event::{AuthEventBuilder, AuthEventType, AuthFailureReason};
use crate::authn::factor::FactorKind;
use crate::authn::ids::UserId;
use crate::authn::service::RequestAuthnService;
use crate::authn::store::{FactorStore, IdentityStore};

const TARGET: &str = "axess::authn::provider_reload";

/// The reason a provider change a follower applied from its source carries
/// on its audit row, in place of an administrator.
pub const PROVIDER_SOURCE_REASON: &str = "provider_source";

/// Why an audited provider change did not happen. The previous provider
/// stays in force in every case.
#[derive(Debug, thiserror::Error)]
pub enum ProviderChangeError {
    /// The reload or removal itself was refused.
    #[error(transparent)]
    Refused(#[from] ProviderReloadError),
    /// The audit row of the change could not be written, so the change was
    /// undone: a provider change that cannot be accounted for does not stand.
    #[error("the provider change was undone because its audit row could not be written: {reason}")]
    Audit {
        /// The audit store's error.
        reason: String,
    },
    /// The operator who would attest a tenant's client, or hand a pair to
    /// a tenant, is a user of that tenant: a tenant does not vouch for
    /// itself, a deployment operator does.
    #[error(
        "the operator acts for the tenant it would attest or hand a pair to; a deployment \
         operator, who checks ownership out of band, must do it"
    )]
    OperatorActsForTenant,
    /// The operator is not a user of the deployment's operator tenant,
    /// [`TenantId::SYSTEM`](crate::authn::ids::TenantId::SYSTEM): a user of
    /// any other tenant acts for that tenant, and a party that holds two
    /// tenants would otherwise take one tenant's client for the other.
    #[error(
        "the operator is not a user of the deployment's operator tenant (the system tenant), \
         so it cannot attest a client or hand a pair over"
    )]
    NotADeploymentOperator,
    /// The operator is the reserved
    /// [`UserId::SYSTEM`](crate::authn::ids::UserId::SYSTEM), which automated
    /// paths (seeding, signup) act as: it names nobody who checked ownership.
    #[error(
        "the reserved system user names no operator, so it cannot attest a client or hand a \
         pair over"
    )]
    OperatorIsSystemUser,
    /// The operator's account is not active (suspended, pending
    /// verification, or not yet provisioned) as of the service's clock.
    #[error(
        "the operator's account is not active, so it cannot attest a client or hand a pair over"
    )]
    OperatorNotActive,
    /// The operator is not a known user, so nothing shows which tenant it
    /// acts for.
    #[error("the operator is not a known user, so nothing shows it is a deployment operator")]
    OperatorUnknown,
    /// The identity store could not say which tenant the operator acts for.
    #[error("the operator's tenant could not be read: {reason}")]
    OperatorLookup {
        /// The identity store's error.
        reason: String,
    },
    /// The directory refused an operator's hand-over of a pair; nothing was
    /// removed or written.
    #[cfg(feature = "oauth")]
    #[error("the hand-over was refused: {0}")]
    HandOver(#[source] axess_factors::oauth::OAuthError),
}

impl ProviderKey {
    /// The factor the audit row of a change of this key names when the
    /// change names no kind and removed nothing: for an OAuth key the
    /// name's `Custom(name)`.
    fn factor_kind(&self) -> FactorKind {
        match self {
            #[cfg(feature = "oauth")]
            Self::OAuth { name, .. } => FactorKind::Federated(
                crate::authn::factor::FederatedProvider::Custom(name.to_string()),
            ),
            #[cfg(feature = "fido2")]
            Self::Fido2 => FactorKind::Fido2,
            #[cfg(feature = "ldap")]
            Self::Ldap => FactorKind::LdapBind,
        }
    }

    /// The factor the audit row of a removal of this key names: the kind
    /// of the provider it took out, or [`factor_kind`](Self::factor_kind)
    /// when it took nothing out.
    #[cfg(feature = "oauth")]
    fn removal_factor(&self, removed: &Result<Swapped, ProviderReloadError>) -> FactorKind {
        match removed {
            Ok(swapped) => swapped.previous.removed_factor(),
            Err(_) => self.factor_kind(),
        }
    }

    /// The tenant an audit row for this key belongs to: a tenant's provider's
    /// tenant, none for a global provider.
    fn audit_tenant(&self) -> Option<crate::authn::ids::TenantId> {
        match self {
            #[cfg(feature = "oauth")]
            Self::OAuth { tenant, .. } => *tenant,
            #[cfg(any(feature = "fido2", feature = "ldap"))]
            _ => None,
        }
    }
}

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Replace or add the global OAuth provider named `name` with the one
    /// `candidate` builds, as `actor`: the change is recorded as a
    /// `MethodEnabled` audit row naming them and the provider, and a refusal
    /// as a failure row.
    ///
    /// `kind` is the [`FederatedProvider`](crate::authn::factor::FederatedProvider)
    /// every login through the new provider records, as
    /// [`with_oauth_provider_of_kind`](crate::authn::service::AuthnServiceBuilder::with_oauth_provider_of_kind)
    /// names it at construction: `FederatedProvider::Google` for a provider
    /// that is Google's, `FederatedProvider::Custom(name)` for one of no
    /// named kind. It replaces the kind the name had with the provider, and
    /// the audit row names it as the factor.
    ///
    /// `candidate` is awaited under the validation deadline; pass the future
    /// of `OAuthProviderConfig::discover(..)` finished with `.build()`, so the
    /// discovery fetch and the issuer check run before anything is swapped.
    /// The provider's own name must equal `name`. On success the next
    /// `begin_oauth_login(name, ..)` uses the new provider; a login begun
    /// against the old one finishes only if the issuer is unchanged.
    ///
    /// # Errors
    ///
    /// [`ProviderChangeError::Refused`] with the reload's refusal
    /// ([`ProviderReloadError::Build`],
    /// [`TimedOut`](ProviderReloadError::TimedOut) or
    /// [`NameMismatch`](ProviderReloadError::NameMismatch)), or
    /// [`ProviderChangeError::Audit`] when the row could not be written, in
    /// which case the swap is undone. The previous provider keeps serving in
    /// every case.
    #[cfg(feature = "oauth")]
    pub async fn reload_oauth_provider_as<P, E>(
        &self,
        actor: &UserId,
        name: &str,
        kind: crate::authn::factor::FederatedProvider,
        candidate: impl std::future::Future<Output = Result<P, E>>,
    ) -> Result<ProviderChange, ProviderChangeError>
    where
        P: axess_factors::oauth::OAuthProvider,
        E: std::fmt::Display,
    {
        let key = super::oauth_key(None, name);
        let factor = FactorKind::Federated(kind.clone());
        let swapped = self.oauth_swap(&key, kind, candidate).await;
        self.settle_as(actor, &key, false, factor, swapped).await
    }

    /// Take the global OAuth provider named `name` out, as `actor`, recorded
    /// as a `MethodDisabled` audit row naming the kind it was configured
    /// with. Its routes refuse by name
    /// (`OAuthError::UnknownProvider`) from the next call on; a login in
    /// flight fails its callback the same way.
    ///
    /// # Errors
    ///
    /// [`ProviderChangeError::Refused`] with
    /// [`ProviderReloadError::NotFound`] when no such provider is
    /// registered, or [`ProviderChangeError::Audit`] as for
    /// [`reload_oauth_provider_as`](Self::reload_oauth_provider_as).
    #[cfg(feature = "oauth")]
    pub async fn remove_oauth_provider_as(
        &self,
        actor: &UserId,
        name: &str,
    ) -> Result<ProviderChange, ProviderChangeError> {
        let key = super::oauth_key(None, name);
        let removed = self.remove_key(&key);
        let factor = key.removal_factor(&removed);
        self.settle_as(actor, &key, true, factor, removed).await
    }

    /// As [`reload_oauth_provider_as`](Self::reload_oauth_provider_as), for
    /// the provider `tenant` has under `name`: the audit row names the
    /// actor, the provider's `kind` and the tenant, and every login through
    /// the entry records `kind`
    /// ([`TenantOAuthProviders::provider_kind`](crate::federation::oauth_tenant::TenantOAuthProviders::provider_kind)).
    /// Only that entry changes: another tenant's provider of the same name
    /// is not read or rebuilt.
    ///
    /// # Errors
    ///
    /// As [`reload_oauth_provider_as`](Self::reload_oauth_provider_as), and
    /// a refusal with [`ProviderReloadError::NoTenantRegistry`] without
    /// [`with_live_tenant_oauth_providers`](crate::authn::service::AuthnServiceBuilder::with_live_tenant_oauth_providers),
    /// or with [`PairHeld`](ProviderReloadError::PairHeld) when another
    /// provider holds the candidate's issuer and client id.
    #[cfg(feature = "oauth")]
    pub async fn reload_tenant_oauth_provider_as<P, E>(
        &self,
        actor: &UserId,
        tenant: &crate::authn::ids::TenantId,
        name: &str,
        kind: crate::authn::factor::FederatedProvider,
        candidate: impl std::future::Future<Output = Result<P, E>>,
    ) -> Result<ProviderChange, ProviderChangeError>
    where
        P: axess_factors::oauth::OAuthProvider,
        E: std::fmt::Display,
    {
        let key = super::oauth_key(Some(*tenant), name);
        let factor = FactorKind::Federated(kind.clone());
        let swapped = self.oauth_swap(&key, kind, candidate).await;
        self.settle_as(actor, &key, false, factor, swapped).await
    }

    /// Take the provider `tenant` has under `name` out of the live registry,
    /// as `actor`, recorded as a `MethodDisabled` audit row of the tenant
    /// naming the kind the entry was installed with.
    ///
    /// # Errors
    ///
    /// [`ProviderChangeError::Refused`] with
    /// [`ProviderReloadError::NotFound`] or
    /// [`NoTenantRegistry`](ProviderReloadError::NoTenantRegistry), or
    /// [`ProviderChangeError::Audit`] as for
    /// [`reload_oauth_provider_as`](Self::reload_oauth_provider_as).
    #[cfg(feature = "oauth")]
    pub async fn remove_tenant_oauth_provider_as(
        &self,
        actor: &UserId,
        tenant: &crate::authn::ids::TenantId,
        name: &str,
    ) -> Result<ProviderChange, ProviderChangeError> {
        let key = super::oauth_key(Some(*tenant), name);
        let removed = self.remove_key(&key);
        let factor = key.removal_factor(&removed);
        self.settle_as(actor, &key, true, factor, removed).await
    }

    /// Replace or add the FIDO2 provider with the one `candidate` builds, as
    /// `actor`, recorded as a `MethodEnabled` audit row.
    ///
    /// `candidate` parses the relying party (`WebauthnBuilder::build`), so an
    /// invalid RP id or origin is refused before the swap. Changing the RP id
    /// orphans every registered credential, so a candidate whose
    /// [`relying_party_id`](axess_factors::fido2::Fido2Provider::relying_party_id)
    /// differs from the provider in force is refused as
    /// [`RpIdChanged`](ProviderReloadError::RpIdChanged); use
    /// [`reload_fido2_with_as`](Self::reload_fido2_with_as) to acknowledge
    /// it.
    ///
    /// # Errors
    ///
    /// [`ProviderChangeError::Refused`] with [`ProviderReloadError::Build`],
    /// [`TimedOut`](ProviderReloadError::TimedOut) or
    /// [`RpIdChanged`](ProviderReloadError::RpIdChanged), or
    /// [`ProviderChangeError::Audit`] as for
    /// [`reload_oauth_provider_as`](Self::reload_oauth_provider_as).
    #[cfg(feature = "fido2")]
    pub async fn reload_fido2_as<P, E>(
        &self,
        actor: &UserId,
        candidate: impl std::future::Future<Output = Result<P, E>>,
    ) -> Result<ProviderChange, ProviderChangeError>
    where
        P: axess_factors::fido2::Fido2Provider,
        E: std::fmt::Display,
    {
        self.reload_fido2_with_as(actor, candidate, super::ReloadFido2::default())
            .await
    }

    /// As [`reload_fido2_as`](Self::reload_fido2_as), with `options` stating
    /// what the caller accepts.
    /// [`ReloadFido2::allow_rp_id_change`](super::ReloadFido2::allow_rp_id_change)
    /// lets a changed relying-party id through; the change is counted
    /// (`ProviderRegistryMetrics::fido2_rp_id_changed`) and logged with both
    /// ids on `axess::authn::provider_reload`.
    ///
    /// # Errors
    ///
    /// As [`reload_fido2_as`](Self::reload_fido2_as).
    #[cfg(feature = "fido2")]
    pub async fn reload_fido2_with_as<P, E>(
        &self,
        actor: &UserId,
        candidate: impl std::future::Future<Output = Result<P, E>>,
        options: super::ReloadFido2,
    ) -> Result<ProviderChange, ProviderChangeError>
    where
        P: axess_factors::fido2::Fido2Provider,
        E: std::fmt::Display,
    {
        let key = ProviderKey::Fido2;
        let swapped = self.fido2_swap(&key, candidate, options).await;
        self.settle_as(actor, &key, false, key.factor_kind(), swapped)
            .await
    }

    /// Take the FIDO2 provider out, as `actor`, recorded as a
    /// `MethodDisabled` audit row. Its ceremony steps answer
    /// `AuthnError::NoFlow` from the next call on; credentials already
    /// registered stay in the store.
    ///
    /// # Errors
    ///
    /// [`ProviderChangeError::Refused`] with
    /// [`ProviderReloadError::NotFound`] when no FIDO2 provider is attached,
    /// or [`ProviderChangeError::Audit`] as for
    /// [`reload_oauth_provider_as`](Self::reload_oauth_provider_as).
    #[cfg(feature = "fido2")]
    pub async fn remove_fido2_as(
        &self,
        actor: &UserId,
    ) -> Result<ProviderChange, ProviderChangeError> {
        let key = ProviderKey::Fido2;
        let removed = self.remove_key(&key);
        self.settle_as(actor, &key, true, key.factor_kind(), removed)
            .await
    }

    /// Replace or add the LDAP provider with the one `candidate` builds, as
    /// `actor`, recorded as a `MethodEnabled` audit row, after its directory
    /// answered
    /// [`check_reachable`](axess_factors::ldap::LdapProvider::check_reachable)
    /// within the validation deadline.
    ///
    /// # Errors
    ///
    /// [`ProviderChangeError::Refused`] with [`ProviderReloadError::Build`],
    /// [`TimedOut`](ProviderReloadError::TimedOut) or
    /// [`Unreachable`](ProviderReloadError::Unreachable), or
    /// [`ProviderChangeError::Audit`] as for
    /// [`reload_oauth_provider_as`](Self::reload_oauth_provider_as).
    #[cfg(feature = "ldap")]
    pub async fn reload_ldap_as<P, E>(
        &self,
        actor: &UserId,
        candidate: impl std::future::Future<Output = Result<P, E>>,
    ) -> Result<ProviderChange, ProviderChangeError>
    where
        P: axess_factors::ldap::LdapProvider,
        E: std::fmt::Display,
    {
        let key = ProviderKey::Ldap;
        let swapped = self.ldap_swap(&key, candidate).await;
        self.settle_as(actor, &key, false, key.factor_kind(), swapped)
            .await
    }

    /// Take the LDAP provider out, as `actor`, recorded as a
    /// `MethodDisabled` audit row. A factor chain with
    /// [`FactorKind::LdapBind`]
    /// answers `FactorOutcome::InvalidCredential` from the next call on.
    ///
    /// # Errors
    ///
    /// [`ProviderChangeError::Refused`] with
    /// [`ProviderReloadError::NotFound`] when no LDAP provider is attached,
    /// or [`ProviderChangeError::Audit`] as for
    /// [`reload_oauth_provider_as`](Self::reload_oauth_provider_as).
    #[cfg(feature = "ldap")]
    pub async fn remove_ldap_as(
        &self,
        actor: &UserId,
    ) -> Result<ProviderChange, ProviderChangeError> {
        let key = ProviderKey::Ldap;
        let removed = self.remove_key(&key);
        self.settle_as(actor, &key, true, key.factor_kind(), removed)
            .await
    }

    /// Record the outcome of a swap as `actor`'s, with `factor` as the row's
    /// factor, then count, log and announce it as every change is. A swap
    /// whose row cannot be written is undone.
    async fn settle_as(
        &self,
        actor: &UserId,
        key: &ProviderKey,
        removal: bool,
        factor: FactorKind,
        swapped: Result<Swapped, ProviderReloadError>,
    ) -> Result<ProviderChange, ProviderChangeError> {
        let swapped = match swapped {
            Ok(swapped) => swapped,
            Err(refusal) => {
                // The change did not happen; its refusal is recorded as well
                // as the store allows, and reported whether or not it was.
                if let Err(reason) = self
                    .record_provider_change(Some(actor), key, removal, factor, Err(&refusal))
                    .await
                {
                    tracing::error!(
                        target: TARGET,
                        provider = %crate::authn::service::log_text::logged_request_text(&key.label()),
                        error = %reason,
                        "the refusal of a provider change could not be recorded"
                    );
                }
                let settled = self.settle(key, Err(refusal), true).await;
                return settled.map_err(ProviderChangeError::Refused);
            }
        };
        if let Err(reason) = self
            .record_provider_change(Some(actor), key, removal, factor, Ok(()))
            .await
        {
            self.undo(swapped.previous);
            tracing::error!(
                target: TARGET,
                provider = %crate::authn::service::log_text::logged_request_text(&key.label()),
                error = %reason,
                "the provider change was undone: its audit row could not be written"
            );
            return Err(ProviderChangeError::Audit { reason });
        }
        self.settle(key, Ok(swapped.kind), true)
            .await
            .map_err(ProviderChangeError::Refused)
    }

    /// One audit row for a provider change: `MethodEnabled` for a reload,
    /// `MethodDisabled` for a removal, naming the actor, the provider as
    /// `factor` (an OAuth provider's configured kind) and the tenant, with
    /// the refusal as the failure reason when it was refused. With no actor
    /// the change is a follower's, from its source, and the row says so with
    /// [`PROVIDER_SOURCE_REASON`].
    pub(super) async fn record_provider_change(
        &self,
        actor: Option<&UserId>,
        key: &ProviderKey,
        removal: bool,
        factor: FactorKind,
        outcome: Result<(), &ProviderReloadError>,
    ) -> Result<(), String> {
        let event_type = if removal {
            AuthEventType::MethodDisabled
        } else {
            AuthEventType::MethodEnabled
        };
        let builder = match (outcome, actor) {
            (Ok(()), Some(_)) => AuthEventBuilder::success(event_type),
            (Ok(()), None) => AuthEventBuilder::success(event_type)
                .with_error(AuthFailureReason::from(PROVIDER_SOURCE_REASON)),
            (Err(refusal), _) => AuthEventBuilder::failure(event_type)
                .with_error(AuthFailureReason::Other(refusal.to_string())),
        };
        let builder = match actor {
            Some(actor) => builder.with_actor(*actor),
            None => builder,
        };
        let tenant = key.audit_tenant();
        self.emit_audit(
            builder
                .maybe_attributed_to(None, tenant.as_ref())
                .with_factor(factor),
        )
        .await
        .map_err(|e| e.to_string())
    }
}
