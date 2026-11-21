//! An operator's acts on a tenant's ownership of an OAuth client: the
//! attestation that a tenant owns one, and the hand-over of a pair another
//! record took. Both are a deployment operator's, a user of the operator
//! tenant [`TenantId::SYSTEM`], never a user of any other tenant, and both
//! are on the audit trail before they count.

use super::ProviderChangeError;
use crate::authn::event::{AuthEventBuilder, AuthEventType, AuthFailureReason};
use crate::authn::factor::FactorKind;
use crate::authn::ids::{TenantId, UserId};
use crate::authn::service::RequestAuthnService;
use crate::authn::store::{FactorStore, IdentityStore};
use crate::federation::oauth_tenant::{
    OwnershipAttestation, OwnershipPurpose, ReassignedPair, StoredTenantOAuthProviders,
    TenantOAuthProviderRecord, TenantOAuthProviderStore,
};

const TARGET: &str = "axess::authn::provider_reload";

/// The tag that opens the reason on the audit row of an operator's
/// attestation that a tenant owns an OAuth client; the write it is for, the
/// issuer and the client id follow it:
/// `client_ownership_attested purpose=register issuer="https://idp.example" client_id="app"`.
pub const CLIENT_OWNERSHIP_ATTESTED_REASON: &str = "client_ownership_attested";

/// The tag that opens the reason on the row an operator's hand-over of an
/// `(issuer, client_id)` pair writes before the store is asked, naming the
/// tenant and provider it is handed to; the issuer and the client id follow
/// it, quoted.
///
/// The row is the request, not its outcome, and its `Failure` status means
/// pending, not failed: as with
/// [`OAUTH_REVOCATION_REQUESTED_REASON`](crate::authn::service::OAUTH_REVOCATION_REQUESTED_REASON),
/// a request whose outcome was never recorded (a crash in between, or an
/// outcome row the store refused) never reads as a provider enabled. The
/// outcome follows under the same `request_id`: a `Success` row with
/// [`CLIENT_PAIR_HANDED_OVER_REASON`] when the pair moved, or a `Failure`
/// row with the refusal. Count hand-overs by the outcome rows, never by
/// this one.
pub const CLIENT_PAIR_HAND_OVER_REQUESTED_REASON: &str = "client_pair_hand_over_requested";

/// The tag that opens the reason on the `MethodDisabled` row a hand-over
/// writes for each record it removed, naming that record's tenant and
/// provider; the issuer, the client id and the tenant the pair went to
/// follow it, quoted.
pub const CLIENT_PAIR_HANDED_OVER_REASON: &str = "client_pair_handed_over";

/// The factor an audit row names for a tenant's provider: the kind its
/// record is configured with
/// ([`federated_kind`](TenantOAuthProviderRecord::federated_kind)).
fn factor(record: &TenantOAuthProviderRecord) -> FactorKind {
    FactorKind::Federated(record.federated_kind())
}

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Attest, as `actor`, that the tenant of `record` owns the record's
    /// client (its `client_id` at its `issuer`), for the record's provider
    /// name and the write `purpose` names: the
    /// [`OwnershipAttestation`] that write carries, to
    /// [`StoredTenantOAuthProviders::upsert_attested`] for
    /// [`OwnershipPurpose::Register`] or to
    /// [`reassign_tenant_oauth_pair_as`](Self::reassign_tenant_oauth_pair_as)
    /// for [`OwnershipPurpose::HandOver`], for the
    /// [`OperatorAttestation`](crate::federation::oauth_tenant::OperatorAttestation)
    /// proof, the route for a public client.
    ///
    /// The attesting operator is a deployment operator who checks ownership
    /// out of band (with the identity provider's administrator, in its
    /// console): an active user the identity store places in the operator
    /// tenant, [`TenantId::SYSTEM`], the tenant axess reserves for
    /// platform-operator principals and keeps self-service signup out of.
    /// An operator whose account is suspended, pending verification or not
    /// yet provisioned, as of the service's clock, is refused. A user of any other
    /// tenant is refused by name, whichever tenant it is, so a party that
    /// holds two tenants cannot have one attest for the other; so is one
    /// the identity store does not know, and an operator attesting the
    /// operator tenant itself. The reserved [`UserId::SYSTEM`], which
    /// automated paths such as seeding and signup act as, is refused too: it
    /// names nobody who checked ownership, and the attestation is worth what
    /// a named operator's word is. Call it from the same administrative path
    /// as the other `_as` provider changes, never on a tenant's word. The
    /// attestation is a `MethodEnabled` audit row naming the operator as the
    /// actor, the tenant, the provider as the factor (the kind the record
    /// is configured with), and the purpose, the issuer and the client id in
    /// its reason
    /// ([`CLIENT_OWNERSHIP_ATTESTED_REASON`]), written before the
    /// attestation is returned; a refusal writes a failure row.
    ///
    /// # Errors
    ///
    /// [`ProviderChangeError::NotADeploymentOperator`],
    /// [`ProviderChangeError::OperatorIsSystemUser`],
    /// [`ProviderChangeError::OperatorNotActive`],
    /// [`ProviderChangeError::OperatorActsForTenant`],
    /// [`ProviderChangeError::OperatorUnknown`] or
    /// [`ProviderChangeError::OperatorLookup`] when the actor is not a
    /// deployment operator, or cannot be shown to be one.
    /// [`ProviderChangeError::Audit`] when the row cannot be written: there
    /// is then no attestation, since one nobody can account for proves
    /// nothing.
    pub async fn attest_tenant_oauth_client_as(
        &self,
        actor: &UserId,
        record: &TenantOAuthProviderRecord,
        purpose: OwnershipPurpose,
    ) -> Result<OwnershipAttestation, ProviderChangeError> {
        let tenant = &record.tenant_id;
        let (name, issuer, client_id) = (&record.name, &record.issuer, &record.client_id);
        let reason = format!(
            "{CLIENT_OWNERSHIP_ATTESTED_REASON} purpose={purpose} issuer={issuer:?} \
             client_id={client_id:?}"
        );
        self.require_a_deployment_operator(actor, record, &reason)
            .await?;
        let row = AuthEventBuilder::success(AuthEventType::MethodEnabled)
            .with_error(AuthFailureReason::Other(reason))
            .with_actor(*actor)
            .maybe_attributed_to(None, Some(tenant))
            .with_factor(factor(record));
        self.emit_audit(row)
            .await
            .map_err(|e| ProviderChangeError::Audit {
                reason: e.to_string(),
            })?;
        Ok(OwnershipAttestation::recorded(
            *actor,
            *tenant,
            (name, issuer, client_id),
            purpose,
        ))
    }

    /// Hand `record`'s issuer and client id to `record`, as `actor`: the
    /// operator's override for a pair a tenant registered before its owner
    /// (a record stored before the directory asked for proof, or one
    /// [`StoredTenantOAuthProviders::reprove`] refuses). The records that
    /// held the pair and their providers are removed and `record` is
    /// written in one store write
    /// ([`TenantOAuthProviderStore::reassign_pair`]), so the tenant that
    /// took the pair cannot take it again in between, from this process or
    /// another. Returns the record as stored and each record removed.
    /// `attestation`, made for [`OwnershipPurpose::HandOver`], is for a
    /// deployment that accepts
    /// [`OperatorAttestation`](crate::federation::oauth_tenant::OperatorAttestation);
    /// without it the record proves itself as a registration would.
    ///
    /// `actor` is a deployment operator, as for
    /// [`attest_tenant_oauth_client_as`](Self::attest_tenant_oauth_client_as):
    /// a user of any tenant but [`TenantId::SYSTEM`] is refused, the tenant
    /// the pair goes to and the one that holds it included. Each row names a
    /// record's provider by the kind the record is configured with. A row
    /// naming the actor, the tenant and provider the pair goes to, the
    /// issuer and the client id
    /// ([`CLIENT_PAIR_HAND_OVER_REQUESTED_REASON`], `Failure` until
    /// it is done) is written before anything changes, and nothing changes
    /// when it cannot be. Then the hand-over writes a `MethodEnabled` row
    /// for the record it stored and a `MethodDisabled` row for each record it
    /// removed ([`CLIENT_PAIR_HANDED_OVER_REASON`], attributed to the removed
    /// record's tenant), or a failure row with the refusal. A row after the
    /// store write that cannot be written is logged as an error: the
    /// hand-over has happened, and the request row accounts for it.
    ///
    /// # Errors
    ///
    /// As [`attest_tenant_oauth_client_as`](Self::attest_tenant_oauth_client_as)
    /// for the actor, [`ProviderChangeError::Audit`] when the request row
    /// cannot be written, and [`ProviderChangeError::HandOver`] with the
    /// directory's refusal: the record is incomplete, its issuer URL is one
    /// the egress policy refuses, ownership is not proven, the global
    /// registration holds the pair, the credential cannot be sealed, or the
    /// store fails or cannot make the removal and the write one step
    /// ([`TenantOAuthProviderStoreError::reassign_pair_unsupported`](crate::federation::oauth_tenant::TenantOAuthProviderStoreError::reassign_pair_unsupported)).
    /// Nothing was removed or written then.
    pub async fn reassign_tenant_oauth_pair_as<S: TenantOAuthProviderStore>(
        &self,
        actor: &UserId,
        directory: &StoredTenantOAuthProviders<S>,
        record: TenantOAuthProviderRecord,
        attestation: Option<OwnershipAttestation>,
    ) -> Result<ReassignedPair, ProviderChangeError> {
        let (tenant, name) = (record.tenant_id, record.name.clone());
        let factor_of_record = factor(&record);
        let pair = format!(
            "issuer={:?} client_id={:?}",
            record.issuer, record.client_id
        );
        let requested = format!("{CLIENT_PAIR_HAND_OVER_REQUESTED_REASON} {pair}");
        self.require_a_deployment_operator(actor, &record, &requested)
            .await?;
        let row = AuthEventBuilder::failure(AuthEventType::MethodEnabled)
            .with_error(AuthFailureReason::Other(requested))
            .with_actor(*actor)
            .maybe_attributed_to(None, Some(&tenant))
            .with_factor(factor_of_record.clone());
        self.emit_audit(row)
            .await
            .map_err(|e| ProviderChangeError::Audit {
                reason: e.to_string(),
            })?;
        let handed = directory.hand_over(record, attestation.as_ref()).await;
        let rows = match &handed {
            Ok(handed) => {
                let done = format!("{CLIENT_PAIR_HANDED_OVER_REASON} {pair}");
                let mut rows = vec![
                    AuthEventBuilder::success(AuthEventType::MethodEnabled)
                        .with_error(AuthFailureReason::Other(done))
                        .maybe_attributed_to(None, Some(&tenant))
                        .with_factor(factor_of_record.clone()),
                ];
                for removed in &handed.removed {
                    rows.push(
                        AuthEventBuilder::success(AuthEventType::MethodDisabled)
                            .with_error(AuthFailureReason::Other(format!(
                                "{CLIENT_PAIR_HANDED_OVER_REASON} {pair} to_tenant=\"{tenant}\""
                            )))
                            .maybe_attributed_to(None, Some(&removed.tenant_id))
                            .with_factor(factor(removed)),
                    );
                }
                rows
            }
            Err(refused) => vec![
                AuthEventBuilder::failure(AuthEventType::MethodEnabled)
                    .with_error(AuthFailureReason::Other(refused.to_string()))
                    .maybe_attributed_to(None, Some(&tenant))
                    .with_factor(factor_of_record),
            ],
        };
        for row in rows {
            if let Err(error) = self.emit_audit(row.with_actor(*actor)).await {
                tracing::error!(
                    target: TARGET,
                    %tenant,
                    provider = %crate::authn::service::log_text::logged_request_text(&name),
                    %error,
                    "a row of a pair's hand-over could not be written; its request row stands"
                );
            }
        }
        handed.map_err(ProviderChangeError::HandOver)
    }

    /// Refuse `actor` unless it is a deployment operator acting for another
    /// tenant than `record`'s: a user the identity store places in the
    /// operator tenant, [`TenantId::SYSTEM`], whose account is active as of
    /// the service's clock, when the record's tenant is not that tenant, and
    /// never the reserved [`UserId::SYSTEM`]. A refusal writes a failure row
    /// with `reason` and the refusal.
    async fn require_a_deployment_operator(
        &self,
        actor: &UserId,
        record: &TenantOAuthProviderRecord,
        reason: &str,
    ) -> Result<(), ProviderChangeError> {
        let tenant = &record.tenant_id;
        let Some(refused) = self.deployment_operator_refusal(actor, tenant).await else {
            return Ok(());
        };
        let row = AuthEventBuilder::failure(AuthEventType::MethodEnabled)
            .with_error(AuthFailureReason::Other(format!("{reason}: {refused}")))
            .with_actor(*actor)
            .maybe_attributed_to(None, Some(tenant))
            .with_factor(factor(record));
        if let Err(error) = self.emit_audit(row).await {
            tracing::error!(
                target: TARGET,
                %tenant,
                provider = %crate::authn::service::log_text::logged_request_text(&record.name),
                %error,
                "the refusal of an operator's act on a client's ownership could not be recorded"
            );
        }
        Err(refused)
    }

    /// Why `actor` may not act as a deployment operator for `tenant`, or
    /// `None` when it may.
    async fn deployment_operator_refusal(
        &self,
        actor: &UserId,
        tenant: &TenantId,
    ) -> Option<ProviderChangeError> {
        if actor.is_system() {
            return Some(ProviderChangeError::OperatorIsSystemUser);
        }
        let user = match self.inner.identity.get_user(actor).await {
            Ok(Some(user)) => user,
            Ok(None) => return Some(ProviderChangeError::OperatorUnknown),
            Err(e) => {
                return Some(ProviderChangeError::OperatorLookup {
                    reason: e.to_string(),
                });
            }
        };
        if user.tenant_id == *tenant {
            Some(ProviderChangeError::OperatorActsForTenant)
        } else if !user.tenant_id.is_system() {
            Some(ProviderChangeError::NotADeploymentOperator)
        } else if !user.status.effective_at(self.inner.clock.now()).is_active() {
            Some(ProviderChangeError::OperatorNotActive)
        } else {
            None
        }
    }
}
