//! The directory's writes: a registration and an operator's hand-over, each
//! asking the deployment's proofs of ownership first, and the check of a
//! stored record against them.

use super::{StoredTenantOAuthProviders, store_error};
use crate::authn::ids::TenantId;
use crate::federation::oauth_tenant::ownership::{
    OwnershipAttestation, OwnershipClaim, OwnershipProven, OwnershipPurpose, OwnershipRefused,
};
use crate::federation::oauth_tenant::{
    ReassignedPair, TenantOAuthProviderRecord, TenantOAuthProviderStore,
};
use axess_factors::oauth::OAuthError;

/// What [`StoredTenantOAuthProviders::reprove`] found for a stored record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reproved {
    /// A proof the deployment accepts holds for the record as stored.
    Proven(OwnershipProven),
    /// No accepted proof holds: the record's tenant has not shown that it
    /// owns the client. An operator who finds the pair taken from its owner
    /// hands it over
    /// ([`reassign_tenant_oauth_pair_as`](crate::authn::service::RequestAuthnService::reassign_tenant_oauth_pair_as)).
    Refused(OwnershipRefused),
    /// There is no record under that tenant and name.
    NoRecord,
}

impl<S: TenantOAuthProviderStore> StoredTenantOAuthProviders<S> {
    /// Write a record (sealing its credential when a cipher is set). Returns
    /// the stored record with its new revision, which the next resolution
    /// builds.
    ///
    /// # Errors
    ///
    /// [`OAuthError::Config`] when the record is incomplete, its issuer URL is
    /// one the egress policy refuses, the tenant's ownership of the client is
    /// not proven (the refusal names the
    /// [`OwnershipRefused`](super::super::OwnershipRefused) of each proof tried), or
    /// its issuer and client id are already registered by another record
    /// (another tenant's, or this tenant's under another name) or by the
    /// global registration
    /// ([`with_global_registration`](Self::with_global_registration)): the
    /// refusal names which, never the other record or the issuer.
    /// [`OAuthError::Store`] when the credential cannot be sealed or the
    /// store fails.
    ///
    /// A tenant that registers through a path of its own can call this as
    /// often as the path lets it; bound the registrations per tenant there
    /// (a named setting, as the OAuth page's example shows).
    ///
    /// A pair already held is refused before the proof is asked, so it costs
    /// no request to the identity provider. A free pair's proof may make
    /// requests to it (the [`TokenEndpointProbe`](super::super::TokenEndpointProbe)
    /// makes up to four per call), from the deployment's own address, as
    /// often as a tenant calls: limit the calls per tenant on the path that
    /// takes them.
    ///
    /// Registrations in one process are serialised, so two of them cannot both
    /// take a free pair. Across processes the store's own unique constraint
    /// over the pair decides, and its refusal
    /// ([`TenantOAuthProviderStoreError::is_pair_held`](super::super::TenantOAuthProviderStoreError::is_pair_held))
    /// is reported as the same [`OAuthError::Config`]; the shipped stores
    /// enforce it, and a store of your own must.
    pub async fn upsert(
        &self,
        record: TenantOAuthProviderRecord,
    ) -> Result<TenantOAuthProviderRecord, OAuthError> {
        self.register(record, None).await
    }

    /// As [`upsert`](Self::upsert), carrying an operator's attestation that
    /// the record's tenant owns its client, for the
    /// [`OperatorAttestation`](super::super::OperatorAttestation) proof: the route
    /// for a public client, which has no credential to prove with. The
    /// attestation must be made for
    /// [`OwnershipPurpose::Register`](super::super::OwnershipPurpose::Register).
    /// It takes the attestation by value: the write uses it up, refused or
    /// not.
    ///
    /// # Errors
    ///
    /// As [`upsert`](Self::upsert).
    pub async fn upsert_attested(
        &self,
        record: TenantOAuthProviderRecord,
        attestation: OwnershipAttestation,
    ) -> Result<TenantOAuthProviderRecord, OAuthError> {
        self.register(record, Some(&attestation)).await
    }

    async fn register(
        &self,
        mut record: TenantOAuthProviderRecord,
        attestation: Option<&OwnershipAttestation>,
    ) -> Result<TenantOAuthProviderRecord, OAuthError> {
        self.refuse_an_incomplete_record(&record)?;
        // A held pair is refused before the proof, so a tenant that names
        // another's pair sends nothing to its identity provider: neither a
        // guess at its secret nor a request against its client's limits.
        // The check under the lock below is the one that decides a race.
        self.refuse_a_held_pair(&record).await?;
        self.seal(&mut record)?;
        self.prove_ownership(&record, attestation, OwnershipPurpose::Register)
            .await?;
        let registering = self.registering.lock().await;
        self.refuse_a_held_pair(&record).await?;
        let stored = self.store.put(record).await.map_err(store_error)?;
        self.bump();
        drop(registering);
        Ok(stored)
    }

    /// Run the proofs the deployment accepts against the stored record of
    /// `(tenant, name)`, as a registration of it would, and write nothing.
    ///
    /// For records stored before the directory asked for proof (0.19.0 and
    /// earlier), which keep serving: run it over every pair, and hand each
    /// pair it refuses to its owner, or remove the record, from the
    /// operator's path. An [`OperatorAttestation`](super::super::OperatorAttestation)
    /// never holds here, since no attestation is offered: a record only an
    /// operator can vouch for is reported as refused, and the operator
    /// decides.
    ///
    /// # Errors
    ///
    /// [`OAuthError::Store`] when the store fails or the credential does not
    /// open.
    pub async fn reprove(&self, tenant: &TenantId, name: &str) -> Result<Reproved, OAuthError> {
        let Some(record) = self.store.get(tenant, name).await.map_err(store_error)? else {
            return Ok(Reproved::NoRecord);
        };
        Ok(
            match self
                .verdict(&record, None, OwnershipPurpose::Register)
                .await?
            {
                Ok(proven) => Reproved::Proven(proven),
                Err(refused) => Reproved::Refused(refused),
            },
        )
    }

    /// Refuse a record whose tenant's ownership of the client none of the
    /// accepted proofs holds. Asked before the registration lock is taken:
    /// a proof may wait on the identity provider, and other registrations
    /// do not wait for it.
    pub(crate) async fn prove_ownership(
        &self,
        record: &TenantOAuthProviderRecord,
        attestation: Option<&OwnershipAttestation>,
        purpose: OwnershipPurpose,
    ) -> Result<(), OAuthError> {
        match self.verdict(record, attestation, purpose).await? {
            Ok(_) => Ok(()),
            Err(refused) => Err(OAuthError::Config(format!(
                "tenant provider refused: ownership of its client is not proven: {refused}"
            ))),
        }
    }

    /// What the accepted proofs say of `record` for `purpose`.
    async fn verdict(
        &self,
        record: &TenantOAuthProviderRecord,
        attestation: Option<&OwnershipAttestation>,
        purpose: OwnershipPurpose,
    ) -> Result<Result<OwnershipProven, OwnershipRefused>, OAuthError> {
        let (credential, _) = record
            .open_credential(self.cipher.as_deref())
            .map_err(|e| OAuthError::Store(Box::new(e)))?;
        let claim = OwnershipClaim {
            record,
            credential: &credential,
            purpose,
            attestation,
            egress: self.egress,
            clock: self.clock.clone(),
            rng: self.rng.clone(),
        };
        let verdict = self.ownership.prove(&claim).await;
        if let Ok(proven) = &verdict {
            tracing::info!(
                target: "axess::federation::oauth_tenant",
                tenant = %record.tenant_id,
                name = %crate::authn::service::log_text::logged_request_text(&record.name),
                %purpose,
                proven = ?proven,
                "a tenant's ownership of its client is proven"
            );
        }
        Ok(verdict)
    }

    /// Refuse a record with no name, issuer or client id, or whose issuer URL
    /// the egress policy refuses.
    fn refuse_an_incomplete_record(
        &self,
        record: &TenantOAuthProviderRecord,
    ) -> Result<(), OAuthError> {
        if record.name.is_empty() || record.issuer.is_empty() || record.client_id.is_empty() {
            return Err(OAuthError::Config(
                "a tenant provider needs a name, an issuer and a client id".to_string(),
            ));
        }
        self.egress
            .check_url(&record.issuer, "issuer URL")
            .map_err(|e| OAuthError::Config(e.to_string()))
    }

    /// Seal the record's credential when a cipher is set.
    fn seal(&self, record: &mut TenantOAuthProviderRecord) -> Result<(), OAuthError> {
        if let Some(cipher) = &self.cipher {
            record
                .seal(cipher)
                .map_err(|e| OAuthError::Store(Box::new(e)))?;
        }
        Ok(())
    }

    /// Refuse a record whose issuer and client id another record (any tenant's,
    /// this one's under another name included), or the global registration,
    /// already holds: the rule the store's unique constraint enforces, applied
    /// here first so the refusal names which and nothing is written.
    /// A record that does not build counts as holding its pair: the logout
    /// route counts it too.
    async fn refuse_a_held_pair(
        &self,
        record: &TenantOAuthProviderRecord,
    ) -> Result<(), OAuthError> {
        self.refuse_a_global_pair(record)?;
        let held = self
            .store
            .list_by_issuer(&record.issuer)
            .await
            .map_err(store_error)?;
        if held.iter().any(|other| {
            (other.tenant_id, other.name.as_str()) != (record.tenant_id, record.name.as_str())
                && other.client_id == record.client_id
        }) {
            return Err(OAuthError::Config(
                "tenant provider refused: its issuer and client id are already registered by \
                 another record"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Refuse a record whose issuer and client id the global registration
    /// holds.
    fn refuse_a_global_pair(&self, record: &TenantOAuthProviderRecord) -> Result<(), OAuthError> {
        if self
            .global
            .iter()
            .any(|(issuer, client_id)| *issuer == record.issuer && *client_id == record.client_id)
        {
            return Err(OAuthError::Config(
                "tenant provider refused: its issuer and client id are already registered by \
                 the global provider"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Remove a record and the provider held for it; `true` when there was a
    /// record.
    ///
    /// # Errors
    ///
    /// [`OAuthError::Store`] when the store fails.
    pub async fn remove(&self, tenant: &TenantId, name: &str) -> Result<bool, OAuthError> {
        let removed = self.store.delete(tenant, name).await.map_err(store_error)?;
        self.invalidate(tenant, name);
        Ok(removed)
    }

    /// The record that holds `(issuer, client_id)`, as `(tenant, name)`, or
    /// `None` when the pair is free.
    ///
    /// # Errors
    ///
    /// [`OAuthError::Store`] when the store fails.
    pub async fn holder_of(
        &self,
        issuer: &str,
        client_id: &str,
    ) -> Result<Option<(TenantId, String)>, OAuthError> {
        let held = self
            .store
            .list_by_issuer(issuer)
            .await
            .map_err(store_error)?;
        Ok(held
            .into_iter()
            .find(|record| record.client_id == client_id)
            .map(|record| (record.tenant_id, record.name)))
    }

    /// Hand `record`'s issuer and client id to `record` in one store write,
    /// removing whichever records held them and the providers held for
    /// those; the operator's override for a squatted pair, which
    /// [`RequestAuthnService::reassign_tenant_oauth_pair_as`](crate::authn::service::RequestAuthnService::reassign_tenant_oauth_pair_as)
    /// calls and audits. The owner's record needs the proof any write does,
    /// for [`OwnershipPurpose::HandOver`].
    pub(crate) async fn hand_over(
        &self,
        mut record: TenantOAuthProviderRecord,
        attestation: Option<&OwnershipAttestation>,
    ) -> Result<ReassignedPair, OAuthError> {
        self.refuse_an_incomplete_record(&record)?;
        // Only the global pairs are refused before the proof. A hand-over
        // exists to take a pair another record holds, so a held pair is not
        // refused here, and its proof runs for an operator, not a tenant.
        self.refuse_a_global_pair(&record)?;
        self.seal(&mut record)?;
        self.prove_ownership(&record, attestation, OwnershipPurpose::HandOver)
            .await?;
        let registering = self.registering.lock().await;
        let reassigned = self
            .store
            .reassign_pair(record)
            .await
            .map_err(store_error)?;
        for removed in &reassigned.removed {
            let (tenant, name) = (removed.tenant_id, &removed.name);
            self.lock().remove(&(tenant, name.clone()));
            tracing::warn!(
                target: "axess::federation::oauth_tenant",
                %tenant,
                name = %crate::authn::service::log_text::logged_request_text(name),
                "a tenant provider was removed to hand its issuer and client id to another record"
            );
        }
        self.bump();
        drop(registering);
        Ok(reassigned)
    }
}
