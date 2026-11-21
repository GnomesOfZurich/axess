//! [`DeviceKeyService`] with its store's type erased, so the session layer
//! holds one whatever device store a deployment uses.

use std::future::Future;
use std::pin::Pin;

use axess_clock::Timestamp;

use super::{DeviceKeyConfig, DeviceKeyError, DeviceKeyService, KeyChallenge, KeyProof, ProvedKey};
use super::{KeyThumbprint, ProvenKey, RegisteredKey, RequestProof, RequestProofSender};
use crate::authn::event::AuthEvent;
use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::device::store::DeviceStore;

/// A device store's error, kept as its text.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(crate) struct StoreFault(String);

/// A refusal of the erased service.
pub(crate) type KeyRefusal = DeviceKeyError<StoreFault>;

type Answer<'a, T> = Pin<Box<dyn Future<Output = Result<T, KeyRefusal>> + Send + 'a>>;

/// A registration as the layer hands it over.
pub(crate) struct Registration<'a> {
    pub(crate) tenant: &'a TenantId,
    pub(crate) device: &'a DeviceId,
    pub(crate) owner: &'a UserId,
    pub(crate) proof: KeyProof<'a>,
    pub(crate) offer: &'a str,
    pub(crate) now: Timestamp,
}

pub(crate) trait ErasedDeviceKeys: Send + Sync + 'static {
    fn config(&self) -> &DeviceKeyConfig;
    fn metrics(&self) -> &dyn crate::metrics::DeviceKeyMetrics;
    fn register<'a>(&'a self, registration: Registration<'a>) -> Answer<'a, RegisteredKey>;
    fn prove<'a>(
        &'a self,
        tenant: &'a TenantId,
        device: &'a DeviceId,
        proof: KeyProof<'a>,
        now: Timestamp,
    ) -> Answer<'a, ProvedKey>;
    fn challenge<'a>(
        &'a self,
        tenant: &'a TenantId,
        device: &'a DeviceId,
        now: Timestamp,
    ) -> Answer<'a, (KeyThumbprint, KeyChallenge)>;
    fn emit<'a>(&'a self, event: AuthEvent) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
    /// Whether a session of `user` may be bound to `proven`
    /// ([`DeviceKeyService::claim_for_binding`]); a store that cannot answer
    /// binds nothing.
    fn claim_for_binding<'a>(
        &'a self,
        proven: &'a ProvenKey,
        user: &'a UserId,
        now: Timestamp,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;
    /// Whether the service takes proofs on ordinary requests.
    fn takes_request_proofs(&self) -> bool;
    /// The key a proof riding on an ordinary request proves for `device` of
    /// `tenant`, `None` when the service takes no such proofs or the proof
    /// does not stand.
    fn request_proof<'a>(
        &'a self,
        tenant: &'a TenantId,
        device: &'a DeviceId,
        sender: RequestProofSender,
        proof: RequestProof<'a>,
        now: Timestamp,
    ) -> Pin<Box<dyn Future<Output = Option<ProvenKey>> + Send + 'a>>;
}

fn erase<E>(refusal: DeviceKeyError<E>) -> KeyRefusal
where
    E: std::error::Error + Send + Sync + 'static,
{
    match refusal {
        DeviceKeyError::Proof(e) => DeviceKeyError::Proof(e),
        DeviceKeyError::Registered => DeviceKeyError::Registered,
        DeviceKeyError::NotOwner => DeviceKeyError::NotOwner,
        DeviceKeyError::Keyless => DeviceKeyError::Keyless,
        DeviceKeyError::Ended => DeviceKeyError::Ended,
        DeviceKeyError::Stale { current } => DeviceKeyError::Stale { current },
        DeviceKeyError::Contended => DeviceKeyError::Contended,
        DeviceKeyError::Replayed => DeviceKeyError::Replayed,
        DeviceKeyError::ReplayStore(m) => DeviceKeyError::ReplayStore(m),
        DeviceKeyError::RequestProofsOff => DeviceKeyError::RequestProofsOff,
        DeviceKeyError::Store(e) => DeviceKeyError::Store(StoreFault(e.to_string())),
    }
}

impl<S: DeviceStore> ErasedDeviceKeys for DeviceKeyService<S> {
    fn config(&self) -> &DeviceKeyConfig {
        DeviceKeyService::config(self)
    }

    fn metrics(&self) -> &dyn crate::metrics::DeviceKeyMetrics {
        DeviceKeyService::metrics(self)
    }

    fn register<'a>(&'a self, r: Registration<'a>) -> Answer<'a, RegisteredKey> {
        Box::pin(async move {
            self.register_device_key(r.tenant, r.device, r.owner, r.proof, r.offer, r.now)
                .await
                .map_err(erase)
        })
    }

    fn prove<'a>(
        &'a self,
        tenant: &'a TenantId,
        device: &'a DeviceId,
        proof: KeyProof<'a>,
        now: Timestamp,
    ) -> Answer<'a, ProvedKey> {
        Box::pin(async move {
            self.prove_device_key(tenant, device, proof, now)
                .await
                .map_err(erase)
        })
    }

    fn challenge<'a>(
        &'a self,
        tenant: &'a TenantId,
        device: &'a DeviceId,
        now: Timestamp,
    ) -> Answer<'a, (KeyThumbprint, KeyChallenge)> {
        Box::pin(async move {
            self.key_and_challenge(tenant, device, now)
                .await
                .map_err(erase)
        })
    }

    fn emit<'a>(&'a self, event: AuthEvent) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(DeviceKeyService::emit(self, event))
    }

    fn claim_for_binding<'a>(
        &'a self,
        proven: &'a ProvenKey,
        user: &'a UserId,
        now: Timestamp,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            match DeviceKeyService::claim_for_binding(self, proven, user, now).await {
                Ok(owned) => owned,
                Err(DeviceKeyError::Ended) => false,
                Err(refusal) => {
                    tracing::error!(error = %refusal, "the device's owner could not be read; the session is not bound");
                    false
                }
            }
        })
    }

    fn takes_request_proofs(&self) -> bool {
        self.accepts_request_proofs()
    }

    fn request_proof<'a>(
        &'a self,
        tenant: &'a TenantId,
        device: &'a DeviceId,
        sender: RequestProofSender,
        proof: RequestProof<'a>,
        now: Timestamp,
    ) -> Pin<Box<dyn Future<Output = Option<ProvenKey>> + Send + 'a>> {
        Box::pin(async move {
            match self.prove_request(tenant, device, sender, proof, now).await {
                Ok(proven) => Some(proven),
                Err(DeviceKeyError::RequestProofsOff) => None,
                Err(refusal) => {
                    tracing::debug!(error = %refusal, "a request proof did not stand");
                    None
                }
            }
        })
    }
}
