//! Refreshing a session only with the device's key, when the device has one.

use super::rotation::{KeyGate, KeyRefusal, Refresh};
// Named by the doc links below.
#[cfg(doc)]
use super::types::RefreshError;
use crate::authn::ids::{DeviceId, TenantId};
use crate::device::DeviceStore;
use crate::device_key::{DeviceKeyError, DeviceKeyService, KeyProof, KeyThumbprint};
use axess_clock::Timestamp;
use std::future::Future;
use std::pin::Pin;

struct ProvedBy<'a, D: DeviceStore> {
    keys: &'a DeviceKeyService<D>,
    proof: Option<KeyProof<'a>>,
}

impl<D: DeviceStore> KeyGate for ProvedBy<'_, D> {
    fn prove<'a>(
        &'a self,
        tenant: &'a TenantId,
        device: &'a DeviceId,
        now: Timestamp,
    ) -> Pin<Box<dyn Future<Output = Result<Option<KeyThumbprint>, KeyRefusal>> + Send + 'a>> {
        Box::pin(async move {
            match self
                .keys
                .prove_key_of_secret_holder(tenant, device, self.proof, now)
                .await
            {
                Ok(proved) => Ok(Some(proved.thumbprint)),
                // A device without a key is held to none.
                Err(DeviceKeyError::Keyless) => Ok(None),
                Err(DeviceKeyError::Stale { current }) => {
                    Err(KeyRefusal::Required(current.to_text()))
                }
                Err(DeviceKeyError::Proof(_)) => Err(KeyRefusal::Invalid),
                Err(DeviceKeyError::Ended) => Err(KeyRefusal::Ended),
                Err(DeviceKeyError::Store(error)) => Err(KeyRefusal::Store(error.to_string())),
                Err(other) => Err(KeyRefusal::Store(other.to_string())),
            }
        })
    }
}

impl<'a, F, C> Refresh<'a, F, C> {
    /// Hold the refresh to the device's key: a token whose device has a key
    /// refreshes only with a proof by that key over the device's current
    /// challenge.
    ///
    /// - A proof that stands replaces the challenge, the token rotates as
    ///   usual, and the session the refresh builds is bound to the key.
    /// - A proof that is the key's and answers a stale challenge changes
    ///   nothing: [`RefreshError::KeyProofRequired`] carries the challenge
    ///   to sign.
    /// - No proof, or one that is not the key's, means the token is held
    ///   without the key. The family is revoked and the compromise hook
    ///   runs, as for a rotated-out token that comes back, and the answer is
    ///   [`RefreshError::KeyProofInvalid`].
    /// - A revoked or missing device is [`RefreshError::DeviceRevoked`], and
    ///   a device store that cannot answer is [`RefreshError::DeviceStore`].
    ///
    /// The device row decides, not the token: a token issued before its
    /// device took a key is held to the key from then on, and a token whose
    /// device has no key, or that names no device, refreshes as before.
    ///
    /// `proof` is what the client sent with the token, with the method and
    /// URL of the refresh request as the server knows them. The key check
    /// runs after every other check, since it is the one that consumes
    /// something.
    pub fn device_key<D: DeviceStore>(
        self,
        keys: &'a DeviceKeyService<D>,
        proof: Option<KeyProof<'a>>,
    ) -> Self {
        self.key_gate(Box::new(ProvedBy { keys, proof }))
    }
}
