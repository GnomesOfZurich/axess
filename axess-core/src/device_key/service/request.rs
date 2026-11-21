//! Proofs that ride on ordinary requests of an app's bound session: the
//! replay store they are recorded in, and their verification.

use std::sync::Arc;

use axess_clock::Timestamp;
use axess_factors::jwt::verifier::{JtiReplayError, JtiReplayStore};
use axess_factors::key_proof::{
    P256Key, ProofKey, ProofTarget, RequestProofCheck, parse_key_proof,
};

use super::{DeviceKeyError, DeviceKeyService, key_of};
use crate::authn::ids::{DeviceId, TenantId};
use crate::device::store::DeviceStore;
use crate::device::types::DeviceTrustLevel;

/// A [`JtiReplayStore`] with its type erased, so the service holds one
/// whatever store a deployment chose.
pub(super) trait ErasedReplay: Send + Sync + 'static {
    fn record<'a>(
        &'a self,
        jti: &'a str,
        ttl: std::time::Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), JtiReplayError>> + Send + 'a>>;
}

impl<R: JtiReplayStore + 'static> ErasedReplay for R {
    fn record<'a>(
        &'a self,
        jti: &'a str,
        ttl: std::time::Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), JtiReplayError>> + Send + 'a>>
    {
        Box::pin(self.check_and_record(jti, ttl))
    }
}

/// How proofs that ride on ordinary requests are checked.
pub(super) struct RequestProofs {
    replay: Box<dyn ErasedReplay>,
    max_age: std::time::Duration,
}

/// The longest lifetime a request proof may be given.
pub const MAX_REQUEST_PROOF_AGE: std::time::Duration = std::time::Duration::from_secs(300);

/// How far ahead of the server's clock a request proof's `iat` may lie:
/// what clocks kept by a time service differ by, with room. A proof dated
/// further ahead was made before it is used, and is refused.
pub const REQUEST_PROOF_CLOCK_ALLOWANCE: std::time::Duration = std::time::Duration::from_secs(5);

/// The namespace request-proof `jti`s are recorded in, so a replay store
/// that another verifier also records into never takes one for the other's.
const REQUEST_JTI_NAMESPACE: &str = "axess.device-key.request";

impl<S: DeviceStore> DeviceKeyService<S> {
    /// Accept a proof by the device key on any request, in place of the
    /// proof cookie: the mode of an app that signs every request.
    ///
    /// The proof is RFC 9449's: the public key in the `jwk` header, `htm`
    /// and `htu` naming the request, an `iat` no more than `max_age` before
    /// the server's clock and no more than [`REQUEST_PROOF_CLOCK_ALLOWANCE`]
    /// after it, and a `jti`. Its signature is checked first, under the key
    /// it carries, so a request that shows no valid signature costs no store
    /// read; the key must then be the one on the device row. For a session
    /// bound to the device that row is read past any cache on every such
    /// request, so revoking the device or forgetting its key ends the
    /// session on every node at its next request. The `jti` is recorded in
    /// `replay` for the whole span over which the proof is accepted, under
    /// the tenant and the key it belongs to and in a namespace of this
    /// service's own, so a proof is accepted once and one device's `jti`
    /// never refuses another's.
    ///
    /// A request of a session bound to a key names its device by the
    /// binding. Any other request (a guest's, the one that signs a user in)
    /// names it in the identifier header the refresh path reads, and a proof
    /// that stands recognises the device, so a sign-in on it binds the new
    /// session with no registration. Such a request has shown no secret, so
    /// its device row is read through the cache, at most once and only
    /// after its signature held; the bind step reads the row again, fresh,
    /// so a device recognised from a cached row is never bound after it was
    /// revoked or its key replaced.
    ///
    /// What a copy of everything the app holds is then worth: where request
    /// proofs are accepted, a registration in the app shape sets no proof
    /// cookie, and an app that never calls the refresh path never holds
    /// one, so it holds no bearer value at all; a proof it sent names one
    /// request and is used once. An app that does call the refresh path is
    /// handed a proof cookie as every client is, a bearer value for the
    /// proof lifetime plus the acceptance grace.
    ///
    /// `replay` must record what it is handed: a store that records nothing
    /// (`NoReplay`) is refused here. It is shared by every node in a fleet
    /// (`ValkeyJtiReplayStore` with the `valkey` feature); a store in one
    /// process ([`MemoryJtiReplayStore`](crate::replay::MemoryJtiReplayStore))
    /// serves a single node, and behind a load balancer lets a proof be
    /// replayed once per node. `max_age` is between one second and
    /// [`MAX_REQUEST_PROOF_AGE`].
    pub fn with_request_proofs<R: JtiReplayStore + 'static>(
        mut self,
        replay: R,
        max_age: std::time::Duration,
    ) -> Result<Self, crate::device_key::DeviceKeyConfigError> {
        if !replay.records() {
            return Err(crate::device_key::DeviceKeyConfigError {
                setting: "replay",
                problem: "must record what it is handed; this store records nothing",
            });
        }
        if max_age < std::time::Duration::from_secs(1) || max_age > MAX_REQUEST_PROOF_AGE {
            return Err(crate::device_key::DeviceKeyConfigError {
                setting: "max_age",
                problem: "must be between 1 second and 5 minutes",
            });
        }
        self.request_proofs = Some(Arc::new(RequestProofs {
            replay: Box::new(replay),
            max_age,
        }));
        Ok(self)
    }

    /// Whether the service takes proofs on ordinary requests.
    pub fn accepts_request_proofs(&self) -> bool {
        self.request_proofs.is_some()
    }

    /// Verify a proof that rides on an ordinary request for `device` of
    /// `tenant`, and record its `jti`.
    ///
    /// Nothing is read for a request that has shown nothing. The proof's
    /// signature is checked first, under the key the proof itself carries
    /// (its `jwk` header), with the request it names (`method`, and `url` as
    /// the server knows it), its `iat` and its `jti`: a value that is no
    /// proof, or a proof that does not verify, costs no store read. Only
    /// then is the device row read, and how depends on `sender`:
    ///
    /// - [`RequestProofSender::BoundSession`], a request that presented a
    ///   session cookie whose row is bound to this device: the row is read
    ///   past any cache, so a revocation or a forgotten key on any node ends
    ///   the session at its next request.
    /// - [`RequestProofSender::Unbound`], a request that names the device in
    ///   the identifier header and holds no session bound to it: the row is
    ///   read through the store's own `load`, which a cache in front of the
    ///   store serves. Such a request costs at most one cached read, and
    ///   what it gains is recognition only: before a session is bound to the
    ///   device the row is read again, fresh.
    ///
    /// The device must exist, not be revoked, and hold exactly the key the
    /// proof carries; the `jti` must then be new to the replay store, where
    /// it is recorded only for a proof by the device's own key. A store that
    /// cannot answer refuses the proof. The answer names the key: a caller
    /// that serves a bound session compares it with the binding
    /// ([`SessionKeyBinding::is_met_by`](crate::device_key::SessionKeyBinding::is_met_by)).
    pub async fn prove_request(
        &self,
        tenant: &TenantId,
        device: &DeviceId,
        sender: RequestProofSender,
        proof: RequestProof<'_>,
        now: Timestamp,
    ) -> Result<crate::device_key::ProvenKey, DeviceKeyError<S::Error>> {
        let outcome = self.prove_riding(tenant, device, sender, proof, now).await;
        match &outcome {
            Ok(_) => self.metrics.request_proof_accepted(),
            Err(DeviceKeyError::RequestProofsOff) => {}
            // Not the client's fault and not a refusal of its proof: a
            // store did not answer. Said at warn and counted apart.
            Err(DeviceKeyError::Store(error)) => {
                tracing::warn!(error = %error, "a request proof was not judged: the device store did not answer");
                self.metrics.request_proof_unanswered();
            }
            Err(DeviceKeyError::ReplayStore(message)) => {
                tracing::warn!(error = %message, "a request proof was not judged: the replay store did not answer");
                self.metrics.request_proof_unanswered();
            }
            Err(refusal) => {
                // Counted apart, so what anybody can send beside a device's
                // identifier never hides a refusal under a bound session.
                match sender {
                    RequestProofSender::BoundSession => self.metrics.request_proof_refused(),
                    RequestProofSender::Unbound => self.metrics.unbound_request_proof_refused(),
                }
                // Two refusals say something about who sent the proof: one
                // by the device's key that comes twice was captured and sent
                // again, and one by another key under the bound session is
                // the session cookie held without the key. Another key's
                // proof beside nothing but an identifier is anybody's.
                let captured = matches!(refusal, DeviceKeyError::Replayed);
                let without_the_key = sender == RequestProofSender::BoundSession
                    && matches!(
                        refusal,
                        DeviceKeyError::Proof(axess_factors::key_proof::KeyProofError::Signature)
                    );
                if captured || without_the_key {
                    self.write_proof_refused_row(tenant, device, now).await;
                }
            }
        }
        outcome
    }

    async fn prove_riding(
        &self,
        tenant: &TenantId,
        device: &DeviceId,
        sender: RequestProofSender,
        proof: RequestProof<'_>,
        now: Timestamp,
    ) -> Result<crate::device_key::ProvenKey, DeviceKeyError<S::Error>> {
        let RequestProof { jws, method, url } = proof;
        let Some(proofs) = &self.request_proofs else {
            return Err(DeviceKeyError::RequestProofsOff);
        };
        let parsed = parse_key_proof(jws, axess_factors::key_proof::KeyProofShape::App)
            .map_err(DeviceKeyError::Proof)?;
        // The signature first, under the key the proof carries: whoever sent
        // this holds that key, and nothing has been read to learn it.
        let verified = parsed
            .verify_request(RequestProofCheck {
                target: ProofTarget { method, url },
                now_unix: now.unix_seconds(),
                max_age: proofs.max_age,
                max_ahead: REQUEST_PROOF_CLOCK_ALLOWANCE,
                key: ProofKey::Embedded,
            })
            .map_err(DeviceKeyError::Proof)?;
        let carried = crate::device_key::KeyThumbprint::from_bytes(verified.thumbprint);
        let row = match sender {
            // Past any cache, as every key decision for a session is.
            RequestProofSender::BoundSession => self.live_row(tenant, device).await?,
            // Through the cache: this request has shown no secret of the
            // device, and a session is bound only after a fresh read.
            RequestProofSender::Unbound => match self
                .store
                .load(tenant, device)
                .await
                .map_err(DeviceKeyError::Store)?
            {
                Some(row) if row.trust_level != DeviceTrustLevel::Revoked => row,
                _ => return Err(DeviceKeyError::Ended),
            },
        };
        let key = key_of(&row.bindings).ok_or(DeviceKeyError::Keyless)?;
        // The key the device holds, from its coordinates, not the row's word
        // for its name. A proof by any other key is not the device's.
        let held = crate::device_key::KeyThumbprint::from_bytes(
            P256Key {
                x: key.public_key.x,
                y: key.public_key.y,
            }
            .thumbprint(),
        );
        if !held.matches(&carried) {
            return Err(DeviceKeyError::Proof(
                axess_factors::key_proof::KeyProofError::Signature,
            ));
        }
        // Kept for the whole span over which the proof is accepted, in the
        // whole seconds the check counts, and a second for the truncation
        // of the request's time to whole seconds.
        let window = proofs
            .max_age
            .as_secs()
            .saturating_add(REQUEST_PROOF_CLOCK_ALLOWANCE.as_secs())
            .saturating_add(1);
        let record = format!(
            "{REQUEST_JTI_NAMESPACE}:{tenant}:{}:{}",
            held.to_text(),
            verified.jti
        );
        match proofs
            .replay
            .record(&record, std::time::Duration::from_secs(window))
            .await
        {
            Ok(()) => Ok(crate::device_key::ProvenKey {
                tenant: *tenant,
                device: *device,
                thumbprint: held,
            }),
            Err(refusal) => Err(replay_refusal(refusal)),
        }
    }
}

/// The most bytes of a replay store's own text a [`DeviceKeyError`] keeps.
const REPLAY_STORE_TEXT_BYTES: usize = 256;

/// The error a replay store's refusal of a request proof's record becomes.
///
/// A store's text may quote the key it was handed, which ends in the
/// proof's `jti`: up to 256 bytes the client chose. The text reaches a warn
/// log line and the error's `Display`, so it is made safe by the one
/// log-text predicate (escaped and cut at [`REPLAY_STORE_TEXT_BYTES`]),
/// whatever store wrote it.
fn replay_refusal<E: std::error::Error + Send + Sync + 'static>(
    refusal: JtiReplayError,
) -> DeviceKeyError<E> {
    match refusal {
        JtiReplayError::AlreadyUsed(_) => DeviceKeyError::Replayed,
        JtiReplayError::Backend(message) => DeviceKeyError::ReplayStore(
            axess_identity::log_text::log_safe(&message, REPLAY_STORE_TEXT_BYTES),
        ),
    }
}

#[cfg(test)]
mod replay_refusal_tests {
    use super::*;

    /// A store that quotes the key it was handed, `jti` included, cannot
    /// carry a forged line, a reordering character or a long text into the
    /// error and its log line.
    #[test]
    fn a_store_quoting_the_key_reaches_the_error_escaped_and_cut() {
        let jti = format!("j\nWARN forged line\u{202E}\u{200B}{}", "A".repeat(400));
        let refused: DeviceKeyError<std::convert::Infallible> =
            replay_refusal(JtiReplayError::Backend(format!("SET rq:t:k:{jti} failed")));
        let DeviceKeyError::ReplayStore(text) = &refused else {
            panic!("a store's failure is not a refusal of the proof: {refused:?}");
        };
        assert!(
            text.len() <= REPLAY_STORE_TEXT_BYTES,
            "{} bytes",
            text.len()
        );
        assert!(
            !text.chars().any(axess_identity::log_text::escapes),
            "{text:?}"
        );
        assert!(text.contains("j\\nWARN forged line"), "{text}");
        let shown = refused.to_string();
        assert!(
            !shown.chars().any(axess_identity::log_text::escapes),
            "{shown:?}"
        );
        assert!(matches!(
            replay_refusal::<std::convert::Infallible>(JtiReplayError::already_used("j")),
            DeviceKeyError::Replayed
        ));
    }
}

/// A proof that rides on an ordinary request, and the request it rides on.
#[derive(Clone, Copy)]
pub struct RequestProof<'a> {
    /// The proof: the compact JWS of the request's `DPoP` header.
    pub jws: &'a str,
    /// The request's method.
    pub method: &'a str,
    /// The request's URL as the server knows it: the origin it serves the
    /// request's host at, and the path.
    pub url: &'a str,
}

/// What a request that carries a request proof has already shown, which
/// decides how its device row is read
/// ([`DeviceKeyService::prove_request`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestProofSender {
    /// The request presented a session cookie whose row is bound to the
    /// device the proof is for: it holds a secret of that device's session.
    BoundSession,
    /// The request holds no session bound to the device and names the device
    /// in the identifier header, which is no secret.
    Unbound,
}
