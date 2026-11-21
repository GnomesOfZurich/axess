//! [`DeviceKeyService`]: registering a device's key and proving it.
//!
//! Both operations are one compare-and-swap on the device row's bindings
//! ([`DeviceStore::replace_bindings`]). That is what makes a device take one
//! key and a challenge be accepted once, on one node or on many: of two
//! writers that read the same row, one writes and the other reads again. No
//! replay cache is involved.

use std::sync::Arc;

use axess_clock::Timestamp;
use axess_factors::key_proof::{
    KeyProofError, P256Key, ParsedKeyProof, ProofKey, ProofTarget, parse_key_proof,
};
use axess_rng::SecureRng;

use super::{DeviceKeyConfig, KeyChallenge, KeyProofShape, KeyThumbprint, P256PublicKey};
use crate::authn::event::{AuthEventBuilder, AuthEventStatus, AuthEventType, AuthFailureReason};
use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::device::events::{DeviceEventSink, NoopDeviceEventSink};
use crate::device::store::{BindingsUpdate, DeviceStore};
use crate::device::types::{Device, DeviceBinding, DeviceTrustLevel};

/// How often a key write reads the row again after losing its
/// compare-and-swap to a concurrent writer.
const KEY_WRITE_ATTEMPTS: usize = 4;

/// A proof as a front-end received it, and the request it arrived on.
#[derive(Debug, Clone, Copy)]
pub struct KeyProof<'a> {
    /// The proof, a compact JWS.
    pub jws: &'a str,
    /// The front-end that sent it.
    pub shape: KeyProofShape,
    /// The method of the request that carried it.
    pub method: &'a str,
    /// Scheme, host and path of that request, as the server knows them (the
    /// configured origin and the path), never as the request's `Host` header
    /// claims.
    pub url: &'a str,
}

/// A key that was registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredKey {
    /// The key's thumbprint.
    pub thumbprint: KeyThumbprint,
    /// The challenge the first refresh must answer.
    pub challenge: KeyChallenge,
}

/// A key that was proven.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvedKey {
    /// The key's thumbprint.
    pub thumbprint: KeyThumbprint,
    /// The challenge the next proof must answer.
    pub next_challenge: KeyChallenge,
}

/// Why a key was not registered or not proven.
#[derive(Debug, thiserror::Error)]
pub enum DeviceKeyError<E: std::error::Error + Send + Sync + 'static> {
    /// The proof itself was refused.
    #[error("the key proof was refused: {0}")]
    Proof(#[source] KeyProofError),
    /// The device already has a key; it takes one.
    #[error("the device already has a key")]
    Registered,
    /// The device belongs to another user than the one registering.
    #[error("the device belongs to another user")]
    NotOwner,
    /// The device has no key to prove.
    #[error("the device has no key")]
    Keyless,
    /// The device is revoked or no longer exists.
    #[error("the device is revoked or gone")]
    Ended,
    /// The proof answers a challenge that is not the current one. Nothing
    /// was accepted; `current` is the challenge to sign.
    #[error("the proof answers a challenge that is not the current one")]
    Stale {
        /// The challenge the device must sign now.
        current: KeyChallenge,
    },
    /// Concurrent writers kept changing the device row.
    #[error("the device row kept changing under the write")]
    Contended,
    /// A request proof's `jti` was recorded before: the proof is a replay.
    #[error("the request proof was presented before")]
    Replayed,
    /// The replay store could not answer, so the request proof was refused.
    #[error("the replay store could not answer: {0}")]
    ReplayStore(String),
    /// The service takes no request proofs
    /// ([`DeviceKeyService::with_request_proofs`] was not called).
    #[error("request proofs are not accepted")]
    RequestProofsOff,
    /// The device store failed.
    #[error("device store error: {0}")]
    Store(#[source] E),
}

/// Which of a proof's two judgements is made first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Order {
    /// The challenge, then the signature: an anonymous caller with a stale
    /// or invented challenge costs no signature verification.
    ChallengeFirst,
    /// The signature, then the challenge: the caller presented a secret (a
    /// refresh token), and what matters first is whether it also holds the
    /// key.
    SignatureFirst,
}

/// Registers device keys and proves them. Cheap to clone.
///
/// The session layer drives it for the two key paths
/// ([`SessionLayer::with_device_keys`](crate::session::SessionLayer::with_device_keys));
/// the methods are public for a deployment whose transport is not the
/// layer's.
#[derive(Clone)]
pub struct DeviceKeyService<S: DeviceStore> {
    store: S,
    config: Arc<DeviceKeyConfig>,
    rng: Arc<dyn SecureRng>,
    event_sink: Arc<dyn DeviceEventSink>,
    request_proofs: Option<Arc<request::RequestProofs>>,
    metrics: Arc<dyn crate::metrics::DeviceKeyMetrics>,
}

impl<S: DeviceStore> DeviceKeyService<S> {
    /// A service over `store`. Refuses a configuration
    /// [`DeviceKeyConfig::validate`] refuses.
    pub fn new(
        store: S,
        config: DeviceKeyConfig,
    ) -> Result<Self, super::config::DeviceKeyConfigError> {
        config.validate()?;
        Ok(Self {
            store,
            config: Arc::new(config),
            rng: Arc::new(axess_rng::SystemRng),
            event_sink: Arc::new(NoopDeviceEventSink),
            request_proofs: None,
            metrics: Arc::new(crate::metrics::NoopMetrics),
        })
    }

    /// Report to the device-key concern of `metrics`
    /// ([`DeviceKeyMetrics`](crate::metrics::DeviceKeyMetrics)): the
    /// service's registrations and proofs, and what a session layer given
    /// this service does with the sessions it holds to keys.
    pub fn with_metrics(mut self, metrics: crate::metrics::MetricSinks) -> Self {
        self.metrics = metrics.device_keys.clone();
        self
    }

    /// The device-key sink the service reports to.
    pub(crate) fn metrics(&self) -> &dyn crate::metrics::DeviceKeyMetrics {
        self.metrics.as_ref()
    }

    /// Replace the source of challenges (default: `SystemRng`).
    pub fn with_rng(mut self, rng: impl SecureRng) -> Self {
        self.rng = Arc::new(rng);
        self
    }

    /// Write the audit rows of registrations and refused proofs to `sink`.
    pub fn with_event_sink<E: DeviceEventSink>(mut self, sink: E) -> Self {
        self.event_sink = Arc::new(sink);
        self
    }

    /// The configuration.
    pub fn config(&self) -> &DeviceKeyConfig {
        &self.config
    }

    /// The device store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// The two routes a key is registered and proven at, on the configured
    /// paths. Merge the router into the application's, inside a session
    /// layer that was given this service
    /// ([`SessionLayer::with_device_keys`](crate::session::SessionLayer::with_device_keys)):
    /// the layer hands the routes what they need through the request, and a
    /// route reached without it (no session layer, a layer with no key
    /// service, or one whose policy is `Off`) answers 404, as a path this
    /// deployment does not serve.
    ///
    /// ```text
    /// let app = Router::new()
    ///     .merge(application_routes)
    ///     .merge(keys.router())
    ///     .layer(SessionLayer::new(store, signing_key, registry, audit).with_device_keys(keys));
    /// ```
    pub fn router<St>(&self) -> axum::Router<St>
    where
        St: Clone + Send + Sync + 'static,
    {
        crate::session::layer::device_keys::routes(
            self.config.registration_path(),
            self.config.refresh_path(),
        )
    }

    /// Verify a registration proof and add its key to a device that has
    /// none, as one compare-and-swap on the device's bindings.
    ///
    /// Crate-private: a registration has two preconditions only the session
    /// layer can meet, and the layer's registration path is the one caller.
    /// `offer` is the challenge the proof must answer, which the layer has
    /// checked was made to this session for this device and has not expired.
    /// `owner` is the user the session is authenticated as: a device that
    /// belongs to another user is refused, and one with no owner is claimed
    /// for `owner` by the store's conditional write before it takes the key.
    pub(crate) async fn register_device_key(
        &self,
        tenant: &TenantId,
        device: &DeviceId,
        owner: &UserId,
        proof: KeyProof<'_>,
        offer: &str,
        now: Timestamp,
    ) -> Result<RegisteredKey, DeviceKeyError<S::Error>> {
        let parsed = parse(&proof)?;
        let verified = if parsed.answers(offer) {
            parsed.verify(target(&proof), ProofKey::Embedded)
        } else {
            Err(KeyProofError::Challenge)
        };
        let verified = match verified {
            Ok(verified) => verified,
            Err(refusal) => {
                self.record_registration_refused(tenant, device, Some(owner), "proof_refused", now)
                    .await;
                return Err(DeviceKeyError::Proof(refusal));
            }
        };
        let thumbprint = KeyThumbprint::from_bytes(verified.thumbprint);
        for _ in 0..KEY_WRITE_ATTEMPTS {
            let row = self.live_row(tenant, device).await?;
            let owned = match row.user_id.as_ref() {
                Some(row_owner) => row_owner == owner,
                // The claim changes the owner and nothing else, so the
                // bindings read above are still the ones to swap against.
                None => matches!(
                    self.store
                        .claim_owner(tenant, device, owner, now)
                        .await
                        .map_err(DeviceKeyError::Store)?,
                    crate::device::store::OwnerClaim::Claimed
                ),
            };
            if !owned {
                self.record_registration_refused(tenant, device, Some(owner), "not_owner", now)
                    .await;
                return Err(DeviceKeyError::NotOwner);
            }
            if key_of(&row.bindings).is_some() {
                self.record_registration_refused(
                    tenant,
                    device,
                    Some(owner),
                    "already_registered",
                    now,
                )
                .await;
                return Err(DeviceKeyError::Registered);
            }
            let challenge = KeyChallenge::mint(&*self.rng);
            let mut bindings = row.bindings.clone();
            bindings.push(DeviceBinding::Key {
                thumbprint,
                public_key: P256PublicKey {
                    x: verified.key.x,
                    y: verified.key.y,
                },
                shape: proof.shape,
                bound_at: now,
                proven_at: now,
                challenge: challenge.clone(),
                challenge_issued_at: now,
            });
            match self.swap(tenant, device, &row, &bindings, now).await? {
                Swap::Written => {
                    self.metrics.key_registered();
                    let event = AuthEventBuilder::success(AuthEventType::DeviceKeyRegistered)
                        .maybe_attributed_to(Some(owner), Some(tenant))
                        .with_device(*device)
                        .build_at(now);
                    self.event_sink.emit(event).await;
                    return Ok(RegisteredKey {
                        thumbprint,
                        challenge,
                    });
                }
                Swap::Moved => continue,
            }
        }
        Err(DeviceKeyError::Contended)
    }

    /// Verify a proof over the device's current challenge under its stored
    /// key, and replace the challenge, as one compare-and-swap on the
    /// device's bindings.
    ///
    /// The challenge is judged before the signature. A proof for another
    /// challenge, or for one older than the configured lifetime, is answered
    /// [`DeviceKeyError::Stale`] with the challenge to sign and costs no
    /// signature verification. A proof for the current challenge whose
    /// signature is not the key's is refused and recorded as `Suspicious`;
    /// nothing is revoked, since the caller gained nothing and presented no
    /// secret.
    pub async fn prove_device_key(
        &self,
        tenant: &TenantId,
        device: &DeviceId,
        proof: KeyProof<'_>,
        now: Timestamp,
    ) -> Result<ProvedKey, DeviceKeyError<S::Error>> {
        let outcome = self
            .prove(tenant, device, &proof, now, Order::ChallengeFirst)
            .await;
        // A refusal of the structure reads no row and says nothing about
        // anyone: anybody can post bytes. One that comes after the current
        // challenge matched does.
        match &outcome {
            Ok(_) => self.metrics.key_proof_accepted(),
            Err(DeviceKeyError::Stale { .. }) => self.metrics.key_proof_challenged(),
            Err(DeviceKeyError::Proof(
                KeyProofError::Signature | KeyProofError::Target | KeyProofError::Key,
            )) => self.record_proof_refused(tenant, device, now).await,
            Err(_) => {}
        }
        outcome
    }

    /// [`prove_device_key`](Self::prove_device_key) for a caller that
    /// presented a secret of the device (a refresh token): the signature is
    /// judged before the challenge.
    ///
    /// The device's row is read before anything the caller sent is looked
    /// at: a device that is gone is [`DeviceKeyError::Ended`] and one that
    /// has no key is [`DeviceKeyError::Keyless`], whatever came with the
    /// secret, so a header a keyless device's client sends beside its token
    /// (a proof in another algorithm, bytes that are no proof) is never read
    /// as a theft and writes no row.
    ///
    /// For a device that has a key, [`DeviceKeyError::Proof`] means the
    /// caller holds the secret and not the key, which is the theft signal;
    /// the caller acts on it (a refresh revokes the token's family) and this
    /// records it as `Suspicious`. A sound signature over a stale challenge
    /// is [`DeviceKeyError::Stale`]: nothing happened, sign the current one.
    pub async fn prove_key_of_secret_holder(
        &self,
        tenant: &TenantId,
        device: &DeviceId,
        proof: Option<KeyProof<'_>>,
        now: Timestamp,
    ) -> Result<ProvedKey, DeviceKeyError<S::Error>> {
        // A device that has no key is not held to one, whatever was sent.
        if key_of(&self.live_row(tenant, device).await?.bindings).is_none() {
            return Err(DeviceKeyError::Keyless);
        }
        let outcome = match proof {
            Some(proof) => {
                self.prove(tenant, device, &proof, now, Order::SignatureFirst)
                    .await
            }
            // No proof at all: the secret is held without the key.
            None => Err(DeviceKeyError::Proof(KeyProofError::Malformed)),
        };
        match &outcome {
            Ok(_) => self.metrics.key_proof_accepted(),
            Err(DeviceKeyError::Stale { .. }) => self.metrics.key_proof_challenged(),
            Err(DeviceKeyError::Proof(_)) => self.record_proof_refused(tenant, device, now).await,
            Err(_) => {}
        }
        outcome
    }

    async fn prove(
        &self,
        tenant: &TenantId,
        device: &DeviceId,
        proof: &KeyProof<'_>,
        now: Timestamp,
        order: Order,
    ) -> Result<ProvedKey, DeviceKeyError<S::Error>> {
        // Structure first: a value that is no proof reads no row.
        let parsed = parse(proof)?;
        for _ in 0..KEY_WRITE_ATTEMPTS {
            let row = self.live_row(tenant, device).await?;
            let Some(key) = key_of(&row.bindings) else {
                return Err(DeviceKeyError::Keyless);
            };
            let stored = P256Key {
                x: key.public_key.x,
                y: key.public_key.y,
            };
            let signed = || parsed.verify(target(proof), ProofKey::Stored(&stored));
            if order == Order::SignatureFirst {
                signed().map_err(DeviceKeyError::Proof)?;
            }
            if self.is_expired(key.challenge_issued_at, now) {
                // Too old to answer: issue another and hand it out.
                let fresh = KeyChallenge::mint(&*self.rng);
                let bindings = with_challenge(&row.bindings, &fresh, now, None);
                match self.swap(tenant, device, &row, &bindings, now).await? {
                    Swap::Written => return Err(DeviceKeyError::Stale { current: fresh }),
                    Swap::Moved => continue,
                }
            }
            if !parsed.answers(&key.challenge.to_text()) {
                return Err(DeviceKeyError::Stale {
                    current: key.challenge.clone(),
                });
            }
            if order == Order::ChallengeFirst {
                signed().map_err(DeviceKeyError::Proof)?;
            }
            // The proof stands. Accepting it and replacing the challenge are
            // one write, so the same proof cannot be accepted twice.
            let next = KeyChallenge::mint(&*self.rng);
            let bindings = with_challenge(&row.bindings, &next, now, Some(now));
            match self.swap(tenant, device, &row, &bindings, now).await? {
                Swap::Written => {
                    return Ok(ProvedKey {
                        // Of the key the signature held under.
                        thumbprint: KeyThumbprint::from_bytes(stored.thumbprint()),
                        next_challenge: next,
                    });
                }
                Swap::Moved => continue,
            }
        }
        Err(DeviceKeyError::Contended)
    }

    /// The challenge the device's next proof must answer, replaced first
    /// when it is older than the configured lifetime.
    pub async fn current_key_challenge(
        &self,
        tenant: &TenantId,
        device: &DeviceId,
        now: Timestamp,
    ) -> Result<KeyChallenge, DeviceKeyError<S::Error>> {
        self.key_and_challenge(tenant, device, now)
            .await
            .map(|(_, challenge)| challenge)
    }

    /// The device's key and the challenge its next proof must answer, from
    /// one read of the row (and one write when the challenge had expired):
    /// what a caller with no credentials costs at the refresh path.
    pub(crate) async fn key_and_challenge(
        &self,
        tenant: &TenantId,
        device: &DeviceId,
        now: Timestamp,
    ) -> Result<(KeyThumbprint, KeyChallenge), DeviceKeyError<S::Error>> {
        for _ in 0..KEY_WRITE_ATTEMPTS {
            let row = self.live_row(tenant, device).await?;
            let Some(key) = key_of(&row.bindings) else {
                return Err(DeviceKeyError::Keyless);
            };
            if !self.is_expired(key.challenge_issued_at, now) {
                return Ok((key.thumbprint, key.challenge.clone()));
            }
            let fresh = KeyChallenge::mint(&*self.rng);
            let bindings = with_challenge(&row.bindings, &fresh, now, None);
            match self.swap(tenant, device, &row, &bindings, now).await? {
                Swap::Written => return Ok((key.thumbprint, fresh)),
                Swap::Moved => continue,
            }
        }
        Err(DeviceKeyError::Contended)
    }

    /// Whether a session of `user` may be bound to `proven`: the device is
    /// live, still holds that key, and is owned by `user`, or has no owner
    /// and is claimed for `user` by the store's conditional write
    /// ([`DeviceStore::claim_owner`]). A device another user owns binds
    /// nothing, whoever proved its key.
    pub(crate) async fn claim_for_binding(
        &self,
        proven: &crate::device_key::ProvenKey,
        user: &UserId,
        now: Timestamp,
    ) -> Result<bool, DeviceKeyError<S::Error>> {
        let row = self.live_row(&proven.tenant, &proven.device).await?;
        if !key_of(&row.bindings).is_some_and(|key| key.thumbprint.matches(&proven.thumbprint)) {
            return Ok(false);
        }
        match row.user_id.as_ref() {
            Some(owner) => Ok(owner == user),
            None => {
                let claim = self
                    .store
                    .claim_owner(&proven.tenant, &proven.device, user, now)
                    .await
                    .map_err(DeviceKeyError::Store)?;
                Ok(matches!(claim, crate::device::store::OwnerClaim::Claimed))
            }
        }
    }

    /// The thumbprint of the device's key, `None` when it has none.
    pub async fn key_thumbprint(
        &self,
        tenant: &TenantId,
        device: &DeviceId,
    ) -> Result<Option<KeyThumbprint>, DeviceKeyError<S::Error>> {
        let row = self.live_row(tenant, device).await?;
        Ok(key_of(&row.bindings).map(|key| key.thumbprint))
    }

    /// Remove the key from a device, `true` when it had one. The device is
    /// then proven by its token again, and a session bound to the key can no
    /// longer be served. The maintenance call a rollback to a release
    /// without device keys needs, since that release cannot read a row that
    /// holds one.
    pub async fn forget_device_key(
        &self,
        tenant: &TenantId,
        device: &DeviceId,
        now: Timestamp,
    ) -> Result<bool, DeviceKeyError<S::Error>> {
        for _ in 0..KEY_WRITE_ATTEMPTS {
            let row = self.live_row(tenant, device).await?;
            if key_of(&row.bindings).is_none() {
                return Ok(false);
            }
            let bindings: Vec<DeviceBinding> = row
                .bindings
                .iter()
                .filter(|binding| !matches!(binding, DeviceBinding::Key { .. }))
                .cloned()
                .collect();
            match self.swap(tenant, device, &row, &bindings, now).await? {
                Swap::Written => return Ok(true),
                Swap::Moved => continue,
            }
        }
        Err(DeviceKeyError::Contended)
    }

    /// Whether a challenge issued at `issued_at` is too old to answer at
    /// `now`: it is good for the configured lifetime and not at its end.
    fn is_expired(&self, issued_at: Timestamp, now: Timestamp) -> bool {
        axess_clock::SignedDuration::try_from(self.config.challenge_ttl())
            .ok()
            .and_then(|ttl| issued_at.checked_add(ttl))
            .is_none_or(|end| now >= end)
    }

    /// The device's row, read past any cache, when it exists and is not
    /// revoked.
    async fn live_row(
        &self,
        tenant: &TenantId,
        device: &DeviceId,
    ) -> Result<Device, DeviceKeyError<S::Error>> {
        match self
            .store
            .load_fresh(tenant, device)
            .await
            .map_err(DeviceKeyError::Store)?
        {
            Some(row) if row.trust_level != DeviceTrustLevel::Revoked => Ok(row),
            _ => Err(DeviceKeyError::Ended),
        }
    }

    /// Replace the row's bindings only while they are the ones read.
    async fn swap(
        &self,
        tenant: &TenantId,
        device: &DeviceId,
        row: &Device,
        bindings: &[DeviceBinding],
        now: Timestamp,
    ) -> Result<Swap, DeviceKeyError<S::Error>> {
        match self
            .store
            .replace_bindings(tenant, device, &row.bindings, bindings, now)
            .await
            .map_err(DeviceKeyError::Store)?
        {
            BindingsUpdate::Written => Ok(Swap::Written),
            BindingsUpdate::Conflict => Ok(Swap::Moved),
            BindingsUpdate::Revoked | BindingsUpdate::Missing => Err(DeviceKeyError::Ended),
        }
    }

    /// Count a refused registration and write its `Failure` row.
    async fn record_registration_refused(
        &self,
        tenant: &TenantId,
        device: &DeviceId,
        user: Option<&UserId>,
        reason: &'static str,
        now: Timestamp,
    ) {
        self.metrics.key_registration_refused();
        let event = AuthEventBuilder::failure(AuthEventType::DeviceKeyRegistered)
            .maybe_attributed_to(user, Some(tenant))
            .with_device(*device)
            .with_error(AuthFailureReason::Other(reason.to_string()))
            .build_at(now);
        self.event_sink.emit(event).await;
    }

    /// Count a proof that was not the key's and write its `Suspicious` row.
    async fn record_proof_refused(&self, tenant: &TenantId, device: &DeviceId, now: Timestamp) {
        self.metrics.key_proof_refused();
        self.write_proof_refused_row(tenant, device, now).await;
    }

    /// The `Suspicious` row of a proof that says something about who sent
    /// it: one that was not the key's where the sender also held a secret
    /// of the device, or one that was the key's and came twice.
    pub(crate) async fn write_proof_refused_row(
        &self,
        tenant: &TenantId,
        device: &DeviceId,
        now: Timestamp,
    ) {
        let event = AuthEventBuilder::unattributed(
            AuthEventType::DeviceKeyProofRefused,
            AuthEventStatus::Suspicious,
        )
        .maybe_attributed_to(None, Some(tenant))
        .with_device(*device)
        .build_at(now);
        self.event_sink.emit(event).await;
    }

    /// Write an event through the service's sink: the rows the session layer
    /// causes (a session bound, an unbound session ended) go the same way as
    /// the service's own.
    pub(crate) async fn emit(&self, event: crate::authn::event::AuthEvent) {
        self.event_sink.emit(event).await;
    }
}

/// What a compare-and-swap of the bindings did.
enum Swap {
    Written,
    /// Another writer changed the row: read it again.
    Moved,
}

/// The fields of a device's key that proving reads.
struct StoredKey<'a> {
    thumbprint: KeyThumbprint,
    public_key: &'a P256PublicKey,
    challenge: &'a KeyChallenge,
    challenge_issued_at: Timestamp,
}

/// The device's key among its bindings, if it has one.
fn key_of(bindings: &[DeviceBinding]) -> Option<StoredKey<'_>> {
    bindings.iter().find_map(|binding| match binding {
        DeviceBinding::Key {
            thumbprint,
            public_key,
            challenge,
            challenge_issued_at,
            ..
        } => Some(StoredKey {
            thumbprint: *thumbprint,
            public_key,
            challenge,
            challenge_issued_at: *challenge_issued_at,
        }),
        _ => None,
    })
}

/// `bindings` with the key's challenge replaced by `challenge`, issued at
/// `issued_at`, and its last proof moved to `proven_at` when one was made.
fn with_challenge(
    bindings: &[DeviceBinding],
    challenge: &KeyChallenge,
    issued_at: Timestamp,
    proven_at: Option<Timestamp>,
) -> Vec<DeviceBinding> {
    bindings
        .iter()
        .cloned()
        .map(|binding| match binding {
            DeviceBinding::Key {
                thumbprint,
                public_key,
                shape,
                bound_at,
                proven_at: last_proven_at,
                ..
            } => DeviceBinding::Key {
                thumbprint,
                public_key,
                shape,
                bound_at,
                proven_at: proven_at.unwrap_or(last_proven_at),
                challenge: challenge.clone(),
                challenge_issued_at: issued_at,
            },
            other => other,
        })
        .collect()
}

fn parse<'a, E>(proof: &KeyProof<'a>) -> Result<ParsedKeyProof<'a>, DeviceKeyError<E>>
where
    E: std::error::Error + Send + Sync + 'static,
{
    let shape = match proof.shape {
        KeyProofShape::Browser => axess_factors::key_proof::KeyProofShape::Browser,
        KeyProofShape::App => axess_factors::key_proof::KeyProofShape::App,
    };
    parse_key_proof(proof.jws, shape).map_err(DeviceKeyError::Proof)
}

fn target<'a>(proof: &KeyProof<'a>) -> ProofTarget<'a> {
    ProofTarget {
        method: proof.method,
        url: proof.url,
    }
}

mod request;
pub use request::{
    MAX_REQUEST_PROOF_AGE, REQUEST_PROOF_CLOCK_ALLOWANCE, RequestProof, RequestProofSender,
};

#[cfg(test)]
mod props;
#[cfg(test)]
mod tests;
