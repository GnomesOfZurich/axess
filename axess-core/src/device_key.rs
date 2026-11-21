//! Device keys: the values a device-bound session is made of.
//!
//! A device key is a P-256 key pair the client generates where the private
//! half can be used and cannot be read. The server keeps the public half on
//! the device row, and from then on serves a bound session, and counts the
//! device as proven, only for a request that proves the key: by a
//! short-lived proof cookie minted against a signature by that key, or by a
//! request proof signed by it. The design, the threat it
//! answers and what it does not answer are in
//! `docs/sessions/device-bound-sessions.md`.
//!
//! The types here are plain values and are compiled whatever the features,
//! so a stored device row and a stored session have one shape in every
//! build. The service that registers and proves keys, the proof cookie and
//! the routes are behind the `device-keys` feature.

use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::session::data::AuthState;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

#[cfg(feature = "device-keys")]
mod config;
#[cfg(feature = "device-keys")]
pub(crate) mod cookie;
#[cfg(feature = "device-keys")]
pub(crate) mod erased;
#[cfg(feature = "device-keys")]
mod service;

#[cfg(feature = "device-keys")]
pub use config::{DeviceKeyConfig, DeviceKeyConfigError, RequestHead};
#[cfg(feature = "device-keys")]
pub use service::{
    DeviceKeyError, DeviceKeyService, KeyProof, MAX_REQUEST_PROOF_AGE, ProvedKey,
    REQUEST_PROOF_CLOCK_ALLOWANCE, RegisteredKey, RequestProof, RequestProofSender,
};

/// What the session layer does about device keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyBindingPolicy {
    /// Nothing: no key is offered, the two key paths are not answered, a
    /// bound session is served without proof and a device is proven by its
    /// token, as before device keys existed. What is stored stays stored,
    /// so switching back resumes where it stopped. The operator's switch for
    /// a fault in a browser's implementation; a client cannot reach it.
    Off,
    /// Offer a key to every client and hold every session and device that
    /// has one to it. A client that registers none keeps a bearer session.
    #[default]
    Prefer,
    /// As [`Prefer`](Self::Prefer), and a signed-in session that is not bound
    /// ends once the registration window has passed since its login. A
    /// session in a step-up is held to the same window, which the step-up
    /// neither pauses nor restarts. The session layer ends it as it ends
    /// every session it ends by itself: the layer's audit sink records it
    /// (reason `key_binding_required`) before its row is removed. For a fleet
    /// of managed clients: a browser with no support cannot stay signed in.
    Require,
}

/// Thirty-two bytes stored as 64 hex characters, as a device's fingerprint
/// hash is.
mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&axess_rng::hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        let mut out = [0u8; 32];
        axess_rng::hex::decode_to_slice(&text, &mut out)
            .map_err(|_| serde::de::Error::custom("expected 64 hex characters"))?;
        Ok(out)
    }
}

/// The RFC 7638 SHA-256 thumbprint of a device key: the key's name.
///
/// Not a secret. Two thumbprints are compared in constant time all the same
/// ([`matches`](Self::matches)), because one side of the comparison is
/// usually a value a client sent.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyThumbprint(#[serde(with = "hex32")] [u8; 32]);

impl KeyThumbprint {
    /// Wrap the 32 bytes of a thumbprint.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The unpadded base64url text, as a `cnf.jkt` claim spells it.
    pub fn to_text(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    /// Whether the two are the same thumbprint, in constant time.
    pub fn matches(&self, other: &KeyThumbprint) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl std::fmt::Debug for KeyThumbprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyThumbprint({})", self.to_text())
    }
}

/// A P-256 public key as its two affine coordinates, as stored on a device
/// row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct P256PublicKey {
    /// The x coordinate, big-endian.
    #[serde(with = "hex32")]
    pub x: [u8; 32],
    /// The y coordinate, big-endian.
    #[serde(with = "hex32")]
    pub y: [u8; 32],
}

/// Which front-end registered a key, and so which shape its proofs have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyProofShape {
    /// A browser that implements the Device Bound Session Credentials draft.
    Browser,
    /// A client that signs RFC 9449 proofs itself.
    App,
}

/// A challenge a device key signs: 32 bytes from the injected RNG, accepted
/// once.
///
/// It is unpredictable before it is issued and worthless without the key, so
/// a stored one is no secret; `Debug` still prints none of it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyChallenge(#[serde(with = "hex32")] [u8; 32]);

impl KeyChallenge {
    /// Draw a challenge from `rng`.
    pub fn mint(rng: &dyn axess_rng::SecureRng) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Wrap 32 bytes, for a store that kept them.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The text a client is handed and signs: unpadded base64url.
    pub fn to_text(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
}

impl std::fmt::Debug for KeyChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyChallenge(***)")
    }
}

/// How a request proved its device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceProof {
    /// By the secret token on the device cookie, or by being the request the
    /// device was created on. A bearer proof: whoever copied the cookie
    /// store holds it too.
    Token,
    /// By a proof of the device's key that the session layer verified: a
    /// proof cookie minted against a signature of the key, or a request
    /// proof signed by it. The thumbprint names the key.
    Key(KeyThumbprint),
}

/// The device key a request proved: what its proof cookie or its request
/// proof, verified by the session layer, says. It is the request's own
/// answer and is never stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvenKey {
    /// The tenant the device belongs to.
    pub tenant: TenantId,
    /// The device.
    pub device: DeviceId,
    /// The key the proof was made with.
    pub thumbprint: KeyThumbprint,
}

/// Placed in the request extensions by a session layer that enforces device
/// keys, before the device resolver runs: the keys this request proved, if
/// any.
///
/// Its presence is what turns enforcement on. With it, a device that has a
/// key is proven only by that key, and its token alone proves nothing. A
/// layer with no key service, or one whose policy is off, places nothing,
/// and a device is proven by its token as before.
///
/// Only the session layer makes one: what it holds is what the layer
/// verified, so nothing else can say a request proved a key. A device
/// resolution reads it through `KeyEnforcement::of`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyCheck {
    /// The keys the request proved: one per device registered in the
    /// browser profile whose proof it carried, usually one or none.
    proven: Vec<ProvenKey>,
}

/// Whether device keys are enforced for a request and what the request
/// proved: what a device resolution is held to
/// ([`DeviceRequest::keys`](crate::device::DeviceRequest)).
///
/// [`of`](Self::of) reads it from the request the session layer prepared,
/// and nothing else makes one, so a resolver cannot leave enforcement out
/// or claim a proof the layer did not verify: under an enforcing layer a
/// device that has a key is proven only by that key, whichever resolver
/// asks.
#[cfg(feature = "device")]
#[derive(Debug, Clone, Copy)]
pub struct KeyEnforcement<'a>(Option<&'a KeyCheck>);

#[cfg(feature = "device")]
impl<'a> KeyEnforcement<'a> {
    /// What the session layer left for this request: enforcement and the
    /// proven keys under a layer that enforces device keys, no enforcement
    /// under one that does not.
    pub fn of(parts: &'a axum::http::request::Parts) -> Self {
        Self(parts.extensions.get::<KeyCheck>())
    }

    /// The layer's check, `None` where keys are not enforced.
    pub(crate) fn check(self) -> Option<&'a KeyCheck> {
        self.0
    }

    /// No enforcement, for a test that resolves a device with no request.
    /// Not available in a production build.
    #[cfg(any(test, feature = "testing"))]
    pub fn none_for_tests() -> Self {
        Self(None)
    }

    /// Enforcement with `check`, for a test that resolves a device with no
    /// request. Not available in a production build.
    #[cfg(any(test, feature = "testing"))]
    pub fn for_tests(check: &'a KeyCheck) -> Self {
        Self(Some(check))
    }
}

impl KeyCheck {
    /// What the layer verified of one request.
    #[cfg(any(test, feature = "testing", feature = "device-keys"))]
    pub(crate) fn new(proven: Vec<ProvenKey>) -> Self {
        Self { proven }
    }

    /// A check holding `proven`, for a test that has no layer to verify a
    /// proof. Not available in a production build.
    #[cfg(any(test, feature = "testing"))]
    pub fn for_tests(proven: Vec<ProvenKey>) -> Self {
        Self::new(proven)
    }

    /// The key the request proved for `device` of `tenant`, if it proved one.
    pub fn for_device(&self, tenant: &TenantId, device: &DeviceId) -> Option<&ProvenKey> {
        self.proven
            .iter()
            .find(|proven| proven.tenant == *tenant && proven.device == *device)
    }

    /// The proven key that names `device` and has `thumbprint`, with the
    /// tenant its proof was made for.
    #[cfg(feature = "device")]
    pub(crate) fn key_of(
        &self,
        device: &DeviceId,
        thumbprint: &KeyThumbprint,
    ) -> Option<ProvenKey> {
        self.proven
            .iter()
            .find(|proven| proven.device == *device && proven.thumbprint.matches(thumbprint))
            .copied()
    }
}

/// Marks a request the session layer admitted to one of the two device-key
/// paths. Such a request is authenticated by a signature over a challenge
/// the server chose, which no other site can make a browser produce, so the
/// CSRF layer lets it through without a token. Only the session layer can
/// place it.
#[cfg(feature = "device-keys")]
#[derive(Debug, Clone, Copy)]
pub(crate) struct SignedKeyRequest;

/// The binding of a session to a device key: which device, which key, for
/// whom, and since when. Stored on the session row.
///
/// A binding is made for one person, the owner of the device: the
/// administrator while the session is an impersonation, else the
/// signed-in user. It is in force only while that person is the one at the
/// browser of the session ([`in_force_for`](Self::in_force_for)); a binding
/// that is not in force binds nothing, and the session layer drops it from
/// the row at the next write. While it is in force, the session is served
/// only to a request that proves exactly this tenant, device and key, by a
/// valid proof cookie or a request proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionKeyBinding {
    /// The person the device belongs to, for whom the binding was made: the
    /// administrator of an impersonation, else the signed-in user.
    pub owner: UserId,
    /// The tenant the device belongs to.
    pub tenant_id: TenantId,
    /// The device.
    pub device_id: DeviceId,
    /// The device's key.
    pub thumbprint: KeyThumbprint,
    /// When the session was bound, from the injected clock.
    pub bound_at: axess_clock::Timestamp,
}

impl SessionKeyBinding {
    /// Whether this binding holds for a session in `state`: the session is
    /// signed in (authenticated, or in a step-up of that session) and the
    /// person at its browser is the one the binding was made for.
    ///
    /// Only the owner is compared, not the tenant. `tenant_id` is the
    /// tenant the device belongs to, and a user belongs to one tenant, so
    /// the same owner means the same device tenant. An administrator who
    /// impersonates a user of another tenant is still the person at the
    /// browser, with their own device and key, and the binding holds.
    pub fn in_force_for(&self, state: &AuthState) -> bool {
        state.person_at_browser() == Some(self.owner)
    }

    /// Whether `proven` is the key this session is bound to.
    pub fn is_met_by(&self, proven: &ProvenKey) -> bool {
        self.tenant_id == proven.tenant
            && self.device_id == proven.device
            && self.thumbprint.matches(&proven.thumbprint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stored_forms_round_trip_as_hex_strings() {
        let thumbprint = KeyThumbprint::from_bytes([0xab; 32]);
        let json = serde_json::to_string(&thumbprint).unwrap();
        assert_eq!(json, format!("\"{}\"", "ab".repeat(32)));
        assert_eq!(
            serde_json::from_str::<KeyThumbprint>(&json).unwrap(),
            thumbprint
        );

        let key = P256PublicKey {
            x: [1; 32],
            y: [2; 32],
        };
        let json = serde_json::to_value(key).unwrap();
        assert_eq!(json["x"], "01".repeat(32));
        assert_eq!(json["y"], "02".repeat(32));
        assert_eq!(serde_json::from_value::<P256PublicKey>(json).unwrap(), key);

        let challenge = KeyChallenge::from_bytes([3; 32]);
        let json = serde_json::to_string(&challenge).unwrap();
        assert_eq!(
            serde_json::from_str::<KeyChallenge>(&json).unwrap(),
            challenge
        );
        assert_eq!(
            serde_json::to_string(&KeyProofShape::Browser).unwrap(),
            "\"browser\""
        );
        assert!(serde_json::from_str::<KeyThumbprint>("\"abcd\"").is_err());
    }

    #[test]
    fn a_challenge_comes_from_the_injected_rng_and_prints_nothing() {
        let rng = crate::testing::mock_random::MockRng::new(11);
        let first = KeyChallenge::mint(&rng);
        let second = KeyChallenge::mint(&rng);
        assert_ne!(first, second);
        assert_eq!(
            first,
            KeyChallenge::mint(&crate::testing::mock_random::MockRng::new(11))
        );
        assert_eq!(format!("{first:?}"), "KeyChallenge(***)");
        assert_eq!(first.to_text().len(), 43);
    }

    #[test]
    fn a_thumbprint_prints_and_hands_back_its_own_bytes() {
        let thumbprint = KeyThumbprint::from_bytes([0xff; 32]);
        assert_eq!(thumbprint.as_bytes(), &[0xff; 32]);
        let text = format!("{}8", "_".repeat(42));
        assert_eq!(thumbprint.to_text(), text);
        assert_eq!(format!("{thumbprint:?}"), format!("KeyThumbprint({text})"));
    }

    #[test]
    fn a_key_check_answers_only_for_its_own_tenant_and_device() {
        let tenant = crate::authn::ids::testing::tenant("t");
        let device = crate::authn::ids::testing::device("d");
        let proven = ProvenKey {
            tenant,
            device,
            thumbprint: KeyThumbprint::from_bytes([5; 32]),
        };
        let check = KeyCheck::new(vec![proven]);
        assert_eq!(check.for_device(&tenant, &device), Some(&proven));
        let other_tenant = crate::authn::ids::testing::tenant("other");
        let other_device = crate::authn::ids::testing::device("other");
        assert_eq!(check.for_device(&other_tenant, &device), None);
        assert_eq!(check.for_device(&tenant, &other_device), None);
        assert_eq!(KeyCheck::new(Vec::new()).for_device(&tenant, &device), None);
    }

    #[test]
    fn a_binding_is_met_only_by_its_own_tenant_device_and_key() {
        let tenant = crate::authn::ids::testing::tenant("t");
        let device = crate::authn::ids::testing::device("d");
        let binding = SessionKeyBinding {
            owner: crate::authn::ids::testing::user("u"),
            tenant_id: tenant,
            device_id: device,
            thumbprint: KeyThumbprint::from_bytes([5; 32]),
            bound_at: axess_clock::testing::MockClock::reference_time(),
        };
        let proven = ProvenKey {
            tenant,
            device,
            thumbprint: KeyThumbprint::from_bytes([5; 32]),
        };
        assert!(binding.is_met_by(&proven));
        assert!(!binding.is_met_by(&ProvenKey {
            tenant: crate::authn::ids::testing::tenant("other"),
            ..proven
        }));
        assert!(!binding.is_met_by(&ProvenKey {
            device: crate::authn::ids::testing::device("other"),
            ..proven
        }));
        assert!(!binding.is_met_by(&ProvenKey {
            thumbprint: KeyThumbprint::from_bytes([6; 32]),
            ..proven
        }));
    }
}
