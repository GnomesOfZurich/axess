//! HKDF sub-key derivation and HMAC cookie sign/verify primitives.
//!
//! All HMAC use sites in the session layer derive a per-use sub-key from
//! a single master key via `HKDF-Expand`. Distinct `info` labels make the
//! sub-keys independent: a side-channel on one path (e.g. cookie verify)
//! cannot be replayed against another (e.g. fingerprint binding). The
//! master and every sub-key of a `SigningKeys` bundle are held in buffers
//! that are zeroed on drop, and a sub-key leaves its derivation in such a
//! buffer too.

use crate::session::id::{SessionId, SessionKey};
use axess_rng::SecureRng;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::Mac;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// HKDF-Expand a 32-byte sub-key from a master key + per-use
/// `info` label. RFC 5869 §2.3. Domain-separating session signing,
/// fingerprint binding, and any future per-key use prevents
/// cross-protocol forgery: a successful compromise of one HMAC
/// instance (e.g. a side-channel on the cookie verify path) cannot be
/// replayed against a different consumer of the same raw key.
///
/// The sub-key is returned in a buffer that is zeroed on drop, and the HMAC
/// output it is copied from is zeroed before this returns.
pub(super) fn hkdf_expand_subkey(prk: &[u8; 32], info: &[u8]) -> Zeroizing<[u8; 32]> {
    // For 32-byte output (= one SHA-256 block) the iteration is a single
    // HMAC call: T(1) = HMAC(prk, info || 0x01). No iteration needed
    // since `L = HashLen`.
    let mut mac = crate::hmac::new_signer(prk);
    mac.update(info);
    mac.update(&[0x01]);
    crate::hmac::finalize_key(mac)
}

/// The session a cookie names: the value the cookie carries and the key
/// that value is stored, registered and recorded under.
///
/// This is the one type that holds a session id outside the cookie text.
/// The id is private to this file, which signs and verifies cookies; the
/// key is computed from it once, in [`CookieSession::holding`], so that no
/// code path derives it a second time or from another value. Two sessions
/// are compared by [`key`](Self::key): the type has no equality of its own,
/// so that a comparison never reads the id.
#[derive(Clone, Copy)]
pub(crate) struct CookieSession {
    id: SessionId,
    key: SessionKey,
}

impl CookieSession {
    /// The session of `id`, with its key. Every `CookieSession` is built
    /// here: from an id a cookie's signature vouched for, or a fresh one.
    fn holding(id: SessionId) -> Self {
        Self {
            id,
            key: SessionKey::of(&id),
        }
    }

    /// A fresh session id from `rng`, and its key.
    pub(crate) fn mint(rng: &dyn SecureRng) -> Self {
        Self::holding(SessionId::new(rng))
    }

    /// The session of a known id, for a test that plants a row or signs a
    /// cookie for it.
    #[cfg(test)]
    pub(crate) fn of_id(id: SessionId) -> Self {
        Self::holding(id)
    }

    /// The key. Every caller outside this file reads the session through it:
    /// there is no accessor of the id, so no code outside the cookie codec
    /// can read the value the cookie carries, whatever it does with a
    /// session.
    pub(crate) fn key(&self) -> &SessionKey {
        &self.key
    }
}

/// Prints the key's log form and never the id, so a session in a `Debug`
/// of whatever holds it is not a value a cookie could carry.
impl std::fmt::Debug for CookieSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CookieSession({:?})", self.key)
    }
}

/// HKDF info labels: distinct byte strings ensure the derived
/// sub-keys are unrelated. Changing these values invalidates every
/// existing session and fingerprint cookie; treat as a wire-format
/// constant.
const HKDF_INFO_COOKIE: &[u8] = b"axess.v1.session.cookie.hmac";
const HKDF_INFO_FINGERPRINT: &[u8] = b"axess.v1.session.fingerprint.hmac";

/// Bundle of HKDF-derived sub-keys, one per HMAC use site.
/// Each sub-key is independent of the others, so a compromise on one
/// path (oracle, side-channel) cannot be replayed against the others.
/// The master and both sub-keys are each held in a `Zeroizing` buffer,
/// which is zeroed on drop.
///
/// Kept as an internal implementation detail of the signing module:
/// external callers reach the HMAC operations via [`SigningKeyRing`]
/// methods (`sign_cookie`, `decode_cookie`, `compute_binding_fingerprints`,
/// `derive_subkey`) so no consumer needs to touch a specific sub-key.
#[derive(Clone)]
pub(super) struct SigningKeys {
    /// Master key: kept around so applications can derive *additional*
    /// sub-keys for domain-specific HMAC uses (CSRF, push tokens, etc.).
    master: Zeroizing<[u8; 32]>,
    cookie: Zeroizing<[u8; 32]>,
    fingerprint: Zeroizing<[u8; 32]>,
}

impl SigningKeys {
    /// Takes the master by reference, so the only copy this makes of it is
    /// the one in the bundle's own buffer.
    fn from_master(master: &[u8; 32]) -> Self {
        Self {
            cookie: hkdf_expand_subkey(master, HKDF_INFO_COOKIE),
            fingerprint: hkdf_expand_subkey(master, HKDF_INFO_FINGERPRINT),
            master: Zeroizing::new(*master),
        }
    }
}

/// Rotation-aware wrapper around [`SigningKeys`]. Holds a `current` set
/// of derived sub-keys and an optional `previous` set for zero-downtime
/// signing-key rotation.
///
/// # Rotation semantics
///
/// - **Signing**: always uses `current` sub-keys. New cookies and new
///   fingerprints are minted under the current master only.
/// - **Verification**: tries `current` first; on mismatch, falls back
///   to `previous` if present. Callers receive a
///   [`VerifiedCookie::verified_by_previous`] signal so they can
///   re-issue the cookie under the current key and update any
///   stored-at-rest values (fingerprint) to converge onto `current`.
/// - **Zeroization**: every key of both sets is zeroed when the set is
///   dropped, which dropping the last `Arc<SigningKeyRing>` does.
///
/// # Rotation cadence
///
/// Only one previous slot is maintained. Chained rotation faster than
/// one session-TTL window forces re-auth for cookies signed under the
/// pre-first-rotation key (they no longer verify under current OR
/// previous). This is the correct security behavior: see
/// `OPERATIONS.md#signing-key-rotation`.
#[derive(Clone)]
pub(crate) struct SigningKeyRing {
    current: SigningKeys,
    previous: Option<SigningKeys>,
}

impl SigningKeyRing {
    pub(super) fn from_master(master: &[u8; 32]) -> Self {
        Self {
            current: SigningKeys::from_master(master),
            previous: None,
        }
    }

    /// Install a previous master. Called through
    /// [`SessionLayer::with_previous_signing_key`](super::SessionLayer::with_previous_signing_key)
    /// via `Arc::make_mut` on the ring.
    pub(super) fn set_previous(&mut self, previous_master: &[u8; 32]) {
        self.previous = Some(SigningKeys::from_master(previous_master));
    }

    /// Clear any previous master. Called through
    /// [`SessionLayer::remove_previous_signing_key`](super::SessionLayer::remove_previous_signing_key)
    /// via `Arc::make_mut` on the ring. The `SigningKeys`' sub-keys
    /// zeroize on drop.
    pub(super) fn clear_previous(&mut self) {
        self.previous = None;
    }

    /// `true` when a previous master is configured, a signing-key
    /// rotation window is currently active.
    pub(crate) fn has_previous(&self) -> bool {
        self.previous.is_some()
    }

    /// Sign a session's id under the CURRENT cookie sub-key and format
    /// it as the wire cookie value (`base64(id) . base64(mac)`).
    ///
    /// New / re-issued cookies always sign under the current key
    /// regardless of rotation state; the previous key is used only on
    /// verify.
    pub(crate) fn sign_cookie(&self, session: &CookieSession) -> String {
        let id_enc = URL_SAFE_NO_PAD.encode(session.id.as_bytes());
        let mac = sign_bytes(session.id.as_bytes(), &self.current.cookie);
        format!("{id_enc}.{mac}")
    }

    /// Verify a signed session-id cookie against the current cookie
    /// sub-key; on mismatch (and only if a previous key is configured)
    /// fall back to the previous sub-key. Returns `None` when neither
    /// key verifies.
    ///
    /// The returned [`VerifiedCookie::verified_by_previous`] flag
    /// signals whether the response layer must re-issue the cookie
    /// under the current key.
    pub(crate) fn decode_cookie(&self, value: &str) -> Option<VerifiedCookie> {
        if let Some(session) = decode_cookie_with_key(value, &self.current.cookie) {
            return Some(VerifiedCookie {
                session,
                verified_by_previous: false,
            });
        }
        if let Some(previous) = &self.previous
            && let Some(session) = decode_cookie_with_key(value, &previous.cookie)
        {
            tracing::debug!(
                "session cookie verified with previous (rotated) signing key; \
                 response will re-sign with current key"
            );
            return Some(VerifiedCookie {
                session,
                verified_by_previous: true,
            });
        }
        None
    }

    /// Compute the binding fingerprint pair for the given material.
    ///
    /// Returns `(current_fingerprint, previous_fingerprint)`:
    /// - `current_fingerprint`: always `Some` (HMAC of `material`
    ///   under the current fingerprint sub-key).
    /// - `previous_fingerprint`: `Some` iff a previous master is
    ///   configured (rotation window active). Callers use this pair
    ///   to verify a stored fingerprint against both eras and, on
    ///   previous-key match, update the stored value to
    ///   `current_fingerprint` so the fast path resumes.
    pub(crate) fn compute_binding_fingerprints(&self, material: &[u8]) -> (String, Option<String>) {
        let current = sign_bytes(material, &self.current.fingerprint);
        let previous = self
            .previous
            .as_ref()
            .map(|k| sign_bytes(material, &k.fingerprint));
        (current, previous)
    }

    /// HKDF-Expand an application sub-key from the CURRENT master
    /// under `info`. Rotating the master changes what this returns;
    /// adopters using this for their own HMAC sites must maintain
    /// their own previous-key state if they need rotation coverage.
    ///
    /// The two labels the layer derives its own keys under are reserved:
    /// asking for one returns a key from a separate namespace, never the
    /// key that signs cookies or binds fingerprints. The list is the check
    /// below, not a registry: a new label the layer derives for its own
    /// use must be added to it, or an adopter asking for that label would
    /// get the layer's key.
    ///
    /// # Panics
    ///
    /// Panics on a label that starts with `axess.v1.reserved-label.`, the
    /// namespace the reserved labels are remapped into: such a label would
    /// share its key with the remap of another one.
    pub(crate) fn derive_subkey(&self, info: &'static [u8]) -> Zeroizing<[u8; 32]> {
        assert!(
            !info.starts_with(RESERVED_LABEL_PREFIX),
            "derive_subkey: labels starting with `axess.v1.reserved-label.` are reserved"
        );
        if info == HKDF_INFO_COOKIE || info == HKDF_INFO_FINGERPRINT {
            let mut separated = RESERVED_LABEL_PREFIX.to_vec();
            separated.extend_from_slice(info);
            return hkdf_expand_subkey(&self.current.master, &separated);
        }
        hkdf_expand_subkey(&self.current.master, info)
    }
}

/// The namespace the reserved labels are remapped into.
const RESERVED_LABEL_PREFIX: &[u8] = b"axess.v1.reserved-label.";

/// Label of the sub-key that signs device-key proof cookies and registration
/// offers. Under the reserved prefix, so `derive_subkey` cannot hand the same
/// key to an application.
#[cfg(feature = "device-keys")]
const HKDF_INFO_DEVICE_KEY: &[u8] = b"axess.v1.reserved-label.device-key.cookie.hmac";

#[cfg(feature = "device-keys")]
impl SigningKeyRing {
    /// The keys device-key proof cookies and offers are signed with: under
    /// the current signing key, and under the previous one while a rotation
    /// window is open, so a rotation does not cost every client a failed
    /// request.
    pub(crate) fn device_key_cookie_keys(&self) -> crate::device_key::cookie::KeyCookieKeys {
        // Each sub-key is copied out of the wiping buffer it was derived
        // into, which is wiped as it drops, into a struct that wipes itself
        // on drop.
        crate::device_key::cookie::KeyCookieKeys {
            current: *hkdf_expand_subkey(&self.current.master, HKDF_INFO_DEVICE_KEY),
            previous: self
                .previous
                .as_ref()
                .map(|keys| *hkdf_expand_subkey(&keys.master, HKDF_INFO_DEVICE_KEY)),
        }
    }
}

/// Compute HMAC-SHA256 of `bytes` under `key`; return the raw 32-byte
/// tag. Verify paths compare against this directly to avoid a
/// pointless base64 round-trip.
pub(super) fn hmac_bytes(bytes: &[u8], key: &[u8; 32]) -> [u8; 32] {
    let mut mac = crate::hmac::new_signer(key);
    mac.update(bytes);
    mac.finalize().into_bytes().into()
}

/// Compute HMAC-SHA256 of `bytes` under `key`, return URL-safe
/// base64 (no padding). Shared between the cookie sign path
/// ([`SigningKeyRing::sign_cookie`]) and the fingerprint compute path
/// ([`SigningKeyRing::compute_binding_fingerprints`]). `pub(super)`
/// so tests can exercise it directly.
pub(super) fn sign_bytes(bytes: &[u8], key: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(hmac_bytes(bytes, key))
}

/// Outcome of a rotation-aware cookie verification.
///
/// The `verified_by_previous` flag drives the caller's re-issue path:
/// when `true`, the response handler emits a fresh `Set-Cookie` signed
/// under the current key so the client stops presenting a
/// previous-key cookie on subsequent requests.
#[derive(Debug, Clone, Copy)]
pub(crate) struct VerifiedCookie {
    /// The session the cookie names.
    pub(crate) session: CookieSession,
    pub(crate) verified_by_previous: bool,
}

/// Verify a signed session-id cookie against a single key.
///
/// Primitive used by [`SigningKeyRing::decode_cookie`] which composes
/// it across current + previous keys during rotation without
/// duplicating the parse / length-check / constant-time-compare
/// logic. `pub(super)` so tests can exercise the crypto primitive
/// independently of the rotation wrapper.
///
/// The session's key is computed here, once, and only for an id whose
/// signature verified: a forged cookie costs no hash and names no key.
pub(super) fn decode_cookie_with_key(value: &str, key: &[u8; 32]) -> Option<CookieSession> {
    let (id_enc, mac_enc) = value.split_once('.')?;

    let id_bytes = URL_SAFE_NO_PAD.decode(id_enc).ok()?;
    if id_bytes.len() != 16 {
        return None;
    }

    let mac_bytes = URL_SAFE_NO_PAD.decode(mac_enc).ok()?;
    let expected = hmac_bytes(&id_bytes, key);

    // Reject truncated or oversized tags before constant-time comparison.
    if mac_bytes.len() != expected.len() {
        return None;
    }

    // Constant-time comparison prevents timing side-channels.
    if mac_bytes.ct_eq(&expected).into() {
        let arr: [u8; 16] = id_bytes.try_into().ok()?;
        Some(CookieSession::holding(SessionId::from_bytes(arr)))
    } else {
        None
    }
}

// HKDF sub-key derivation depends on the master key and on the info
// label. A `hkdf_expand_subkey` or `derive_subkey` that answered a
// constant (`[0; 32]`, `[1; 32]`) would give every deployment the same
// cookie sub-keys and make every session forgeable; these tests fail on
// either.
#[cfg(test)]
mod subkey_derivation_tests {
    use super::*;
    use crate::session::layer::SessionLayer;
    use crate::session::store::MemorySessionStore;

    /// Different master keys MUST produce different sub-keys for the
    /// same info label. Kills the `replace ... -> [0; 32]` and
    /// `replace ... -> [1; 32]` mutants on both `hkdf_expand_subkey`
    /// and `derive_subkey`.
    #[test]
    fn different_masters_yield_different_subkeys() {
        let layer_a = SessionLayer::new_unchecked(
            MemorySessionStore::new(),
            [0xAA; 32],
            crate::MemorySessionRegistry::new().handle(),
            std::sync::Arc::new(crate::session::UnrecordedSessionEnds),
        );
        let layer_b = SessionLayer::new_unchecked(
            MemorySessionStore::new(),
            [0xBB; 32],
            crate::MemorySessionRegistry::new().handle(),
            std::sync::Arc::new(crate::session::UnrecordedSessionEnds),
        );

        let info = b"axess.test.v1";
        let key_a = layer_a.derive_subkey(info);
        let key_b = layer_b.derive_subkey(info);

        assert_ne!(
            *key_a, *key_b,
            "derive_subkey must depend on the master key; \
             two layers with different masters produced the same sub-key"
        );
        // Each constant is also refused by name, so a derivation that
        // answers one fails on that property alone.
        assert_ne!(
            *key_a, [0u8; 32],
            "derive_subkey returned the [0;32] mutant value"
        );
        assert_ne!(
            *key_a, [1u8; 32],
            "derive_subkey returned the [1;32] mutant value"
        );
        assert_ne!(*key_b, [0u8; 32]);
        assert_ne!(*key_b, [1u8; 32]);
    }

    /// The labels the session layer itself derives its keys under are not
    /// available to an application: asking for one must not return the key
    /// that signs cookies or binds fingerprints.
    #[test]
    fn reserved_labels_do_not_return_the_layers_own_keys() {
        let layer = SessionLayer::new_unchecked(
            MemorySessionStore::new(),
            [0x42; 32],
            crate::MemorySessionRegistry::new().handle(),
            std::sync::Arc::new(crate::session::UnrecordedSessionEnds),
        );
        let cookie_key = *layer.signing_keys.current.cookie;
        let fingerprint_key = *layer.signing_keys.current.fingerprint;

        let asked_cookie = layer.derive_subkey(b"axess.v1.session.cookie.hmac");
        let asked_fingerprint = layer.derive_subkey(b"axess.v1.session.fingerprint.hmac");

        assert_ne!(
            *asked_cookie, cookie_key,
            "the cookie HMAC key was handed out"
        );
        assert_ne!(*asked_fingerprint, fingerprint_key);
        assert_ne!(*asked_cookie, *asked_fingerprint);
    }

    /// The reserved labels are remapped into a namespace of their own; a label
    /// that starts with that namespace's prefix would collide with the remap
    /// of another label, so it is refused.
    #[test]
    fn a_label_in_the_reserved_namespace_is_refused() {
        let layer = SessionLayer::new_unchecked(
            MemorySessionStore::new(),
            [0x42; 32],
            crate::MemorySessionRegistry::new().handle(),
            std::sync::Arc::new(crate::session::UnrecordedSessionEnds),
        );
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            layer.derive_subkey(b"axess.v1.reserved-label.axess.v1.session.cookie.hmac")
        }));
        assert!(
            refused.is_err(),
            "a label in the reserved namespace shares a key with another label"
        );
        // A label that merely resembles the prefix is still allowed.
        let _ = layer.derive_subkey(b"axess.v1.reserved-label");
        let _ = layer.derive_subkey(b"my-app.axess.v1.reserved-label.x");
    }

    /// Different info labels MUST produce different sub-keys for the
    /// same master. This is the domain-separation property:
    /// a side-channel on the cookie path cannot replay against the
    /// fingerprint path because the keys are unrelated.
    #[test]
    fn different_info_labels_yield_different_subkeys() {
        let layer = SessionLayer::new_unchecked(
            MemorySessionStore::new(),
            [0x42; 32],
            crate::MemorySessionRegistry::new().handle(),
            std::sync::Arc::new(crate::session::UnrecordedSessionEnds),
        );
        let key_cookie = layer.derive_subkey(b"axess.v1.session.cookie.hmac");
        let key_csrf = layer.derive_subkey(b"axess.v1.csrf");
        let key_push = layer.derive_subkey(b"axess.v1.push");

        assert_ne!(key_cookie, key_csrf);
        assert_ne!(key_cookie, key_push);
        assert_ne!(key_csrf, key_push);
    }

    /// Same master + same info MUST produce a stable sub-key. Kills
    /// any future mutant that would inject randomness or a counter
    /// into the derivation, and confirms the determinism that a
    /// session cookie's HMAC depends on across requests.
    #[test]
    fn subkey_is_deterministic_under_same_inputs() {
        let layer = SessionLayer::new_unchecked(
            MemorySessionStore::new(),
            [0x77; 32],
            crate::MemorySessionRegistry::new().handle(),
            std::sync::Arc::new(crate::session::UnrecordedSessionEnds),
        );
        let info = b"axess.v1.session.cookie.hmac";
        let k1 = layer.derive_subkey(info);
        let k2 = layer.derive_subkey(info);
        assert_eq!(
            k1, k2,
            "derive_subkey is not deterministic; \
                            two calls with identical inputs produced different keys"
        );
    }

    /// The internal `SigningKeys::from_master` MUST produce a non-zero
    /// `cookie` sub-key. Kills the `hkdf_expand_subkey -> [0;32]`
    /// mutation on the call sites inside `from_master` (the public
    /// `derive_subkey` only covers one call site; this asserts the
    /// other two).
    #[test]
    fn signing_keys_cookie_subkey_is_non_constant() {
        let keys_a = SigningKeys::from_master(&[0xAA; 32]);
        let keys_b = SigningKeys::from_master(&[0xBB; 32]);
        assert_ne!(*keys_a.cookie, [0u8; 32]);
        assert_ne!(*keys_a.cookie, [1u8; 32]);
        assert_ne!(*keys_a.fingerprint, [0u8; 32]);
        assert_ne!(*keys_a.fingerprint, [1u8; 32]);
        // Different masters → different cookie sub-keys.
        assert_ne!(
            keys_a.cookie, keys_b.cookie,
            "two different masters produced the same cookie sub-key"
        );
        assert_ne!(
            keys_a.fingerprint, keys_b.fingerprint,
            "two different masters produced the same fingerprint sub-key"
        );
        // Cookie and fingerprint sub-keys MUST differ inside one
        // SigningKeys (different info labels, domain separation).
        assert_ne!(
            keys_a.cookie, keys_a.fingerprint,
            "cookie and fingerprint sub-keys collapsed to the same value"
        );
    }

    /// The master and each sub-key are `Zeroizing` buffers, which wipe
    /// themselves when the bundle is dropped. The bundle has no `Drop` of
    /// its own to keep in step with its fields: taking them out of it
    /// compiles only while it has none, and only while every field is named.
    #[test]
    fn every_signing_key_is_held_in_a_zeroizing_buffer() {
        let SigningKeys {
            master,
            cookie,
            fingerprint,
        } = SigningKeys::from_master(&[0xAA; 32]);
        let held: [Zeroizing<[u8; 32]>; 3] = [master, cookie, fingerprint];
        assert_eq!(*held[0], [0xAA; 32]);
        assert_ne!(held[1], held[2]);
    }

    /// A sub-key leaves both derivations in a buffer that wipes itself, so
    /// no plain copy of it stays behind where the derivation ran. The ring
    /// derives an application's label from the current master as it is.
    #[test]
    fn a_derived_subkey_is_returned_in_a_zeroizing_buffer() {
        let expanded: Zeroizing<[u8; 32]> = hkdf_expand_subkey(&[0xAA; 32], b"axess.test.v1");
        let ring = SigningKeyRing::from_master(&[0xAA; 32]);
        let derived: Zeroizing<[u8; 32]> = ring.derive_subkey(b"axess.test.v1");
        assert_eq!(expanded, derived);
        assert_ne!(*expanded, [0u8; 32]);
    }
}

#[cfg(test)]
mod signing_helpers_tests {
    //! Pin `sign_bytes` and `decode_cookie`
    //! pure-function bodies. The encode/decode pair must round-trip a
    //! known `SessionId` and reject malformed inputs.
    use super::*;
    use axess_rng::testing::MockRng;

    fn fixture_key() -> [u8; 32] {
        [0xA5; 32]
    }

    /// Kills the mutant `replace -> String::new()`: HMAC output is
    /// always non-empty. Also kills `-> "xyzzy".into()`: HMAC output
    /// is base64-url-encoded SHA256 (43 chars without padding) and
    /// not the literal "xyzzy".
    #[test]
    fn sign_bytes_returns_url_safe_base64_of_hmac() {
        let key = fixture_key();
        let sig = sign_bytes(b"axess:session-id-bytes", &key);
        assert!(!sig.is_empty(), "HMAC encoding must not be empty");
        // SHA256 = 32 bytes → base64 (no-pad) = ceil(32 * 4 / 3) = 43 chars.
        assert_eq!(
            sig.len(),
            43,
            "URL_SAFE_NO_PAD-encoded SHA256 must be 43 chars, got {sig:?}"
        );
        // Same key + same bytes must produce identical output (HMAC
        // determinism). Pins the function against any mutation that
        // randomises or zeroes the output.
        let sig2 = sign_bytes(b"axess:session-id-bytes", &key);
        assert_eq!(sig, sig2);
    }

    /// Different keys must produce different signatures: pins the
    /// function against ignoring the `key` argument.
    #[test]
    fn sign_bytes_depends_on_key() {
        let sig_a = sign_bytes(b"same-input", &[0xAA; 32]);
        let sig_b = sign_bytes(b"same-input", &[0xBB; 32]);
        assert_ne!(sig_a, sig_b, "different keys must yield different HMACs");
    }

    /// Kills the mutant `decode_cookie -> None`: a freshly
    /// signed cookie must round-trip back to the original
    /// `SessionId`.
    #[test]
    fn decode_cookie_round_trips_a_signed_cookie() {
        let key = fixture_key();
        let id = SessionId::new(&MockRng::new(1));
        let id_enc = URL_SAFE_NO_PAD.encode(id.as_bytes());
        let mac_enc = sign_bytes(id.as_bytes(), &key);
        let cookie = format!("{id_enc}.{mac_enc}");

        let decoded = decode_cookie_with_key(&cookie, &key)
            .expect("signed cookie must decode back to a SessionId");
        assert_eq!(decoded.id, id);
    }

    /// Kills the mutant `!= → ==` on the id-length guard. With the
    /// mutation, `id_bytes.len() == 16` returns None (and only
    /// non-16-byte ids pass). Construct a valid 16-byte id, encode
    /// + sign; mutation rejects (None), original accepts (Some).
    #[test]
    fn decode_cookie_accepts_16_byte_id() {
        let key = fixture_key();
        let id = SessionId::from_bytes([0xC3; 16]);
        let id_enc = URL_SAFE_NO_PAD.encode(id.as_bytes());
        let mac_enc = sign_bytes(id.as_bytes(), &key);
        let cookie = format!("{id_enc}.{mac_enc}");

        let decoded = decode_cookie_with_key(&cookie, &key);
        assert!(
            decoded.is_some(),
            "16-byte id must decode; `!= → ==` mutant would reject"
        );
    }

    /// Companion to the previous test: a NON-16-byte id must be
    /// rejected. Forces the original guard's reject path; mutation
    /// `==` would accept here.
    #[test]
    fn decode_cookie_rejects_wrong_length_id() {
        let key = fixture_key();
        // 15-byte id (one byte short of 16).
        let id_bytes = [0xC3; 15];
        let id_enc = URL_SAFE_NO_PAD.encode(id_bytes);
        let mac_enc = sign_bytes(&id_bytes, &key);
        let cookie = format!("{id_enc}.{mac_enc}");

        let decoded = decode_cookie_with_key(&cookie, &key);
        assert!(
            decoded.is_none(),
            "15-byte id must reject; `!= → ==` mutant would accept"
        );
    }

    /// Kills the mutant `!= → ==` on the MAC-length guard. A truncated
    /// MAC must be rejected. With the mutation, only mismatched
    /// lengths would pass; and there's no path that reaches
    /// constant-time comparison with a same-length MAC.
    #[test]
    fn decode_cookie_rejects_truncated_mac() {
        let key = fixture_key();
        let id = SessionId::from_bytes([0xD4; 16]);
        let id_enc = URL_SAFE_NO_PAD.encode(id.as_bytes());

        // Take the full MAC and truncate to half its byte length.
        let full_mac_enc = sign_bytes(id.as_bytes(), &key);
        let full_mac_bytes = URL_SAFE_NO_PAD.decode(&full_mac_enc).unwrap();
        let truncated_bytes = &full_mac_bytes[..full_mac_bytes.len() / 2];
        let truncated_mac_enc = URL_SAFE_NO_PAD.encode(truncated_bytes);
        let cookie = format!("{id_enc}.{truncated_mac_enc}");

        let decoded = decode_cookie_with_key(&cookie, &key);
        assert!(
            decoded.is_none(),
            "truncated MAC must reject; `!= → ==` mutant on length guard would invert this"
        );
    }
}

#[cfg(test)]
mod rotation_tests {
    //! Rotation semantics for [`decode_cookie`] over a
    //! [`SigningKeyRing`]. Pins the four-state matrix:
    //!
    //! 1. no-rotation baseline (single key): current verify passes.
    //! 2. rotation active, cookie signed under current key: fast path,
    //!    `verified_by_previous = false`.
    //! 3. rotation active, cookie signed under previous key: falls
    //!    back, `verified_by_previous = true`.
    //! 4. rotation active, cookie signed under a third unknown key:
    //!    both keys fail → `None`, no false accept.
    //!
    //! Plus a chained-rotation test: after two rotations, a cookie
    //! signed under the pre-first-rotation key no longer verifies
    //! (previous slot has been overwritten by the once-current key).
    //! This is the correct security behavior documented in
    //! `OPERATIONS.md#signing-key-rotation`.
    use super::*;
    use axess_rng::testing::MockRng;

    /// Craft a signed cookie under a given master's derived cookie
    /// sub-key. Helper mirrors what a real request cookie would carry.
    fn cookie_signed_by(master: [u8; 32], id: SessionId) -> String {
        let keys = SigningKeys::from_master(&master);
        let id_enc = URL_SAFE_NO_PAD.encode(id.as_bytes());
        let mac = sign_bytes(id.as_bytes(), &keys.cookie);
        format!("{id_enc}.{mac}")
    }

    /// (1) No-rotation baseline: a cookie signed under the current
    /// master verifies without fallback.
    #[test]
    fn no_rotation_verifies_current_and_flags_no_fallback() {
        let master = [0xAA; 32];
        let ring = SigningKeyRing::from_master(&master);
        let id = SessionId::new(&MockRng::new(1));
        let cookie = cookie_signed_by(master, id);

        let out = ring
            .decode_cookie(&cookie)
            .expect("current-key cookie must verify");
        assert_eq!(out.session.id, id);
        assert!(
            !out.verified_by_previous,
            "no rotation window → must not flag previous-key fallback"
        );
    }

    /// (2) Rotation active, cookie under current master: fast path;
    /// still no fallback flag.
    #[test]
    fn rotation_active_current_cookie_flags_no_fallback() {
        let current = [0xBB; 32];
        let previous = [0xAA; 32];
        let ring = SigningKeyRing {
            current: SigningKeys::from_master(&current),
            previous: Some(SigningKeys::from_master(&previous)),
        };
        let id = SessionId::new(&MockRng::new(1));
        let cookie = cookie_signed_by(current, id);

        let out = ring
            .decode_cookie(&cookie)
            .expect("current-key cookie must verify under rotation");
        assert_eq!(out.session.id, id);
        assert!(
            !out.verified_by_previous,
            "current-key match must not flag fallback"
        );
    }

    /// (3) Rotation active, cookie under previous master: falls back,
    /// flag is set, id round-trips. This is the load-bearing case that
    /// drives the layer service's re-issue-cookie path.
    #[test]
    fn rotation_active_previous_cookie_falls_back_and_flags() {
        let current = [0xBB; 32];
        let previous = [0xAA; 32];
        let ring = SigningKeyRing {
            current: SigningKeys::from_master(&current),
            previous: Some(SigningKeys::from_master(&previous)),
        };
        let id = SessionId::new(&MockRng::new(1));
        let cookie = cookie_signed_by(previous, id);

        let out = ring
            .decode_cookie(&cookie)
            .expect("previous-key cookie must verify under rotation");
        assert_eq!(out.session.id, id);
        assert!(
            out.verified_by_previous,
            "previous-key match MUST flag fallback so caller re-signs under current"
        );
    }

    /// (4) Rotation active, cookie under a third unknown master:
    /// neither key verifies → `None`. No forgery through the rotation
    /// slot.
    #[test]
    fn rotation_active_unknown_cookie_rejected() {
        let current = [0xBB; 32];
        let previous = [0xAA; 32];
        let unknown = [0xCC; 32];
        let ring = SigningKeyRing {
            current: SigningKeys::from_master(&current),
            previous: Some(SigningKeys::from_master(&previous)),
        };
        let id = SessionId::new(&MockRng::new(1));
        let cookie = cookie_signed_by(unknown, id);

        assert!(
            ring.decode_cookie(&cookie).is_none(),
            "cookie signed under a third unknown key must reject; no forgery via rotation slot"
        );
    }

    /// Chained rotation: rotate twice in quick succession. The
    /// pre-first-rotation key falls out of the ring entirely and its
    /// cookies fail. Documented as the correct security behavior for
    /// emergency rotate-again scenarios.
    #[test]
    fn chained_rotation_drops_the_original_key() {
        let k0 = [0xAA; 32]; // pre-first-rotation key
        let k1 = [0xBB; 32]; // rotated once
        let k2 = [0xCC; 32]; // rotated twice

        // After the second rotation, the ring holds (current=k2, previous=k1).
        // k0 is gone.
        let ring_after_two_rotations = SigningKeyRing {
            current: SigningKeys::from_master(&k2),
            previous: Some(SigningKeys::from_master(&k1)),
        };

        let id = SessionId::new(&MockRng::new(1));
        let cookie_from_k0 = cookie_signed_by(k0, id);

        assert!(
            ring_after_two_rotations
                .decode_cookie(&cookie_from_k0)
                .is_none(),
            "cookie signed under a key rotated out two windows ago must not verify"
        );

        // Sanity: cookies from k1 (now the previous) still verify with fallback flag.
        let cookie_from_k1 = cookie_signed_by(k1, id);
        let out = ring_after_two_rotations
            .decode_cookie(&cookie_from_k1)
            .expect("k1 is now the previous slot and must still verify");
        assert!(out.verified_by_previous);
    }

    /// `SigningKeyRing::has_previous` reflects the runtime rotation
    /// state: used by `SessionLayer::has_previous_signing_key` for
    /// operator-facing introspection.
    #[test]
    fn ring_has_previous_reflects_state() {
        let no_rotation = SigningKeyRing::from_master(&[0xAA; 32]);
        assert!(!no_rotation.has_previous());

        let rotation_active = SigningKeyRing {
            current: SigningKeys::from_master(&[0xBB; 32]),
            previous: Some(SigningKeys::from_master(&[0xAA; 32])),
        };
        assert!(rotation_active.has_previous());
    }

    /// `clear_previous` retires the rotation slot: cookies signed under
    /// the retired master must fail verification afterwards, and the
    /// ring reports `has_previous() == false`. Companion to
    /// [`ring_verifies_previous_cookie_and_flags_fallback`]: proves the
    /// operator can end the rotation window explicitly.
    #[test]
    fn ring_clear_previous_ends_rotation_window() {
        let old = [0xAA; 32];
        let new = [0xBB; 32];
        let id = SessionId::new(&MockRng::new(1));

        let mut ring = SigningKeyRing::from_master(&new);
        ring.set_previous(&old);
        assert!(ring.has_previous());

        let cookie_from_old = cookie_signed_by(old, id);
        ring.decode_cookie(&cookie_from_old)
            .expect("previous key must verify while rotation slot is populated");

        ring.clear_previous();
        assert!(!ring.has_previous());
        assert!(
            ring.decode_cookie(&cookie_from_old).is_none(),
            "cookies signed under the retired previous key must no longer verify"
        );
    }
}

#[cfg(test)]
mod cookie_session_tests;
