//! HKDF sub-key derivation and HMAC cookie sign/verify primitives.
//!
//! All HMAC use sites in the session layer derive a per-use sub-key from
//! a single master key via `HKDF-Expand`. Distinct `info` labels make the
//! sub-keys independent: a side-channel on one path (e.g. cookie verify)
//! cannot be replayed against another (e.g. fingerprint binding). The
//! `SigningKeys` bundle and the master are zeroed on drop.

use crate::session::id::SessionId;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::Mac;
use subtle::ConstantTimeEq;

/// HKDF-Expand a 32-byte sub-key from a master key + per-use
/// `info` label. RFC 5869 §2.3. Domain-separating session signing,
/// fingerprint binding, and any future per-key use prevents
/// cross-protocol forgery: a successful compromise of one HMAC
/// instance (e.g. a side-channel on the cookie verify path) cannot be
/// replayed against a different consumer of the same raw key.
pub(super) fn hkdf_expand_subkey(prk: &[u8; 32], info: &'static [u8]) -> [u8; 32] {
    // For 32-byte output (= one SHA-256 block) the iteration is a single
    // HMAC call: T(1) = HMAC(prk, info || 0x01). No iteration needed
    // since `L = HashLen`.
    let mut mac = crate::hmac::new_signer(prk);
    mac.update(info);
    mac.update(&[0x01]);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
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
/// All three keys (and the master) are zeroed on drop.
///
/// Kept as an internal implementation detail of the signing module:
/// external callers reach the HMAC operations via [`SigningKeyRing`]
/// methods (`sign_cookie`, `decode_cookie`, `compute_binding_fingerprints`,
/// `derive_subkey`) so no consumer needs to touch a specific sub-key.
#[derive(Clone)]
pub(super) struct SigningKeys {
    /// Master key: kept around so applications can derive *additional*
    /// sub-keys for domain-specific HMAC uses (CSRF, push tokens, etc.).
    master: [u8; 32],
    cookie: [u8; 32],
    fingerprint: [u8; 32],
}

impl SigningKeys {
    fn from_master(master: [u8; 32]) -> Self {
        Self {
            cookie: hkdf_expand_subkey(&master, HKDF_INFO_COOKIE),
            fingerprint: hkdf_expand_subkey(&master, HKDF_INFO_FINGERPRINT),
            master,
        }
    }
}

impl Drop for SigningKeys {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.master.zeroize();
        self.cookie.zeroize();
        self.fingerprint.zeroize();
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
///   [`VerifiedSessionId::verified_by_previous`] signal so they can
///   re-issue the cookie under the current key and update any
///   stored-at-rest values (fingerprint) to converge onto `current`.
/// - **Zeroization**: both sets zero on drop via [`SigningKeys::drop`].
///   Dropping the last `Arc<SigningKeyRing>` runs Drop on both.
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
    pub(super) fn from_master(master: [u8; 32]) -> Self {
        Self {
            current: SigningKeys::from_master(master),
            previous: None,
        }
    }

    /// Install a previous master. Called through
    /// [`SessionLayer::with_previous_signing_key`](super::SessionLayer::with_previous_signing_key)
    /// via `Arc::make_mut` on the ring.
    pub(super) fn set_previous(&mut self, previous_master: [u8; 32]) {
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

    /// Sign a session-id under the CURRENT cookie sub-key and format
    /// it as the wire cookie value (`base64(id) . base64(mac)`).
    ///
    /// New / re-issued cookies always sign under the current key
    /// regardless of rotation state; the previous key is used only on
    /// verify.
    pub(crate) fn sign_cookie(&self, id: SessionId) -> String {
        let id_enc = URL_SAFE_NO_PAD.encode(id.as_bytes());
        let mac = sign_bytes(id.as_bytes(), &self.current.cookie);
        format!("{id_enc}.{mac}")
    }

    /// Verify a signed session-id cookie against the current cookie
    /// sub-key; on mismatch (and only if a previous key is configured)
    /// fall back to the previous sub-key. Returns `None` when neither
    /// key verifies.
    ///
    /// The returned [`VerifiedSessionId::verified_by_previous`] flag
    /// signals whether the response layer must re-issue the cookie
    /// under the current key.
    pub(crate) fn decode_cookie(&self, value: &str) -> Option<VerifiedSessionId> {
        if let Some(id) = decode_cookie_with_key(value, &self.current.cookie) {
            return Some(VerifiedSessionId {
                id,
                verified_by_previous: false,
            });
        }
        if let Some(previous) = &self.previous
            && let Some(id) = decode_cookie_with_key(value, &previous.cookie)
        {
            tracing::debug!(
                "session cookie verified with previous (rotated) signing key; \
                 response will re-sign with current key"
            );
            return Some(VerifiedSessionId {
                id,
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
    pub(crate) fn derive_subkey(&self, info: &'static [u8]) -> [u8; 32] {
        hkdf_expand_subkey(&self.current.master, info)
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedSessionId {
    pub(crate) id: SessionId,
    pub(crate) verified_by_previous: bool,
}

/// Verify a signed session-id cookie against a single key.
///
/// Primitive used by [`SigningKeyRing::decode_cookie`] which composes
/// it across current + previous keys during rotation without
/// duplicating the parse / length-check / constant-time-compare
/// logic. `pub(super)` so tests can exercise the crypto primitive
/// independently of the rotation wrapper.
pub(super) fn decode_cookie_with_key(value: &str, key: &[u8; 32]) -> Option<SessionId> {
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
        Some(SessionId::from_bytes(arr))
    } else {
        None
    }
}

// Closes the layer.rs mutants finding: HKDF sub-key
// derivation must actually depend on the master key and the info
// label. The mutation-testing pass on `session/layer.rs` discovered
// that `hkdf_expand_subkey` and `derive_subkey` could be replaced
// with `[0; 32]` or `[1; 32]` and the test suite would not notice;
// a deployment shipping with constant cookie sub-keys (every session
// forgeable) would have passed CI. These tests anchor the contract.
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
        let layer_a = SessionLayer::new(MemorySessionStore::new(), [0xAA; 32]);
        let layer_b = SessionLayer::new(MemorySessionStore::new(), [0xBB; 32]);

        let info = b"axess.test.v1";
        let key_a = layer_a.derive_subkey(info);
        let key_b = layer_b.derive_subkey(info);

        assert_ne!(
            *key_a, *key_b,
            "derive_subkey must depend on the master key; \
             two layers with different masters produced the same sub-key"
        );
        // Also assert against the constant mutants directly so a
        // future cargo-mutants run kills them on a single property.
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

    /// Different info labels MUST produce different sub-keys for the
    /// same master. This is the domain-separation property:
    /// a side-channel on the cookie path cannot replay against the
    /// fingerprint path because the keys are unrelated.
    #[test]
    fn different_info_labels_yield_different_subkeys() {
        let layer = SessionLayer::new(MemorySessionStore::new(), [0x42; 32]);
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
        let layer = SessionLayer::new(MemorySessionStore::new(), [0x77; 32]);
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
        let keys_a = SigningKeys::from_master([0xAA; 32]);
        let keys_b = SigningKeys::from_master([0xBB; 32]);
        assert_ne!(keys_a.cookie, [0u8; 32]);
        assert_ne!(keys_a.cookie, [1u8; 32]);
        assert_ne!(keys_a.fingerprint, [0u8; 32]);
        assert_ne!(keys_a.fingerprint, [1u8; 32]);
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
}

#[cfg(test)]
mod signing_helpers_tests {
    //! Pin `sign_bytes` and `decode_cookie`
    //! pure-function bodies. The encode/decode pair must round-trip a
    //! known `SessionId` and reject malformed inputs.
    use super::*;
    use axess_rng::SystemRng;

    fn fixture_key() -> [u8; 32] {
        [0xA5; 32]
    }

    /// Kills line 717 `replace -> String::new()`: HMAC output is
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

    /// Kills line 723 `decode_cookie -> None`: a freshly
    /// signed cookie must round-trip back to the original
    /// `SessionId`.
    #[test]
    fn decode_cookie_round_trips_a_signed_cookie() {
        let key = fixture_key();
        let id = SessionId::new(&SystemRng);
        let id_enc = URL_SAFE_NO_PAD.encode(id.as_bytes());
        let mac_enc = sign_bytes(id.as_bytes(), &key);
        let cookie = format!("{id_enc}.{mac_enc}");

        let decoded = decode_cookie_with_key(&cookie, &key)
            .expect("signed cookie must decode back to a SessionId");
        assert_eq!(decoded, id);
    }

    /// Kills line 726 `!= → ==` on the id-length guard. With the
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

    /// Kills line 735 `!= → ==` on the MAC-length guard. A truncated
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
    use axess_rng::SystemRng;

    /// Craft a signed cookie under a given master's derived cookie
    /// sub-key. Helper mirrors what a real request cookie would carry.
    fn cookie_signed_by(master: [u8; 32], id: SessionId) -> String {
        let keys = SigningKeys::from_master(master);
        let id_enc = URL_SAFE_NO_PAD.encode(id.as_bytes());
        let mac = sign_bytes(id.as_bytes(), &keys.cookie);
        format!("{id_enc}.{mac}")
    }

    /// (1) No-rotation baseline: a cookie signed under the current
    /// master verifies without fallback.
    #[test]
    fn no_rotation_verifies_current_and_flags_no_fallback() {
        let master = [0xAA; 32];
        let ring = SigningKeyRing::from_master(master);
        let id = SessionId::new(&SystemRng);
        let cookie = cookie_signed_by(master, id);

        let out = ring
            .decode_cookie(&cookie)
            .expect("current-key cookie must verify");
        assert_eq!(out.id, id);
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
            current: SigningKeys::from_master(current),
            previous: Some(SigningKeys::from_master(previous)),
        };
        let id = SessionId::new(&SystemRng);
        let cookie = cookie_signed_by(current, id);

        let out = ring
            .decode_cookie(&cookie)
            .expect("current-key cookie must verify under rotation");
        assert_eq!(out.id, id);
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
            current: SigningKeys::from_master(current),
            previous: Some(SigningKeys::from_master(previous)),
        };
        let id = SessionId::new(&SystemRng);
        let cookie = cookie_signed_by(previous, id);

        let out = ring
            .decode_cookie(&cookie)
            .expect("previous-key cookie must verify under rotation");
        assert_eq!(out.id, id);
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
            current: SigningKeys::from_master(current),
            previous: Some(SigningKeys::from_master(previous)),
        };
        let id = SessionId::new(&SystemRng);
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
            current: SigningKeys::from_master(k2),
            previous: Some(SigningKeys::from_master(k1)),
        };

        let id = SessionId::new(&SystemRng);
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
        let no_rotation = SigningKeyRing::from_master([0xAA; 32]);
        assert!(!no_rotation.has_previous());

        let rotation_active = SigningKeyRing {
            current: SigningKeys::from_master([0xBB; 32]),
            previous: Some(SigningKeys::from_master([0xAA; 32])),
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
        let id = SessionId::new(&SystemRng);

        let mut ring = SigningKeyRing::from_master(new);
        ring.set_previous(old);
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
