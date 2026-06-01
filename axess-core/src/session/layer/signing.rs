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
#[derive(Clone)]
pub(crate) struct SigningKeys {
    /// Master key: kept around so applications can derive *additional*
    /// sub-keys for domain-specific HMAC uses (CSRF, push tokens, etc.).
    pub(super) master: [u8; 32],
    pub(crate) cookie: [u8; 32],
    pub(crate) fingerprint: [u8; 32],
}

impl SigningKeys {
    pub(super) fn from_master(master: [u8; 32]) -> Self {
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

pub(super) fn signing_sign_bytes(bytes: &[u8], key: &[u8; 32]) -> String {
    let mut mac = crate::hmac::new_signer(key.as_ref());
    mac.update(bytes);
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

pub(super) fn signing_decode_cookie(value: &str, key: &[u8; 32]) -> Option<SessionId> {
    let (id_enc, mac_enc) = value.split_once('.')?;

    let id_bytes = URL_SAFE_NO_PAD.decode(id_enc).ok()?;
    if id_bytes.len() != 16 {
        return None;
    }

    let mac_bytes = URL_SAFE_NO_PAD.decode(mac_enc).ok()?;
    let expected = signing_sign_bytes(&id_bytes, key);
    let expected_bytes = URL_SAFE_NO_PAD.decode(expected).ok()?;

    // Reject truncated or oversized tags before constant-time comparison.
    if mac_bytes.len() != expected_bytes.len() {
        return None;
    }

    // Constant-time comparison prevents timing side-channels.
    if mac_bytes.ct_eq(&expected_bytes).into() {
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
    //! Pin `signing_sign_bytes` and `signing_decode_cookie`
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
    fn signing_sign_bytes_returns_url_safe_base64_of_hmac() {
        let key = fixture_key();
        let sig = signing_sign_bytes(b"axess:session-id-bytes", &key);
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
        let sig2 = signing_sign_bytes(b"axess:session-id-bytes", &key);
        assert_eq!(sig, sig2);
    }

    /// Different keys must produce different signatures: pins the
    /// function against ignoring the `key` argument.
    #[test]
    fn signing_sign_bytes_depends_on_key() {
        let sig_a = signing_sign_bytes(b"same-input", &[0xAA; 32]);
        let sig_b = signing_sign_bytes(b"same-input", &[0xBB; 32]);
        assert_ne!(sig_a, sig_b, "different keys must yield different HMACs");
    }

    /// Kills line 723 `signing_decode_cookie -> None`: a freshly
    /// signed cookie must round-trip back to the original
    /// `SessionId`.
    #[test]
    fn signing_decode_cookie_round_trips_a_signed_cookie() {
        let key = fixture_key();
        let id = SessionId::new(&SystemRng);
        let id_enc = URL_SAFE_NO_PAD.encode(id.as_bytes());
        let mac_enc = signing_sign_bytes(id.as_bytes(), &key);
        let cookie = format!("{id_enc}.{mac_enc}");

        let decoded = signing_decode_cookie(&cookie, &key)
            .expect("signed cookie must decode back to a SessionId");
        assert_eq!(decoded, id);
    }

    /// Kills line 726 `!= → ==` on the id-length guard. With the
    /// mutation, `id_bytes.len() == 16` returns None (and only
    /// non-16-byte ids pass). Construct a valid 16-byte id, encode
    /// + sign; mutation rejects (None), original accepts (Some).
    #[test]
    fn signing_decode_cookie_accepts_16_byte_id() {
        let key = fixture_key();
        let id = SessionId::from_bytes([0xC3; 16]);
        let id_enc = URL_SAFE_NO_PAD.encode(id.as_bytes());
        let mac_enc = signing_sign_bytes(id.as_bytes(), &key);
        let cookie = format!("{id_enc}.{mac_enc}");

        let decoded = signing_decode_cookie(&cookie, &key);
        assert!(
            decoded.is_some(),
            "16-byte id must decode; `!= → ==` mutant would reject"
        );
    }

    /// Companion to the previous test: a NON-16-byte id must be
    /// rejected. Forces the original guard's reject path; mutation
    /// `==` would accept here.
    #[test]
    fn signing_decode_cookie_rejects_wrong_length_id() {
        let key = fixture_key();
        // 15-byte id (one byte short of 16).
        let id_bytes = [0xC3; 15];
        let id_enc = URL_SAFE_NO_PAD.encode(id_bytes);
        let mac_enc = signing_sign_bytes(&id_bytes, &key);
        let cookie = format!("{id_enc}.{mac_enc}");

        let decoded = signing_decode_cookie(&cookie, &key);
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
    fn signing_decode_cookie_rejects_truncated_mac() {
        let key = fixture_key();
        let id = SessionId::from_bytes([0xD4; 16]);
        let id_enc = URL_SAFE_NO_PAD.encode(id.as_bytes());

        // Take the full MAC and truncate to half its byte length.
        let full_mac_enc = signing_sign_bytes(id.as_bytes(), &key);
        let full_mac_bytes = URL_SAFE_NO_PAD.decode(&full_mac_enc).unwrap();
        let truncated_bytes = &full_mac_bytes[..full_mac_bytes.len() / 2];
        let truncated_mac_enc = URL_SAFE_NO_PAD.encode(truncated_bytes);
        let cookie = format!("{id_enc}.{truncated_mac_enc}");

        let decoded = signing_decode_cookie(&cookie, &key);
        assert!(
            decoded.is_none(),
            "truncated MAC must reject; `!= → ==` mutant on length guard would invert this"
        );
    }
}
