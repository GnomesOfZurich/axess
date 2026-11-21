//! Device identity types: opaque IDs, trust level, fingerprint hash, bindings.
//!
//! Identifying metadata (display name, last-known IP, user-agent string) is
//! deliberately **not** carried on [`Device`]. Per the design in
//! [`docs/identity/device.md`](../../../../docs/identity/device.md), PII lives
//! exclusively in a separate, deletable mapping table; see the `pii` module.

use crate::authn::ids::{DeviceId, TenantId, UserId};
use axess_clock::Timestamp;
use serde::{Deserialize, Serialize};

// ── FingerprintHash ───────────────────────────────────────────────────────────

/// Keyed digest of the request fingerprint inputs (User-Agent, Accept-Language,
/// Accept, etc.).
///
/// Computed as `HMAC-SHA256(tenant_fingerprint_key, canonicalised_inputs)`. The
/// digest itself is not PII because it is keyed (the key is rotated per
/// tenant), but the inputs are. Only the digest is ever persisted on a
/// [`Device`] row.
///
/// Equality / hashing is on the raw 32-byte payload; constant-time comparison
/// is provided through [`subtle::ConstantTimeEq`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FingerprintHash(#[serde(with = "fingerprint_serde")] [u8; 32]);

impl FingerprintHash {
    /// Construct from a raw 32-byte HMAC-SHA256 output.
    #[inline]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying 32 bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

mod fingerprint_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&axess_rng::hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let mut out = [0u8; 32];
        axess_rng::hex::decode_to_slice(&s, &mut out)
            .map_err(|_| serde::de::Error::custom("FingerprintHash must be 64 hex characters"))?;
        Ok(out)
    }
}

// ── DeviceTrustLevel ──────────────────────────────────────────────────────────

/// Three-stage assurance ladder for a device, plus a terminal `Revoked` state.
///
/// Transition policy lives in the [`DeviceStore`](super::store::DeviceStore)
/// implementations; promotion and demotion are explicit operations rather
/// than derived from idle time at read time. The retention sweep
/// drives demotions on a schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub enum DeviceTrustLevel {
    /// First sighting: the device exists in the table but no ceremony has
    /// granted any assurance. `Authenticated` sessions originating from an
    /// `Unknown` device should trigger step-up per PSD2 RTS Art 4 / NIST SP
    /// 800-63B-4 §5.2.6.
    #[default]
    Unknown,

    /// A user has authenticated on the device at least once
    /// ([`promote_on_authn`](crate::device::DeviceLifecycleService::promote_on_authn)
    /// moves `Unknown` to `Seen`), or the retention sweep demoted it from
    /// `Trusted`. Suitable for low-risk operations only; not a possession
    /// factor by itself.
    Seen,

    /// The device has completed a trust ceremony (typically a WebAuthn
    /// registration or admin-driven trust assignment). Valid as a
    /// possession factor under PSD2 RTS Art 4 when paired with a
    /// `WebAuthn` binding of attestation class ≠ `none`.
    Trusted,

    /// The device is no longer trusted. Sessions bound to a `Revoked`
    /// device must be invalidated; the row remains for the configured
    /// grace window before the sweep job purges it.
    Revoked,
}

// ── DeviceBinding ─────────────────────────────────────────────────────────────

/// Evidence linking a [`Device`] row to a concrete authentication artefact.
///
/// A device may carry multiple bindings: typically the `Cookie` binding of
/// the token issued when the device was created, one `WebAuthn` per passkey
/// registered on the physical device, and one `Refresh` per refresh-token
/// family the device takes part in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum DeviceBinding {
    /// SHA-256 digest of the device token the browser holds in its
    /// long-lived device cookie
    /// ([`DeviceToken::digest`](crate::device::proof::DeviceToken::digest)):
    /// unkeyed and domain-separated, because the token is 32 random bytes
    /// and needs no key to resist guessing. Not a possession factor on its
    /// own; it is what lets a later request prove it comes from the browser
    /// the `Device` row was issued to, across session rotations.
    Cookie {
        /// The 32-byte digest of the token, hex-encoded for transport. The
        /// field has the type of a fingerprint hash and holds none.
        token_hash: FingerprintHash,
        /// When the cookie was issued (from injected
        /// [`Clock`](axess_clock::Clock)).
        issued_at: Timestamp,
        /// When the cookie was last presented and validated.
        last_used_at: Timestamp,
    },

    /// Reference to a FIDO2 credential registered against this device. The
    /// `credential_id` is the WebAuthn-spec credential ID (opaque bytes,
    /// hex-encoded for serde transport). Filled when the `fido2`
    /// feature is on (WebAuthn binding work).
    WebAuthn {
        /// WebAuthn credential id (opaque to axess).
        credential_id: String,
        /// One of `"none"`, `"self"`, `"basic"`, `"attca"`, `"anonca"` per
        /// the WebAuthn registration ceremony. `"none"` does NOT meet the
        /// PSD2 RTS Art 4 possession-factor bar; basic/attca/anonca do.
        attestation_class: AttestationClass,
        /// When the credential was registered against this device.
        bound_at: Timestamp,
        /// When the credential was last used to authenticate.
        last_used_at: Timestamp,
    },

    /// Reference to a refresh-token family this device participates in.
    ///
    /// Recorded when a refresh-token family is created in the context of
    /// a session that already has a `device_id`. Lets
    /// [`cascade_revoke_by_refresh_family_and_tokens`](super::cascade::cascade_revoke_by_refresh_family_and_tokens)
    /// find every `Device` to revoke, with its tokens, when a
    /// refresh-token-family theft is detected (rotated-out token reuse).
    ///
    /// A device can carry multiple `Refresh` bindings, one per family it
    /// has been associated with, so cycling refresh-token families
    /// (e.g. across long-lived sessions) doesn't lose history. The
    /// retention sweep is responsible for purging stale entries
    /// once the underlying family is no longer reachable.
    Refresh {
        /// Refresh-token family identifier. Matches
        /// [`TokenFamilyId`](crate::session::refresh::TokenFamilyId);
        /// stored as `String` here to keep the binding enum free of a
        /// dependency on the `session::refresh` module's serde shape.
        family_id: String,
        /// When the binding was first recorded (matches the family's
        /// initial-issue instant).
        issued_at: Timestamp,
        /// When a token from this family was last successfully used to
        /// refresh a session on this device.
        last_used_at: Timestamp,
    },

    /// The device's key: the public half of a key pair whose private half
    /// the client can use and cannot read. A device has at most one.
    ///
    /// Unlike the cookie token, this is not a bearer value. A device that has
    /// a key is proven, where device keys are enforced, only by a signature
    /// of that key over the stored `challenge`, and a session
    /// bound to the key is served only to a request that carries the
    /// short-lived cookie such a signature buys. See
    /// [`device_key`](crate::device_key).
    ///
    /// The variant is compiled whatever the features, so a row has one shape
    /// in every build. A release before the variant existed cannot read a
    /// row that holds one.
    Key {
        /// The key's RFC 7638 thumbprint.
        thumbprint: crate::device_key::KeyThumbprint,
        /// The public key.
        public_key: crate::device_key::P256PublicKey,
        /// The front-end that registered it.
        shape: crate::device_key::KeyProofShape,
        /// When the key was registered (from injected
        /// [`Clock`](axess_clock::Clock)).
        bound_at: Timestamp,
        /// When the key last signed a challenge.
        proven_at: Timestamp,
        /// The challenge the next proof must answer. Replaced by the write
        /// that accepts a proof, which is what makes it single-use.
        challenge: crate::device_key::KeyChallenge,
        /// When that challenge was issued.
        challenge_issued_at: Timestamp,
    },
}

/// WebAuthn attestation class, bucketed for SCA-decision purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationClass {
    /// No attestation. Insufficient for PSD2 RTS Art 4 possession-factor
    /// claims.
    None,
    /// Self-attestation. The authenticator signed for itself; insufficient
    /// for high-assurance use cases.
    Self_,
    /// Basic attestation backed by a vendor certificate.
    Basic,
    /// AttCA: attestation CA chain.
    AttCa,
    /// AnonCA: anonymisation CA, preserves user privacy while still
    /// proving authenticator-model class.
    AnonCa,
}

// ── Device ────────────────────────────────────────────────────────────────────

/// First-class device aggregate.
///
/// Carries no PII; identifying metadata lives in `DevicePiiMapping`.
/// `user_id` is `Option` because a device can exist before it has an owner:
/// [`ensure_device`](crate::device::DeviceLifecycleService::ensure_device)
/// creates one for a guest's request and the first authenticated user to
/// resolve it claims it. A device created by
/// [`resolve_or_keep`](crate::device::DeviceLifecycleService::resolve_or_keep)
/// always has its owner, since a guest's request creates none there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// Opaque identifier for this device, scoped to the tenant.
    pub id: DeviceId,
    /// Tenant that owns this device row. Devices are tenant-scoped to
    /// prevent cross-tenant correlation.
    pub tenant_id: TenantId,
    /// Authenticated user this device is associated with. `None` for a
    /// device created before any user was identified and not yet claimed.
    pub user_id: Option<UserId>,
    /// Current trust level. See [`DeviceTrustLevel`].
    pub trust_level: DeviceTrustLevel,
    /// Keyed digest of the fingerprint inputs of the request the device
    /// was created on. A hint, not an identity:
    /// [`resolve_or_keep`](crate::device::DeviceLifecycleService::resolve_or_keep)
    /// stores it and finds no device by it, and only
    /// [`ensure_device`](crate::device::DeviceLifecycleService::ensure_device)
    /// looks a device up by it.
    pub fingerprint_hash: FingerprintHash,
    /// When the device was first sighted (from injected
    /// [`Clock`](axess_clock::Clock)).
    pub first_seen_at: Timestamp,
    /// When the device was last sighted. Drives the retention-sweep
    /// demotion ladder.
    pub last_seen_at: Timestamp,
    /// Set when the device transitions to [`DeviceTrustLevel::Revoked`].
    pub revoked_at: Option<Timestamp>,
    /// Set when a `Trusted` device is moved down to [`DeviceTrustLevel::Seen`]
    /// (by the retention sweep or an explicit downgrade) and cleared by any
    /// other transition. It is what tells a `Seen` device that was never
    /// trusted (revoked `seen_idle` after its last sighting) from one that
    /// was demoted (revoked `seen_idle` after the demotion): the retention
    /// ladder reads it, nothing else does. Absent in rows written before the
    /// field existed, which then read as never trusted.
    #[serde(default)]
    pub demoted_at: Option<Timestamp>,
    /// Bindings attached to this device: the cookie token's digest, WebAuthn
    /// credentials and refresh-token families (see [`DeviceBinding`]).
    #[serde(default)]
    pub bindings: Vec<DeviceBinding>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_hash_round_trips_through_json() {
        let h = FingerprintHash::from_bytes([0xab; 32]);
        let json = serde_json::to_string(&h).unwrap();
        // 32 bytes → 64 hex chars, all 0xab.
        assert_eq!(json, format!("\"{}\"", "ab".repeat(32)));
        let back: FingerprintHash = serde_json::from_str(&json).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn fingerprint_hash_rejects_wrong_length() {
        let json = "\"deadbeef\"";
        assert!(serde_json::from_str::<FingerprintHash>(json).is_err());
    }

    #[test]
    fn device_trust_level_default_is_unknown() {
        assert_eq!(DeviceTrustLevel::default(), DeviceTrustLevel::Unknown);
    }

    // ── nibble / hex_decode ──────────────────────────────────────────────
    //
    // The tests below decode digits, lowercase and uppercase letters, so
    // every arm of `fingerprint_serde::nibble` runs (`b'0'..=b'9'`,
    // `b'a'..=b'f'`, `b'A'..=b'F'`) and each arm's offset is pinned.
    //
    // In `(hi << 4) | lo`, `|` and `^` give the same result for
    // nibble-bounded inputs (`hi << 4` only sets bits 4-7, `lo` only sets
    // bits 0-3), so no test tells the two apart: no value can.

    #[test]
    fn fingerprint_hash_as_bytes_returns_stored_value() {
        // Kills `as_bytes -> Box::leak(Box::new([1; 32]))`: any returned
        // [1; 32] would not match the [0xab; 32] / [0; 32] payloads.
        let h = FingerprintHash::from_bytes([0xab; 32]);
        assert_eq!(h.as_bytes(), &[0xab; 32]);

        let zero = FingerprintHash::from_bytes([0; 32]);
        assert_eq!(zero.as_bytes(), &[0; 32]);
    }

    #[test]
    fn fingerprint_hash_round_trips_digit_only_payload() {
        // Drives the `b'0'..=b'9'` match arm in nibble; kills:
        //  * `delete match arm b'0'..= b'9'` (no decode path covers digits)
        //  * `b - b'0' -> +` (would yield ~97 for '1', not 1)
        //  * `b - b'0' -> /` (would yield 1 for every digit)
        let bytes = [0x12u8; 32];
        let h = FingerprintHash::from_bytes(bytes);
        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(json, format!("\"{}\"", "12".repeat(32)));

        let back: FingerprintHash = serde_json::from_str(&json).unwrap();
        assert_eq!(back.as_bytes(), &bytes);
    }

    #[test]
    fn fingerprint_hash_decodes_uppercase_hex_payload() {
        // Drives the `b'A'..=b'F'` match arm; kills:
        //  * `delete match arm b'A'..= b'F'`
        //  * `b - b'A' -> +` (would overflow / produce wrong byte)
        //  * `b - b'A' -> /` (would map every letter to the same value)
        //  * `+ 10 -> - 10` (would underflow on 'A')
        let upper = format!("\"{}\"", "AB".repeat(32));
        let h: FingerprintHash = serde_json::from_str(&upper).unwrap();
        assert_eq!(h.as_bytes(), &[0xab; 32]);
    }

    #[test]
    fn fingerprint_hash_decodes_full_nibble_range() {
        // Smoke-test every nibble value 0..=15 in a single 32-byte
        // payload. Confirms hex_decode handles boundary digits ('0',
        // '9'), lowercase ('a', 'f'), and that hi/lo combine correctly.
        let mut payload = [0u8; 32];
        for (i, b) in payload.iter_mut().enumerate() {
            // hi nibble = (i % 16), lo nibble = (15 - (i % 16))
            let hi = (i % 16) as u8;
            let lo = (15 - (i % 16)) as u8;
            *b = (hi << 4) | lo;
        }
        let h = FingerprintHash::from_bytes(payload);
        let json = serde_json::to_string(&h).unwrap();
        let back: FingerprintHash = serde_json::from_str(&json).unwrap();
        assert_eq!(back.as_bytes(), &payload);
    }

    #[test]
    fn fingerprint_hash_rejects_non_hex_byte() {
        // The `_` arm of `nibble` returns Err. A 64-char string of 'z'
        // forces every byte through that arm.
        let bad = format!("\"{}\"", "z".repeat(64));
        assert!(serde_json::from_str::<FingerprintHash>(&bad).is_err());
    }
}
