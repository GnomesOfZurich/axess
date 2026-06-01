//! Device identity types: opaque IDs, trust level, fingerprint hash, bindings.
//!
//! Identifying metadata (display name, last-known IP, user-agent string) is
//! deliberately **not** carried on [`Device`]. Per the design in
//! [`docs/identity/device.md`](../../../../docs/identity/device.md), PII lives
//! exclusively in a separate, deletable mapping table; see the `pii` module.

use crate::authn::ids::{DeviceId, TenantId, UserId};
use chrono::{DateTime, Utc};
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
        s.serialize_str(&hex_encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        hex_decode(&s).map_err(serde::de::Error::custom)
    }

    fn hex_encode(bytes: &[u8; 32]) -> String {
        let mut out = String::with_capacity(64);
        for b in bytes {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }

    fn hex_decode(s: &str) -> Result<[u8; 32], &'static str> {
        if s.len() != 64 {
            return Err("FingerprintHash must be 64 hex characters");
        }
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
            let hi = nibble(chunk[0])?;
            let lo = nibble(chunk[1])?;
            out[i] = (hi << 4) | lo;
        }
        Ok(out)
    }

    fn nibble(b: u8) -> Result<u8, &'static str> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err("FingerprintHash contains non-hex character"),
        }
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

    /// The device has been sighted across multiple sessions and presents a
    /// stable cookie+fingerprint pair. Suitable for low-risk operations
    /// only; not a possession factor by itself.
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
/// A device may carry multiple bindings, typically one `Cookie` issued at
/// each fresh login, plus one `WebAuthn` per registered passkey on the
/// physical device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum DeviceBinding {
    /// HMAC-SHA256 hash of a long-lived device-binding cookie. Not a
    /// possession factor on its own; provides cookie-jar continuity so that
    /// the same physical browser maps to the same `Device` row across
    /// session rotations.
    Cookie {
        /// 32-byte HMAC of the cookie value, hex-encoded for transport.
        token_hash: FingerprintHash,
        /// When the cookie was issued (from injected
        /// [`Clock`](axess_clock::Clock)).
        issued_at: DateTime<Utc>,
        /// When the cookie was last presented and validated.
        last_used_at: DateTime<Utc>,
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
        bound_at: DateTime<Utc>,
        /// When the credential was last used to authenticate.
        last_used_at: DateTime<Utc>,
    },

    /// Reference to a refresh-token family this device participates in.
    ///
    /// Recorded when a refresh-token family is created in the context of
    /// a session that already has a `device_id`. Lets
    /// [`cascade_revoke_by_refresh_family`](super::cascade::cascade_revoke_by_refresh_family)
    /// find every `Device` to revoke when a refresh-token-family theft is
    /// detected (rotated-out token reuse).
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
        issued_at: DateTime<Utc>,
        /// When a token from this family was last successfully used to
        /// refresh a session on this device.
        last_used_at: DateTime<Utc>,
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
/// `user_id` is `Option` because the system can sight a device pre-
/// identification (e.g. failed login on a brand-new browser) and only later
/// associate it with a user once authn completes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// Opaque identifier for this device, scoped to the tenant.
    pub id: DeviceId,
    /// Tenant that owns this device row. Devices are tenant-scoped to
    /// prevent cross-tenant correlation.
    pub tenant_id: TenantId,
    /// Authenticated user this device is associated with. `None` when the
    /// device was sighted pre-identification.
    pub user_id: Option<UserId>,
    /// Current trust level. See [`DeviceTrustLevel`].
    pub trust_level: DeviceTrustLevel,
    /// Keyed digest of the request fingerprint inputs. Used as the
    /// fast-lookup key when an inbound request carries no `device_id`
    /// cookie yet.
    pub fingerprint_hash: FingerprintHash,
    /// When the device was first sighted (from injected
    /// [`Clock`](axess_clock::Clock)).
    pub first_seen_at: DateTime<Utc>,
    /// When the device was last sighted. Drives the retention-sweep
    /// demotion ladder.
    pub last_seen_at: DateTime<Utc>,
    /// Set when the device transitions to [`DeviceTrustLevel::Revoked`].
    pub revoked_at: Option<DateTime<Utc>>,
    /// Bindings attached to this device (cookie, webauthn).
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

    // ── mutation-testing follow-up: nibble / hex_decode coverage ─────────────────────────
    //
    // The original test suite only exercised lowercase `"ab"` repeating;
    // the `b'0'..=b'9'` and `b'A'..=b'F'` arms of `fingerprint_serde::nibble`
    // were never executed, so mutations on those arms (arm deletion, arithmetic
    // sign flips, `b'0'`/`b'A'` substitutions) all escaped detection.
    //
    // The `(hi << 4) | lo` mutation `| -> ^` is mathematically equivalent
    // for nibble-bounded inputs (`hi << 4` only sets bits 4-7, `lo` only
    // sets bits 0-3, so `|` and `^` produce identical results). Documented
    // inert; no test covers it because no value distinguishes the two.

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
