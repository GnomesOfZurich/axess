//! Shared logic for SQL-backed device stores (SQLite, PostgreSQL).
//!
//! Mirrors the shape of
//! [`session::storage::session_codec`](crate::session::storage::session_codec):
//! a small codec that handles the bindings-blob serialisation + optional
//! AES-256-GCM envelope encryption, and a shared error type so each
//! backend doesn't reinvent the failure surface.
//!
//! # What's encrypted, what isn't
//!
//! Only the **bindings blob** runs through the optional codec. The
//! structured columns (tenant_id, id, user_id, trust_level,
//! fingerprint_hash, first_seen_at, last_seen_at, revoked_at) stay
//! plaintext because every one of them is either a tenant-scoped
//! opaque id, a keyed HMAC, or a timestamp the indexes need to be
//! able to range-scan. Encrypting the bindings blob covers the
//! material that *could* leak something operationally interesting
//! (refresh-token family identifiers, WebAuthn credential references)
//! without giving up the tenant-scoped query primitives that drive
//! the rest of the device subsystem.

use crate::device::types::DeviceBinding;
use crate::session::crypto::{CryptoError, SessionCrypto};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

/// Codec for the bindings column on a device row.
///
/// Serialises `Vec<DeviceBinding>` with `rmp-serde` (MessagePack) and
/// optionally encrypts with AES-256-GCM. The encrypted output is then
/// base64-encoded so the column stays TEXT: same shape as the
/// session store, intentionally.
///
/// `SessionCrypto` is reused as a *generic* AES-256-GCM envelope
/// primitive. The "session" prefix in its name is historical; the
/// implementation has no session-specific behaviour. Renaming to
/// `EnvelopeCrypto` is a separate refactor (would touch every
/// session-store call site).
#[derive(Clone)]
pub(crate) struct BindingsCodec {
    crypto: Option<SessionCrypto>,
}

impl BindingsCodec {
    pub fn encrypted(crypto: SessionCrypto) -> Self {
        Self {
            crypto: Some(crypto),
        }
    }

    pub fn plaintext() -> Self {
        Self { crypto: None }
    }

    /// Serialise (and optionally encrypt) the bindings vector.
    pub fn encode(&self, bindings: &[DeviceBinding]) -> Result<String, SqlDeviceStoreError> {
        let bytes = rmp_serde::to_vec_named(bindings)?;
        let payload = match &self.crypto {
            Some(crypto) => crypto.encrypt(&bytes)?,
            None => bytes,
        };
        Ok(BASE64.encode(payload))
    }

    /// Deserialise (and optionally decrypt) the bindings vector.
    /// Empty input is treated as `Vec::new()` so legacy NULL columns
    /// or rows written before the bindings column existed still load.
    pub fn decode(&self, stored: &str) -> Result<Vec<DeviceBinding>, SqlDeviceStoreError> {
        if stored.is_empty() {
            return Ok(Vec::new());
        }
        let payload = BASE64
            .decode(stored)
            .map_err(|_| SqlDeviceStoreError::Crypto(CryptoError))?;
        let plaintext = match &self.crypto {
            Some(crypto) => crypto.decrypt(&payload)?,
            None => payload,
        };
        Ok(rmp_serde::from_slice(&plaintext)?)
    }
}

/// Wire-form trust-level identifiers persisted in the `trust_level`
/// column. Stable across schema changes: bump the schema version
/// before changing these.
pub(crate) mod trust_level_codec {
    use crate::device::types::DeviceTrustLevel;

    pub fn to_str(level: DeviceTrustLevel) -> &'static str {
        match level {
            DeviceTrustLevel::Unknown => "Unknown",
            DeviceTrustLevel::Seen => "Seen",
            DeviceTrustLevel::Trusted => "Trusted",
            DeviceTrustLevel::Revoked => "Revoked",
        }
    }

    pub fn from_str(s: &str) -> Option<DeviceTrustLevel> {
        match s {
            "Unknown" => Some(DeviceTrustLevel::Unknown),
            "Seen" => Some(DeviceTrustLevel::Seen),
            "Trusted" => Some(DeviceTrustLevel::Trusted),
            "Revoked" => Some(DeviceTrustLevel::Revoked),
            _ => None,
        }
    }
}

/// Errors from SQL-backed device stores.
///
/// Same shape as [`SqlStoreError`](crate::session::storage::session_codec::SqlStoreError)
/// Distinct type so the device-store error surface doesn't widen
/// when the session-store one does (and vice versa).
#[derive(Debug, thiserror::Error)]
pub enum SqlDeviceStoreError {
    /// Underlying database driver returned an error.
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),

    /// MessagePack encoding of the bindings vector failed.
    #[error("device-bindings MessagePack encoding failed: {0}")]
    Encode(#[from] rmp_serde::encode::Error),

    /// MessagePack decoding of a stored bindings blob failed.
    #[error("device-bindings MessagePack decoding failed: {0}")]
    Decode(#[from] rmp_serde::decode::Error),

    /// AES-256-GCM encryption or decryption of the bindings blob failed.
    #[error("encryption/decryption error: {0}")]
    Crypto(#[from] CryptoError),

    /// Stored row carried a trust-level string the codec doesn't
    /// recognise. Indicates schema drift (a future trust level was
    /// written by a newer process and an older one is now reading it).
    #[error("unrecognised trust_level value: {0}")]
    UnknownTrustLevel(String),

    /// Stored row carried a value that couldn't be parsed into the
    /// expected newtype (e.g. `tenant_id` / `device_id` validation
    /// rejected the bytes). Indicates row corruption: the value was
    /// either written by a buggy producer or hand-edited.
    #[error("malformed stored value: {0}")]
    MalformedRow(String),
}

#[cfg(test)]
mod device_sql_common_tests {
    use super::*;
    use crate::device::types::{
        AttestationClass, DeviceBinding, DeviceTrustLevel, FingerprintHash,
    };
    use chrono::Utc;

    /// line 68: `decode -> Ok(vec![])` body replacement.
    /// Discriminator: encode a non-empty bindings vector and confirm
    /// decode round-trips the same content. Mutation returns an empty
    /// Vec for any non-empty input.
    #[test]
    fn bindings_codec_round_trips_non_empty_vector() {
        let codec = BindingsCodec::plaintext();
        let now = Utc::now();
        let bindings = vec![
            DeviceBinding::Cookie {
                token_hash: FingerprintHash::from_bytes([0xAA; 32]),
                issued_at: now,
                last_used_at: now,
            },
            DeviceBinding::WebAuthn {
                credential_id: "cred-AX028".to_string(),
                attestation_class: AttestationClass::None,
                bound_at: now,
                last_used_at: now,
            },
        ];
        let encoded = codec.encode(&bindings).expect("encode");
        let decoded = codec.decode(&encoded).expect("decode");
        assert_eq!(
            decoded.len(),
            2,
            "decode must round-trip 2 bindings, not return empty"
        );
        assert_eq!(decoded, bindings, "round-trip must preserve content");
    }

    /// line 89: `to_str` body replacement (`""`, `"xyzzy"`).
    /// Pin every variant's wire-form value.
    #[test]
    fn trust_level_to_str_pins_variant_strings() {
        assert_eq!(
            trust_level_codec::to_str(DeviceTrustLevel::Unknown),
            "Unknown"
        );
        assert_eq!(trust_level_codec::to_str(DeviceTrustLevel::Seen), "Seen");
        assert_eq!(
            trust_level_codec::to_str(DeviceTrustLevel::Trusted),
            "Trusted"
        );
        assert_eq!(
            trust_level_codec::to_str(DeviceTrustLevel::Revoked),
            "Revoked"
        );
    }

    /// line 98 + 99-102: `from_str` body replacement and arm
    /// deletions. Each variant string must round-trip; an unknown
    /// string must yield None.
    #[test]
    fn trust_level_from_str_round_trips_each_variant() {
        assert_eq!(
            trust_level_codec::from_str("Unknown"),
            Some(DeviceTrustLevel::Unknown)
        );
        assert_eq!(
            trust_level_codec::from_str("Seen"),
            Some(DeviceTrustLevel::Seen)
        );
        assert_eq!(
            trust_level_codec::from_str("Trusted"),
            Some(DeviceTrustLevel::Trusted)
        );
        assert_eq!(
            trust_level_codec::from_str("Revoked"),
            Some(DeviceTrustLevel::Revoked)
        );
        assert_eq!(
            trust_level_codec::from_str("not-a-level"),
            None,
            "unknown input must yield None, not Some(Default)"
        );
    }

    /// Belt-and-suspenders: `to_str` and `from_str` form a
    /// bijection on the four variants. Pins both directions in one go.
    #[test]
    fn trust_level_codec_is_a_bijection_on_known_variants() {
        for level in [
            DeviceTrustLevel::Unknown,
            DeviceTrustLevel::Seen,
            DeviceTrustLevel::Trusted,
            DeviceTrustLevel::Revoked,
        ] {
            let s = trust_level_codec::to_str(level);
            assert_eq!(
                trust_level_codec::from_str(s),
                Some(level),
                "{level:?} must round-trip via to_str/from_str"
            );
        }
    }
}
