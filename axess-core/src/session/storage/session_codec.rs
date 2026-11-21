//! Shared codec for backend session stores (SQLite, PostgreSQL, MySQL, Valkey).
//!
//! Extracts the encode/decode/expiry logic that is identical across backends.
//! Each backend still owns its own `SessionStore` impl because the storage
//! shape differs (SQL dialect quirks; key-value semantics), but the session-
//! data serialization and crypto layer is shared here.

// Duration only feeds the SQL-side expiry helper; gated behind the SQL
// backend features so a valkey-only build doesn't surface it as an unused
// import.
use crate::session::{
    crypto::{BoundFormat, SessionCrypto},
    data::{SESSION_DATA_VERSION, SessionData, stored_version},
    id::SessionKey,
};

#[cfg(any(
    feature = "sqlite",
    feature = "sqlite-unbundled",
    feature = "postgres",
    feature = "mysql"
))]
use std::time::Duration;

/// Shared session-data codec (MessagePack + optional AES-256-GCM encryption).
///
/// # Encrypted blob format and binding to the session's key
///
/// An encrypted blob is `AXS 0x82 || salt(16) || ciphertext+tag`, sealed
/// under a key derived for the record from the configured key, the salt
/// and the AAD, with a fixed nonce. The four marker bytes are
/// `0x41 0x58 0x53 0x82`. The AES-256-GCM additional authenticated data is
/// exactly `"axess.session.v2" || 0x00 || session_key_bytes(32)`. The key
/// is not stored in the blob; it is supplied again on every read, so an
/// encrypted stored value copied from one row into a row with a different
/// key fails authentication instead of decrypting under the new key.
///
/// # One form is read
///
/// A blob is opened through
/// [`SessionCrypto::open_current`](crate::session::crypto::SessionCrypto::open_current):
/// it must carry the marker and authenticate under the AAD of its own row.
/// Every other blob is refused whatever
/// [`LegacyBlobs`](crate::session::crypto::LegacyBlobs) policy the crypto
/// carries: the first session format (`AXS 0x81`, bound to the session id),
/// the direct layout under the configured key itself, and a blob with no
/// marker and no binding, which would open under any row. Sessions stored
/// by an earlier release are not carried over, so nothing is lost by
/// refusing them, and a deployment that reads legacy device blobs through
/// the same `SessionCrypto` does not thereby read a moved session.
///
/// A blob in the current form that only the previous key opened is re-sealed
/// under the current key by the store that reads it (a conditional write
/// that keeps the row's expiry and never overwrites a newer save). Plaintext
/// codecs have nothing to bind.
///
/// Used by [`SqliteSessionStore`](super::sqlite::SqliteSessionStore),
/// [`PostgresSessionStore`](super::postgres::PostgresSessionStore), and
/// [`ValkeySessionStore`](super::valkey::ValkeySessionStore). Every backend
/// stores the raw bytes ([`encode_bytes`](Self::encode_bytes)) and reads
/// them back ([`decode_bytes_checked`](Self::decode_bytes_checked)): the SQL
/// backends in their binary column, whose value
/// [`binary_column`](Self::binary_column) requires, Valkey as the value.
#[derive(Clone)]
pub(crate) struct SessionCodec {
    crypto: Option<SessionCrypto>,
}

impl SessionCodec {
    pub fn encrypted(crypto: SessionCrypto) -> Self {
        Self {
            crypto: Some(crypto),
        }
    }

    pub fn plaintext() -> Self {
        Self { crypto: None }
    }

    /// The value of a SQL row's binary column, which holds the stored
    /// session. A row whose binary column is NULL holds no session this
    /// release wrote (a row of an earlier release kept its session in the
    /// text column, which is not read) and is refused as undecodable.
    #[cfg(any(
        feature = "sqlite",
        feature = "sqlite-unbundled",
        feature = "postgres",
        feature = "mysql"
    ))]
    pub fn binary_column(binary: Option<Vec<u8>>) -> Result<Vec<u8>, SqlStoreError> {
        binary.ok_or_else(|| {
            SqlStoreError::Decode(serde::de::Error::custom(
                "the stored session has no value in its binary column",
            ))
        })
    }

    /// Serialize (and optionally encrypt) session data for binary
    /// storage; no base64 wrap.
    ///
    /// Every backend writes this form: the SQL stores into their binary
    /// column, Valkey as the value.
    pub fn encode_bytes(
        &self,
        key: &SessionKey,
        data: &SessionData,
    ) -> Result<Vec<u8>, SqlStoreError> {
        let bytes = rmp_serde::to_vec_named(data)?;
        Ok(match &self.crypto {
            Some(crypto) => crypto.seal_bound(BoundFormat::SESSION, key.as_bytes(), &bytes)?,
            None => bytes,
        })
    }

    /// [`encode_bytes`](Self::encode_bytes) refusing a payload over `max`
    /// bytes with [`SqlStoreError::PayloadTooLarge`]. The SQL stores write
    /// through this.
    #[cfg(any(
        feature = "sqlite",
        feature = "sqlite-unbundled",
        feature = "postgres",
        feature = "mysql"
    ))]
    pub fn encode_bytes_within(
        &self,
        key: &SessionKey,
        data: &SessionData,
        max: usize,
    ) -> Result<Vec<u8>, SqlStoreError> {
        let encoded = self.encode_bytes(key, data)?;
        if encoded.len() > max {
            tracing::warn!(
                size = encoded.len(),
                max,
                "session payload exceeds maximum allowed size"
            );
            return Err(SqlStoreError::PayloadTooLarge {
                size: encoded.len(),
                max,
            });
        }
        Ok(encoded)
    }

    /// Deserialize (and optionally decrypt) session data from binary
    /// storage; no base64 wrap.
    ///
    /// Counterpart to [`encode_bytes`](Self::encode_bytes): the session is
    /// read as MessagePack and as nothing else, so a blob in any other
    /// encoding is refused with [`SqlStoreError::Decode`]. Production reads
    /// use
    /// [`decode_bytes_checked`](Self::decode_bytes_checked), which also
    /// reports whether the blob needs re-sealing.
    #[cfg(test)]
    pub fn decode_bytes(
        &self,
        key: &SessionKey,
        payload: &[u8],
    ) -> Result<SessionData, SqlStoreError> {
        Ok(self.decode_bytes_checked(key, payload)?.data)
    }

    /// [`decode_bytes`](Self::decode_bytes) plus whether the store that read
    /// the blob should re-seal it ([`encode_bytes`](Self::encode_bytes) writes
    /// it under the current key): true for one case only, a blob in the
    /// current form that only the previous key opened, holding a row at or
    /// above the current schema version. A blob in any other form is not
    /// read at all.
    pub fn decode_bytes_checked(
        &self,
        key: &SessionKey,
        payload: &[u8],
    ) -> Result<Decoded, SqlStoreError> {
        let (data, reseal) = self.decode_payload(key, payload)?;
        Ok(Decoded { data, reseal })
    }

    /// Decrypt (when the codec encrypts) and deserialize a blob, and say
    /// whether only the previous key opened it.
    ///
    /// A sealed blob is opened in the current form only
    /// ([`SessionCrypto::open_current`](crate::session::crypto::SessionCrypto::open_current)),
    /// for every legacy policy: see the type's documentation.
    ///
    /// The session is MessagePack, the one encoding `encode_bytes` has
    /// written since 0.2.0; no second decoder is tried, so a payload that is
    /// not a MessagePack session (a JSON row of the 0.1.x line, plain or
    /// sealed, or one a hand-written tool made) fails with
    /// [`SqlStoreError::Decode`] and its user signs in again.
    ///
    /// The schema version is read first. A row below
    /// [`SESSION_DATA_VERSION`] is not decoded: it is handed up as its
    /// version alone ([`SessionData::below_version`]), for the session layer
    /// to count and refuse, and never re-sealed, so no store writes it back.
    fn decode_payload(
        &self,
        key: &SessionKey,
        payload: &[u8],
    ) -> Result<(SessionData, bool), SqlStoreError> {
        let opened;
        let mut under_previous_key = false;
        let plaintext: &[u8] = match &self.crypto {
            Some(crypto) => {
                opened = crypto.open_current(BoundFormat::SESSION, key.as_bytes(), payload)?;
                under_previous_key = opened.stale;
                &opened.plaintext
            }
            None => payload,
        };
        let version = stored_version(plaintext)?;
        if version < SESSION_DATA_VERSION {
            return Ok((SessionData::below_version(version), false));
        }
        let data = rmp_serde::from_slice(plaintext)?;
        Ok((data, under_previous_key))
    }
}

/// A stored session as a store read it.
pub(crate) struct Decoded {
    /// The session.
    pub data: SessionData,
    /// The store that read it should write it back in the current form
    /// ([`SessionCodec::encode_bytes`]) under the same revision, on the
    /// condition that the row still holds what was read.
    pub reseal: bool,
}

/// Compute the `expires_at` Unix timestamp from the current time and a TTL.
/// SQL-only; Valkey delegates TTL enforcement to the server (`EXPIRE`).
///
/// The expiry is whole seconds, and a sub-second TTL is raised to one second
/// (as the Valkey store does), so any positive TTL leaves the row loadable
/// for at least a second (a row loads only while `expires_at` is after now).
/// A zero TTL gives `now`, a row that can never be loaded, and the write
/// paths store nothing for it: `save` and `update` remove the row,
/// `update_if_revision` removes the row whose revision matched, and `cycle`
/// removes both rows; each reports the session gone or not kept (see the
/// trait's "Zero TTL" section).
#[cfg(any(
    feature = "sqlite",
    feature = "sqlite-unbundled",
    feature = "postgres",
    feature = "mysql"
))]
pub(crate) fn expires_at(clock: &dyn axess_clock::Clock, ttl: Duration) -> i64 {
    let secs = if ttl.is_zero() {
        0
    } else {
        ttl.as_secs().clamp(1, i64::MAX as u64) as i64
    };
    clock.now().unix_seconds().saturating_add(secs)
}

/// Shared error type for backend session stores.
///
/// The name is historical (originated when only SQL backends used it);
/// the codec methods used by Valkey return the same enum. Variants
/// that depend on a SQL driver (`Db`, backed by `sqlx::Error`) are
/// gated on the SQL backend features so a `--features valkey` build
/// without any of `sqlite` / `postgres` / `mysql` does not pull
/// `sqlx` into the dependency graph. The backend-specific error
/// aliases (`SqliteStoreError`, `PostgresStoreError`) are retained as
/// type aliases for backward compatibility.
#[derive(Debug, thiserror::Error)]
pub enum SqlStoreError {
    /// Underlying database driver returned an error. Only constructed
    /// by the SQL backends; gated out under valkey-only builds so the
    /// enum does not reference `sqlx::Error` when `sqlx` is not in
    /// the dep graph.
    #[cfg(any(
        feature = "sqlite",
        feature = "sqlite-unbundled",
        feature = "postgres",
        feature = "mysql"
    ))]
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),

    /// MessagePack encoding of `SessionData` failed.
    #[error("session MessagePack encoding failed: {0}")]
    Encode(#[from] rmp_serde::encode::Error),

    /// A stored row is not a session in the stored form: a SQL row with no
    /// value in its binary column, or bytes (opened first, when the codec
    /// encrypts) that are not a MessagePack session in the shape this
    /// release writes. MessagePack is the only encoding
    /// read; a row in any other one, such as JSON from the 0.1.x line, is
    /// refused with this error and loads no session.
    #[error("stored session decoding failed: {0}")]
    Decode(#[from] rmp_serde::decode::Error),

    /// AES-256-GCM encryption or decryption of session payload failed.
    #[error("encryption/decryption error: {0}")]
    Crypto(#[from] crate::session::crypto::CryptoError),

    /// The encoded session payload exceeds the store's maximum size
    /// (`with_max_payload`; 64 KiB by default).
    #[error("encoded session payload too large ({size} bytes, max {max} bytes)")]
    PayloadTooLarge {
        /// Encoded payload length in bytes.
        size: usize,
        /// Configured maximum payload length in bytes.
        max: usize,
    },

    /// The store cannot do what was asked; the text names the method.
    #[error("not supported by this store: {0}")]
    Unsupported(&'static str),
}

/// The default largest encoded session payload a store accepts: 64 KiB.
pub(crate) const DEFAULT_MAX_PAYLOAD_BYTES: usize = 64 * 1024;

#[cfg(test)]
mod tests;
