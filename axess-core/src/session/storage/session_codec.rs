//! Shared codec for backend session stores (SQLite, PostgreSQL, Valkey).
//!
//! Extracts the encode/decode/expiry logic that is identical across backends.
//! Each backend still owns its own `SessionStore` impl because the storage
//! shape differs (SQL dialect quirks; key-value semantics), but the session-
//! data serialization and crypto layer is shared here.

// base64 + Duration only feed the SQL-side helpers (encode/decode/expires_at);
// gate behind the SQL backend features so a valkey-only build doesn't
// surface them as unused-import warnings.
#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use crate::session::{crypto::SessionCrypto, data::SessionData};

#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
use std::time::Duration;

/// Shared session-data codec (MessagePack + optional AES-256-GCM encryption).
///
/// Used by [`SqliteSessionStore`](super::sqlite::SqliteSessionStore),
/// [`PostgresSessionStore`](super::postgres::PostgresSessionStore), and
/// [`ValkeySessionStore`](super::valkey::ValkeySessionStore). SQL backends
/// use the base64-TEXT path (`encode` / `decode`); Valkey uses the raw-bytes
/// path (`encode_bytes` / `decode_bytes`).
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

    /// Serialize (and optionally encrypt) session data for storage.
    ///
    /// Payload is encoded with `rmp-serde` (MessagePack) to
    /// match the Valkey backend and to avoid the JSON-tag rewrite of
    /// the full `AuthState` on every save. The Valkey store already
    /// uses MessagePack; moving SQL to the same codec drops a layer
    /// of "JSON-only here" branching at no public-API cost. Output
    /// is always base64-encoded so the column stays TEXT (no schema
    /// migration), with format detection on read for migration from
    /// the historical JSON wire form. SQL-only; Valkey uses
    /// [`encode_bytes`](Self::encode_bytes) for the raw-bytes path.
    #[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
    pub fn encode(&self, data: &SessionData) -> Result<String, SqlStoreError> {
        let bytes = rmp_serde::to_vec_named(data)?;
        let payload = match &self.crypto {
            Some(crypto) => crypto.encrypt(&bytes)?,
            None => bytes,
        };
        Ok(BASE64.encode(payload))
    }

    /// Deserialize (and optionally decrypt) session data from storage.
    ///
    /// Reads both the new MessagePack wire form and legacy JSON rows.
    /// New writes are always MessagePack; legacy rows remain readable
    /// until they expire and are overwritten. SQL-only; Valkey uses
    /// [`decode_bytes`](Self::decode_bytes) for the raw-bytes path.
    #[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
    pub fn decode(&self, stored: &str) -> Result<SessionData, SqlStoreError> {
        // Plaintext-legacy fast path: a JSON object always starts with
        // `{`, which is never a valid base64 character. If we see one,
        // we know we are reading a pre-MessagePack plaintext row; decode
        // it as JSON and return.
        if self.crypto.is_none() && stored.starts_with('{') {
            return Ok(serde_json::from_str(stored)?);
        }

        let payload = BASE64
            .decode(stored)
            .map_err(|_| SqlStoreError::Crypto(crate::session::crypto::CryptoError))?;
        self.decode_bytes(&payload)
    }

    /// Serialize (and optionally encrypt) session data for binary
    /// storage; no base64 wrap.
    ///
    /// Provided for the Valkey backend (which stores raw bytes)
    /// so all three encrypted backends share one codec rather than each
    /// re-implementing the rmp-serde + AES-GCM dance. The SQL backends
    /// continue to use [`encode`](Self::encode) which base64-wraps the
    /// output for TEXT-column storage.
    #[cfg(feature = "valkey")]
    pub fn encode_bytes(&self, data: &SessionData) -> Result<Vec<u8>, SqlStoreError> {
        let bytes = rmp_serde::to_vec_named(data)?;
        Ok(match &self.crypto {
            Some(crypto) => crypto.encrypt(&bytes)?,
            None => bytes,
        })
    }

    /// Deserialize (and optionally decrypt) session data from binary
    /// storage; no base64 wrap.
    ///
    /// Counterpart to [`encode_bytes`](Self::encode_bytes).
    /// Tries MessagePack first; falls back to JSON to tolerate legacy
    /// blobs that adopters may still have in storage from before the
    /// MessagePack switch.
    pub fn decode_bytes(&self, payload: &[u8]) -> Result<SessionData, SqlStoreError> {
        let plaintext = match &self.crypto {
            Some(crypto) => crypto.decrypt(payload)?,
            None => payload.to_vec(),
        };
        match rmp_serde::from_slice(&plaintext) {
            Ok(data) => Ok(data),
            Err(_) => Ok(serde_json::from_slice(&plaintext)?),
        }
    }
}

/// Compute the `expires_at` Unix timestamp from the current time and a TTL.
/// SQL-only; Valkey delegates TTL enforcement to the server (`EXPIRE`).
#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
pub(crate) fn expires_at(clock: &dyn axess_clock::Clock, ttl: Duration) -> i64 {
    clock
        .now()
        .timestamp()
        .saturating_add(ttl.as_secs().min(i64::MAX as u64) as i64)
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
    #[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),

    /// JSON deserialisation of a stored row failed. Either a legacy
    /// row whose JSON is corrupt, or a backend wire-format drift bug.
    #[error("session JSON deserialisation failed: {0}")]
    Serialization(#[from] serde_json::Error),

    /// MessagePack encoding of `SessionData` failed. Distinct
    /// from `Serialization` (which is JSON-only) so the variant
    /// reflects the actual codec in use on the write path.
    #[error("session MessagePack encoding failed: {0}")]
    Encode(#[from] rmp_serde::encode::Error),

    /// MessagePack decoding of a stored row failed AFTER
    /// the JSON-fallback path also rejected the bytes. Indicates true
    /// row corruption rather than a routine format-detection miss.
    #[error("session MessagePack decoding failed: {0}")]
    Decode(#[from] rmp_serde::decode::Error),

    /// AES-256-GCM encryption or decryption of session payload failed.
    #[error("encryption/decryption error: {0}")]
    Crypto(#[from] crate::session::crypto::CryptoError),
}
