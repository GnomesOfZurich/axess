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

use crate::session::{
    crypto::{BoundFormat, SessionCrypto},
    data::SessionData,
    id::SessionId,
};

#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
use std::time::Duration;

/// Shared session-data codec (MessagePack + optional AES-256-GCM encryption).
///
/// # Encrypted blob format and binding to the session id
///
/// An encrypted blob is `AXS 0x01 || nonce(12) || ciphertext+tag`. The
/// four marker bytes are `0x41 0x58 0x53 0x01`. The AES-256-GCM additional
/// authenticated data is exactly
/// `"axess.session.v1" || 0x00 || session_id_uuid_bytes(16)`. The id is not
/// stored in the blob; it is supplied again on every read, so an encrypted
/// stored value copied from one row into a row with a different id fails
/// authentication instead of decrypting under the new id.
///
/// A blob that carries the marker is opened under the bound AAD. A blob
/// without the marker predates this format (random nonce first, empty AAD)
/// and is opened under the empty AAD only when the
/// [`LegacyBlobs`](crate::session::crypto::LegacyBlobs) policy reads such
/// blobs. A pre-binding nonce that happens to begin with the four marker
/// bytes (probability 2^-32 per legacy row) is tried as a pre-binding blob
/// after the bound open fails, under a policy that reads them; under the
/// default policy such a row is refused and the user signs in again.
///
/// # Upgrade path
///
/// The default policy refuses a blob without a binding, which opens under
/// any session id. A deployment that still holds pre-binding rows sets
/// [`LegacyBlobs::AcceptUntil`](crate::session::crypto::LegacyBlobs::AcceptUntil)
/// for one session lifetime: reads then accept both formats and the store
/// that read a pre-binding row re-seals it in the bound format right away (a
/// conditional write that keeps the row's expiry and never overwrites a
/// newer save); every write (`save`, `update`, `cycle`) seals the bound
/// format too. Session data carries no session id, so the cutoff is the only
/// protection against a moved legacy row. Plaintext codecs have nothing to
/// bind.
///
/// Used by [`SqliteSessionStore`](super::sqlite::SqliteSessionStore),
/// [`PostgresSessionStore`](super::postgres::PostgresSessionStore), and
/// [`ValkeySessionStore`](super::valkey::ValkeySessionStore). SQL backends
/// store the raw bytes (`encode_bytes`) in a binary column and read legacy
/// base64 text rows through `decode_row`; Valkey uses the raw-bytes path
/// (`encode_bytes` / `decode_bytes`).
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

    /// Apply a [`LegacyBlobs`] choice to the codec's crypto. A plaintext
    /// codec has nothing to refuse and is returned unchanged.
    #[cfg(feature = "valkey")]
    pub fn with_legacy_blobs(mut self, policy: crate::session::crypto::LegacyBlobs) -> Self {
        self.crypto = self.crypto.map(|c| c.with_legacy_blobs(policy));
        self
    }

    /// The legacy text form of a stored value: base64 of
    /// [`encode_bytes`](Self::encode_bytes). Production writes use the
    /// binary column; this exists so tests can plant rows as an earlier
    /// release wrote them.
    #[cfg(all(test, feature = "sqlite"))]
    pub fn encode_text(&self, id: &SessionId, data: &SessionData) -> Result<String, SqlStoreError> {
        Ok(BASE64.encode(self.encode_bytes(id, data)?))
    }

    /// Decode a SQL row: the binary column when it holds a value, the legacy
    /// base64 text column otherwise. A row an earlier release wrote has only
    /// the text; every save writes the binary column and empties the text.
    ///
    /// The flag says the row is stale: its blob lacks the current row
    /// binding, or it still lives in the legacy text column. The SQL stores
    /// re-seal a stale row on load.
    #[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
    pub fn decode_row(
        &self,
        id: &SessionId,
        binary: Option<&[u8]>,
        text: &str,
    ) -> Result<(SessionData, bool), SqlStoreError> {
        match binary {
            Some(bytes) => self.decode_bytes_checked(id, bytes),
            None => {
                let (data, _) = self.decode_text(id, text)?;
                Ok((data, true))
            }
        }
    }

    #[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
    fn decode_text(
        &self,
        id: &SessionId,
        stored: &str,
    ) -> Result<(SessionData, bool), SqlStoreError> {
        // Plaintext-legacy fast path: a JSON object always starts with
        // `{`, which is never a valid base64 character. If we see one,
        // we know we are reading a pre-MessagePack plaintext row; decode
        // it as JSON and return.
        if self.crypto.is_none() && stored.starts_with('{') {
            return Ok((serde_json::from_str(stored)?, true));
        }

        let payload = BASE64
            .decode(stored)
            .map_err(|_| SqlStoreError::Crypto(crate::session::crypto::CryptoError))?;
        self.decode_bytes_checked(id, &payload)
    }

    /// Serialize (and optionally encrypt) session data for binary
    /// storage; no base64 wrap.
    ///
    /// Every backend writes this form: the SQL stores into their binary
    /// column, Valkey as the value.
    pub fn encode_bytes(
        &self,
        id: &SessionId,
        data: &SessionData,
    ) -> Result<Vec<u8>, SqlStoreError> {
        let bytes = rmp_serde::to_vec_named(data)?;
        Ok(match &self.crypto {
            Some(crypto) => crypto.seal_bound(BoundFormat::SESSION, id.as_bytes(), &bytes)?,
            None => bytes,
        })
    }

    /// Deserialize (and optionally decrypt) session data from binary
    /// storage; no base64 wrap.
    ///
    /// Counterpart to [`encode_bytes`](Self::encode_bytes).
    /// Tries MessagePack first; falls back to JSON to tolerate legacy
    /// blobs that adopters may still have in storage from before the
    /// MessagePack switch. Production reads use
    /// [`decode_bytes_checked`](Self::decode_bytes_checked), which also
    /// reports whether the blob needs re-sealing.
    #[cfg(test)]
    pub fn decode_bytes(
        &self,
        id: &SessionId,
        payload: &[u8],
    ) -> Result<SessionData, SqlStoreError> {
        Ok(self.decode_bytes_checked(id, payload)?.0)
    }

    /// [`decode_bytes`](Self::decode_bytes) plus whether the blob is stale:
    /// sealed without the row binding of the current format. A stale blob is
    /// re-sealed by the store that read it ([`encode_bytes`](Self::encode_bytes)
    /// writes the current format).
    pub fn decode_bytes_checked(
        &self,
        id: &SessionId,
        payload: &[u8],
    ) -> Result<(SessionData, bool), SqlStoreError> {
        let opened;
        let mut stale = false;
        let plaintext: &[u8] = match &self.crypto {
            Some(crypto) => {
                opened = crypto.open_bound(BoundFormat::SESSION, id.as_bytes(), &[], payload)?;
                stale = opened.stale;
                &opened.plaintext
            }
            None => payload,
        };
        let data = match rmp_serde::from_slice(plaintext) {
            Ok(data) => data,
            Err(_) => serde_json::from_slice(plaintext)?,
        };
        Ok((data, stale))
    }
}

/// Compute the `expires_at` Unix timestamp from the current time and a TTL.
/// SQL-only; Valkey delegates TTL enforcement to the server (`EXPIRE`).
///
/// The expiry is whole seconds, and a sub-second TTL is raised to one second
/// (as the Valkey store does), so any positive TTL leaves the row loadable
/// for at least a second (a row loads only while `expires_at` is after now).
/// A zero TTL gives `now`, a row that can never be loaded; the write paths
/// report that as an ended session.
#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
pub(crate) fn expires_at(clock: &dyn axess_clock::Clock, ttl: Duration) -> i64 {
    let secs = if ttl.is_zero() {
        0
    } else {
        ttl.as_secs().clamp(1, i64::MAX as u64) as i64
    };
    clock.now().timestamp().saturating_add(secs)
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

#[cfg(test)]
mod tests;
