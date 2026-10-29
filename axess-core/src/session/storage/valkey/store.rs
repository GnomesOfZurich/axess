//! Valkey-backed [`SessionStore`] implementation.
//!
//! See the [module-level docs](super) for the encryption-at-rest
//! contract, key layout, and adopter-facing usage examples.

use super::encryption::{encrypted_codec, encrypted_codec_with_rotation, plaintext_codec};
use super::internal::{
    COMPARE_SET_SCRIPT, CYCLE_SCRIPT, DEFAULT_MAX_PAYLOAD_BYTES, DEFAULT_PREFIX, RESEAL_SCRIPT,
    ValkeyStoreError, ex_seconds, expired_cycle_outcome, script_unavailable, session_key,
};
use crate::session::{
    data::SessionData,
    id::SessionId,
    storage::session_codec::SessionCodec,
    store::{ConditionalUpdate, CycleOutcome, SessionStore},
};
use fred::bytes::Bytes;
use fred::prelude::*;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};

// ── ValkeySessionStore ───────────────────────────────────────────────────────

/// Valkey-backed session store with optional AES-256-GCM encryption at rest.
///
/// Session data is serialized with MessagePack and optionally encrypted before
/// storage. TTL is managed by Valkey-native key expiry.
/// Clone is cheap: the inner client and keys are `Arc`-based.
#[derive(Clone)]
pub struct ValkeySessionStore {
    pub(super) client: Client,
    prefix: Arc<str>,
    /// Shared session codec: handles MessagePack serialization and
    /// optional AES-256-GCM encryption uniformly across SQL and Valkey
    /// backends.
    codec: SessionCodec,
    /// Maximum encoded payload size in bytes. Prevents unbounded session
    /// growth from consuming Valkey memory.
    max_payload_bytes: usize,
}

impl ValkeySessionStore {
    /// Create an **encrypted** store using AES-256-GCM (recommended for production).
    ///
    /// All session data is encrypted before writing to Valkey and decrypted on
    /// read. The 32-byte key should be loaded from a secret store and persisted
    /// across restarts.
    pub fn new(client: Client, key: [u8; 32]) -> Self {
        Self {
            client,
            prefix: DEFAULT_PREFIX.into(),
            codec: encrypted_codec(key),
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
        }
    }

    /// Create a **plaintext** store (development/testing only).
    ///
    /// Session data is stored unencrypted in Valkey. Do not use in production.
    pub fn plaintext(client: Client) -> Self {
        tracing::warn!(
            "ValkeySessionStore created without encryption: \
             do not use in production"
        );
        Self {
            client,
            prefix: DEFAULT_PREFIX.into(),
            codec: plaintext_codec(),
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
        }
    }

    /// Create an **encrypted** store using AES-256-GCM.
    ///
    /// Alias for [`new`](ValkeySessionStore::new).
    pub fn encrypted(client: Client, key: [u8; 32]) -> Self {
        Self::new(client, key)
    }

    /// Create an **encrypted** store with key rotation support.
    ///
    /// Writes always use `current_key`. Reads try `current_key` first; if
    /// decryption fails, they retry with `previous_key`. This allows
    /// zero-downtime key rotation: deploy the new key as `current`, keep the
    /// old key as `previous` until all sessions have been naturally refreshed
    /// (i.e. one full TTL window), then remove the previous key.
    pub fn encrypted_with_rotation(
        client: Client,
        current_key: [u8; 32],
        previous_key: [u8; 32],
    ) -> Self {
        Self {
            client,
            prefix: DEFAULT_PREFIX.into(),
            codec: encrypted_codec_with_rotation(current_key, previous_key),
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
        }
    }

    /// Override the key prefix (default: `"axess"`).
    ///
    /// Use this to namespace sessions per tenant or application when multiple
    /// services share the same Valkey instance. For multi-tenant setups,
    /// include the tenant ID in the prefix (e.g. `"axess:tenant_abc"`).
    pub fn with_prefix(mut self, prefix: impl Into<Arc<str>>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// Override the maximum encoded payload size (default: 64 KiB).
    ///
    /// Encoded size is checked after serialization (and encryption, if enabled)
    /// but before writing to Valkey. This protects against unbounded growth of
    /// `SessionData.custom`.
    pub fn with_max_payload(mut self, max_bytes: usize) -> Self {
        self.max_payload_bytes = max_bytes;
        self
    }

    /// Serialize (and optionally encrypt) session data for storage.
    ///
    /// Delegates the MessagePack + AES-GCM round-trip to the shared
    /// [`SessionCodec`], then enforces the Valkey-specific
    /// `max_payload_bytes` cap on the encoded bytes.
    pub(super) fn encode(
        &self,
        id: &SessionId,
        data: &SessionData,
    ) -> Result<Vec<u8>, ValkeyStoreError> {
        let encoded = self.codec.encode_bytes(id, data)?;

        if encoded.len() > self.max_payload_bytes {
            warn!(
                size = encoded.len(),
                max = self.max_payload_bytes,
                "session payload exceeds maximum allowed size"
            );
            return Err(ValkeyStoreError::PayloadTooLarge {
                size: encoded.len(),
                max: self.max_payload_bytes,
            });
        }

        Ok(encoded)
    }

    /// Deserialize (and optionally decrypt) session data from storage.
    ///
    /// Delegates to the shared [`SessionCodec`]. The load path calls the
    /// codec directly so it can re-seal a stale blob.
    #[cfg(test)]
    pub(super) fn decode(
        &self,
        id: &SessionId,
        bytes: &[u8],
    ) -> Result<SessionData, ValkeyStoreError> {
        Ok(self.codec.decode_bytes(id, bytes)?)
    }

    /// Choose whether blobs written before row binding are read; see
    /// [`LegacyBlobs`](crate::session::crypto::LegacyBlobs). The default is
    /// to read them and re-seal each on load. Has no effect on a plaintext
    /// store.
    pub fn with_legacy_blobs(mut self, policy: crate::session::crypto::LegacyBlobs) -> Self {
        self.codec = self.codec.with_legacy_blobs(policy);
        self
    }

    /// Re-seal a blob that was read without the current row binding. Best
    /// effort and conditional on the key still holding the bytes that were
    /// read (so a save that landed meanwhile is kept); the key keeps its
    /// expiry. Without scripting the blob is re-sealed by its next save.
    async fn reseal(&self, id: &SessionId, old: &[u8], data: &SessionData) {
        let key = session_key(&self.prefix, id);
        let sealed = match self.encode(id, data) {
            Ok(sealed) => sealed,
            Err(e) => {
                warn!(error = %e, "could not re-seal a stale session blob");
                return;
            }
        };
        let result: Result<i64, _> = self
            .client
            .eval(
                RESEAL_SCRIPT,
                vec![key],
                vec![
                    Value::Bytes(Bytes::from(old.to_vec())),
                    Value::Bytes(Bytes::from(sealed)),
                ],
            )
            .await;
        if let Err(e) = result {
            warn!(error = %e, "could not re-seal a stale session blob");
        }
    }
}

impl SessionStore for ValkeySessionStore {
    type Error = ValkeyStoreError;

    async fn load(&self, id: &SessionId) -> Result<Option<SessionData>, Self::Error> {
        let key = session_key(&self.prefix, id);
        let bytes: Option<Vec<u8>> = self.client.get(&key).await?;
        match bytes {
            Some(b) => {
                let (data, stale) = self.codec.decode_bytes_checked(id, &b)?;
                if stale {
                    self.reseal(id, &b, &data).await;
                }
                debug!(session_id = %id, "session loaded from valkey");
                Ok(Some(data))
            }
            None => {
                debug!(session_id = %id, "session not found in valkey");
                Ok(None)
            }
        }
    }

    async fn save(
        &self,
        id: &SessionId,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<(), Self::Error> {
        let key = session_key(&self.prefix, id);
        let bytes = self.encode(id, data)?;
        let Some(ex) = ex_seconds(ttl) else {
            // Already expired: nothing may be stored, and a previous value
            // under this id must not outlive the expiry it was just given.
            self.client.del::<(), _>(&key).await?;
            return Ok(());
        };
        self.client
            .set::<(), _, _>(&key, bytes, Some(Expiration::EX(ex)), None, false)
            .await?;
        debug!(session_id = %id, ttl_secs = ttl.as_secs(), "session saved to valkey");
        Ok(())
    }

    async fn delete(&self, id: &SessionId) -> Result<(), Self::Error> {
        let key = session_key(&self.prefix, id);
        self.client.del::<(), _>(&key).await?;
        debug!(session_id = %id, "session deleted from valkey");
        Ok(())
    }

    async fn update(
        &self,
        id: &SessionId,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<bool, Self::Error> {
        let key = session_key(&self.prefix, id);
        let bytes = self.encode(id, data)?;
        let Some(ex) = ex_seconds(ttl) else {
            // Already expired: nothing may stay stored under this id.
            self.client.del::<(), _>(&key).await?;
            return Ok(false);
        };
        // `SET ... XX` writes only while the key exists, so a session deleted
        // since the caller loaded it is not brought back.
        let written: Option<String> = self
            .client
            .set(
                &key,
                bytes,
                Some(Expiration::EX(ex)),
                Some(SetOptions::XX),
                false,
            )
            .await?;
        Ok(written.is_some())
    }

    async fn update_if_revision(
        &self,
        id: &SessionId,
        expected_revision: u64,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<ConditionalUpdate, Self::Error> {
        let key = session_key(&self.prefix, id);
        let Some(old): Option<Vec<u8>> = self.client.get(&key).await? else {
            return Ok(ConditionalUpdate::Gone);
        };
        let (stored, _) = self.codec.decode_bytes_checked(id, &old)?;
        if stored.revision != expected_revision {
            return Ok(ConditionalUpdate::Conflict);
        }
        let Some(ex) = ex_seconds(ttl) else {
            // Already expired: nothing loadable may be stored.
            return Ok(ConditionalUpdate::Gone);
        };
        let bytes = self.encode(id, data)?;
        // The script writes only while the key still holds the bytes that
        // were compared. A deployment without scripting returns the error
        // rather than a weaker compare: the caller then fails closed.
        let swapped: i64 = self
            .client
            .eval(
                COMPARE_SET_SCRIPT,
                vec![key],
                vec![
                    Value::Bytes(Bytes::from(old)),
                    Value::Bytes(Bytes::from(bytes)),
                    Value::Integer(ex),
                ],
            )
            .await?;
        Ok(match swapped {
            1 => ConditionalUpdate::Written,
            0 => ConditionalUpdate::Conflict,
            _ => ConditionalUpdate::Gone,
        })
    }

    async fn cycle(
        &self,
        old_id: &SessionId,
        new_id: &SessionId,
        data: &SessionData,
        ttl: Duration,
        require_old: bool,
    ) -> Result<CycleOutcome, Self::Error> {
        let old_key = session_key(&self.prefix, old_id);
        let new_key = session_key(&self.prefix, new_id);
        let bytes = self.encode(new_id, data)?;
        let Some(ex) = ex_seconds(ttl) else {
            // The rotated session is already expired: store nothing and let
            // the old one go with it.
            let removed: i64 = self.client.del(&old_key).await?;
            return Ok(expired_cycle_outcome(require_old, removed));
        };

        // One server-side script removes the old key and writes the new one,
        // deciding on the DEL's count whether the old session was live.
        let scripted: Result<i64, _> = self
            .client
            .eval(
                CYCLE_SCRIPT,
                vec![old_key.clone(), new_key.clone()],
                vec![
                    Value::Bytes(Bytes::from(bytes.clone())),
                    Value::Integer(ex),
                    Value::from(if require_old { "1" } else { "0" }),
                ],
            )
            .await;
        match scripted {
            Ok(0) => return Ok(CycleOutcome::SessionGone),
            Ok(_) => {}
            Err(e) if script_unavailable(&e) => {
                // Scripting is unavailable here (disabled, or the two keys
                // hash to different cluster slots). Fall back to the
                // sequenced form: the old key is deleted first because its
                // count decides whether the session was live, then the new
                // key is written. A failed SET after the DEL leaves the user
                // signed out, which the layer's fail-closed path wants anyway;
                // a crash between the calls leaves neither key. (MULTI/EXEC
                // is no substitute: the server runs every queued command even
                // when an earlier one fails.)
                warn!(error = %e, "session cycle script unavailable; using DEL then SET");
                if old_key != new_key {
                    let removed: i64 = self.client.del(&old_key).await?;
                    if require_old && removed == 0 {
                        return Ok(CycleOutcome::SessionGone);
                    }
                    self.client
                        .set::<(), _, _>(&new_key, bytes, Some(Expiration::EX(ex)), None, false)
                        .await?;
                } else {
                    let options = require_old.then_some(SetOptions::XX);
                    let written: Option<String> = self
                        .client
                        .set(&new_key, bytes, Some(Expiration::EX(ex)), options, false)
                        .await?;
                    if require_old && written.is_none() {
                        return Ok(CycleOutcome::SessionGone);
                    }
                }
            }
            Err(e) => return Err(e.into()),
        }

        debug!(
            old_session_id = %old_id,
            new_session_id = %new_id,
            ttl_secs = ex,
            "session cycled in valkey"
        );
        Ok(CycleOutcome::Rotated)
    }

    /// Valkey/Redis evicts expired keys natively (active +
    /// passive expiry, see Redis docs §EXPIRE). There is nothing for
    /// the application to sweep; the server already does it. This
    /// returns `Ok(0)` deliberately, not as the "unsupported" sentinel
    /// the trait once defaulted to.
    async fn prune_expired(&self) -> Result<u64, Self::Error> {
        Ok(0)
    }
}

// ── HealthCheck ──────────────────────────────────────────────────────────────

use crate::health::{HealthCheck, HealthStatus};
use std::future::Future;
use std::pin::Pin;

/// Health check timeout for Valkey PING operations.
const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(2);

impl HealthCheck for ValkeySessionStore {
    fn check(&self) -> Pin<Box<dyn Future<Output = HealthStatus> + Send + '_>> {
        Box::pin(async {
            match tokio::time::timeout(HEALTH_CHECK_TIMEOUT, self.client.ping::<String>(None)).await
            {
                Ok(Ok(_)) => HealthStatus::Healthy,
                Ok(Err(e)) => HealthStatus::Unhealthy(format!("valkey PING failed: {e}")),
                Err(_) => HealthStatus::Unhealthy("valkey PING timeout (2s)".into()),
            }
        })
    }
}

// ── Store<SessionId, SessionData> ────────────────────────────────────────────
//
// surface: see the same impl on `SqliteSessionStore` for rationale.
// `Store::prune_expired` returns `Ok(0)` deliberately: Valkey's native
// passive + active key expiry already evicts; the trait doc records this
// as a documented no-op for backends with server-side TTL.

impl crate::store::Store<SessionId, SessionData> for ValkeySessionStore {
    type Error = ValkeyStoreError;

    fn get(
        &self,
        key: &SessionId,
    ) -> impl Future<Output = Result<Option<SessionData>, Self::Error>> + Send {
        <Self as SessionStore>::load(self, key)
    }

    fn put(
        &self,
        key: &SessionId,
        value: &SessionData,
        ttl: Duration,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        <Self as SessionStore>::save(self, key, value, ttl)
    }

    fn delete(&self, key: &SessionId) -> impl Future<Output = Result<(), Self::Error>> + Send {
        <Self as SessionStore>::delete(self, key)
    }

    fn prune_expired(&self) -> impl Future<Output = Result<u64, Self::Error>> + Send {
        <Self as SessionStore>::prune_expired(self)
    }
}
