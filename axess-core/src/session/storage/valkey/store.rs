//! Valkey-backed [`SessionStore`] implementation.
//!
//! See the [module-level docs](super) for the encryption-at-rest
//! contract, key layout, and adopter-facing usage examples.

use super::encryption::{encrypted_codec, encrypted_codec_with_rotation, plaintext_codec};
use super::internal::{DEFAULT_MAX_PAYLOAD_BYTES, DEFAULT_PREFIX, ValkeyStoreError, session_key};
use crate::session::{
    data::SessionData, id::SessionId, storage::session_codec::SessionCodec, store::SessionStore,
};
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
    pub(super) fn encode(&self, data: &SessionData) -> Result<Vec<u8>, ValkeyStoreError> {
        let encoded = self.codec.encode_bytes(data)?;

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
    /// Delegates to the shared [`SessionCodec`].
    pub(super) fn decode(&self, bytes: &[u8]) -> Result<SessionData, ValkeyStoreError> {
        Ok(self.codec.decode_bytes(bytes)?)
    }
}

impl SessionStore for ValkeySessionStore {
    type Error = ValkeyStoreError;

    async fn load(&self, id: &SessionId) -> Result<Option<SessionData>, Self::Error> {
        let key = session_key(&self.prefix, id);
        let bytes: Option<Vec<u8>> = self.client.get(&key).await?;
        match bytes {
            Some(b) => {
                let data = self.decode(&b)?;
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
        let bytes = self.encode(data)?;
        let expiry = Expiration::EX(ttl.as_secs() as i64);
        self.client
            .set::<(), _, _>(&key, bytes, Some(expiry), None, false)
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

    async fn cycle(
        &self,
        old_id: &SessionId,
        new_id: &SessionId,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<(), Self::Error> {
        let old_key = session_key(&self.prefix, old_id);
        let new_key = session_key(&self.prefix, new_id);
        let bytes = self.encode(data)?;
        let expiry_secs = ttl.as_secs() as i64;

        // Use a MULTI/EXEC transaction for atomicity: either both the delete
        // and set succeed, or neither does. A pipeline alone does not provide
        // this guarantee: interleaved commands from other clients could
        // observe a state where the old key is deleted but the new key does
        // not yet exist.
        let txn = self.client.multi();
        txn.del::<(), _>(&old_key).await?;
        txn.set::<(), _, _>(
            &new_key,
            bytes,
            Some(Expiration::EX(expiry_secs)),
            None,
            false,
        )
        .await?;
        txn.exec::<()>(false).await?;

        debug!(
            old_session_id = %old_id,
            new_session_id = %new_id,
            ttl_secs = ttl.as_secs(),
            "session cycled in valkey"
        );
        Ok(())
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
