//! Valkey-backed [`SessionStore`] implementation.
//!
//! See the [module-level docs](super) for the encryption-at-rest
//! contract, key layout, and adopter-facing usage examples.

use super::encryption::{encrypted_codec, encrypted_codec_with_rotation, plaintext_codec};
use super::internal::{
    COMPARE_DEL_SCRIPT, COMPARE_SET_SCRIPT, CYCLE_SCRIPT, DEFAULT_MAX_PAYLOAD_BYTES,
    DEFAULT_PREFIX, FallbackNotice, KEYS_IN_TWO_SLOTS, RESEAL_SCRIPT, ScriptRoute,
    ValkeyStoreError, ex_seconds, live_ex_seconds, script_route, script_unavailable,
    session_row_key,
};
use crate::session::{
    data::SessionData,
    id::SessionKey,
    storage::session_codec::{Decoded, SessionCodec},
    store::{
        ConditionalUpdate, CycleOutcome, SessionStore,
        cas::{CasRow, CasWrite, cas_by_revision, cycle_by_revision},
    },
};
use fred::bytes::Bytes;
use fred::prelude::*;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};
use zeroize::Zeroize;

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
    /// Says once, for this store and its clones, that a rotation took the
    /// sequenced form.
    fallback: Arc<FallbackNotice>,
}

impl ValkeySessionStore {
    /// Create an **encrypted** store using AES-256-GCM (recommended for production).
    ///
    /// All session data is encrypted before writing to Valkey and decrypted on
    /// read. The 32-byte key should be loaded from a secret store and persisted
    /// across restarts.
    ///
    /// The key is copied into a buffer that is zeroed on drop, and the copy
    /// handed to this call is zeroed before it returns. The caller's own
    /// copy is the caller's to wipe.
    pub fn new(client: Client, mut key: [u8; 32]) -> Self {
        let store = Self::with_codec(client, encrypted_codec(&key));
        key.zeroize();
        store
    }

    /// The store every constructor returns: the default prefix and payload
    /// limit around `codec`.
    fn with_codec(client: Client, codec: SessionCodec) -> Self {
        Self {
            client,
            prefix: DEFAULT_PREFIX.into(),
            codec,
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
            fallback: Arc::default(),
        }
    }

    /// Create a **plaintext** store (development/testing only).
    ///
    /// Session data (including the user id) is stored **unsealed** in Valkey:
    /// anyone who can read the keyspace can read every session. The named
    /// opt-out beside [`new`](Self::new), which takes the key. Do not use in
    /// production.
    pub fn plaintext_insecure(client: Client) -> Self {
        tracing::warn!(
            "ValkeySessionStore created without encryption: \
             do not use in production"
        );
        Self::with_codec(client, plaintext_codec())
    }

    /// Create an **encrypted** store using AES-256-GCM.
    ///
    /// Alias for [`new`](ValkeySessionStore::new).
    pub fn encrypted(client: Client, mut key: [u8; 32]) -> Self {
        let store = Self::with_codec(client, encrypted_codec(&key));
        key.zeroize();
        store
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
        mut current_key: [u8; 32],
        mut previous_key: [u8; 32],
    ) -> Self {
        let codec = encrypted_codec_with_rotation(&current_key, &previous_key);
        current_key.zeroize();
        previous_key.zeroize();
        Self::with_codec(client, codec)
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
        key: &SessionKey,
        data: &SessionData,
    ) -> Result<Vec<u8>, ValkeyStoreError> {
        let encoded = self.codec.encode_bytes(key, data)?;

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
        key: &SessionKey,
        bytes: &[u8],
    ) -> Result<SessionData, ValkeyStoreError> {
        Ok(self.codec.decode_bytes(key, bytes)?)
    }

    /// Re-seal a blob that only the previous key opened. Best
    /// effort and conditional on the key still holding the bytes that were
    /// read (so a save that landed meanwhile is kept); the key keeps its
    /// expiry. Without scripting the blob is re-sealed by its next save.
    async fn reseal(&self, key: &SessionKey, old: &[u8], data: &SessionData) {
        let row = session_row_key(&self.prefix, key);
        let sealed = match self.encode(key, data) {
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
                vec![row],
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

impl ValkeySessionStore {
    /// The rotation where the cycle script cannot run (scripting disabled, or
    /// the two keys in different cluster slots). The old key is deleted first
    /// because its count decides whether the session was live, then the new
    /// key is written. A failed SET after the DEL leaves the user signed out,
    /// which the layer's fail-closed path wants anyway; a crash between the
    /// calls leaves neither key. (MULTI/EXEC is no substitute: the server
    /// runs every queued command even when an earlier one fails.)
    async fn cycle_sequenced(
        &self,
        old: &SessionKey,
        new: &SessionKey,
        bytes: Vec<u8>,
        ex: i64,
        require_old: bool,
    ) -> Result<CycleOutcome, ValkeyStoreError> {
        let old_row = session_row_key(&self.prefix, old);
        let new_row = session_row_key(&self.prefix, new);
        if old_row != new_row {
            let removed: i64 = self.client.del(&old_row).await?;
            if require_old && removed == 0 {
                return Ok(CycleOutcome::SessionGone);
            }
            self.client
                .set::<(), _, _>(&new_row, bytes, Some(Expiration::EX(ex)), None, false)
                .await?;
        } else {
            let options = require_old.then_some(SetOptions::XX);
            let written: Option<String> = self
                .client
                .set(&new_row, bytes, Some(Expiration::EX(ex)), options, false)
                .await?;
            if require_old && written.is_none() {
                return Ok(CycleOutcome::SessionGone);
            }
        }
        debug!(
            old_session_id = %old.prefix(),
            new_session_id = %new.prefix(),
            ttl_secs = ex,
            "session cycled in valkey, sequenced"
        );
        Ok(CycleOutcome::Rotated)
    }
}

impl SessionStore for ValkeySessionStore {
    /// Sessions are sealed blobs named by their key with the user inside, so Valkey
    /// cannot list them by user without reading every key.
    async fn find_sessions_for_user(
        &self,
        _: &crate::authn::ids::UserId,
        _: usize,
    ) -> Result<Vec<(SessionKey, SessionData)>, Self::Error> {
        Err(ValkeyStoreError::Unsupported("find_sessions_for_user"))
    }

    type Error = ValkeyStoreError;

    async fn load(&self, key: &SessionKey) -> Result<Option<SessionData>, Self::Error> {
        let row = session_row_key(&self.prefix, key);
        let bytes: Option<Vec<u8>> = self.client.get(&row).await?;
        match bytes {
            Some(b) => {
                let Decoded { data, reseal } = self.codec.decode_bytes_checked(key, &b)?;
                if reseal {
                    self.reseal(key, &b, &data).await;
                }
                debug!(session_id = %key.prefix(), "session loaded from valkey");
                Ok(Some(data))
            }
            None => {
                debug!(session_id = %key.prefix(), "session not found in valkey");
                Ok(None)
            }
        }
    }

    async fn save(
        &self,
        key: &SessionKey,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<(), Self::Error> {
        let row = session_row_key(&self.prefix, key);
        let bytes = self.encode(key, data)?;
        let Some(ex) = ex_seconds(ttl) else {
            // Already expired: nothing may be stored, and a previous value
            // under this key must not outlive the expiry it was just given.
            self.client.del::<(), _>(&row).await?;
            return Ok(());
        };
        self.client
            .set::<(), _, _>(&row, bytes, Some(Expiration::EX(ex)), None, false)
            .await?;
        debug!(session_id = %key.prefix(), ttl_secs = ttl.as_secs(), "session saved to valkey");
        Ok(())
    }

    async fn delete(&self, key: &SessionKey) -> Result<(), Self::Error> {
        let row = session_row_key(&self.prefix, key);
        self.client.del::<(), _>(&row).await?;
        debug!(session_id = %key.prefix(), "session deleted from valkey");
        Ok(())
    }

    async fn update(
        &self,
        key: &SessionKey,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<bool, Self::Error> {
        let row = session_row_key(&self.prefix, key);
        let bytes = self.encode(key, data)?;
        let Some(ex) = ex_seconds(ttl) else {
            // Already expired: nothing may stay stored under this key.
            self.client.del::<(), _>(&row).await?;
            return Ok(false);
        };
        // `SET ... XX` writes only while the key exists, so a session deleted
        // since the caller loaded it is not brought back.
        let written: Option<String> = self
            .client
            .set(
                &row,
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
        key: &SessionKey,
        expected_revision: u64,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<ConditionalUpdate, Self::Error> {
        cas_by_revision(self, key, expected_revision, data, ttl).await
    }

    async fn cycle(
        &self,
        old: &SessionKey,
        new: &SessionKey,
        data: &SessionData,
        ttl: Duration,
        require_old: bool,
    ) -> Result<CycleOutcome, Self::Error> {
        let old_row = session_row_key(&self.prefix, old);
        let new_row = session_row_key(&self.prefix, new);
        let bytes = self.encode(new, data)?;
        let Some(ex) = ex_seconds(ttl) else {
            // Already expired: the rotated session is stored nowhere, so both
            // keys go and the session is reported gone, never as rotated.
            // One DEL per key: a cluster refuses one DEL whose keys hash to
            // different slots (CROSSSLOT), and the client sends such a DEL
            // whole.
            self.client.del::<(), _>(&old_row).await?;
            if new_row != old_row {
                self.client.del::<(), _>(&new_row).await?;
            }
            return Ok(CycleOutcome::SessionGone);
        };

        // One server-side script checks that the old key exists when that is
        // required, writes the new key, then removes the old one (which it
        // skips when the two are the same key). On a cluster whose two keys
        // hash to different slots the script is not sent.
        if script_route(self.client.is_clustered(), [&old_row, &new_row]) == ScriptRoute::Sequenced
        {
            self.fallback.note("session cycle", KEYS_IN_TWO_SLOTS);
            return self.cycle_sequenced(old, new, bytes, ex, require_old).await;
        }
        let scripted: Result<i64, _> = self
            .client
            .eval(
                CYCLE_SCRIPT,
                vec![old_row.clone(), new_row.clone()],
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
                self.fallback.note("session cycle", &e.to_string());
                return self.cycle_sequenced(old, new, bytes, ex, require_old).await;
            }
            Err(e) => return Err(e.into()),
        }

        debug!(
            old_session_id = %old.prefix(),
            new_session_id = %new.prefix(),
            ttl_secs = ex,
            "session cycled in valkey"
        );
        Ok(CycleOutcome::Rotated)
    }

    async fn cycle_if_revision(
        &self,
        old: &SessionKey,
        new: &SessionKey,
        data: &SessionData,
        ttl: Duration,
        require_old: bool,
        expected_revision: u64,
    ) -> Result<CycleOutcome, Self::Error> {
        cycle_by_revision(self, old, new, data, ttl, require_old, expected_revision).await
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

/// The Valkey store compares the stored bytes, in a script that writes only
/// while the key still holds them. A deployment without scripting returns
/// the error rather than a weaker compare: the caller then fails closed.
impl CasRow for ValkeySessionStore {
    type Seen = Vec<u8>;
    type Error = ValkeyStoreError;

    async fn read(&self, key: &SessionKey) -> Result<Option<(u64, Vec<u8>)>, Self::Error> {
        let row = session_row_key(&self.prefix, key);
        let Some(old): Option<Vec<u8>> = self.client.get(&row).await? else {
            return Ok(None);
        };
        let stored = self.codec.decode_bytes_checked(key, &old)?.data;
        Ok(Some((stored.revision, old)))
    }

    async fn delete_if(&self, key: &SessionKey, seen: &Vec<u8>) -> Result<CasWrite, Self::Error> {
        let removed: i64 = self
            .client
            .eval(
                COMPARE_DEL_SCRIPT,
                vec![session_row_key(&self.prefix, key)],
                vec![Value::Bytes(Bytes::from(seen.clone()))],
            )
            .await?;
        Ok(script_outcome(removed))
    }

    async fn replace_if(
        &self,
        key: &SessionKey,
        seen: &Vec<u8>,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<CasWrite, Self::Error> {
        let bytes = self.encode(key, data)?;
        let swapped: i64 = self
            .client
            .eval(
                COMPARE_SET_SCRIPT,
                vec![session_row_key(&self.prefix, key)],
                vec![
                    Value::Bytes(Bytes::from(seen.clone())),
                    Value::Bytes(Bytes::from(bytes)),
                    Value::Integer(live_ex_seconds(ttl)),
                ],
            )
            .await?;
        Ok(script_outcome(swapped))
    }
}

/// The answer of a compare script: `1` it ran, `0` the key holds other
/// bytes, anything else the key is gone.
fn script_outcome(answer: i64) -> CasWrite {
    match answer {
        1 => CasWrite::Done,
        0 => CasWrite::Missed,
        _ => CasWrite::Gone,
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

// ── Store<SessionKey, SessionData> ────────────────────────────────────────────
//
// surface: see the same impl on `SqliteSessionStore` for rationale.
// `Store::prune_expired` returns `Ok(0)` deliberately: Valkey's native
// passive + active key expiry already evicts; the trait doc records this
// as a documented no-op for backends with server-side TTL.

impl crate::store::Store<SessionKey, SessionData> for ValkeySessionStore {
    type Error = ValkeyStoreError;

    fn get(
        &self,
        key: &SessionKey,
    ) -> impl Future<Output = Result<Option<SessionData>, Self::Error>> + Send {
        <Self as SessionStore>::load(self, key)
    }

    fn put(
        &self,
        key: &SessionKey,
        value: &SessionData,
        ttl: Duration,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        <Self as SessionStore>::save(self, key, value, ttl)
    }

    fn delete(&self, key: &SessionKey) -> impl Future<Output = Result<(), Self::Error>> + Send {
        <Self as SessionStore>::delete(self, key)
    }

    fn prune_expired(&self) -> impl Future<Output = Result<u64, Self::Error>> + Send {
        <Self as SessionStore>::prune_expired(self)
    }
}
