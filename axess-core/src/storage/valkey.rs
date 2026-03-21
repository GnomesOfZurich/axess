//! Valkey (Redis-compatible) session store and session registry.
//!
//! Uses the `fred` crate for async connection pooling, cluster support, and
//! automatic reconnection. Session data is serialized with MessagePack
//! (`rmp-serde`) for compact binary storage. TTL is managed by Valkey's
//! native key expiry — no background cleanup task needed.
//!
//! # Encryption at rest
//!
//! When an encryption key is provided via [`ValkeySessionStore::encrypted`],
//! session data is AES-256-GCM encrypted before storage. A random 12-byte
//! nonce is prepended to the ciphertext. On read, the nonce is split off and
//! used for decryption.
//!
//! Key rotation is supported: pass both the current key and the previous key.
//! On load, the store tries the current key first; if decryption fails, it
//! retries with the previous key. The next save always uses the current key,
//! so rotated data is transparently re-encrypted on access.
//!
//! # Key layout
//!
//! | Key pattern | Type | Purpose |
//! |---|---|---|
//! | `{prefix}:sess:{session_id}` | String (msgpack bytes or encrypted) | Session data |
//! | `{prefix}:reg:{user_id}` | Set of session ID strings | Session registry |
//!
//! # Usage
//!
//! ```rust,ignore
//! use axess::{SessionLayer, ValkeySessionStore, ValkeySessionRegistry};
//! use fred::prelude::*;
//!
//! let config = Config::from_url("redis://127.0.0.1:6379")?;
//! let client = Client::new(config, None, None, None);
//! client.init().await?;
//!
//! // Without encryption:
//! let store = ValkeySessionStore::new(client.clone());
//!
//! // With encryption (recommended for production):
//! let current_key: [u8; 32] = load_from_secrets("session_encryption_key");
//! let store = ValkeySessionStore::encrypted(client.clone(), current_key);
//!
//! // With key rotation (during a rotation window):
//! let old_key: [u8; 32] = load_from_secrets("session_encryption_key_previous");
//! let store = ValkeySessionStore::encrypted_with_rotation(
//!     client.clone(), current_key, old_key,
//! );
//!
//! let registry = ValkeySessionRegistry::new(client);
//! let session_layer = SessionLayer::new(store, signing_key);
//! ```

use crate::session::{
    data::SessionData,
    id::SessionId,
    store::{SessionRegistry, SessionStore},
};
use crate::utils::random::SecureRng;
use fred::prelude::*;
use std::sync::Arc;
use std::time::Duration;

// ── Key helpers ──────────────────────────────────────────────────────────────

const DEFAULT_PREFIX: &str = "axess";

fn session_key(prefix: &str, id: &SessionId) -> String {
    format!("{prefix}:sess:{id}")
}

fn registry_key(prefix: &str, user_id: &str) -> String {
    format!("{prefix}:reg:{user_id}")
}

// ── Error type ───────────────────────────────────────────────────────────────

/// Errors from the Valkey session store or registry.
#[derive(Debug, thiserror::Error)]
pub enum ValkeyStoreError {
    #[error("valkey error: {0}")]
    Redis(#[from] fred::error::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] rmp_serde::encode::Error),

    #[error("deserialization error: {0}")]
    Deserialization(#[from] rmp_serde::decode::Error),

    #[error("encryption/decryption error")]
    Crypto,
}

// ── Encryption ───────────────────────────────────────────────────────────────

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};

const NONCE_LEN: usize = 12;

/// Zeroize-on-drop wrapper for a 32-byte AES key.
#[derive(Clone)]
struct EncryptionKey([u8; 32]);

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

/// Optional encryption configuration.
#[derive(Clone)]
struct CryptoConfig {
    /// Current encryption key — always used for writes.
    current: Arc<EncryptionKey>,
    /// Previous key for rotation — tried on read if the current key fails.
    previous: Option<Arc<EncryptionKey>>,
}

fn encrypt(config: &CryptoConfig, plaintext: &[u8]) -> Result<Vec<u8>, ValkeyStoreError> {
    let cipher =
        Aes256Gcm::new_from_slice(&config.current.0).map_err(|_| ValkeyStoreError::Crypto)?;

    // Generate a random 12-byte nonce.
    let mut nonce_bytes = [0u8; NONCE_LEN];
    crate::utils::random::SystemRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| ValkeyStoreError::Crypto)?;

    // Prepend nonce to ciphertext: nonce (12 bytes) || ciphertext.
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt(config: &CryptoConfig, data: &[u8]) -> Result<Vec<u8>, ValkeyStoreError> {
    if data.len() < NONCE_LEN {
        return Err(ValkeyStoreError::Crypto);
    }

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Try current key first.
    let cipher =
        Aes256Gcm::new_from_slice(&config.current.0).map_err(|_| ValkeyStoreError::Crypto)?;

    if let Ok(plaintext) = cipher.decrypt(nonce, ciphertext) {
        return Ok(plaintext);
    }

    // If that failed and we have a previous key, try key rotation fallback.
    if let Some(prev) = &config.previous {
        let old_cipher =
            Aes256Gcm::new_from_slice(&prev.0).map_err(|_| ValkeyStoreError::Crypto)?;

        if let Ok(plaintext) = old_cipher.decrypt(nonce, ciphertext) {
            return Ok(plaintext);
        }
    }

    Err(ValkeyStoreError::Crypto)
}

// ── ValkeySessionStore ───────────────────────────────────────────────────────

/// Valkey-backed session store with optional AES-256-GCM encryption at rest.
///
/// Session data is serialized with MessagePack and optionally encrypted before
/// storage. TTL is managed by Valkey-native key expiry.
/// Clone is cheap — the inner client and keys are `Arc`-based.
#[derive(Clone)]
pub struct ValkeySessionStore {
    client: Client,
    prefix: Arc<str>,
    crypto: Option<CryptoConfig>,
}

impl ValkeySessionStore {
    /// Create an **unencrypted** store with the default key prefix (`"axess"`).
    pub fn new(client: Client) -> Self {
        Self {
            client,
            prefix: DEFAULT_PREFIX.into(),
            crypto: None,
        }
    }

    /// Create an **encrypted** store using AES-256-GCM.
    ///
    /// All session data is encrypted before writing to Valkey and decrypted on
    /// read. The 32-byte key should be loaded from a secret store and persisted
    /// across restarts.
    pub fn encrypted(client: Client, key: [u8; 32]) -> Self {
        Self {
            client,
            prefix: DEFAULT_PREFIX.into(),
            crypto: Some(CryptoConfig {
                current: Arc::new(EncryptionKey(key)),
                previous: None,
            }),
        }
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
            crypto: Some(CryptoConfig {
                current: Arc::new(EncryptionKey(current_key)),
                previous: Some(Arc::new(EncryptionKey(previous_key))),
            }),
        }
    }

    /// Override the key prefix (default: `"axess"`).
    ///
    /// Useful when multiple applications share the same Valkey instance.
    pub fn with_prefix(mut self, prefix: impl Into<Arc<str>>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// Serialize (and optionally encrypt) session data for storage.
    fn encode(&self, data: &SessionData) -> Result<Vec<u8>, ValkeyStoreError> {
        let msgpack = rmp_serde::to_vec(data)?;
        match &self.crypto {
            Some(cfg) => encrypt(cfg, &msgpack),
            None => Ok(msgpack),
        }
    }

    /// Deserialize (and optionally decrypt) session data from storage.
    fn decode(&self, bytes: &[u8]) -> Result<SessionData, ValkeyStoreError> {
        let plaintext = match &self.crypto {
            Some(cfg) => decrypt(cfg, bytes)?,
            None => bytes.to_vec(),
        };
        Ok(rmp_serde::from_slice(&plaintext)?)
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
                Ok(Some(data))
            }
            None => Ok(None),
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
        Ok(())
    }

    async fn delete(&self, id: &SessionId) -> Result<(), Self::Error> {
        let key = session_key(&self.prefix, id);
        self.client.del::<(), _>(&key).await?;
        Ok(())
    }

    async fn cycle(
        &self,
        old_id: &SessionId,
        data: &SessionData,
        ttl: Duration,
        rng: &mut impl SecureRng,
    ) -> Result<SessionId, Self::Error> {
        let new_id = SessionId::new(rng);
        let old_key = session_key(&self.prefix, old_id);
        let new_key = session_key(&self.prefix, &new_id);
        let bytes = self.encode(data)?;
        let expiry_secs = ttl.as_secs() as i64;

        // Pipeline: delete old + set new in one round-trip.
        let pipeline = self.client.pipeline();
        pipeline.del::<(), _>(&old_key).await?;
        pipeline
            .set::<(), _, _>(
                &new_key,
                bytes,
                Some(Expiration::EX(expiry_secs)),
                None,
                false,
            )
            .await?;
        pipeline.all::<()>().await?;

        Ok(new_id)
    }
}

// ── ValkeySessionRegistry ────────────────────────────────────────────────────

/// Valkey-backed session registry using sets.
///
/// Each user has a Valkey set containing their valid session IDs.
/// Forced logout removes the set (or a single member).
/// Clone is cheap — the inner client is `Arc`-based.
#[derive(Clone)]
pub struct ValkeySessionRegistry {
    client: Client,
    prefix: Arc<str>,
    /// TTL for registry entries. Should be >= session TTL to avoid
    /// premature eviction. Default: 24 hours.
    ttl: Duration,
}

impl ValkeySessionRegistry {
    /// Create a new registry with the default prefix and 24-hour TTL.
    pub fn new(client: Client) -> Self {
        Self {
            client,
            prefix: DEFAULT_PREFIX.into(),
            ttl: Duration::from_secs(24 * 60 * 60),
        }
    }

    /// Create a new registry with custom prefix and TTL.
    pub fn with_options(client: Client, prefix: impl Into<Arc<str>>, ttl: Duration) -> Self {
        Self {
            client,
            prefix: prefix.into(),
            ttl,
        }
    }
}

impl SessionRegistry for ValkeySessionRegistry {
    type Error = ValkeyStoreError;

    async fn register(&self, user_id: &str, session_id: &SessionId) -> Result<(), Self::Error> {
        let key = registry_key(&self.prefix, user_id);
        let sid_str = session_id.to_string();
        self.client.sadd::<(), _, _>(&key, &sid_str).await?;
        // Refresh TTL on every registration so the set lives as long as
        // the user has active sessions.
        self.client
            .expire::<(), _>(&key, self.ttl.as_secs() as i64, None)
            .await?;
        Ok(())
    }

    async fn is_valid(&self, user_id: &str, session_id: &SessionId) -> Result<bool, Self::Error> {
        let key = registry_key(&self.prefix, user_id);
        let sid_str = session_id.to_string();
        let is_member: bool = self.client.sismember(&key, &sid_str).await?;
        Ok(is_member)
    }

    async fn invalidate_user(&self, user_id: &str) -> Result<(), Self::Error> {
        let key = registry_key(&self.prefix, user_id);
        self.client.del::<(), _>(&key).await?;
        Ok(())
    }

    async fn invalidate_session(
        &self,
        user_id: &str,
        session_id: &SessionId,
    ) -> Result<(), Self::Error> {
        let key = registry_key(&self.prefix, user_id);
        let sid_str = session_id.to_string();
        self.client.srem::<(), _, _>(&key, &sid_str).await?;
        Ok(())
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::data::SessionData;
    use crate::utils::random::SystemRng;

    /// Unit test: encrypt → decrypt round-trip with current key.
    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let config = CryptoConfig {
            current: Arc::new(EncryptionKey(key)),
            previous: None,
        };

        let plaintext = b"hello session data";
        let encrypted = encrypt(&config, plaintext).expect("encrypt");
        assert_ne!(
            &encrypted, plaintext,
            "ciphertext should differ from plaintext"
        );
        assert!(
            encrypted.len() > NONCE_LEN,
            "must include nonce + ciphertext"
        );

        let decrypted = decrypt(&config, &encrypted).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    /// Unit test: key rotation — data encrypted with old key is decrypted via fallback.
    #[test]
    fn key_rotation_decrypt_with_previous() {
        let old_key = [1u8; 32];
        let new_key = [2u8; 32];

        // Encrypt with old key.
        let old_config = CryptoConfig {
            current: Arc::new(EncryptionKey(old_key)),
            previous: None,
        };
        let plaintext = b"rotated session";
        let encrypted = encrypt(&old_config, plaintext).expect("encrypt with old key");

        // Decrypt with new key as current + old key as previous.
        let rotation_config = CryptoConfig {
            current: Arc::new(EncryptionKey(new_key)),
            previous: Some(Arc::new(EncryptionKey(old_key))),
        };
        let decrypted = decrypt(&rotation_config, &encrypted).expect("decrypt with rotation");
        assert_eq!(decrypted, plaintext);
    }

    /// Unit test: decryption fails with wrong key and no fallback.
    #[test]
    fn decrypt_wrong_key_fails() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];

        let config_a = CryptoConfig {
            current: Arc::new(EncryptionKey(key_a)),
            previous: None,
        };
        let config_b = CryptoConfig {
            current: Arc::new(EncryptionKey(key_b)),
            previous: None,
        };

        let encrypted = encrypt(&config_a, b"secret").expect("encrypt");
        assert!(decrypt(&config_b, &encrypted).is_err());
    }

    /// Unit test: encode/decode round-trip through ValkeySessionStore (encrypted).
    #[test]
    fn store_encode_decode_encrypted() {
        // We can't construct a full ValkeySessionStore without a Valkey connection,
        // but we can test encode/decode by constructing one with a dummy client.
        // Instead, test the encrypt/decrypt path directly with SessionData.
        let key = [99u8; 32];
        let config = CryptoConfig {
            current: Arc::new(EncryptionKey(key)),
            previous: None,
        };

        let data = SessionData::default();
        let msgpack = rmp_serde::to_vec(&data).expect("serialize");
        let encrypted = encrypt(&config, &msgpack).expect("encrypt");
        let decrypted = decrypt(&config, &encrypted).expect("decrypt");
        let restored: SessionData = rmp_serde::from_slice(&decrypted).expect("deserialize");

        assert_eq!(
            serde_json::to_string(&data).unwrap(),
            serde_json::to_string(&restored).unwrap(),
        );
    }

    /// Integration test: full store + registry round-trip against a live Valkey.
    ///
    /// Requires a running Valkey instance at `127.0.0.1:6379`.
    /// Run with: `cargo test --features valkey -- --ignored valkey_integration`
    #[tokio::test]
    #[ignore = "requires a running Valkey instance at 127.0.0.1:6379"]
    async fn valkey_integration() {
        let config = Config::from_url("redis://127.0.0.1:6379").expect("parse redis URL");
        let client = Client::new(config, None, None, None);
        client.init().await.expect("connect to Valkey");

        let encryption_key = [77u8; 32];
        let store =
            ValkeySessionStore::encrypted(client.clone(), encryption_key).with_prefix("axess_test");
        let registry = ValkeySessionRegistry::with_options(
            client.clone(),
            "axess_test",
            Duration::from_secs(60),
        );

        let mut rng = SystemRng;
        let sid = SessionId::new(&mut rng);
        let data = SessionData::default();
        let ttl = Duration::from_secs(30);

        // Store: save → load → matches.
        store.save(&sid, &data, ttl).await.expect("save");
        let loaded = store.load(&sid).await.expect("load");
        assert!(loaded.is_some(), "session should exist after save");

        // Store: cycle → old gone, new exists.
        let new_sid = store
            .cycle(&sid, &data, ttl, &mut rng)
            .await
            .expect("cycle");
        assert!(store.load(&sid).await.expect("load old").is_none());
        assert!(store.load(&new_sid).await.expect("load new").is_some());

        // Store: delete → gone.
        store.delete(&new_sid).await.expect("delete");
        assert!(store.load(&new_sid).await.expect("load deleted").is_none());

        // Registry: register → is_valid → invalidate.
        let user_id = "test-user-integration";
        let reg_sid = SessionId::new(&mut rng);
        registry
            .register(user_id, &reg_sid)
            .await
            .expect("register");
        assert!(
            registry
                .is_valid(user_id, &reg_sid)
                .await
                .expect("is_valid"),
            "session should be valid after register"
        );

        // Registry: invalidate single session.
        registry
            .invalidate_session(user_id, &reg_sid)
            .await
            .expect("invalidate_session");
        assert!(
            !registry
                .is_valid(user_id, &reg_sid)
                .await
                .expect("is_valid after invalidate"),
        );

        // Registry: invalidate all sessions for user.
        let sid_a = SessionId::new(&mut rng);
        let sid_b = SessionId::new(&mut rng);
        registry.register(user_id, &sid_a).await.expect("reg a");
        registry.register(user_id, &sid_b).await.expect("reg b");
        registry
            .invalidate_user(user_id)
            .await
            .expect("invalidate_user");
        assert!(!registry.is_valid(user_id, &sid_a).await.expect("a"));
        assert!(!registry.is_valid(user_id, &sid_b).await.expect("b"));

        // Key rotation: save with old key, load with new key + old as fallback.
        let old_key = [77u8; 32];
        let new_key = [88u8; 32];
        let old_store =
            ValkeySessionStore::encrypted(client.clone(), old_key).with_prefix("axess_test");
        let rotation_store =
            ValkeySessionStore::encrypted_with_rotation(client.clone(), new_key, old_key)
                .with_prefix("axess_test");

        let rot_sid = SessionId::new(&mut rng);
        old_store
            .save(&rot_sid, &data, ttl)
            .await
            .expect("save with old key");
        let loaded = rotation_store
            .load(&rot_sid)
            .await
            .expect("load with rotation");
        assert!(
            loaded.is_some(),
            "should decrypt with previous key fallback"
        );

        // Cleanup.
        old_store.delete(&rot_sid).await.expect("cleanup");

        client.quit().await.expect("disconnect");
    }
}
