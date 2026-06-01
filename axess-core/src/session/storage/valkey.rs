//! Valkey (Redis-compatible) session store and session registry.
//!
//! Uses the `fred` crate for async connection pooling, cluster support, and
//! automatic reconnection. Session data is serialized with MessagePack
//! (`rmp-serde`) for compact binary storage. TTL is managed by Valkey's
//! native key expiry: no background cleanup task needed.
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
//! | `{prefix}:reg:{user_id}` | Sorted set (member = session ID, score = `register` instant in epoch ms) | Session registry |
//!
//! # Registry data type
//!
//! The registry uses a Redis **sorted set** keyed on `register`-time
//! `clock.now().timestamp_millis()` (from the injected
//! [`Clock`](axess_clock::Clock); default
//! [`SystemClock`](axess_clock::SystemClock)) as the score. This is load-bearing
//! for [`SessionRegistry::active_sessions`](crate::session::store::SessionRegistry::active_sessions):
//! the trait promises "ordered oldest first" so that the
//! [`max_sessions_per_user`](crate::authn::service::AuthnService::with_max_sessions_per_user)
//! eviction loop in `complete_factor_step` can FIFO-evict (rather than
//! arbitrary-evict, which an attacker could exploit by spawning a burst
//! of short-lived sessions to push the legitimate user out). Previously
//! this used a plain Redis SET (`SADD`/`SISMEMBER`/`SREM`) and never
//! overrode `active_sessions`, so the trait default `Ok(vec![])` made
//! `max_sessions_per_user` enforcement silently no-op for every Valkey
//! deployment.
//!
//! # Usage
//!
//! ```rust,ignore
//! use axess::{SessionLayer, ValkeySessionStore, ValkeySessionRegistry};
//! use fred::prelude::*;
//!
//! // Valkey uses the redis:// URI scheme (full wire-protocol compatibility).
//! let config = Config::from_url("redis://127.0.0.1:6379")?;
//! let client = Client::new(config, None, None, None);
//! client.init().await?;
//!
//! // Encrypted (default: recommended for production):
//! let current_key: [u8; 32] = load_from_secrets("session_encryption_key");
//! let store = ValkeySessionStore::new(client.clone(), current_key);
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

mod encryption;
mod internal;
mod registry;
mod store;

#[cfg(test)]
mod tests;

pub use internal::ValkeyStoreError;
pub use registry::ValkeySessionRegistry;
pub use store::ValkeySessionStore;
