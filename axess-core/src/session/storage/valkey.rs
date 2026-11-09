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
//! session data is AES-256-GCM encrypted before storage, bound to the row it
//! lives in. A stored value is `marker || salt || ciphertext`: a four-byte
//! format marker (`AXS\x01` with the top bit of its last byte set, which
//! says the key is derived per record), a random 16-byte salt, and the
//! AES-GCM ciphertext under a key derived from the configured key, the salt
//! and the session id. The additional authenticated data is
//! `axess.session.v1 || 0x00 || session id`; the id is not stored in the
//! value but supplied again on read, so a value copied under another session
//! id (or restored from a backup into a different row) fails authentication
//! and reads as a decryption failure.
//!
//! Values written before row binding carry no marker and no binding: they
//! open under any session id, so an attacker who can write to the store could
//! move one between rows. [`LegacyBlobs`](crate::session::crypto::LegacyBlobs)
//! decides what happens to them. The default, `Reject`, refuses them (the
//! user signs in again). `AcceptUntil(instant)` reads them until the instant
//! and refuses them afterwards; until then an unbound value can be moved
//! between rows undetected, and a read leaves it as it is (the session's next
//! save writes the bound form). `Accept` reads them with no end date. Set the
//! policy with [`ValkeySessionStore::with_legacy_blobs`].
//!
//! Key rotation is supported: pass both the current key and the previous key.
//! On load, the store tries the current key first; if decryption fails, it
//! retries with the previous key. A save always uses the current key, so a
//! row is re-sealed under it when it is next written; a row that is only read
//! stays under the previous key until it expires.
//!
//! # Key layout
//!
//! | Key pattern | Type | Purpose |
//! |---|---|---|
//! | `{prefix}:sess:{session_id}` | String (msgpack bytes or encrypted) | Session data |
//! | `{prefix}:reg:{user_id}` | Sorted set (member = session ID, score = `register` instant, moved forward by use, in epoch ms) | Session registry: liveness |
//! | `{prefix}:reg-at:{user_id}` | Sorted set (member = session ID, score = `register` instant in epoch ms, never moved) | Session registry: eviction order |
//!
//! # Registry data type
//!
//! The registry uses a Redis **sorted set** keyed on the `register`-time
//! epoch milliseconds as the score; the score of the first set moves forward
//! as a session is used, so a second sorted set holds the registration time
//! that `active_sessions` orders by. The time is the Valkey server's own
//! (`TIME`), so app nodes with skewed clocks agree on scores and expiry
//! cutoffs; a [`Clock`](axess_clock::Clock) injected with `with_clock`
//! (tests) replaces it. This is load-bearing
//! for [`SessionRegistry::active_sessions`](crate::session::store::SessionRegistry::active_sessions):
//! the trait promises "ordered oldest first" so that the
//! [`max_sessions_per_user`](crate::authn::service::AuthnServiceBuilder::with_max_sessions_per_user)
//! eviction loop in `complete_factor_step` can FIFO-evict (rather than
//! arbitrary-evict, which an attacker could exploit by spawning a burst
//! of short-lived sessions to push the legitimate user out). A plain SET
//! has no order to enumerate, so `active_sessions` could not honour the
//! contract and `max_sessions_per_user` would never fire.
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
//! let session_layer = SessionLayer::new(
//!     store,
//!     signing_key,
//!     std::sync::Arc::new(SessionRegistryAdapter(registry)),
//! );
//! ```

mod encryption;
mod internal;
mod registry;
mod store;
mod subscriber;

#[cfg(test)]
mod registry_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod ttl_tests;
#[cfg(test)]
mod watch_tests;

/// The live tests that open a subscriber connection run one at a time: the
/// watch tests count the server's pub/sub connections, and a watcher another
/// test opens or closes meanwhile would be counted with theirs.
#[cfg(test)]
static SUBSCRIBER_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub use internal::ValkeyStoreError;
pub use registry::ValkeySessionRegistry;
pub use store::ValkeySessionStore;
