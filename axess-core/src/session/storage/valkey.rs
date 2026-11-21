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
//! format marker (`AXS\x02` with the top bit of its last byte set, which
//! says the key is derived per record), a random 16-byte salt, and the
//! AES-GCM ciphertext under a key derived from the configured key, the salt
//! and the session's key. The additional authenticated data is
//! `axess.session.v2 || 0x00 || session key`; the key is not stored in the
//! value but supplied again on read, so a value copied under another session's
//! key (or restored from a backup into a different row) fails authentication
//! and reads as a decryption failure.
//!
//! A value is read in that form and in no other. One written by an earlier
//! release (bound to the session id, or with no binding at all) is refused:
//! sessions stored before this format are not carried over, and their users
//! sign in again. No [`LegacyBlobs`](crate::session::crypto::LegacyBlobs)
//! policy applies to a session.
//!
//! Key rotation is supported: pass both the current key and the previous key.
//! On load, the store tries the current key first; if decryption fails, it
//! retries with the previous key. A save always uses the current key, and a
//! load that opened a row under the previous key writes it back under the
//! current one (only while the stored bytes are still the ones it read), so
//! rows move to the new key as they are read or written.
//!
//! # Key layout
//!
//! | Key pattern | Type | Purpose |
//! |---|---|---|
//! | `<prefix>:sess:<session_key>` | String (msgpack bytes or encrypted) | Session data, named by the 64 hexadecimal characters of the session's key (a digest of its id, never the id) |
//! | `<prefix>:reg:{<user_id>}` | Sorted set (member = the session's key, score = `register` instant, moved forward by use, in epoch ms) | Session registry: liveness |
//! | `<prefix>:reg-at:{<user_id>}` | Sorted set (member = the session's key, score = `register` instant in epoch ms, never moved) | Session registry: eviction order |
//! | `<prefix>:fwd:{<user_id>}` | Hash (field = a key the session was moved away from, value = the key it is under now) | Session registry: the records of the user's moves |
//! | `<prefix>:fwd-at:{<user_id>}` | Sorted set (member = a field of the hash beside it, score = its place in the order of the user's moves) | Session registry: which record a move gives up at the bound |
//!
//! Angle brackets stand for the prefix, the session's key and the
//! hyphenated user id; a registry member is the 64 characters of a session's
//! key, as are the fields and values of the records of moves and the last
//! part of the channel `<prefix>:revoked-session:<key>` that the registry
//! publishes when it ends one session, so neither a member, a record, a
//! key name nor a channel holds a value a cookie could carry. The
//! braces around the user id are literal: a hash
//! tag. A cluster hashes such a key by the user id alone, so one user's
//! four registry keys share a cluster slot and the registry's scripts (the
//! move of a session, the ending by key, the cut-off of a user's other
//! sessions, the orphan sweep) run as single scripts on any cluster, with
//! no hash tag in the prefix. A prefix that closes a tag of its own (`{axess}`) puts every
//! user in that tag's one slot instead. A prefix that opens a brace it does
//! not close (`a{b`) would split a user's keys, and the registry refuses it
//! when it is built and at every call. Keys the registry wrote before the
//! user id was a hash tag are named without braces; nothing reads them, and
//! they expire with their own TTL.
//!
//! The registry is built only on a server that runs its scripts:
//! [`ValkeySessionRegistry::new`] and
//! [`ValkeySessionRegistry::with_options`] send a script that reads and
//! writes nothing over a user's keys and refuse to start with
//! [`ValkeyStoreError::ScriptsRefused`] when the server refuses it. The
//! session store's rotation of a session the request did not load is a
//! two-key script that runs as one step on a cluster only with a hash tag
//! in the store's prefix, and takes a sequenced form otherwise.
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
//! // The registry checks, on the connected client, that the server runs its
//! // scripts, and refuses to start otherwise.
//! let registry = ValkeySessionRegistry::new(client).await?;
//! let session_layer = SessionLayer::new(
//!     store,
//!     signing_key,
//!     std::sync::Arc::new(SessionRegistryAdapter(registry)),
//!     authn.session_end_audit(),
//! );
//! ```

mod encryption;
mod internal;
mod registry;
mod registry_keys;
mod store;
mod subscriber;

#[cfg(test)]
mod cluster_tests;
#[cfg(test)]
mod fallback_tests;
#[cfg(test)]
mod layout_tests;
#[cfg(test)]
mod member_tests;
#[cfg(test)]
mod move_tests;
#[cfg(test)]
mod registry_tests;
#[cfg(test)]
mod sequenced_tests;
#[cfg(test)]
mod stored_form_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod ttl_tests;
#[cfg(test)]
mod watch_tests;

/// The live tests that open a subscriber connection run one at a time. The
/// watch tests count and kill only the connection that carries their own
/// registry's name, so no other client's pub/sub connection moves a count;
/// taking turns keeps each test's wait for its connection clear of the
/// connections the others open and kill.
#[cfg(test)]
static SUBSCRIBER_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub use internal::ValkeyStoreError;
pub use registry::ValkeySessionRegistry;
pub use store::ValkeySessionStore;
