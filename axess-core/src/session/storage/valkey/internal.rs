//! Shared internals for the Valkey session backend submodules.
//!
//! Holds the key-formatting helpers, default constants, and the
//! [`ValkeyStoreError`] type used by both
//! [`ValkeySessionStore`](super::ValkeySessionStore) and
//! [`ValkeySessionRegistry`](super::ValkeySessionRegistry).

use crate::session::id::SessionId;

// ── Key helpers ──────────────────────────────────────────────────────────────

pub(super) const DEFAULT_PREFIX: &str = "axess";

/// Default maximum encoded session payload size: 64 KiB.
///
/// This guards against unbounded growth of `SessionData.custom` blowing up
/// Valkey memory. Configurable via
/// [`ValkeySessionStore::with_max_payload`](super::ValkeySessionStore::with_max_payload).
pub(super) const DEFAULT_MAX_PAYLOAD_BYTES: usize = 64 * 1024;

pub(super) fn session_key(prefix: &str, id: &SessionId) -> String {
    format!("{prefix}:sess:{id}")
}

pub(super) fn registry_key(prefix: &str, user_id: &str) -> String {
    format!("{prefix}:reg:{user_id}")
}

/// Pub/sub channel published when a single session is invalidated.
pub(super) fn revocation_session_channel(prefix: &str, session_id: &str) -> String {
    format!("{prefix}:revoked-session:{session_id}")
}

/// Pub/sub channel published when all sessions for a user are invalidated.
pub(super) fn revocation_user_channel(prefix: &str, user_id: &str) -> String {
    format!("{prefix}:revoked-user:{user_id}")
}

// ── Error type ───────────────────────────────────────────────────────────────

/// Errors from the Valkey session store or registry.
///
/// Internal implementation details (fred, codec) are wrapped in
/// domain-level variants so callers don't need those crates in their
/// dependency tree.
#[derive(Debug, thiserror::Error)]
pub enum ValkeyStoreError {
    /// A network or protocol error communicating with Valkey.
    #[error("connection error: {0}")]
    Connection(#[source] fred::error::Error),

    /// Codec error: serialization, deserialization, or encryption
    /// failure. Valkey's `rmp_serde` + AES-GCM stack routes through the
    /// shared `SessionCodec` (`pub(crate)`) so a single codec contract
    /// serves all three encrypted backends.
    /// The wrapped `SqlStoreError` covers serialize-encode /
    /// deserialize-decode / crypto failure variants; the `SqlStoreError::Db`
    /// variant is unreachable on this path (Valkey
    /// never produces SQL errors).
    #[error("codec error: {0}")]
    Codec(#[from] crate::session::storage::session_codec::SqlStoreError),

    /// The encoded session payload exceeds the configured maximum size.
    #[error("encoded session payload too large ({size} bytes, max {max} bytes)")]
    PayloadTooLarge {
        /// Encoded payload length in bytes.
        size: usize,
        /// Configured maximum payload length in bytes.
        max: usize,
    },
}

impl From<fred::error::Error> for ValkeyStoreError {
    fn from(e: fred::error::Error) -> Self {
        Self::Connection(e)
    }
}

// The crypto round-trip lives behind
// [`SessionCodec`](crate::session::storage::session_codec::SessionCodec):
// the same codec the SQL backends use, so all three encrypted backends
// share one contract. Primitive crypto round-trip tests are in
// `session::crypto::tests`.
