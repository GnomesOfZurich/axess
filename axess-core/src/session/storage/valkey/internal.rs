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

// ── Atomic cycle ─────────────────────────────────────────────────────────────

/// Write the rotated session and drop the old one in a single server-side
/// step.
///
/// KEYS: `[old_session, new_session]`. ARGV: `[payload, ttl_seconds,
/// require_old]` where `require_old` is `"1"` or `"0"`. The script returns
/// `0` and writes nothing when `require_old` is set and the old session is
/// not stored (a logout or revocation removed it after the request loaded
/// it), and `1` after the new session was written. The check, the SET and
/// the DEL run as one step, so of two racing rotations exactly one sees a
/// live old key. The SET runs before the DEL; if it errors the script aborts
/// before the DEL and the old session survives a failed write. When both ids
/// are the same key the DEL is skipped and the key is only rewritten while
/// it exists (under `require_old`), so cycling to the same id keeps the
/// session.
pub(super) const CYCLE_SCRIPT: &str = r#"
if ARGV[3] == '1' and redis.call('EXISTS', KEYS[1]) == 0 then
  return 0
end
redis.call('SET', KEYS[2], ARGV[1], 'EX', tonumber(ARGV[2]))
if KEYS[1] ~= KEYS[2] then
  redis.call('DEL', KEYS[1])
end
return 1
"#;

/// True when an `EVAL` failed because this deployment cannot run the cycle
/// script, as opposed to the write failing: scripting disabled or absent
/// (`unknown command`, `NOSCRIPT`, disabled by ACL) or the two keys living in
/// different cluster slots (`CROSSSLOT`). Only then does `cycle` fall back to
/// a sequenced SET then DEL; any other error is the caller's.
pub(super) fn script_unavailable(err: &fred::error::Error) -> bool {
    let text = err.details().to_ascii_lowercase();
    [
        "crossslot",
        "unknown command",
        "noscript",
        "scripting",
        "noperm",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

/// Replace a stored session blob with its re-sealed form, only while the key
/// still holds exactly the bytes that were read, and keep its expiry.
///
/// KEYS: `[session]`. ARGV: `[old_blob, new_blob]`. Returns `1` when the
/// blob was replaced and `0` when the key changed or went away meanwhile.
pub(super) const RESEAL_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
  redis.call('SET', KEYS[1], ARGV[2], 'KEEPTTL')
  return 1
end
return 0
"#;

// ── TTL helpers ──────────────────────────────────────────────────────────────

use std::time::Duration;

/// Seconds for a Valkey `EX` argument, or `None` when the TTL is already
/// spent.
///
/// `EX 0` is rejected by the server, and truncating a sub-second TTL with
/// `as_secs()` would produce exactly that, so any non-zero TTL is clamped up
/// to one second. A zero TTL means the session is already expired: the caller
/// must not store it.
pub(super) fn ex_seconds(ttl: Duration) -> Option<i64> {
    if ttl.is_zero() {
        return None;
    }
    Some(ttl.as_secs().clamp(1, i64::MAX as u64) as i64)
}

/// A registry member's lifetime in milliseconds (its score is the
/// registration instant, so it expires at `score + lifetime`).
pub(super) fn registry_member_ttl_ms(ttl: Duration) -> i64 {
    ttl.as_millis().min(i64::MAX as u128) as i64
}

/// True while a registry member registered at `score_ms` is still live.
pub(super) fn registry_member_live(score_ms: f64, now_ms: i64, member_ttl_ms: i64) -> bool {
    score_ms + member_ttl_ms as f64 > now_ms as f64
}

/// Scores at or below this value belong to expired members.
pub(super) fn registry_cutoff_ms(now_ms: i64, member_ttl_ms: i64) -> f64 {
    now_ms as f64 - member_ttl_ms as f64
}

/// Seconds for the registry key's own `EXPIRE`: at least the member
/// lifetime rounded up, and never below one second, so the key outlives the
/// newest member it holds and a sub-second TTL cannot wipe the set.
pub(super) fn registry_key_ttl_secs(ttl: Duration) -> i64 {
    let ms = registry_member_ttl_ms(ttl);
    (ms / 1000 + i64::from(ms % 1000 != 0)).max(1)
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
