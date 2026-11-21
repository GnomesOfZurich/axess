//! Shared internals for the Valkey session backend submodules.
//!
//! Holds the key-formatting helpers, default constants, and the
//! [`ValkeyStoreError`] type used by both
//! [`ValkeySessionStore`](super::ValkeySessionStore) and
//! [`ValkeySessionRegistry`](super::ValkeySessionRegistry).

use crate::session::id::SessionKey;
use fred::util::redis_keyslot;

pub(super) use super::registry_keys::{UserKeys, user_keys};

// ── Key helpers ──────────────────────────────────────────────────────────────

pub(super) const DEFAULT_PREFIX: &str = "axess";

/// Default maximum encoded session payload size: 64 KiB.
///
/// This guards against unbounded growth of `SessionData.custom` blowing up
/// Valkey memory. Configurable via
/// [`ValkeySessionStore::with_max_payload`](super::ValkeySessionStore::with_max_payload).
pub(super) const DEFAULT_MAX_PAYLOAD_BYTES: usize =
    crate::session::storage::session_codec::DEFAULT_MAX_PAYLOAD_BYTES;

/// The Valkey key of a session's row: the prefix, `sess`, and the 64
/// characters of the session's key. The session id, which a cookie carries,
/// is in no key name: a `SCAN` of the keyspace yields nothing a cookie
/// could carry.
pub(super) fn session_row_key(prefix: &str, key: &SessionKey) -> String {
    format!("{prefix}:sess:{key}")
}

/// The live members of a registry set in registration order, oldest first.
///
/// `live` pairs each live member with its score in the registry set (the
/// time it was last seen); `registered` holds, in the same order, the time it
/// was registered where the registration set has one. A member registered
/// before the registration set existed has none and is ordered by its score,
/// the best time known for it. Ties break on the member, so the order is the
/// same on every node.
pub(super) fn oldest_first(live: Vec<(String, f64)>, registered: &[Option<f64>]) -> Vec<String> {
    let mut rows: Vec<(f64, String)> = live
        .into_iter()
        .zip(registered.iter().copied().chain(std::iter::repeat(None)))
        .map(|((member, seen), at)| (at.unwrap_or(seen), member))
        .collect();
    rows.sort_by(|a, b| a.0.total_cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    rows.into_iter().map(|(_, member)| member).collect()
}

/// Pub/sub channel published when a single session is invalidated, named by
/// the 64 characters of the session's key.
pub(super) fn revocation_session_channel(prefix: &str, session: &str) -> String {
    format!("{prefix}:revoked-session:{session}")
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

/// How a two-key script is run on this deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScriptRoute {
    /// Send the script: a single node, or a cluster on which every key
    /// hashes to one slot.
    Script,
    /// Do not send it: the keys hash to different slots of a cluster, which
    /// the server refuses (`CROSSSLOT`) and the clustered client refuses
    /// itself when the slots are on different nodes. The caller takes its
    /// sequenced form.
    Sequenced,
}

/// Which way a script over `keys` runs, decided from the keys' hash slots
/// before anything is sent, so the choice does not hang on the wording of a
/// refusal: a clustered client checks the slots itself and answers in a
/// sentence of its own, which a client release may reword.
pub(super) fn script_route(clustered: bool, keys: [&str; 2]) -> ScriptRoute {
    let [first, second] = keys;
    if clustered && redis_keyslot(first.as_bytes()) != redis_keyslot(second.as_bytes()) {
        ScriptRoute::Sequenced
    } else {
        ScriptRoute::Script
    }
}

/// True when an `EVAL` failed because this deployment cannot run a script,
/// as opposed to the write failing: scripting disabled or absent (`unknown
/// command`, `NOSCRIPT`, disabled by ACL), or the server's `CROSSSLOT`,
/// which [`script_route`] keeps from arising for the store and [`user_keys`]
/// for the registry. These are the server's error codes, not a client's
/// sentence. Only then does the store's `cycle` fall back to its sequenced
/// form, the registry refuse to be built
/// ([`ValkeyStoreError::ScriptsRefused`]) and, on a server that stopped
/// running scripts after it was built, skip its orphan sweep; any other
/// error is the caller's.
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

/// Says once per store that a two-key script did not run and its sequenced
/// form ran instead, at `warn`, and at `debug` after that: on a cluster
/// without a hash-tag prefix that is every rotation of a session the request
/// did not load, the deployment's steady state, and one line names it.
#[derive(Debug, Default)]
pub(super) struct FallbackNotice {
    warned: std::sync::atomic::AtomicBool,
}

impl FallbackNotice {
    /// Record one sequenced run of `step` (the script that did not run) for
    /// `reason`.
    pub(super) fn note(&self, step: &'static str, reason: &str) {
        use std::sync::atomic::Ordering;
        if self.warned.swap(true, Ordering::Relaxed) {
            tracing::debug!(target: "axess::session::valkey", step, reason, "two-key script not run; sequenced form used");
        } else {
            tracing::warn!(
                target: "axess::session::valkey",
                step,
                reason,
                "two-key script not run; sequenced form used (said once; on a cluster, a hash-tag prefix such as {{axess}} in the store's prefix restores the script)"
            );
        }
    }
}

/// The reason a [`FallbackNotice`] gives for a [`ScriptRoute::Sequenced`]
/// route.
pub(super) const KEYS_IN_TWO_SLOTS: &str = "the two keys hash to different cluster slots";

/// Remove from the registration set every member that is not in the registry
/// set, in one server-side step, so a session registered meanwhile (in both
/// sets by the time the script reads them) is never taken for an orphan.
///
/// KEYS: `[registry, registered_at]`. Returns the number of members removed.
pub(super) const DROP_ORPHANS_SCRIPT: &str = r#"
local removed = 0
for _, member in ipairs(redis.call('ZRANGE', KEYS[2], 0, -1)) do
  if not redis.call('ZSCORE', KEYS[1], member) then
    redis.call('ZREM', KEYS[2], member)
    removed = removed + 1
  end
end
return removed
"#;

/// End every session of a user but one, in one server-side step, so that no
/// registration, move or ending falls between the look for the session to
/// keep and the last removal: a session registered before the script is
/// ended by it, and one registered after it came later.
///
/// KEYS: `[registry, registered_at, forward, forward_order]`, the user's
/// four keys, which share a slot. ARGV: `[keep, cutoff_ms]`; a member is
/// live while its score in `registry` is above `cutoff_ms`. Answers a list
/// whose first element says which case it is, and whose other elements are
/// the members removed from `registry`:
///
/// 1. `keep` is live: every other member of `registry` and of
///    `registered_at` is removed, and every record that does not lead to
///    `keep`; [`KEEP_ONE_HELD`] and the removed members.
/// 2. `keep` is not live and the record kept under it leads to a live
///    member: the session was moved to another key by another request, so
///    every member is listed and the four keys are deleted;
///    [`KEEP_ONE_MOVED`] and every member.
/// 3. Otherwise nothing is removed: [`KEEP_ONE_ABSENT`] alone.
///
/// The marker is what tells "held, and alone" from "not held": a client
/// reads an empty list and a nil alike as no value.
pub(super) const KEEP_ONE_SCRIPT: &str = r#"
local keep = ARGV[1]
local cutoff = tonumber(ARGV[2])
local function live(member)
  local score = redis.call('ZSCORE', KEYS[1], member)
  return score ~= false and tonumber(score) > cutoff
end
if live(keep) then
  local ended = {'held'}
  for _, member in ipairs(redis.call('ZRANGE', KEYS[1], 0, -1)) do
    if member ~= keep then
      redis.call('ZREM', KEYS[1], member)
      ended[#ended + 1] = member
    end
  end
  for _, member in ipairs(redis.call('ZRANGE', KEYS[2], 0, -1)) do
    if member ~= keep then
      redis.call('ZREM', KEYS[2], member)
    end
  end
  local fields = redis.call('HGETALL', KEYS[3])
  for i = 1, #fields, 2 do
    if fields[i + 1] ~= keep then
      redis.call('HDEL', KEYS[3], fields[i])
      redis.call('ZREM', KEYS[4], fields[i])
    end
  end
  return ended
end
local target = redis.call('HGET', KEYS[3], keep)
if target and live(target) then
  local ended = {'moved'}
  for _, member in ipairs(redis.call('ZRANGE', KEYS[1], 0, -1)) do
    ended[#ended + 1] = member
  end
  redis.call('DEL', KEYS[1], KEYS[2], KEYS[3], KEYS[4])
  return ended
end
return {'absent'}
"#;

/// The first element of [`KEEP_ONE_SCRIPT`]'s reply when the session to keep
/// was held: the removed members follow it.
pub(super) const KEEP_ONE_HELD: &str = "held";

/// The first element of [`KEEP_ONE_SCRIPT`]'s reply when the session to keep
/// had been moved to another key: every member of the user follows it, all
/// of them removed.
pub(super) const KEEP_ONE_MOVED: &str = "moved";

/// The only element of [`KEEP_ONE_SCRIPT`]'s reply when the session to keep
/// was neither held nor moved: nothing was removed.
pub(super) const KEEP_ONE_ABSENT: &str = "absent";

/// End one session by a key it is under or was under before a move, in one
/// server-side step.
///
/// KEYS: `[registry, registered_at, forward, forward_order]`. ARGV: `[key,
/// cutoff_ms]`. The target is `key` when it is live, else the live target
/// of the record kept under `key`, else there is none. Everything under
/// `key` goes (its member, its registration time, its record), then the
/// target's member and registration time, then every record that led to
/// the target. Answers the target, or the empty string when there was none,
/// so the caller knows which channel to tell besides `key`'s own.
pub(super) const END_ONE_SCRIPT: &str = r#"
local key = ARGV[1]
local cutoff = tonumber(ARGV[2])
local function live(member)
  local score = redis.call('ZSCORE', KEYS[1], member)
  return score ~= false and tonumber(score) > cutoff
end
local target = nil
if live(key) then
  target = key
else
  local moved_to = redis.call('HGET', KEYS[3], key)
  if moved_to and live(moved_to) then
    target = moved_to
  end
end
redis.call('ZREM', KEYS[1], key)
redis.call('ZREM', KEYS[2], key)
redis.call('HDEL', KEYS[3], key)
redis.call('ZREM', KEYS[4], key)
if target == nil then
  return ''
end
if target ~= key then
  redis.call('ZREM', KEYS[1], target)
  redis.call('ZREM', KEYS[2], target)
end
local fields = redis.call('HGETALL', KEYS[3])
for i = 1, #fields, 2 do
  if fields[i + 1] == target then
    redis.call('HDEL', KEYS[3], fields[i])
    redis.call('ZREM', KEYS[4], fields[i])
  end
end
return target
"#;

/// Move a session from one key to another in one server-side step, and
/// keep the record of the move: no registration, ending or cut-off of the
/// user falls between the look for `old` and the last write.
///
/// KEYS: `[registry, registered_at, forward, forward_order]`, the user's
/// four keys, which share a slot. ARGV: `[old, new, now_ms, cutoff_ms,
/// key_ttl_secs, max_records]`; a member is live while its score in
/// `registry` is above `cutoff_ms`. In this order:
///
/// 1. `old` not live: answer [`MOVE_GONE`] and touch nothing.
/// 2. `old == new`: renew its score, renew the four keys' expiry, answer
///    [`MOVE_MOVED`].
/// 3. Drop every record whose target is not live.
/// 4. At `max_records` records, give up the earliest record, by its place in
///    `forward_order`, that is not the first of the records with its target
///    (the first is that session's first former key, which no move gives
///    up); answer [`MOVE_FULL`] when every record is the first of its own.
/// 5. Put `new` in `old`'s place: `old`'s registration time (its score where
///    the registration set has none), a last-seen time of now.
/// 6. Re-point the records that led to `old` at `new`, write `old -> new`
///    last in the order, and drop any record kept under `new`.
/// 7. Renew the four keys' expiry and answer [`MOVE_MOVED`].
///
/// The liveness of each target is read once (`known`), so the prune costs
/// one `ZSCORE` per session, not per record.
pub(super) const MOVE_SCRIPT: &str = r#"
local old, new = ARGV[1], ARGV[2]
local cutoff = tonumber(ARGV[4])
local function live(member)
  local score = redis.call('ZSCORE', KEYS[1], member)
  return score ~= false and tonumber(score) > cutoff
end
local function renew()
  for i = 1, 4 do
    redis.call('EXPIRE', KEYS[i], ARGV[5])
  end
end
local seen_at = redis.call('ZSCORE', KEYS[1], old)
if not live(old) then
  return 'gone'
end
if old == new then
  redis.call('ZADD', KEYS[1], ARGV[3], old)
  renew()
  return 'moved'
end
local fields = redis.call('HGETALL', KEYS[3])
local known = {}
local kept = 0
for i = 1, #fields, 2 do
  local target = fields[i + 1]
  if known[target] == nil then
    known[target] = live(target)
  end
  if known[target] then
    kept = kept + 1
  else
    redis.call('HDEL', KEYS[3], fields[i])
    redis.call('ZREM', KEYS[4], fields[i])
  end
end
local given_up = nil
if kept >= tonumber(ARGV[6]) then
  local target_of = {}
  for i = 1, #fields, 2 do
    if known[fields[i + 1]] then
      target_of[fields[i]] = fields[i + 1]
    end
  end
  local first_seen = {}
  for _, field in ipairs(redis.call('ZRANGE', KEYS[4], 0, -1)) do
    local target = target_of[field]
    if target ~= nil then
      if first_seen[target] then
        given_up = field
        break
      end
      first_seen[target] = true
    end
  end
  if given_up == nil then
    return 'full'
  end
  redis.call('HDEL', KEYS[3], given_up)
  redis.call('ZREM', KEYS[4], given_up)
end
local registered = redis.call('ZSCORE', KEYS[2], old) or seen_at
redis.call('ZREM', KEYS[1], old)
redis.call('ZREM', KEYS[2], old)
redis.call('ZADD', KEYS[2], registered, new)
redis.call('ZADD', KEYS[1], ARGV[3], new)
for i = 1, #fields, 2 do
  if fields[i + 1] == old and fields[i] ~= given_up then
    redis.call('HSET', KEYS[3], fields[i], new)
  end
end
local last = redis.call('ZRANGE', KEYS[4], -1, -1, 'WITHSCORES')
local place = 1
if #last == 2 then
  place = tonumber(last[2]) + 1
end
redis.call('HSET', KEYS[3], old, new)
redis.call('ZADD', KEYS[4], place, old)
redis.call('HDEL', KEYS[3], new)
redis.call('ZREM', KEYS[4], new)
renew()
return 'moved'
"#;

/// [`MOVE_SCRIPT`]'s answer when the session was moved.
pub(super) const MOVE_MOVED: &str = "moved";

/// [`MOVE_SCRIPT`]'s answer when `old` was not live: nothing changed.
pub(super) const MOVE_GONE: &str = "gone";

/// [`MOVE_SCRIPT`]'s answer when every record is a first former key and none
/// can be given up: nothing changed.
pub(super) const MOVE_FULL: &str = "full";

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

/// Replace a stored session blob only while the key still holds exactly the
/// bytes that were compared, and give it a fresh expiry.
///
/// KEYS: `[session]`. ARGV: `[old_blob, new_blob, ttl_seconds]`. Returns `1`
/// when the blob was replaced, `0` when the key holds other bytes (a
/// concurrent write), and `-1` when the key is gone.
pub(super) const COMPARE_SET_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if not current then
  return -1
end
if current == ARGV[1] then
  redis.call('SET', KEYS[1], ARGV[2], 'EX', tonumber(ARGV[3]))
  return 1
end
return 0
"#;

/// Remove a stored session blob only while the key still holds exactly the
/// bytes that were compared: the zero-TTL form of a conditional write, where
/// the data to store is already expired.
///
/// Returns `1` when the key was removed, `0` when it holds other bytes, and
/// `-1` when there is no key.
pub(super) const COMPARE_DEL_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if not current then
  return -1
end
if current == ARGV[1] then
  redis.call('DEL', KEYS[1])
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
    (!ttl.is_zero()).then(|| live_ex_seconds(ttl))
}

/// Seconds for a Valkey `EX` argument of a TTL the caller knows is not zero:
/// whole seconds, clamped up to one and down to 2^40 (some 34 000 years):
/// the server turns the seconds into an absolute millisecond time and rejects
/// one that does not fit.
pub(super) fn live_ex_seconds(ttl: Duration) -> i64 {
    ttl.as_secs().clamp(1, EX_MAX_SECS as u64) as i64
}

/// The longest expiry given to a key: 2^40 seconds.
const EX_MAX_SECS: i64 = 1 << 40;

/// How often a watcher without a subscriber connection asks the registry
/// whether its session is still valid, before backoff and spread.
pub(super) const DEGRADED_POLL: Duration = Duration::from_secs(5);

/// The longest the degraded poll backs off to while the registry does not
/// answer.
pub(super) const DEGRADED_POLL_MAX: Duration = Duration::from_secs(60);

/// The wait before a degraded watcher's next poll of the registry. The
/// interval doubles from [`DEGRADED_POLL`] for each consecutive poll the
/// registry failed to answer, up to [`DEGRADED_POLL_MAX`], so the watchers
/// do not hammer a Valkey that is down; and `draw`, a random number, spreads
/// it uniformly over the quarter interval on either side, so the watchers
/// that lost one connection together do not poll in lockstep while it
/// recovers.
pub(super) fn degraded_poll_delay(failed_polls: u32, draw: u64) -> Duration {
    let interval = DEGRADED_POLL
        .saturating_mul(1u32 << failed_polls.min(16))
        .min(DEGRADED_POLL_MAX);
    let quarter = interval / 4;
    // The spread is `[0, 2 * quarter]` in whole milliseconds.
    let spread_ms = u64::try_from((quarter * 2).as_millis()).unwrap_or(u64::MAX);
    interval - quarter + Duration::from_millis(draw % spread_ms.saturating_add(1))
}

/// What a revocation watcher does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Watch {
    /// The session is revoked: the watch ends.
    Ended,
    /// The session is live: wait for events.
    Waiting,
    /// The registry cannot be trusted to have said so: poll it on a timer.
    /// Holds the count of consecutive polls it did not answer, which the next
    /// wait backs off on.
    Polling(u32),
}

/// What a degraded watcher does with the registry's answer to a poll: end the
/// watch when the session is revoked, otherwise keep polling with the count of
/// consecutive polls the registry failed to answer.
pub(super) fn after_degraded_poll<E>(answer: Result<bool, E>, failed_polls: u32) -> Watch {
    match answer {
        Ok(false) => Watch::Ended,
        Ok(true) => Watch::Polling(0),
        Err(_) => Watch::Polling(failed_polls.saturating_add(1)),
    }
}

/// What a subscribed watcher does with the registry's answer to a check it
/// made itself (after joining, after a dropped message): end the watch when
/// the session is revoked, wait for events when it is live. A registry that
/// did not answer is no evidence of liveness, so it moves the watcher into
/// the polling state.
pub(super) fn after_check<E>(answer: Result<bool, E>) -> Watch {
    match answer {
        Ok(false) => Watch::Ended,
        Ok(true) => Watch::Waiting,
        Err(_) => Watch::Polling(0),
    }
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
/// newest member it holds and a sub-second TTL cannot wipe the set. Capped at
/// [`REGISTRY_KEY_TTL_MAX_SECS`]: the server turns the seconds into an
/// absolute millisecond time and rejects one that does not fit.
pub(super) fn registry_key_ttl_secs(ttl: Duration) -> i64 {
    let ms = registry_member_ttl_ms(ttl);
    (ms / 1000 + i64::from(ms % 1000 != 0)).clamp(1, REGISTRY_KEY_TTL_MAX_SECS)
}

/// The longest expiry given to a registry key: 2^40 seconds, some 34 000
/// years, far inside what the server accepts.
const REGISTRY_KEY_TTL_MAX_SECS: i64 = EX_MAX_SECS;

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
    /// serves all four encrypted backends.
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

    /// The store or the registry cannot do what was asked; the text says
    /// what: the method, or a registry prefix under which one user's keys
    /// would lie in different cluster slots.
    #[error("not supported by this store: {0}")]
    Unsupported(&'static str),

    /// The server refuses scripts, which the session registry needs. Returned
    /// when the registry is built.
    #[error("the Valkey server refuses scripts, which the session registry needs: {0}")]
    ScriptsRefused(#[source] fred::error::Error),
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
