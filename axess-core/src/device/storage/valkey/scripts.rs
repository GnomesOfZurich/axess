//! Lua scripts and the pure argument/status helpers around them.
//!
//! The device row is an opaque (optionally encrypted) MessagePack blob, so a
//! script cannot edit individual fields inside it. Every mutation is instead
//! an optimistic compare-and-swap on the whole blob: the caller reads the row,
//! computes the new row, and the script applies it only if the stored bytes
//! are still exactly the bytes that were read. A concurrent writer (for
//! example a revocation) makes the script answer `conflict`, and the caller
//! re-reads and decides again against the fresh row.
//!
//! Scripts touch the row and the fingerprint index (or a membership index and
//! the rows it lists), and the batched row reads address many row keys at
//! once, so a clustered deployment must give every key the same hash slot,
//! for instance with a prefix such as `{axess}` passed to `with_prefix`.

use fred::bytes::Bytes;
use fred::types::Value;

/// Replace the row only if it still holds the bytes the caller read, set or
/// clear its expiry, and keep the fingerprint index alive only while it still
/// points at this device.
///
/// KEYS: `[row, fingerprint_index]`.
/// ARGV: `[expected_row, new_row, ttl_seconds (0 = no expiry), device_id]`.
/// Replies `ok`, `missing` (no row) or `conflict` (row changed since read).
pub(super) const CAS_WRITE: &str = r#"
local current = redis.call('GET', KEYS[1])
if not current then
  return 'missing'
end
if current ~= ARGV[1] then
  return 'conflict'
end
local ttl = tonumber(ARGV[3])
if ttl > 0 then
  redis.call('SET', KEYS[1], ARGV[2], 'EX', ttl)
else
  redis.call('SET', KEYS[1], ARGV[2])
end
if redis.call('GET', KEYS[2]) == ARGV[4] then
  if ttl > 0 then
    redis.call('EXPIRE', KEYS[2], ttl)
  else
    redis.call('PERSIST', KEYS[2])
  end
end
return 'ok'
"#;

/// Delete the row (only if it still holds the expected bytes, when an
/// expectation is given) and delete the fingerprint index only if it still
/// points at this device.
///
/// KEYS: `[row, fingerprint_index]`.
/// ARGV: `[expected_row or empty for unconditional, device_id]`.
/// Replies `ok`, `missing` (no row; the index is still cleaned if it points
/// here) or `conflict` (row changed since read; nothing is deleted).
pub(super) const REMOVE_DEVICE: &str = r#"
local current = redis.call('GET', KEYS[1])
local status = 'ok'
if not current then
  status = 'missing'
elseif ARGV[1] ~= '' and current ~= ARGV[1] then
  return 'conflict'
else
  redis.call('DEL', KEYS[1])
end
if redis.call('GET', KEYS[2]) == ARGV[2] then
  redis.call('DEL', KEYS[2])
end
return status
"#;

/// Delete a fingerprint index key only if it still points at the given
/// device.
///
/// KEYS: `[fingerprint_index]`. ARGV: `[device_id]`. Replies `1` if deleted.
pub(super) const DELETE_IF_POINTS_AT: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
"#;

/// Remove members from a membership index, but only those whose row key no
/// longer exists. The existence check and the removal run as one step, so a
/// device saved again between a reader noticing its row was gone and the
/// cleanup keeps its index entry.
///
/// KEYS: `[index, row_1 .. row_n]`. ARGV: `[member_1 .. member_n]`, where
/// `row_i` is the row key of `member_i`. Replies the number of members
/// removed.
pub(super) const PRUNE_ABSENT: &str = r#"
local removed = 0
for i = 2, #KEYS do
  if redis.call('EXISTS', KEYS[i]) == 0 then
    removed = removed + redis.call('SREM', KEYS[1], ARGV[i - 1])
  end
end
return removed
"#;

/// Row keys for `members`, in order: the keys of one batched read.
pub(super) fn row_keys(prefix: &str, tenant: &str, members: &[String]) -> Vec<String> {
    members
        .iter()
        .map(|id| super::device_key(prefix, tenant, id))
        .collect()
}

/// A member id with the row bytes a batched read returned for it (`None`
/// when the row does not exist).
pub(super) type MemberRow = (String, Option<Vec<u8>>);

/// Pair each member with the bytes its batched read returned (`None` for a
/// nil reply). Fails when the reply count differs from the member count or a
/// reply is not a string.
pub(super) fn pair_replies(
    members: &[String],
    replies: Vec<Value>,
) -> Result<Vec<MemberRow>, String> {
    if members.len() != replies.len() {
        return Err(format!(
            "MGET returned {} replies for {} keys",
            replies.len(),
            members.len()
        ));
    }
    members
        .iter()
        .zip(replies)
        .map(|(id, reply)| match reply {
            Value::Null => Ok((id.clone(), None)),
            Value::Bytes(b) => Ok((id.clone(), Some(b.to_vec()))),
            Value::String(s) => Ok((id.clone(), Some(s.as_bytes().to_vec()))),
            other => Err(format!("MGET reply for {id} is not a string: {other:?}")),
        })
        .collect()
}

/// ARGV for [`PRUNE_ABSENT`].
pub(super) fn prune_args(members: &[String]) -> Vec<Value> {
    members.iter().map(|m| bytes(m.as_bytes())).collect()
}

/// Reply of [`CAS_WRITE`] and [`REMOVE_DEVICE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ScriptStatus {
    Ok,
    Missing,
    Conflict,
}

/// Map a script reply to a [`ScriptStatus`]; `None` for an unknown reply.
pub(super) fn parse_status(reply: &str) -> Option<ScriptStatus> {
    match reply {
        "ok" => Some(ScriptStatus::Ok),
        "missing" => Some(ScriptStatus::Missing),
        "conflict" => Some(ScriptStatus::Conflict),
        _ => None,
    }
}

fn bytes(b: &[u8]) -> Value {
    Value::Bytes(Bytes::copy_from_slice(b))
}

/// ARGV for [`CAS_WRITE`]. `ttl_seconds = None` writes the row without expiry.
pub(super) fn cas_write_args(
    expected: &[u8],
    new_row: &[u8],
    ttl_seconds: Option<i64>,
    device_id: &str,
) -> Vec<Value> {
    vec![
        bytes(expected),
        bytes(new_row),
        Value::Integer(ttl_seconds.unwrap_or(0)),
        bytes(device_id.as_bytes()),
    ]
}

/// ARGV for [`REMOVE_DEVICE`]. `expected = None` deletes unconditionally.
pub(super) fn remove_args(expected: Option<&[u8]>, device_id: &str) -> Vec<Value> {
    vec![bytes(expected.unwrap_or(&[])), bytes(device_id.as_bytes())]
}
