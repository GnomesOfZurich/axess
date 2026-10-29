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
//! Scripts touch the row, the fingerprint index and the membership indexes
//! (tenant, user, refresh family) the row belongs to, and the batched row
//! reads address many row keys at once, so a clustered deployment must give
//! every key the same hash slot, for instance with a prefix such as `{axess}`
//! passed to `with_prefix`.

use fred::bytes::Bytes;
use fred::types::Value;

/// Write the row only if it still holds the bytes the caller read (or, for
/// an empty expectation, only if it does not exist), set or clear its
/// expiry, add the device to its fingerprint set, and apply the membership
/// changes that belong to the new row, all in one step.
///
/// The membership changes ride in the same script as the row write so the
/// row and its indexes cannot disagree, whatever order two writers' scripts
/// run in: a script that lands second sees the row the first one wrote and
/// conflicts instead of applying its own index changes to it.
///
/// The fingerprint index is a set of device ids, so devices that share a
/// fingerprint are all listed. A write also migrates the single-id string key
/// an earlier release used: when it points at this device it is deleted,
/// because the device is now listed in the set.
///
/// KEYS: `[row, fingerprint_set, legacy_fingerprint_key, member_index_1 ..
/// member_index_n]`.
/// ARGV: `[expected_row ("" = must not exist), new_row, ttl_seconds (0 = no
/// expiry), device_id, op_1 .. op_n]`.
/// `op_i` is `A` (add the device to set `i`), `R` (remove it) or `F` (delete
/// key `i`, a stale single-id fingerprint key, only if it points at this
/// device).
/// Replies `ok`, `missing` (a row was expected and there is none) or
/// `conflict` (the row is not what the caller read).
pub(super) const WRITE_ROW: &str = r#"
local current = redis.call('GET', KEYS[1])
if ARGV[1] == '' then
  if current then
    return 'conflict'
  end
else
  if not current then
    return 'missing'
  end
  if current ~= ARGV[1] then
    return 'conflict'
  end
end
local ttl = tonumber(ARGV[3])
if ttl > 0 then
  redis.call('SET', KEYS[1], ARGV[2], 'EX', ttl)
else
  redis.call('SET', KEYS[1], ARGV[2])
end
redis.call('SADD', KEYS[2], ARGV[4])
if redis.call('GET', KEYS[3]) == ARGV[4] then
  redis.call('DEL', KEYS[3])
end
for i = 4, #KEYS do
  local op = ARGV[i + 1]
  if op == 'A' then
    redis.call('SADD', KEYS[i], ARGV[4])
  elseif op == 'R' then
    redis.call('SREM', KEYS[i], ARGV[4])
  elseif op == 'F' then
    if redis.call('GET', KEYS[i]) == ARGV[4] then
      redis.call('DEL', KEYS[i])
    end
  end
end
return 'ok'
"#;

/// Replace the row with the same device sealed in the current format, only
/// if it still holds the bytes the reader decoded, keeping its expiry. The
/// device is unchanged, so the indexes are not touched.
///
/// KEYS: `[row]`. ARGV: `[expected_row, new_row]`.
/// Replies `ok`, `missing` (the row is gone) or `conflict` (the row is not
/// what the caller read; nothing is written).
pub(super) const RESEAL_ROW: &str = r#"
local current = redis.call('GET', KEYS[1])
if not current then
  return 'missing'
end
if current ~= ARGV[1] then
  return 'conflict'
end
redis.call('SET', KEYS[1], ARGV[2], 'KEEPTTL')
return 'ok'
"#;

/// Delete the row (only if it still holds the expected bytes, when an
/// expectation is given), remove the device from its fingerprint set (other
/// devices sharing the fingerprint stay listed), delete the single-id
/// fingerprint key of an earlier release only if it still points at this
/// device, and apply the membership removals, in one step.
///
/// KEYS: `[row, fingerprint_set, legacy_fingerprint_key, member_index_1 ..
/// member_index_n]`.
/// ARGV: `[expected_row or empty for unconditional, device_id, op_1 .. op_n]`
/// with `op_i` as in [`WRITE_ROW`].
/// Replies `ok`, `missing` (no row; the indexes are still cleaned) or
/// `conflict` (row changed since read; nothing is deleted).
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
redis.call('SREM', KEYS[2], ARGV[2])
if redis.call('GET', KEYS[3]) == ARGV[2] then
  redis.call('DEL', KEYS[3])
end
for i = 4, #KEYS do
  local op = ARGV[i - 1]
  if op == 'R' then
    redis.call('SREM', KEYS[i], ARGV[2])
  elseif op == 'F' then
    if redis.call('GET', KEYS[i]) == ARGV[2] then
      redis.call('DEL', KEYS[i])
    end
  end
end
return status
"#;

/// Delete a single-id fingerprint key (the layout of earlier releases) only
/// if it still points at the given
/// device and that device's row still holds the bytes the caller judged to
/// no longer match the fingerprint. A device saved again in the meantime
/// keeps its entry.
///
/// KEYS: `[fingerprint_index, row]`. ARGV: `[device_id, row_bytes_read]`.
/// Replies `1` if deleted.
pub(super) const DROP_STALE_FINGERPRINT: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] and redis.call('GET', KEYS[2]) == ARGV[2] then
  return redis.call('DEL', KEYS[1])
end
return 0
"#;

/// Delete a single-id fingerprint key (the layout of earlier releases) only
/// if it still points at the given device and that device's row is gone. The
/// row's native expiry removes it without touching the key, so nothing else
/// would ever clean the key up. A device saved again in the meantime keeps
/// its entry.
///
/// KEYS: `[fingerprint_index, row]`. ARGV: `[device_id]`.
/// Replies `1` if deleted.
pub(super) const DROP_ABSENT_FINGERPRINT: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] and redis.call('EXISTS', KEYS[2]) == 0 then
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

/// Remove members from a membership index whose row the reader found not
/// to belong there (another owner, another family), but only while the row
/// still holds the bytes the reader judged. Every write of a row moves its
/// index entries in the same script, so unchanged bytes mean no writer has
/// added the entry since; a row rewritten in the meantime keeps its entry.
///
/// KEYS: `[index, row_1 .. row_n]`. ARGV: `[member_1 .. member_n, bytes_1 ..
/// bytes_n]`, where `bytes_i` is the row `row_i` held when it was judged.
/// Replies the number of members removed.
pub(super) const PRUNE_MISMATCH: &str = r#"
local n = #KEYS - 1
local removed = 0
for i = 1, n do
  if redis.call('GET', KEYS[i + 1]) == ARGV[n + i] then
    removed = removed + redis.call('SREM', KEYS[1], ARGV[i])
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

/// Reply of [`WRITE_ROW`] and [`REMOVE_DEVICE`].
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

/// ARGV for [`WRITE_ROW`]. `expected = None` requires the row to be absent;
/// `ttl_seconds = None` writes the row without expiry; `ops` has one entry
/// per membership key after the first three.
pub(super) fn write_row_args(
    expected: Option<&[u8]>,
    new_row: &[u8],
    ttl_seconds: Option<i64>,
    device_id: &str,
    ops: &[&'static str],
) -> Vec<Value> {
    let mut args = vec![
        bytes(expected.unwrap_or(&[])),
        bytes(new_row),
        Value::Integer(ttl_seconds.unwrap_or(0)),
        bytes(device_id.as_bytes()),
    ];
    args.extend(ops.iter().map(|op| bytes(op.as_bytes())));
    args
}

/// ARGV for [`RESEAL_ROW`].
pub(super) fn reseal_args(expected: &[u8], new_row: &[u8]) -> Vec<Value> {
    vec![bytes(expected), bytes(new_row)]
}

/// ARGV for [`REMOVE_DEVICE`]. `expected = None` deletes unconditionally.
pub(super) fn remove_args(
    expected: Option<&[u8]>,
    device_id: &str,
    ops: &[&'static str],
) -> Vec<Value> {
    let mut args = vec![bytes(expected.unwrap_or(&[])), bytes(device_id.as_bytes())];
    args.extend(ops.iter().map(|op| bytes(op.as_bytes())));
    args
}

/// ARGV for [`PRUNE_MISMATCH`]: the members, then the bytes each was judged on.
pub(super) fn prune_mismatch_args(judged: &[(String, Vec<u8>)]) -> Vec<Value> {
    judged
        .iter()
        .map(|(m, _)| bytes(m.as_bytes()))
        .chain(judged.iter().map(|(_, raw)| bytes(raw)))
        .collect()
}
