//! Three-way merge of a session that two requests wrote at once.

use super::SessionData;
use serde_json::{Map, Value};

/// Combine this request's changes with a write that landed meanwhile.
///
/// `base` is the row as this request loaded it, `local` the row as the
/// request left it, and `fresh` the row as the store holds it now, written
/// by a concurrent request. A field this request changed (it differs between
/// `base` and `local`) keeps the local value; every other field takes the
/// store's. The custom bag is merged key by key under the same rule, so a
/// key the concurrent request took stays taken unless this request set it
/// anew, a key this request set or removed is set or removed, and a key the
/// concurrent request added is kept. The revision and the refresh stamp are
/// the store's: the caller sets them for its write. This request's proof of
/// its device and of its key binding stays only beside the device and the
/// binding it proved: a merged row that takes another from the stored row
/// is not proven by this request.
pub(crate) fn merge_concurrent(
    base: &SessionData,
    local: &SessionData,
    fresh: &SessionData,
) -> SessionData {
    merge(base, local, fresh, true)
}

/// [`merge_concurrent`] for a rotation. One rule for what a concurrent
/// request wrote on the retired row: when the rotation changed the
/// authentication state (a login, a logout, a step-up), what it added there
/// is not carried into the new row, because the retired id may be known to
/// an attacker (an anonymous visitor could have planted it before the
/// login). That is a key it added to the custom bag, which the request
/// cleared or rebuilt on purpose, and a device it stamped that the row did
/// not name when this request loaded it. What it took stays taken: a key it
/// removed, a device it cleared.
pub(crate) fn merge_rotating(
    base: &SessionData,
    local: &SessionData,
    fresh: &SessionData,
) -> SessionData {
    merge(base, local, fresh, local.auth_state == base.auth_state)
}

fn merge(
    base: &SessionData,
    local: &SessionData,
    fresh: &SessionData,
    keep_additions: bool,
) -> SessionData {
    // The stored row's device, under the rule of `merge_rotating`: without
    // additions, one it gained after this request loaded it is not taken,
    // and the one this request loaded stands; one it cleared stays cleared.
    let fresh_device = if keep_additions {
        fresh.device_id
    } else {
        fresh.device_id.and(base.device_id)
    };
    let mut merged = SessionData {
        version: pick(&base.version, &local.version, &fresh.version),
        auth_state: pick(&base.auth_state, &local.auth_state, &fresh.auth_state),
        fingerprint: pick(&base.fingerprint, &local.fingerprint, &fresh.fingerprint),
        device_id: pick(&base.device_id, &local.device_id, &fresh_device),
        // This request's own answers, which no stored row carries; below,
        // they are withdrawn from a device or a binding they did not prove.
        device_proven: local.device_proven,
        device_key: local.device_key,
        key_proven: local.key_proven,
        key_binding: pick(&base.key_binding, &local.key_binding, &fresh.key_binding),
        custom: merge_custom(&base.custom, &local.custom, &fresh.custom, keep_additions),
        revision: fresh.revision,
        touched_at: fresh.touched_at,
        // A claim to end the session is the store's: a request that merges
        // its changes onto a claimed row leaves the claim in place.
        ending: fresh.ending,
    };
    // `pick` chose which side's binding is the candidate: this request's
    // when it changed one, else the stored one. The candidate stays only
    // while it is in force for the merged state. A sign-out that raced a
    // bind leaves a guest, and another person's sign-in leaves that person:
    // neither keeps a binding made for someone else. A step-up that raced a
    // registration is still the owner's session, and keeps it.
    merged.drop_binding_not_in_force();
    // The device `pick` chose holds only for the person it was resolved
    // for. A row as stored has passed this judgement, so the device of
    // either side was resolved for that side's person: this request's for
    // the person it began as, which `base` holds, and the stored row's for
    // the stored row's own person. Another person's sign-in that raced a
    // stamp of the first person's device does not take that device.
    let resolved_for = if local.device_id != base.device_id {
        base.auth_state.person_at_browser()
    } else {
        fresh.auth_state.person_at_browser()
    };
    merged.drop_device_not_in_force(resolved_for.as_ref());
    // A proof is of what this request held: the device it resolved, the
    // binding it loaded. Beside a device or a binding the merge took from
    // the stored row (a concurrent request's, or none), it would prove what
    // no request proved.
    if merged.device_id != local.device_id {
        merged.device_proven = false;
        merged.device_key = None;
    }
    if merged.key_binding != local.key_binding {
        merged.key_proven = false;
    }
    merged
}

/// The local value when this request changed it, the stored one otherwise.
fn pick<T: PartialEq + Clone>(base: &T, local: &T, fresh: &T) -> T {
    if local != base {
        local.clone()
    } else {
        fresh.clone()
    }
}

/// Key-by-key merge of the custom bags. A bag that is not a JSON object (a
/// guest's `null`, or a value an application stored whole) counts as empty
/// for the keys it holds; when none of the three is an object the whole
/// value is picked like any other field.
fn merge_custom(base: &Value, local: &Value, fresh: &Value, keep_additions: bool) -> Value {
    if ![base, local, fresh].iter().any(|bag| bag.is_object()) {
        return pick(base, local, fresh);
    }
    let empty = Map::new();
    Value::Object(merge_bags(
        base.as_object().unwrap_or(&empty),
        local.as_object().unwrap_or(&empty),
        fresh.as_object().unwrap_or(&empty),
        keep_additions,
    ))
}

fn merge_bags(
    base: &Map<String, Value>,
    local: &Map<String, Value>,
    fresh: &Map<String, Value>,
    keep_additions: bool,
) -> Map<String, Value> {
    let mut merged = fresh.clone();
    if !keep_additions {
        // Only what this request holds survives, less what a concurrent
        // request took from it.
        merged = local
            .keys()
            .filter_map(|key| fresh.get(key).map(|value| (key.clone(), value.clone())))
            .collect();
    }
    for key in base.keys().chain(local.keys()) {
        let (before, after) = (base.get(key), local.get(key));
        if before == after {
            continue;
        }
        match after {
            Some(value) => {
                merged.insert(key.clone(), value.clone());
            }
            None => {
                merged.remove(key);
            }
        }
    }
    merged
}

#[cfg(test)]
mod tests;
