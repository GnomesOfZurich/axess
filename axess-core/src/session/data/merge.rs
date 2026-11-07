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
/// the store's: the caller sets them for its write.
pub(crate) fn merge_concurrent(
    base: &SessionData,
    local: &SessionData,
    fresh: &SessionData,
) -> SessionData {
    merge(base, local, fresh, true)
}

/// [`merge_concurrent`] for a rotation that changed the authentication state
/// (a login, a logout, a step-up): the request cleared or rebuilt the custom
/// bag on purpose, so a key a concurrent request added to the retired row is
/// not carried into it (an anonymous visitor could have planted it before
/// the login). A key the concurrent request took still stays taken.
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
    SessionData {
        version: pick(&base.version, &local.version, &fresh.version),
        auth_state: pick(&base.auth_state, &local.auth_state, &fresh.auth_state),
        fingerprint: pick(&base.fingerprint, &local.fingerprint, &fresh.fingerprint),
        device_id: pick(&base.device_id, &local.device_id, &fresh.device_id),
        device_proven: pick(
            &base.device_proven,
            &local.device_proven,
            &fresh.device_proven,
        ),
        custom: merge_custom(&base.custom, &local.custom, &fresh.custom, keep_additions),
        revision: fresh.revision,
        touched_at: fresh.touched_at,
    }
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
mod tests {
    use super::*;
    use serde_json::json;

    fn with(custom: Value) -> SessionData {
        SessionData {
            custom,
            ..SessionData::default()
        }
    }

    #[test]
    fn a_key_the_concurrent_request_took_stays_taken() {
        let base = with(json!({"ceremony": "s", "cart": 0}));
        let mut local = base.clone();
        local.custom["cart"] = json!(1);
        let fresh = with(json!({"cart": 0}));
        let merged = merge_concurrent(&base, &local, &fresh);
        assert_eq!(merged.custom, json!({"cart": 1}));
    }

    #[test]
    fn a_key_this_request_set_or_removed_wins_and_concurrent_additions_are_kept() {
        let base = with(json!({"a": 1, "b": 1, "c": 1}));
        let local = with(json!({"a": 2, "c": 1, "mine": true}));
        let fresh = with(json!({"a": 1, "b": 9, "c": 9, "theirs": true}));
        let merged = merge_concurrent(&base, &local, &fresh);
        assert_eq!(
            merged.custom,
            json!({"a": 2, "c": 9, "mine": true, "theirs": true})
        );
    }

    #[test]
    fn a_key_set_anew_by_this_request_survives_a_concurrent_take() {
        let base = with(json!({"ceremony": "old"}));
        let local = with(json!({"ceremony": "new"}));
        let fresh = with(json!({}));
        assert_eq!(
            merge_concurrent(&base, &local, &fresh).custom,
            json!({"ceremony": "new"})
        );
    }

    #[test]
    fn a_guest_bag_counts_as_empty() {
        let base = with(Value::Null);
        let local = with(json!({"mine": 1}));
        let fresh = with(json!({"theirs": 2}));
        assert_eq!(
            merge_concurrent(&base, &local, &fresh).custom,
            json!({"mine": 1, "theirs": 2})
        );
        let untouched = merge_concurrent(&base, &base, &base);
        assert_eq!(untouched.custom, Value::Null);
    }

    #[test]
    fn top_level_fields_follow_the_same_rule_and_the_stored_revision_is_kept() {
        let base = SessionData::default();
        let mut local = base.clone();
        local.fingerprint = Some("mine".into());
        let mut fresh = base.clone();
        fresh.auth_state.set_authenticated(
            crate::authn::ids::testing::user("u"),
            crate::authn::ids::testing::tenant("t"),
            chrono::Utc::now(),
        );
        fresh.revision = 7;
        let merged = merge_concurrent(&base, &local, &fresh);
        assert_eq!(merged.fingerprint.as_deref(), Some("mine"));
        assert!(merged.auth_state.is_authenticated());
        assert_eq!(merged.revision, 7);
    }
}
