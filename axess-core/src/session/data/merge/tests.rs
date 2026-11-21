use super::*;
use serde_json::json;

fn with(custom: Value) -> SessionData {
    SessionData {
        custom,
        ..SessionData::default()
    }
}

/// When the tests' rows were signed in.
fn now() -> axess_clock::Timestamp {
    axess_clock::testing::MockClock::reference_time()
}

/// The person the tests' bindings are made for.
fn owner() -> crate::authn::ids::UserId {
    crate::authn::ids::testing::user("u")
}

/// A binding made for [`owner`], to the key `key`.
fn binding_to(key: u8) -> crate::device_key::SessionKeyBinding {
    crate::device_key::SessionKeyBinding {
        owner: owner(),
        tenant_id: crate::authn::ids::testing::tenant("t"),
        device_id: crate::authn::ids::testing::device("d"),
        thumbprint: crate::device_key::KeyThumbprint::from_bytes([key; 32]),
        bound_at: now(),
    }
}

/// A row signed in as `user`, holding `key_binding`.
fn signed_in_as(
    user: crate::authn::ids::UserId,
    key_binding: Option<crate::device_key::SessionKeyBinding>,
) -> SessionData {
    let mut row = SessionData {
        key_binding,
        ..SessionData::default()
    };
    row.auth_state
        .set_authenticated(user, crate::authn::ids::testing::tenant("t"), now());
    row
}

/// A row signed in as [`owner`], bound to one key or not bound.
fn bound(bound: bool) -> SessionData {
    signed_in_as(owner(), bound.then(|| binding_to(4)))
}

/// On a row that stays its owner's, the binding follows the rule of every
/// top-level field in every combination of a session that is not bound,
/// bound to one key and bound to another, under both merges: this
/// request's value when this request changed it, the stored one otherwise.
#[test]
fn the_binding_follows_the_field_rule_in_every_combination() {
    let states = [None, Some(binding_to(4)), Some(binding_to(5))];
    for base in states {
        for local in states {
            for fresh in states {
                let expected = if local == base { fresh } else { local };
                let (b, l, f) = (
                    signed_in_as(owner(), base),
                    signed_in_as(owner(), local),
                    signed_in_as(owner(), fresh),
                );
                for merged in [merge_concurrent(&b, &l, &f), merge_rotating(&b, &l, &f)] {
                    assert_eq!(
                        merged.key_binding, expected,
                        "base {base:?}, local {local:?}, fresh {fresh:?}"
                    );
                }
            }
        }
    }
}

/// A request that loaded the row before a registration bound it does not
/// write the binding away, and one that did not remove a binding never
/// drops it: the stored value stands unless this request changed it.
#[test]
fn a_binding_is_never_dropped_or_restored_by_a_request_that_did_not_change_it() {
    for rotating in [false, true] {
        let merge = if rotating {
            merge_rotating
        } else {
            merge_concurrent
        };
        // Loaded unbound, left unbound; bound meanwhile: stays bound.
        let merged = merge(&bound(false), &bound(false), &bound(true));
        assert!(merged.key_binding.is_some(), "rotating: {rotating}");
        // Loaded bound, left bound; the row is still bound.
        let merged = merge(&bound(true), &bound(true), &bound(true));
        assert!(merged.key_binding.is_some());
        // This request bound the session itself: its binding is written.
        let merged = merge(&bound(false), &bound(true), &bound(false));
        assert!(merged.key_binding.is_some());
        // Loaded bound, left bound; cleared meanwhile (a logout): the
        // binding does not come back.
        let merged = merge(&bound(true), &bound(true), &bound(false));
        assert!(merged.key_binding.is_none());
    }
}

/// A sign-out races a bind: one request loads the row unbound and clears
/// it, another binds it and writes first. The merged row is a guest's, for
/// whom no binding is in force, and holds none.
#[test]
fn a_sign_out_that_races_a_bind_leaves_no_binding() {
    let (loaded, bound_meanwhile) = (bound(false), bound(true));
    let signed_out = SessionData::default();
    for merged in [
        merge_concurrent(&loaded, &signed_out, &bound_meanwhile),
        merge_rotating(&loaded, &signed_out, &bound_meanwhile),
    ] {
        assert!(merged.auth_state.is_guest());
        assert_eq!(merged.key_binding, None);
    }
}

/// Another person's sign-in races a bind for the first: the merged row is
/// the second person's, and the first person's binding is not carried
/// into it.
#[test]
fn another_persons_sign_in_that_races_a_bind_leaves_no_binding() {
    let (loaded, bound_meanwhile) = (bound(false), bound(true));
    let other = signed_in_as(crate::authn::ids::testing::user("other"), None);
    for merged in [
        merge_concurrent(&loaded, &other, &bound_meanwhile),
        merge_rotating(&loaded, &other, &bound_meanwhile),
    ] {
        assert_eq!(merged.key_binding, None);
    }
}

/// A step-up begins while a registration binds: the step-up changed the
/// state and holds no binding of its own, the registration wrote one, and
/// the merged row, still the owner's session, keeps it.
#[test]
fn a_step_up_that_races_a_registration_keeps_the_binding() {
    let (loaded, bound_meanwhile) = (bound(false), bound(true));
    let mut stepping_up = loaded.clone();
    assert!(stepping_up.auth_state.begin_step_up(Vec::new()));
    for merged in [
        merge_concurrent(&loaded, &stepping_up, &bound_meanwhile),
        merge_rotating(&loaded, &stepping_up, &bound_meanwhile),
    ] {
        assert!(merged.auth_state.is_authenticating());
        assert_eq!(merged.key_binding, Some(binding_to(4)));
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

/// A rotation that changed the authentication state rebuilt the bag on
/// purpose: a key a concurrent request added to the retired row is not
/// carried over, while one this request holds keeps the stored value. A
/// rotation that left the authentication state alone keeps the addition.
#[test]
fn a_rotation_that_changed_the_authentication_drops_concurrent_additions() {
    let base = with(json!({"cart": 1}));
    let fresh = with(json!({"cart": 2, "planted": true}));
    let mut signed_in = base.clone();
    signed_in.auth_state.set_authenticated(
        crate::authn::ids::testing::user("u"),
        crate::authn::ids::testing::tenant("t"),
        axess_clock::testing::MockClock::reference_time(),
    );
    assert_eq!(
        merge_rotating(&base, &signed_in, &fresh).custom,
        json!({"cart": 2})
    );
    assert_eq!(
        merge_rotating(&base, &base, &fresh).custom,
        json!({"cart": 2, "planted": true})
    );
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
        axess_clock::testing::MockClock::reference_time(),
    );
    fresh.revision = 7;
    let merged = merge_concurrent(&base, &local, &fresh);
    assert_eq!(merged.fingerprint.as_deref(), Some("mine"));
    assert!(merged.auth_state.is_authenticated());
    assert_eq!(merged.revision, 7);
}

/// The first person's row names no device. This request turns the session
/// into another person's and leaves the device alone, while a concurrent
/// request of the same row stamps a device it resolved for the first
/// person: the merged row is the other person's and names no device.
#[test]
fn a_device_stamped_for_the_first_person_is_not_carried_to_another() {
    let other = crate::authn::ids::testing::user("other");
    let loaded = signed_in_as(owner(), None);
    let signed_in_by_other = signed_in_as(other, None);
    let mut stamped = loaded.clone();
    stamped.device_id = Some(crate::authn::ids::testing::device("d"));
    for merged in [
        merge_concurrent(&loaded, &signed_in_by_other, &stamped),
        merge_rotating(&loaded, &signed_in_by_other, &stamped),
    ] {
        assert_eq!(merged.auth_state.person_at_browser(), Some(other));
        assert_eq!(merged.device_id, None);
    }
}

/// While this request keeps the person (it leaves the state alone, or
/// begins a step-up), a device a concurrent request stamped is taken from
/// the stored row, as any field this request did not change is. A step-up
/// that rotates the id changed the state, and does not carry what was
/// added to the retired row, the device included.
#[test]
fn a_device_stamped_meanwhile_stays_while_the_person_does() {
    let device = Some(crate::authn::ids::testing::device("d"));
    let loaded = signed_in_as(owner(), None);
    let mut stepping_up = loaded.clone();
    assert!(stepping_up.auth_state.begin_step_up(Vec::new()));
    let mut stamped = loaded.clone();
    stamped.device_id = device;
    for local in [loaded.clone(), stepping_up.clone()] {
        assert_eq!(
            merge_concurrent(&loaded, &local, &stamped).device_id,
            device
        );
    }
    assert_eq!(merge_rotating(&loaded, &loaded, &stamped).device_id, device);
    assert_eq!(
        merge_rotating(&loaded, &stepping_up, &stamped).device_id,
        None
    );
}

/// A rotation that changed the authentication state does not carry a device
/// a concurrent request stamped on the retired row, as it does not carry a
/// key that request added to the custom bag: a login completed on a guest's
/// row leaves out a device planted on it meanwhile, and keeps the device
/// the row named when this request loaded it, which the request took as
/// the browser's. A device the concurrent request cleared stays cleared. A
/// rotation that left the state alone takes the stamp, as a write of an
/// unrotated session does.
#[test]
fn a_rotation_that_changed_the_authentication_does_not_carry_a_device_stamped_meanwhile() {
    let (planted, browsers) = (
        Some(crate::authn::ids::testing::device("planted")),
        Some(crate::authn::ids::testing::device("d")),
    );
    let guest = SessionData::default();
    let stamped = SessionData {
        device_id: planted,
        ..SessionData::default()
    };
    let signed_in = signed_in_as(owner(), None);
    assert_eq!(merge_rotating(&guest, &signed_in, &stamped).device_id, None);

    let on_the_browser = SessionData {
        device_id: browsers,
        ..SessionData::default()
    };
    let mut signed_in_on_it = signed_in.clone();
    signed_in_on_it.device_id = browsers;
    assert_eq!(
        merge_rotating(&on_the_browser, &signed_in_on_it, &stamped).device_id,
        browsers
    );
    assert_eq!(
        merge_rotating(&on_the_browser, &signed_in_on_it, &guest).device_id,
        None
    );

    assert_eq!(merge_rotating(&guest, &guest, &stamped).device_id, planted);
}

/// This request proved its device and left it alone, while a concurrent
/// request stamped another device on the row, unproven: the merged row
/// names the stored device, and this request's proof (its flag and its
/// key) does not make that device proven. With the device unchanged on the
/// stored row, the proof stays.
#[test]
fn a_device_taken_from_the_stored_row_is_not_proven_by_this_request() {
    let (mine, theirs) = (
        crate::authn::ids::testing::device("d1"),
        crate::authn::ids::testing::device("d2"),
    );
    let mut loaded = signed_in_as(owner(), None);
    loaded.device_id = Some(mine);
    let mut proven = loaded.clone();
    proven.device_proven = true;
    proven.device_key = Some(crate::device_key::ProvenKey {
        tenant: crate::authn::ids::testing::tenant("t"),
        device: mine,
        thumbprint: crate::device_key::KeyThumbprint::from_bytes([4; 32]),
    });
    let mut stamped = loaded.clone();
    stamped.device_id = Some(theirs);
    let mut touched = loaded.clone();
    touched.custom = json!({"cart": 1});
    for merge_rows in [merge_concurrent, merge_rotating] {
        let merged = merge_rows(&loaded, &proven, &stamped);
        assert_eq!(merged.device_id, Some(theirs));
        assert!(!merged.device_proven);
        assert_eq!(merged.device_key, None);

        let merged = merge_rows(&loaded, &proven, &touched);
        assert_eq!(merged.device_id, Some(mine));
        assert!(merged.device_proven);
        assert_eq!(merged.device_key, proven.device_key);
    }
}

/// This request proved the key of the binding it loaded, while a
/// concurrent request bound the row to another key: the merged row holds
/// the stored binding, which this request's proof does not prove. With the
/// binding unchanged on the stored row, the proof stays.
#[test]
fn a_binding_taken_from_the_stored_row_is_not_proven_by_this_request() {
    let loaded = bound(true);
    let mut proved = loaded.clone();
    proved.key_proven = true;
    let rebound = signed_in_as(owner(), Some(binding_to(5)));
    let mut touched = loaded.clone();
    touched.custom = json!({"cart": 1});
    for merge_rows in [merge_concurrent, merge_rotating] {
        let merged = merge_rows(&loaded, &proved, &rebound);
        assert_eq!(merged.key_binding, Some(binding_to(5)));
        assert!(!merged.key_proven);

        assert!(merge_rows(&loaded, &proved, &touched).key_proven);
    }
}
