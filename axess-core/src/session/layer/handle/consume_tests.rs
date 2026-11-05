//! A consumed value against a store that another request wrote meanwhile:
//! the request that lost the compare-and-swap hands out what is stored, and
//! its retry carries the concurrent write along instead of overwriting it.

use super::*;
use crate::session::store::{ConditionalUpdate, MemorySessionStore, SessionStore};

/// The row at `id` as the store holds it.
async fn stored(store: &MemorySessionStore, id: &SessionId) -> SessionData {
    SessionStore::load(store, id).await.unwrap().unwrap()
}
use crate::testing::mock_random::MockRng;

const TTL: Duration = Duration::from_secs(600);

fn bag(pairs: &[(&str, &str)]) -> serde_json::Value {
    serde_json::Value::Object(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), serde_json::json!(v)))
            .collect(),
    )
}

/// The in-memory state of a request that loaded `loaded` from `store`.
fn request_holding(
    store: &MemorySessionStore,
    id: SessionId,
    loaded: &SessionData,
) -> SessionInner {
    SessionInner {
        id,
        data: loaded.clone(),
        modified: false,
        needs_persist: false,
        regenerate: false,
        pre_cycle_id: None,
        pending_fingerprint: None,
        max_custom_bytes: 0,
        rng: Arc::new(MockRng::new(1)),
        consume: Some(ConsumeTarget {
            store: Arc::new(store.clone()),
            ttl: TTL,
            loaded: Some(loaded.clone()),
        }),
    }
}

/// Write `custom` over the row at `id` as a concurrent request would: a
/// compare-and-swap from the revision `loaded` carries.
async fn concurrent_write(
    store: &MemorySessionStore,
    id: &SessionId,
    loaded: &SessionData,
    custom: serde_json::Value,
) {
    let mut written = loaded.clone();
    written.custom = custom;
    written.revision = loaded.revision.wrapping_add(1);
    assert_eq!(
        SessionStore::update_if_revision(store, id, loaded.revision, &written, TTL)
            .await
            .unwrap(),
        ConditionalUpdate::Written
    );
}

/// Request A loaded the session, then request B stored a new one-shot value
/// and other data. A's take hands out the value B stored, never the stale
/// copy, and leaves B's other data in place.
#[tokio::test]
async fn a_take_that_lost_the_swap_hands_out_the_stored_value_and_keeps_the_concurrent_write() {
    let store = MemorySessionStore::new();
    let id = SessionId::new(&MockRng::new(1));
    let loaded = SessionData {
        custom: bag(&[("reg_state", "S1"), ("csrf", "T1")]),
        ..SessionData::default()
    };
    store.save(&id, &loaded, TTL).await.unwrap();
    let mut a = request_holding(&store, id, &loaded);
    concurrent_write(
        &store,
        &id,
        &loaded,
        bag(&[("user", "alice"), ("csrf", "T2"), ("reg_state", "S2")]),
    )
    .await;

    let taken = a.consume_custom("reg_state").await;

    assert_eq!(
        taken,
        Some(serde_json::json!("S2")),
        "the value handed out is the one stored, never the stale copy"
    );
    let stored = stored(&store, &id).await;
    assert_eq!(
        stored.custom,
        bag(&[("user", "alice"), ("csrf", "T2")]),
        "the concurrent write survives, less the taken value"
    );
    assert_eq!(
        a.data.custom, stored.custom,
        "the request goes on with the row as stored"
    );
    assert_eq!(a.data.revision, stored.revision);
}

/// A change this request made before the take is kept by the retry: the
/// stored row is the concurrent write with this request's own edits on top.
#[tokio::test]
async fn a_take_that_lost_the_swap_keeps_this_requests_own_changes() {
    let store = MemorySessionStore::new();
    let id = SessionId::new(&MockRng::new(2));
    let loaded = SessionData {
        custom: bag(&[("reg_state", "S1")]),
        ..SessionData::default()
    };
    store.save(&id, &loaded, TTL).await.unwrap();
    let mut a = request_holding(&store, id, &loaded);
    a.data.custom["cart"] = serde_json::json!(1);
    a.modified = true;
    concurrent_write(
        &store,
        &id,
        &loaded,
        bag(&[("reg_state", "S2"), ("csrf", "T2")]),
    )
    .await;

    assert_eq!(
        a.consume_custom("reg_state").await,
        Some(serde_json::json!("S2"))
    );
    let stored = stored(&store, &id).await;
    assert_eq!(stored.custom["cart"], serde_json::json!(1));
    assert_eq!(stored.custom["csrf"], serde_json::json!("T2"));
    assert!(stored.custom.get("reg_state").is_none());
}

/// A value the concurrent write already took is not handed out twice.
#[tokio::test]
async fn a_take_that_lost_the_swap_to_another_take_gets_nothing() {
    let store = MemorySessionStore::new();
    let id = SessionId::new(&MockRng::new(3));
    let loaded = SessionData {
        custom: bag(&[("reg_state", "S1")]),
        ..SessionData::default()
    };
    store.save(&id, &loaded, TTL).await.unwrap();
    let mut a = request_holding(&store, id, &loaded);
    concurrent_write(&store, &id, &loaded, bag(&[])).await;

    assert_eq!(a.consume_custom("reg_state").await, None);
    assert!(stored(&store, &id).await.custom.get("reg_state").is_none());
}

/// A take made after the session was promoted and its id rotated writes only
/// the removal to the row under the id the request arrived with: that id may
/// be known to an attacker, so the authenticated state must reach only the
/// row under the new id (written by the response).
#[tokio::test]
async fn a_take_after_the_id_rotated_does_not_write_the_login_to_the_old_row() {
    let store = MemorySessionStore::new();
    let id = SessionId::new(&MockRng::new(4));
    let loaded = SessionData {
        custom: bag(&[("reg_state", "S1"), ("csrf", "T1")]),
        ..SessionData::default()
    };
    store.save(&id, &loaded, TTL).await.unwrap();
    let mut a = request_holding(&store, id, &loaded);
    a.data.auth_state.set_authenticated(
        axess_identity::testing::user("u-fix"),
        axess_identity::testing::tenant("t-fix"),
        chrono::Utc::now(),
    );
    a.data.fingerprint = Some("fp".into());
    a.modified = true;
    a.rotate_id();

    let taken = a.consume_custom("reg_state").await;

    assert_eq!(taken, Some(serde_json::json!("S1")));
    let old_row = stored(&store, &id).await;
    assert!(
        !old_row.auth_state.is_authenticated(),
        "the row under the pre-rotation id must never hold the login"
    );
    assert_eq!(old_row.fingerprint, None);
    assert!(
        old_row.custom.get("reg_state").is_none(),
        "the take is stored"
    );
    assert!(
        a.data.auth_state.is_authenticated(),
        "the request goes on authenticated, for the response to store under the new id"
    );
    assert!(a.consume_custom("reg_state").await.is_none());
}

/// A rotated request that takes a value after a concurrent request took
/// another: the merge the retry made onto the row reaches the data the
/// response stores under the new id, so the value the other request took
/// does not come back.
#[tokio::test]
async fn a_rotated_take_that_lost_the_swap_carries_the_concurrent_take_into_its_data() {
    let store = MemorySessionStore::new();
    let id = SessionId::new(&MockRng::new(5));
    let loaded = SessionData {
        custom: bag(&[("k1", "one"), ("k2", "two")]),
        ..SessionData::default()
    };
    store.save(&id, &loaded, TTL).await.unwrap();
    let mut a = request_holding(&store, id, &loaded);
    a.data.auth_state.set_authenticated(
        axess_identity::testing::user("u-fix"),
        axess_identity::testing::tenant("t-fix"),
        chrono::Utc::now(),
    );
    a.modified = true;
    a.rotate_id();
    // Request B takes k2 before A takes k1.
    concurrent_write(&store, &id, &loaded, bag(&[("k1", "one")])).await;

    let taken = a.consume_custom("k1").await;

    assert_eq!(taken, Some(serde_json::json!("one")));
    assert!(
        a.data.custom.get("k2").is_none(),
        "the value another request took must not travel to the new id: {:?}",
        a.data.custom
    );
    assert!(a.data.custom.get("k1").is_none());
    assert!(a.data.auth_state.is_authenticated());
}
