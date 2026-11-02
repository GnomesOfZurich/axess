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
