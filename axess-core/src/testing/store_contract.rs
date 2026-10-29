//! A conformance check for [`SessionStore::update_if_revision`], for the
//! stores the crate ships and for an adopter's own.

use crate::session::{
    data::SessionData,
    id::SessionId,
    store::{ConditionalUpdate, SessionStore},
};
use std::time::Duration;

/// Exercise the compare-and-swap contract of a session store and panic with a
/// message naming the broken rule:
///
/// - a write against the stored revision is `Written` and replaces the data;
/// - a write against any other revision is `Conflict` and changes nothing;
/// - of two writers holding the same revision exactly one is `Written`;
/// - a deleted row, and an id never stored, are `Gone`.
///
/// # Panics
///
/// On the first rule the store breaks, or on a store error.
pub async fn assert_update_if_revision_contract<S: SessionStore>(store: &S) {
    let ttl = Duration::from_secs(60);
    let id = SessionId::new(&axess_rng::SystemRng);
    let outcome = |r: Result<ConditionalUpdate, S::Error>| r.expect("update_if_revision errored");

    let stored = SessionData {
        revision: 3,
        ..SessionData::default()
    };
    store.save(&id, &stored, ttl).await.expect("save");
    let next = SessionData {
        revision: 4,
        custom: serde_json::json!({"k": 1}),
        ..SessionData::default()
    };

    assert_eq!(
        outcome(store.update_if_revision(&id, 9, &next, ttl).await),
        ConditionalUpdate::Conflict,
        "a write against another revision must conflict"
    );
    let unchanged = store.load(&id).await.expect("load").expect("row");
    assert_eq!(unchanged.revision, 3, "a conflict must write nothing");
    assert!(unchanged.custom.get("k").is_none());

    assert_eq!(
        outcome(store.update_if_revision(&id, 3, &next, ttl).await),
        ConditionalUpdate::Written,
        "a write against the stored revision must be written"
    );
    let written = store.load(&id).await.expect("load").expect("row");
    assert_eq!(written.revision, 4);
    assert_eq!(written.custom, serde_json::json!({"k": 1}));

    assert_eq!(
        outcome(store.update_if_revision(&id, 3, &next, ttl).await),
        ConditionalUpdate::Conflict,
        "a second writer holding the old revision must conflict"
    );

    // Each writer moves the revision on, as the session layer does.
    let racing = SessionData {
        revision: 5,
        ..next.clone()
    };
    let (a, b) = tokio::join!(
        store.update_if_revision(&id, 4, &racing, ttl),
        store.update_if_revision(&id, 4, &racing, ttl)
    );
    let mut results = [outcome(a), outcome(b)];
    results.sort_by_key(|r| *r == ConditionalUpdate::Conflict);
    assert_eq!(
        results,
        [ConditionalUpdate::Written, ConditionalUpdate::Conflict],
        "of two writers on one revision exactly one may write"
    );

    store.delete(&id).await.expect("delete");
    assert_eq!(
        outcome(store.update_if_revision(&id, 4, &next, ttl).await),
        ConditionalUpdate::Gone,
        "a deleted row is gone"
    );
    let never = SessionId::new(&axess_rng::SystemRng);
    assert_eq!(
        outcome(store.update_if_revision(&never, 0, &next, ttl).await),
        ConditionalUpdate::Gone,
        "an id never stored is gone"
    );
}
