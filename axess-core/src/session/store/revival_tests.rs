//! A session that was ended must stay ended: `update` and `cycle` never
//! write a row back for a session that is no longer stored. The checks are
//! generic over [`SessionStore`] so every backend runs the same ones.

use super::*;
use axess_rng::SystemRng;

const TTL: Duration = Duration::from_secs(60);

fn data(tag: &str) -> SessionData {
    SessionData {
        custom: serde_json::json!({ "tag": tag }),
        ..SessionData::default()
    }
}

fn ids() -> (SessionId, SessionId) {
    (SessionId::new(&SystemRng), SessionId::new(&SystemRng))
}

/// `update` replaces a stored session and refuses a deleted one.
pub(crate) async fn update_never_revives<S: SessionStore>(store: &S) {
    let (id, _) = ids();
    store.save(&id, &data("first"), TTL).await.unwrap();
    assert!(store.update(&id, &data("second"), TTL).await.unwrap());
    let loaded = store.load(&id).await.unwrap().expect("still stored");
    assert_eq!(loaded.custom, data("second").custom);

    store.delete(&id).await.unwrap();
    assert!(
        !store.update(&id, &data("third"), TTL).await.unwrap(),
        "update of a deleted session reports it gone"
    );
    assert!(
        store.load(&id).await.unwrap().is_none(),
        "update must not bring a deleted session back"
    );

    let (never_saved, _) = ids();
    assert!(!store.update(&never_saved, &data("x"), TTL).await.unwrap());
    assert!(store.load(&never_saved).await.unwrap().is_none());
}

/// A rotation that requires its old row does not carry the data over when the
/// old row was deleted, and still works when the old row is live.
pub(crate) async fn cycle_with_required_old_never_revives<S: SessionStore>(store: &S) {
    let (old, new) = ids();
    store.save(&old, &data("auth"), TTL).await.unwrap();
    store.delete(&old).await.unwrap();
    assert_eq!(
        store
            .cycle(&old, &new, &data("auth"), TTL, true)
            .await
            .unwrap(),
        CycleOutcome::SessionGone
    );
    assert!(
        store.load(&new).await.unwrap().is_none(),
        "the rotated id must not hold the data of an ended session"
    );

    let (old, new) = ids();
    store.save(&old, &data("auth"), TTL).await.unwrap();
    assert_eq!(
        store
            .cycle(&old, &new, &data("auth"), TTL, true)
            .await
            .unwrap(),
        CycleOutcome::Rotated
    );
    assert!(store.load(&old).await.unwrap().is_none());
    assert!(store.load(&new).await.unwrap().is_some());
}

/// With `require_old == false` the old id may never have been stored (a
/// login on a fresh guest) and the new row is written anyway.
pub(crate) async fn cycle_without_required_old_creates<S: SessionStore>(store: &S) {
    let (old, new) = ids();
    assert_eq!(
        store
            .cycle(&old, &new, &data("fresh"), TTL, false)
            .await
            .unwrap(),
        CycleOutcome::Rotated
    );
    assert!(store.load(&new).await.unwrap().is_some());
}

/// Cycling a session to its own id requires the row to exist too.
pub(crate) async fn same_id_cycle_requires_the_row<S: SessionStore>(store: &S) {
    let (id, _) = ids();
    store.save(&id, &data("auth"), TTL).await.unwrap();
    assert_eq!(
        store
            .cycle(&id, &id, &data("again"), TTL, true)
            .await
            .unwrap(),
        CycleOutcome::Rotated
    );
    store.delete(&id).await.unwrap();
    assert_eq!(
        store
            .cycle(&id, &id, &data("again"), TTL, true)
            .await
            .unwrap(),
        CycleOutcome::SessionGone
    );
    assert!(store.load(&id).await.unwrap().is_none());
}

/// A rotation conditional on the revision rotates a row that holds it, answers
/// a conflict for a row that was written meanwhile (and leaves it alone), and
/// treats a row that is gone like `cycle`.
pub(crate) async fn cycle_if_revision_checks_the_revision<S: SessionStore>(store: &S) {
    let at = |tag: &str, revision: u64| SessionData {
        revision,
        ..data(tag)
    };
    let (old, new) = ids();
    store.save(&old, &at("seen", 3), TTL).await.unwrap();

    // Another request wrote the row after it was read at revision 3.
    store
        .save(&old, &at("written meanwhile", 4), TTL)
        .await
        .unwrap();
    assert_eq!(
        store
            .cycle_if_revision(&old, &new, &at("mine", 4), TTL, true, 3)
            .await
            .unwrap(),
        CycleOutcome::Conflict
    );
    assert_eq!(
        store.load(&old).await.unwrap().expect("left alone").custom,
        data("written meanwhile").custom
    );
    assert!(store.load(&new).await.unwrap().is_none(), "nothing written");

    assert_eq!(
        store
            .cycle_if_revision(&old, &new, &at("mine", 5), TTL, true, 4)
            .await
            .unwrap(),
        CycleOutcome::Rotated
    );
    assert!(store.load(&old).await.unwrap().is_none());
    assert_eq!(
        store.load(&new).await.unwrap().unwrap().custom,
        data("mine").custom
    );

    // A row that is gone is gone when it was required, and created when not.
    let (gone, next) = ids();
    assert_eq!(
        store
            .cycle_if_revision(&gone, &next, &at("x", 1), TTL, true, 0)
            .await
            .unwrap(),
        CycleOutcome::SessionGone
    );
    assert!(store.load(&next).await.unwrap().is_none());
    assert_eq!(
        store
            .cycle_if_revision(&gone, &next, &at("x", 1), TTL, false, 0)
            .await
            .unwrap(),
        CycleOutcome::Rotated
    );
    assert!(store.load(&next).await.unwrap().is_some());

    // To the same id, the revision decides as well.
    let (same, _) = ids();
    store.save(&same, &at("a", 7), TTL).await.unwrap();
    assert_eq!(
        store
            .cycle_if_revision(&same, &same, &at("b", 8), TTL, true, 6)
            .await
            .unwrap(),
        CycleOutcome::Conflict
    );
    assert_eq!(
        store
            .cycle_if_revision(&same, &same, &at("b", 8), TTL, true, 7)
            .await
            .unwrap(),
        CycleOutcome::Rotated
    );
    assert_eq!(
        store.load(&same).await.unwrap().unwrap().custom,
        data("b").custom
    );
}

/// Run every check against one store.
pub(crate) async fn run_all<S: SessionStore>(store: &S) {
    cycle_if_revision_checks_the_revision(store).await;
    update_never_revives(store).await;
    cycle_with_required_old_never_revives(store).await;
    cycle_without_required_old_creates(store).await;
    same_id_cycle_requires_the_row(store).await;
}

#[tokio::test]
async fn memory_store_never_revives_an_ended_session() {
    run_all(&MemorySessionStore::new()).await;
}

/// An expired row counts as ended for `update` and `cycle`.
#[tokio::test]
async fn memory_store_treats_an_expired_row_as_ended() {
    let clock = Arc::new(axess_clock::testing::MockClock::now());
    let store = MemorySessionStore::new().with_clock(clock.clone());
    let (old, new) = ids();
    store.save(&old, &data("auth"), TTL).await.unwrap();
    clock.advance(chrono::Duration::seconds(61));
    assert!(!store.update(&old, &data("late"), TTL).await.unwrap());
    assert_eq!(
        store
            .cycle(&old, &new, &data("late"), TTL, true)
            .await
            .unwrap(),
        CycleOutcome::SessionGone
    );
    assert!(store.load(&new).await.unwrap().is_none());
}
