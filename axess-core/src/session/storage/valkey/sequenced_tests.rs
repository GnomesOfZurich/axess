//! The sequenced form of the store's two-key rotation script against a
//! running Valkey (`VALKEY_URL`): a server that refuses scripts gets the same
//! rotation as one that runs them, and a server that runs them never takes
//! the sequenced form. The tests that need the server are ignored by default
//! and run by `scripts/check-live-stores.sh`; each removes what it wrote,
//! also when it fails.

use super::fallback_tests::{sequenced_runs, with_scripting_refused};
use super::registry_tests::connect;
use super::store::ValkeySessionStore;
use crate::session::data::SessionData;
use crate::session::id::{SessionId, SessionKey};
use crate::session::store::{CycleOutcome, SessionStore};
use crate::testing::valkey_sweep::KeySweep;
use axess_rng::SystemRng;
use axess_testing::mock_tracing::TracingCapture;
use fred::prelude::*;
use std::time::Duration;

const TTL: Duration = Duration::from_secs(60);

/// A store on `client` under `prefix`, which a test takes from its sweep.
fn store_on(client: Client, prefix: &str) -> ValkeySessionStore {
    ValkeySessionStore::new(client, crate::testing::test_key(4)).with_prefix(prefix)
}

/// The sweep that removes a test's keys when it ends, also when it fails.
fn sweep() -> KeySweep {
    crate::testing::valkey_sweep::on_node("seq")
}

fn revision(n: u64) -> SessionData {
    SessionData {
        revision: n,
        ..SessionData::default()
    }
}

async fn revision_at(store: &ValkeySessionStore, id: &SessionKey) -> Option<u64> {
    store.load(id).await.expect("a load").map(|d| d.revision)
}

/// Each rotation `store` can be asked for, with what it must leave behind.
async fn rotations_hold(store: &ValkeySessionStore) {
    let (old, new) = (
        SessionKey::of(&SessionId::new(&SystemRng)),
        SessionKey::of(&SessionId::new(&SystemRng)),
    );
    store.save(&old, &revision(1), TTL).await.expect("a save");
    let moved = store.cycle(&old, &new, &revision(2), TTL, true).await;
    assert_eq!(moved.expect("a rotation"), CycleOutcome::Rotated);
    assert_eq!(revision_at(store, &old).await, None, "the old id is gone");
    assert_eq!(
        revision_at(store, &new).await,
        Some(2),
        "the new id holds it"
    );

    let (gone, next) = (
        SessionKey::of(&SessionId::new(&SystemRng)),
        SessionKey::of(&SessionId::new(&SystemRng)),
    );
    let refused = store.cycle(&gone, &next, &revision(3), TTL, true).await;
    assert_eq!(refused.expect("a rotation"), CycleOutcome::SessionGone);
    assert_eq!(revision_at(store, &next).await, None, "nothing was written");

    let unrequired = store.cycle(&gone, &next, &revision(4), TTL, false).await;
    assert_eq!(unrequired.expect("a rotation"), CycleOutcome::Rotated);
    assert_eq!(revision_at(store, &next).await, Some(4));

    let in_place = SessionKey::of(&SessionId::new(&SystemRng));
    store
        .save(&in_place, &revision(5), TTL)
        .await
        .expect("a save");
    let kept = store
        .cycle(&in_place, &in_place, &revision(6), TTL, true)
        .await;
    assert_eq!(kept.expect("a rotation"), CycleOutcome::Rotated);
    assert_eq!(revision_at(store, &in_place).await, Some(6));

    let absent = SessionKey::of(&SessionId::new(&SystemRng));
    let required = store.cycle(&absent, &absent, &revision(7), TTL, true).await;
    assert_eq!(required.expect("a rotation"), CycleOutcome::SessionGone);
    assert_eq!(
        revision_at(store, &absent).await,
        None,
        "nothing was written"
    );
}

/// A server that refuses scripts rotates as one that runs them: the session
/// moves to the new id, a required session that is gone is reported and
/// nothing is written, and a rotation in place keeps the id. Each of the
/// five rotations takes the sequenced form there, and none does on the
/// server that runs scripts.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_sequenced_rotation_moves_the_session_as_the_script_does() {
    let capture = TracingCapture::install();
    let sweep = sweep();
    let refused = format!("{}_refused", sweep.prefix());
    with_scripting_refused(|_, restricted| async move {
        rotations_hold(&store_on(restricted, &refused)).await;
    })
    .await;
    assert_eq!(
        sequenced_runs(&capture, "session cycle"),
        5,
        "every rotation took the sequenced form: {:#?}",
        capture.events()
    );

    let scripted = format!("{}_scripted", sweep.prefix());
    rotations_hold(&store_on(connect().await, &scripted)).await;
    assert_eq!(
        sequenced_runs(&capture, "session cycle"),
        5,
        "the server that runs scripts runs the script: {:#?}",
        capture.events()
    );
}

/// On a single node that runs scripts, a rotation runs the script and never
/// says it took the sequenced form.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_single_node_rotation_runs_the_script() {
    let sweep = sweep();
    let store = store_on(connect().await, sweep.prefix());
    let capture = TracingCapture::install();
    rotations_hold(&store).await;
    assert!(
        !capture
            .events()
            .iter()
            .any(|e| e.message.contains("sequenced form used")),
        "{:#?}",
        capture.events()
    );
}

/// An expired rotation leaves the session under neither id, even where
/// something is already stored under the new one.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_an_expired_rotation_removes_both_ids() {
    let sweep = sweep();
    let store = store_on(connect().await, sweep.prefix());
    let (old, new) = (
        SessionKey::of(&SessionId::new(&SystemRng)),
        SessionKey::of(&SessionId::new(&SystemRng)),
    );
    store.save(&old, &revision(1), TTL).await.expect("a save");
    store.save(&new, &revision(1), TTL).await.expect("a save");

    let outcome = store
        .cycle(&old, &new, &revision(2), Duration::ZERO, true)
        .await;

    assert_eq!(outcome.expect("a rotation"), CycleOutcome::SessionGone);
    assert_eq!(revision_at(&store, &old).await, None);
    assert_eq!(revision_at(&store, &new).await, None);
}
