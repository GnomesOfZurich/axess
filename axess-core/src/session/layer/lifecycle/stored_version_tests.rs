//! A stored row below the current schema version is no session of this
//! release. The load refuses it, counted and logged, and leaves it as it
//! lies; every later read of the row in the same request refuses it too,
//! so a row put under the key while the request ran is never served,
//! merged, released or ended. A row above the version is served.

use super::audit_support::{Sink, authenticated, memory_store, stored, user};
use super::concurrency_tests::{TTL, finalize_telling, request_holding};
use super::ending::{Ended, Ending, StoredEnding, ended_record};
use super::*;
use crate::metrics::MetricSinks;
use crate::session::data::{SESSION_DATA_VERSION, SessionData};
use crate::session::id::{SessionId, SessionKey};
use crate::session::layer::UnknownLiveness;
use crate::session::store::{MemorySessionRegistry, SessionRegistryHandle};
use crate::testing::RecordingMetrics;
use crate::testing::mock_random::MockRng;
use axess_clock::testing::MockClock;
use std::sync::Arc;

/// [`authenticated`], with its schema version set to `version`.
fn signed_in_at_version(version: u8) -> SessionData {
    SessionData {
        version,
        ..authenticated()
    }
}

/// What the load made of `row`, held by the memory store under `id` and by
/// the registry for its user: the outcome, the count of refused rows, the
/// calls the sink had, and whether the registry still holds the id.
async fn load_typed(row: &SessionData, id: SessionId) -> (LoadOutcome, u64, usize, bool) {
    let memory = memory_store();
    memory.save(&SessionKey::of(&id), row, TTL).await.unwrap();
    let clock = MockClock::at_reference();
    let registry: Arc<dyn SessionRegistryHandle> = MemorySessionRegistry::new()
        .with_clock(Arc::new(clock.clone()))
        .handle();
    assert!(registry.register(&user(), &SessionKey::of(&id)).await);
    let keys = SigningKeyRing::from_master(&[0xCC; 32]);
    let cfg = SessionConfig::default();
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        axum::http::HeaderValue::from_str(&format!(
            "{}={}",
            cfg.cookie_name.as_ref(),
            keys.sign_cookie(&CookieSession::of_id(id))
        ))
        .unwrap(),
    );
    let recorder = Arc::new(RecordingMetrics::default());
    let metrics = MetricSinks::noop().with_session(recorder.clone());
    let sink = Arc::new(Sink::on(&memory));
    let audit: Arc<dyn SessionEndAudit> = sink.clone();
    let outcome = load_session(
        &memory,
        &keys,
        &cfg,
        &headers,
        Fingerprints::default(),
        &MockRng::new(1),
        &LoadPolicy {
            registry: Some(registry.as_ref()),
            unknown: UnknownLiveness::Reject,
            clock: &clock,
            metrics: Some(&metrics),
            audit: &audit,
        },
    )
    .await;
    assert_eq!(
        stored(&memory.load(&SessionKey::of(&id)).await.unwrap()),
        stored(&Some(row.clone())),
        "the row is left as it was stored"
    );
    let held = registry
        .held_sessions(&user())
        .await
        .unwrap()
        .contains(&SessionKey::of(&id));
    (
        outcome,
        recorder.count("session_row_refused"),
        sink.told().len(),
        held,
    )
}

/// A store that holds typed rows hands the version up as it was saved, and
/// the load alone decides: a signed-in row of version 2 is not served,
/// counted once, told to nobody and asked of no registry.
#[tokio::test]
async fn a_typed_row_below_the_version_is_not_served() {
    let id = SessionId::new(&MockRng::new(61));
    let (outcome, refused, told, held) = load_typed(&signed_in_at_version(2), id).await;
    assert!(!outcome.stored);
    assert_ne!(*outcome.session.key(), SessionKey::of(&id));
    assert!(outcome.data.auth_state.is_guest());
    assert!(!outcome.session_ended);
    assert_eq!(refused, 1);
    assert_eq!(told, 0);
    assert!(held);
}

/// A row of a higher version, which a later release writes during a rolling
/// upgrade, is served as it was stored: its version is not lowered and
/// nothing is counted.
#[tokio::test]
async fn a_row_above_the_version_is_served_unchanged() {
    let id = SessionId::new(&MockRng::new(62));
    let above = SESSION_DATA_VERSION + 1;
    let (outcome, refused, told, _) = load_typed(&signed_in_at_version(above), id).await;
    assert!(outcome.stored);
    assert_eq!(*outcome.session.key(), SessionKey::of(&id));
    assert!(outcome.data.auth_state.is_authenticated());
    assert_eq!(outcome.data.version, above);
    assert_eq!(refused, 0);
    assert_eq!(told, 0);
}

// ── a row below the version put under the key while the request ran ────────

/// A row below the version, as one planted under `key` would read: a
/// signed-in state, a cart nobody else holds, and a revision ahead of the
/// request's.
fn planted(claim: Option<crate::session::data::EndingClaim>) -> SessionData {
    SessionData {
        version: 2,
        revision: 9,
        custom: serde_json::json!({ "planted": true }),
        ending: claim,
        ..authenticated()
    }
}

/// A request that loaded the session and changed it writes through the
/// merging compare-and-swap. A row below the version found there is an
/// error: the swap fails, nothing of the row is merged, and the row is left
/// as it lies.
#[tokio::test]
async fn a_merging_write_does_not_read_a_row_below_the_version() {
    let memory = memory_store();
    let id = SessionId::new(&MockRng::new(63));
    let loaded = authenticated();
    memory
        .save(&SessionKey::of(&id), &loaded, TTL)
        .await
        .unwrap();
    let mut inner = request_holding(&memory, id, &loaded);
    inner.data.custom = serde_json::json!({ "cart": 1 });
    inner.modified = true;
    memory
        .save(&SessionKey::of(&id), &planted(None), TTL)
        .await
        .unwrap();

    let outcome = finalize_telling(&memory, inner, Some(id), &Sink::on(&memory)).await;

    assert!(!outcome.session_changed, "the write failed");
    assert_eq!(
        stored(&memory.load(&SessionKey::of(&id)).await.unwrap()),
        stored(&Some(planted(None))),
        "the row is left as it lies, and nothing of it is merged"
    );
}

/// A request that rotates the session merges what landed on the old row
/// first. A row below the version found there fails the rotation; the
/// stored session the failed rotation then ends is read the same way, so
/// it is left as it lies, unended and untold; and the new id holds nothing.
#[tokio::test]
async fn a_rotation_does_not_read_a_row_below_the_version() {
    let memory = memory_store();
    let id = SessionId::new(&MockRng::new(64));
    let loaded = authenticated();
    memory
        .save(&SessionKey::of(&id), &loaded, TTL)
        .await
        .unwrap();
    let mut inner = request_holding(&memory, id, &loaded);
    inner.data.custom = serde_json::json!({ "cart": 1 });
    inner.modified = true;
    inner.rotate_id();
    let new_key = *inner.session.key();
    memory
        .save(&SessionKey::of(&id), &planted(None), TTL)
        .await
        .unwrap();
    let sink = Sink::on(&memory);

    let outcome = finalize_telling(&memory, inner, Some(id), &sink).await;

    assert!(outcome.rotation.is_none(), "the rotation failed");
    assert!(
        memory.load(&new_key).await.unwrap().is_none(),
        "nothing is carried to the new id"
    );
    assert_eq!(
        stored(&memory.load(&SessionKey::of(&id)).await.unwrap()),
        stored(&Some(planted(None))),
        "the row is left as it lies"
    );
    assert!(sink.told().is_empty(), "no ending is recorded for it");
}

/// The request that claimed a session and could not record its ending takes
/// the claim back on the row as it is stored then. A row below the version
/// found there is not this request's to write: the claim on it is left to
/// lapse, and the row as it lies.
#[tokio::test]
async fn a_release_does_not_write_a_row_below_the_version() {
    let memory = memory_store();
    let id = SessionId::new(&MockRng::new(65));
    let key = SessionKey::of(&id);
    let row = authenticated();
    memory.save(&key, &row, TTL).await.unwrap();
    let sink = Arc::new(Sink::on(&memory).failing().gated());
    let now = MockClock::reference_time();
    let ending = StoredEnding {
        store: memory.clone(),
        audit: sink.clone(),
        what: Ending {
            row: row.clone(),
            ended: ended_record(&row, SessionKey::of(&id), SessionEndReason::AgeCap)
                .expect("signed in"),
            now,
            ttl: TTL,
            resumed: false,
        },
    };
    let running = tokio::spawn(ending.run_detached());
    sink.entered.notified().await;

    // The claim is written and the sink is waiting: the row under the key is
    // replaced by one below the version that carries the same claim.
    let claim = memory
        .load(&key)
        .await
        .unwrap()
        .and_then(|row| row.ending)
        .expect("the claim is written");
    let below = planted(Some(claim));
    memory.save(&key, &below, TTL).await.unwrap();

    sink.open();
    assert_eq!(running.await.unwrap(), Ended::Deferred);
    assert_eq!(
        stored(&memory.load(&key).await.unwrap()),
        stored(&Some(below)),
        "the claim is left on the row as it lies"
    );
}
