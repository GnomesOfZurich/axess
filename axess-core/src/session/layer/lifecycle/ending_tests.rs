//! The three steps that end a stored session (claim, record, remove), one
//! by one: what each leaves behind when it fails, and what a claimed row
//! means to every other writer of the session.

use super::audit_support::{
    Faulty, Sink, authenticated, impersonated_since, memory_store, stored, user,
};
use super::concurrency_tests::{TTL, finalize_telling, request_holding};
use super::ending::{Ended, Ending, StoredEnding, ended_record};
use super::*;
use crate::authn::ids::testing as ids;
use crate::session::data::{ENDING_CLAIM_LEASE, EndingClaim, SessionData};
use crate::session::id::{SessionId, SessionKey};
use crate::session::layer::audit::{LayerSessionEnded, UnrecordedSessionEnds};
use crate::session::store::{ConditionalUpdate, MemorySessionStore};
use crate::testing::mock_random::MockRng;
use axess_clock::testing::MockClock;
use axess_clock::testing::Shift;
use std::sync::Arc;
use std::sync::atomic::Ordering;

/// A store holding an authenticated session under one id, and a sink that
/// reads the store when it is told.
struct Held {
    memory: MemorySessionStore,
    id: SessionId,
    row: SessionData,
    sink: Arc<Sink>,
    now: axess_clock::Timestamp,
}

impl Held {
    async fn new() -> Self {
        let memory = memory_store();
        let id = SessionId::new(&MockRng::new(31));
        let row = authenticated();
        memory.save(&SessionKey::of(&id), &row, TTL).await.unwrap();
        Self {
            sink: Arc::new(Sink::on(&memory)),
            memory,
            id,
            row,
            now: MockClock::reference_time(),
        }
    }

    /// The ending of the session as it was loaded, through `store`.
    fn ending<S: SessionStore>(&self, store: S) -> StoredEnding<S> {
        StoredEnding {
            store,
            audit: self.sink.clone(),
            what: Ending {
                row: self.row.clone(),
                ended: self.record(),
                now: self.now,
                ttl: TTL,
                resumed: false,
            },
        }
    }

    /// The claim an ending of this session stamps.
    fn claim(&self) -> EndingClaim {
        EndingClaim {
            since: self.now,
            reason: SessionEndReason::AgeCap,
        }
    }

    fn record(&self) -> LayerSessionEnded {
        ended_record(
            &self.row,
            SessionKey::of(&self.id),
            SessionEndReason::AgeCap,
        )
        .expect("authenticated")
    }

    async fn stored(&self) -> Option<SessionData> {
        self.memory.load(&SessionKey::of(&self.id)).await.unwrap()
    }
}

/// The order: the sink is told while the row is still stored and carries
/// the claim, and the row is gone once the ending is done.
#[tokio::test]
async fn the_row_is_claimed_then_recorded_then_removed() {
    let held = Held::new().await;

    let ended = held.ending(held.memory.clone()).run_detached().await;

    assert_eq!(ended, Ended::Done);
    let told = held.sink.the_call();
    assert_eq!(told.ended, held.record());
    let seen = told
        .row
        .expect("the row is still stored when the sink is told");
    assert_eq!(seen.ending, Some(held.claim()), "claimed before the call");
    assert_eq!(seen.revision, held.row.revision + 1);
    assert!(held.stored().await.is_none(), "removed after the call");
}

/// A row another request wrote since this one loaded it is not this
/// request's to end: the claim loses, nothing is recorded, and the row is
/// left exactly as that request wrote it.
#[tokio::test]
async fn a_claim_that_loses_records_nothing_and_touches_nothing() {
    let held = Held::new().await;
    let mut written = held.row.clone();
    written.revision += 1;
    written.custom = serde_json::json!({"cart": 3});
    held.memory
        .save(&SessionKey::of(&held.id), &written, TTL)
        .await
        .unwrap();

    let ended = held.ending(held.memory.clone()).run_detached().await;

    assert_eq!(ended, Ended::Deferred);
    assert!(held.sink.told().is_empty());
    assert_eq!(stored(&held.stored().await), stored(&Some(written)));
}

/// Two endings started from the same loaded row record one: the second
/// finds the row claimed or gone.
#[tokio::test]
async fn two_endings_from_one_loaded_row_record_one() {
    let held = Held::new().await;

    let (first, second) = tokio::join!(
        held.ending(held.memory.clone()).run_detached(),
        held.ending(held.memory.clone()).run_detached(),
    );

    let mut outcomes = [first, second];
    outcomes.sort_by_key(|ended| *ended == Ended::Deferred);
    assert_eq!(outcomes, [Ended::Done, Ended::Deferred]);
    assert_eq!(held.sink.told().len(), 1);
    assert!(held.stored().await.is_none());
}

/// A store that cannot write the claim ends nothing and records nothing.
#[tokio::test]
async fn a_claim_the_store_cannot_write_records_nothing() {
    let held = Held::new().await;
    let store = Faulty::over(&held.memory);
    store.faults.swaps_before_failure.store(0, Ordering::SeqCst);

    let ended = held.ending(store).run_detached().await;

    assert_eq!(ended, Ended::Deferred);
    assert!(held.sink.told().is_empty());
    assert_eq!(
        stored(&held.stored().await),
        stored(&Some(held.row.clone()))
    );
}

/// A sink that fails releases the claim: the row is what it was, two
/// revisions on, and nothing was ended.
#[tokio::test]
async fn a_failed_record_releases_the_claim() {
    let held = Held::new().await;
    held.sink.failing.store(true, Ordering::SeqCst);

    let ended = held.ending(held.memory.clone()).run_detached().await;

    assert_eq!(ended, Ended::Deferred);
    assert_eq!(held.sink.told().len(), 1, "the sink was asked");
    let mut released = held.row.clone();
    released.revision += 2;
    assert_eq!(stored(&held.stored().await), stored(&Some(released)));
}

/// When the release fails as well, the claim stays and lapses by itself:
/// the row is refused for a lease, never removed unrecorded.
#[tokio::test]
async fn a_claim_that_cannot_be_released_stays_until_it_lapses() {
    let held = Held::new().await;
    held.sink.failing.store(true, Ordering::SeqCst);
    let store = Faulty::over(&held.memory);
    // The claim is written; the release is not.
    store.faults.swaps_before_failure.store(1, Ordering::SeqCst);

    let ended = held.ending(store).run_detached().await;

    assert_eq!(ended, Ended::Deferred);
    let row = held.stored().await.expect("the row is not removed");
    assert_eq!(row.ending, Some(held.claim()));
    assert!(row.auth_state.is_authenticated());
    let lease = axess_clock::SignedDuration::try_from(ENDING_CLAIM_LEASE).unwrap();
    assert!(
        held.claim().holds_at(
            held.now.plus(
                lease
                    .checked_sub(axess_clock::SignedDuration::seconds(1))
                    .unwrap()
            )
        )
    );
    assert!(!held.claim().holds_at(held.now.plus(lease)));
}

/// A removal that fails once is asked again: the session is removed, and
/// its ending was recorded once.
#[tokio::test]
async fn a_removal_that_fails_once_is_asked_again() {
    let held = Held::new().await;
    let store = Faulty::over(&held.memory);
    store.faults.deletes.store(1, Ordering::SeqCst);

    let ended = held.ending(store).run_detached().await;

    assert_eq!(ended, Ended::Done);
    assert_eq!(held.sink.told().len(), 1);
    assert!(held.stored().await.is_none());
}

/// A removal the store keeps failing leaves the recorded session claimed,
/// not served: the ending is done as far as the request goes, and the row
/// carries the claim that refuses it.
#[tokio::test]
async fn a_removal_that_keeps_failing_leaves_the_row_claimed() {
    let held = Held::new().await;
    let store = Faulty::over(&held.memory);
    store.faults.deletes.store(usize::MAX, Ordering::SeqCst);

    let ended = held.ending(store).run_detached().await;

    assert_eq!(ended, Ended::Done, "the ending is recorded");
    assert_eq!(held.sink.told().len(), 1);
    let row = held.stored().await.expect("the store kept the row");
    assert_eq!(row.ending, Some(held.claim()));
}

/// The claim's lease, to the second, in both directions: a stamp further in
/// the future than a lease (a clock that stepped) holds nothing either.
#[test]
fn a_claim_holds_for_one_lease_either_side_of_now() {
    let now = MockClock::reference_time();
    let lease = axess_clock::SignedDuration::try_from(ENDING_CLAIM_LEASE).unwrap();
    let second = axess_clock::SignedDuration::seconds(1);
    let claimed_at = |since| EndingClaim {
        since,
        reason: SessionEndReason::AgeCap,
    };

    assert!(claimed_at(now).holds_at(now));
    assert!(claimed_at(now.minus(lease).plus(second)).holds_at(now));
    assert!(!claimed_at(now.minus(lease)).holds_at(now));
    assert!(claimed_at(now.plus(lease).minus(second)).holds_at(now));
    assert!(!claimed_at(now.plus(lease)).holds_at(now));
}

/// The claim is stored with the session and reads back as it was written,
/// its reason under the tag the audit row carries.
#[test]
fn a_claim_is_stored_with_its_reason_under_the_audit_tag() {
    let claim = EndingClaim {
        since: MockClock::reference_time(),
        reason: SessionEndReason::ImpersonationNotRegistered,
    };
    let row = SessionData {
        ending: Some(claim),
        ..authenticated()
    };

    let json = serde_json::to_value(&row).unwrap();
    assert_eq!(
        json["ending"]["reason"],
        SessionEndReason::ImpersonationNotRegistered.as_str()
    );
    let restored: SessionData = serde_json::from_value(json).unwrap();
    assert_eq!(restored.ending, Some(claim));

    let unclaimed = serde_json::to_value(authenticated()).unwrap();
    assert!(unclaimed.get("ending").is_none(), "no claim, no field");
    let restored: SessionData = serde_json::from_value(unclaimed).unwrap();
    assert_eq!(restored.ending, None);
}

/// An ending that is finished for an earlier request is not taken back when
/// the sink fails: the claim this attempt stamped stays on the row.
#[tokio::test]
async fn a_resumed_ending_keeps_its_claim_when_the_record_fails() {
    let held = Held::new().await;
    held.sink.failing.store(true, Ordering::SeqCst);
    let mut resumed = held.ending(held.memory.clone());
    resumed.what.resumed = true;

    let ended = resumed.run_detached().await;

    assert_eq!(ended, Ended::Deferred);
    assert_eq!(held.sink.told().len(), 1, "the sink was asked");
    let row = held.stored().await.expect("the row is not removed");
    assert_eq!(row.ending, Some(held.claim()), "the claim is not released");
}

/// A request that was already running writes the claimed row between the
/// claim and its release. The release clears the claim on the row as it
/// is stored then: the other request's write is kept and the claim is gone.
#[tokio::test]
async fn a_release_clears_the_claim_on_a_row_another_request_wrote_meanwhile() {
    let memory = memory_store();
    let id = SessionId::new(&MockRng::new(35));
    let row = authenticated();
    memory.save(&SessionKey::of(&id), &row, TTL).await.unwrap();
    let sink = Arc::new(Sink::on(&memory).failing().gated());
    let ending = StoredEnding {
        store: memory.clone(),
        audit: sink.clone(),
        what: Ending {
            row: row.clone(),
            ended: ended_record(&row, SessionKey::of(&id), SessionEndReason::AgeCap)
                .expect("authenticated"),
            now: MockClock::reference_time(),
            ttl: TTL,
            resumed: false,
        },
    };
    let running = tokio::spawn(ending.run_detached());
    sink.entered.notified().await;

    // The claim is written and the sink is waiting: a request that loaded
    // the session before the claim writes its change now.
    let mut inner = request_holding(&memory, id, &row);
    inner.data.custom = serde_json::json!({"cart": 1});
    inner.modified = true;
    let outcome = finalize_telling(&memory, inner, Some(id), &UnrecordedSessionEnds).await;
    assert!(outcome.session_changed, "the write landed");
    let written = memory.load(&SessionKey::of(&id)).await.unwrap().unwrap();
    assert!(written.ending.is_some(), "and left the claim in place");

    sink.open();
    assert_eq!(running.await.unwrap(), Ended::Deferred);
    let released = memory.load(&SessionKey::of(&id)).await.unwrap().unwrap();
    assert_eq!(released.ending, None, "the claim is taken back");
    assert_eq!(released.custom, serde_json::json!({"cart": 1}));
    assert!(released.auth_state.is_authenticated());
}

/// The record of an ending is read from the session: its user, its tenant,
/// its administrator when it carries an impersonation. A session that is
/// not signed in (a guest, a login in progress) has none; a session in a
/// step-up has the record of the signed-in session it began from.
#[test]
fn the_record_is_read_from_the_session() {
    let id = SessionId::new(&MockRng::new(32));
    let plain = ended_record(
        &authenticated(),
        SessionKey::of(&id),
        SessionEndReason::NotRegistered,
    )
    .unwrap();
    assert_eq!(
        plain,
        LayerSessionEnded {
            user_id: user(),
            tenant_id: ids::tenant("t"),
            session_id: SessionKey::of(&id),
            impersonator: None,
            reason: SessionEndReason::NotRegistered,
        }
    );
    let impersonated = ended_record(
        &impersonated_since(0),
        SessionKey::of(&id),
        SessionEndReason::AgeCap,
    )
    .unwrap();
    assert_eq!(
        impersonated.impersonator,
        Some(super::audit_support::admin())
    );
    assert_eq!(impersonated.user_id, user());
    assert!(
        ended_record(
            &SessionData::default(),
            SessionKey::of(&id),
            SessionEndReason::AgeCap
        )
        .is_none()
    );
}

/// A session in a step-up is still the signed-in session it began from, and
/// its ending is recorded as that session's: its user, its tenant and the
/// administrator of its impersonation. A login in progress is nobody's
/// session yet and has no record.
#[test]
fn a_step_up_is_recorded_as_the_session_it_began_from() {
    use crate::authn::factor::{FactorKind, FactorStep};
    let id = SessionId::new(&MockRng::new(33));
    let mut stepping_up = impersonated_since(0);
    assert!(
        stepping_up
            .auth_state
            .begin_step_up(vec![FactorStep::Required(FactorKind::Totp)])
    );
    assert_eq!(
        ended_record(&stepping_up, SessionKey::of(&id), SessionEndReason::AgeCap),
        Some(LayerSessionEnded {
            user_id: user(),
            tenant_id: ids::tenant("t"),
            session_id: SessionKey::of(&id),
            impersonator: Some(super::audit_support::admin()),
            reason: SessionEndReason::AgeCap,
        })
    );

    let mut logging_in = SessionData::default();
    logging_in.auth_state.begin_authenticating(
        user(),
        ids::tenant("t"),
        "password+totp".into(),
        vec![FactorStep::Required(FactorKind::Password)],
    );
    assert!(logging_in.auth_state.is_authenticating());
    assert_eq!(
        ended_record(&logging_in, SessionKey::of(&id), SessionEndReason::AgeCap),
        None
    );
}

// ── a claimed row and the session's other writers ──────────────────────────

/// The row as a concurrent request claimed it after this request loaded it.
async fn claim_meanwhile(held: &Held) -> SessionData {
    let mut claimed = held.row.clone();
    claimed.revision += 1;
    claimed.ending = Some(held.claim());
    assert_eq!(
        held.memory
            .update_if_revision(&SessionKey::of(&held.id), held.row.revision, &claimed, TTL)
            .await
            .unwrap(),
        ConditionalUpdate::Written
    );
    claimed
}

/// A request that changed a session another request claimed meanwhile is
/// not dropped: its change is merged onto the claimed row and the claim is
/// left in place, so the write is kept if the claim is taken back and the
/// request that ends the session still finds its claim. The age of the
/// claim makes no difference to a writer.
#[tokio::test]
async fn a_write_that_meets_a_claim_is_merged_and_leaves_the_claim() {
    let lease = axess_clock::SignedDuration::try_from(ENDING_CLAIM_LEASE).unwrap();
    for age in [
        axess_clock::SignedDuration::ZERO,
        lease.checked_mul(4).unwrap(),
    ] {
        let held = Held::new().await;
        let mut inner = request_holding(&held.memory, held.id, &held.row);
        inner.data.custom = serde_json::json!({"cart": 1});
        inner.modified = true;
        let claim = EndingClaim {
            since: held.now.minus(age),
            reason: SessionEndReason::NotRegistered,
        };
        let mut claimed = held.row.clone();
        claimed.revision += 1;
        claimed.ending = Some(claim);
        held.memory
            .save(&SessionKey::of(&held.id), &claimed, TTL)
            .await
            .unwrap();

        let outcome =
            finalize_telling(&held.memory, inner, Some(held.id), &UnrecordedSessionEnds).await;

        assert!(outcome.session_changed, "the change is written: {age:?}");
        let row = held.stored().await.expect("the row stays");
        assert_eq!(row.custom, serde_json::json!({"cart": 1}), "{age:?}");
        assert_eq!(
            row.ending,
            Some(claim),
            "the claim is left in place: {age:?}"
        );
        assert_eq!(row.revision, claimed.revision + 1, "{age:?}");
    }
}

/// A rotation of a session another request claimed meanwhile carries
/// nothing to the new id: the claimed row stays where it is, and no cookie
/// is set for a row that was not written.
#[tokio::test]
async fn a_rotation_does_not_carry_a_claimed_session_to_a_new_id() {
    let held = Held::new().await;
    let new = SessionId::new(&MockRng::new(33));
    let mut inner = request_holding(&held.memory, new, &held.row);
    inner.regenerate = true;
    inner.pre_cycle = Some(SessionKey::of(&held.id));
    let claimed = claim_meanwhile(&held).await;

    let outcome = finalize_telling(&held.memory, inner, Some(held.id), held.sink.as_ref()).await;

    assert!(!outcome.session_changed);
    assert!(outcome.rotation.is_none());
    assert!(
        held.memory
            .load(&SessionKey::of(&new))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(stored(&held.stored().await), stored(&Some(claimed)));
    assert!(
        held.sink.told().is_empty(),
        "the ending is the claimant's to record"
    );
}

/// A one-shot value taken from a session another request claimed meanwhile
/// is handed out once, as from any other row: the removal is written onto
/// the claimed row and the claim is left in place.
#[tokio::test]
async fn a_one_shot_value_taken_from_a_claimed_row_leaves_the_claim() {
    let memory = memory_store();
    let id = SessionId::new(&MockRng::new(34));
    let row = SessionData {
        custom: serde_json::json!({"ceremony": "state"}),
        ..authenticated()
    };
    memory.save(&SessionKey::of(&id), &row, TTL).await.unwrap();
    let mut inner = request_holding(&memory, id, &row);
    let claim = EndingClaim {
        since: MockClock::reference_time(),
        reason: SessionEndReason::AgeCap,
    };
    let mut claimed = row.clone();
    claimed.revision += 1;
    claimed.ending = Some(claim);
    memory
        .save(&SessionKey::of(&id), &claimed, TTL)
        .await
        .unwrap();

    assert_eq!(
        inner.consume_custom("ceremony").await,
        Some(serde_json::json!("state"))
    );

    let stored_row = memory
        .load(&SessionKey::of(&id))
        .await
        .unwrap()
        .expect("the row stays");
    assert_eq!(stored_row.ending, Some(claim), "the claim is left in place");
    assert!(
        stored_row.custom.get("ceremony").is_none(),
        "the value is taken in the store"
    );
}

/// A request that took a one-shot value from a claimed row while rotating
/// its id knows the claimed row's revision. Its rotation is still not
/// carried out: the session is ended under the id its claim is on.
#[tokio::test]
async fn a_rotation_after_a_take_from_a_claimed_row_is_not_carried_out() {
    let memory = memory_store();
    let (old, new) = (
        SessionId::new(&MockRng::new(36)),
        SessionId::new(&MockRng::new(37)),
    );
    let row = SessionData {
        custom: serde_json::json!({"ceremony": "state"}),
        ..authenticated()
    };
    memory.save(&SessionKey::of(&old), &row, TTL).await.unwrap();
    let mut inner = request_holding(&memory, new, &row);
    inner.regenerate = true;
    inner.pre_cycle = Some(SessionKey::of(&old));
    let claim = EndingClaim {
        since: MockClock::reference_time(),
        reason: SessionEndReason::AgeCap,
    };
    let mut claimed = row.clone();
    claimed.revision += 1;
    claimed.ending = Some(claim);
    memory
        .save(&SessionKey::of(&old), &claimed, TTL)
        .await
        .unwrap();
    assert_eq!(
        inner.consume_custom("ceremony").await,
        Some(serde_json::json!("state"))
    );

    let outcome = finalize_telling(&memory, inner, Some(old), &UnrecordedSessionEnds).await;

    assert!(!outcome.session_changed, "no cookie for the new id");
    assert!(outcome.rotation.is_none());
    assert!(memory.load(&SessionKey::of(&new)).await.unwrap().is_none());
    let stays = memory
        .load(&SessionKey::of(&old))
        .await
        .unwrap()
        .expect("the claimed row");
    assert_eq!(stays.ending, Some(claim));
}
