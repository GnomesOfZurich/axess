//! The audit sink at the load: one call for each session the load ends (an
//! age cap, a registry entry gone), made while the session's row is still
//! stored; none for a session the load keeps or only distrusts; and a sink
//! that fails leaves the session stored and refused.

use super::audit_support::{Sink, Told, admin, authenticated, impersonated_since, stored, user};
use super::*;
use crate::authn::ids::testing as ids;
use crate::session::data::{AuthState, ENDING_CLAIM_LEASE, EndingClaim, SessionData};
use crate::session::id::{SessionId, SessionKey};
use crate::session::layer::UnknownLiveness;
use crate::session::layer::audit::{LayerSessionEnded, UnrecordedSessionEnds};
use crate::session::store::{
    MemorySessionRegistry, MemorySessionStore, SessionRegistry, SessionRegistryAdapter,
};
use crate::testing::mock_random::MockRng;
use crate::testing::registry_double::{RegistryDouble, RegistryOp, Step};
use axess_clock::testing::MockClock;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// One hour for a session and ten minutes for an impersonation.
fn caps() -> SessionConfig {
    SessionConfig::builder()
        .max_authenticated_age(Some(Duration::from_secs(3600)))
        .max_impersonation_age(Some(Duration::from_secs(600)))
        .build()
}

/// A registry that cannot answer: every entry is `Unknown`, and no session
/// registers.
fn unanswering() -> Arc<dyn SessionRegistryHandle> {
    RegistryDouble::new()
        .before(|call, _| async move {
            match call.op() {
                RegistryOp::IsValid | RegistryOp::Register => {
                    Step::Fail("the registry does not answer")
                }
                _ => Step::Forward,
            }
        })
        .handle()
}

/// A store holding `data` under one session id, the registry the load asks,
/// the clock it reads and the sink it reports to.
struct World {
    store: MemorySessionStore,
    registry: MemorySessionRegistry,
    clock: MockClock,
    sink: Arc<Sink>,
    keys: SigningKeyRing,
    cfg: SessionConfig,
    id: SessionId,
}

/// What one request made of the session.
struct Seen {
    /// The request ran as the session's user.
    kept: bool,
    /// The load ended the session, so the response replaces its cookie.
    ended: bool,
    /// The row as the store holds it after the request.
    row: Option<SessionData>,
}

impl World {
    /// `data` stored and its session registered, with the impersonation
    /// anchor registered under the administrator when it carries one.
    async fn holding(data: &SessionData) -> Self {
        Self::holding_with(data, Sink::on).await
    }

    async fn holding_with(data: &SessionData, sink: fn(&MemorySessionStore) -> Sink) -> Self {
        // The store and the registry judge their own lifetimes on the
        // clock the load reads, so no part of the test reads the system's.
        let clock = MockClock::at_reference();
        let store = MemorySessionStore::new().with_clock(Arc::new(clock.clone()));
        let registry = MemorySessionRegistry::new().with_clock(Arc::new(clock.clone()));
        let cfg = caps();
        let id = SessionId::new(&MockRng::new(5));
        store
            .save(&SessionKey::of(&id), data, cfg.ttl)
            .await
            .unwrap();
        registry
            .register(&user(), &SessionKey::of(&id))
            .await
            .unwrap();
        if let AuthState::Authenticated {
            impersonator: Some(imp),
            ..
        } = &data.auth_state
        {
            registry
                .register(&imp.admin, &imp.registry_anchor(&user()))
                .await
                .unwrap();
        }
        Self {
            sink: Arc::new(sink(&store)),
            store,
            registry,
            clock,
            keys: SigningKeyRing::from_master(&[0xCC; 32]),
            cfg,
            id,
        }
    }

    /// One request carrying the session's cookie, judged by `registry`.
    async fn load(&self, registry: &dyn SessionRegistryHandle, unknown: UnknownLiveness) -> Seen {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            axum::http::HeaderValue::from_str(&format!(
                "{}={}",
                self.cfg.cookie_name.as_ref(),
                self.keys.sign_cookie(&CookieSession::of_id(self.id))
            ))
            .unwrap(),
        );
        let audit: Arc<dyn SessionEndAudit> = self.sink.clone();
        let outcome = load_session(
            &self.store,
            &self.keys,
            &self.cfg,
            &headers,
            Fingerprints::default(),
            &MockRng::new(1),
            &LoadPolicy {
                registry: Some(registry),
                unknown,
                clock: &self.clock,
                metrics: None,
                audit: &audit,
            },
        )
        .await;
        let kept = outcome.data.auth_state.is_authenticated();
        assert!(!(kept && outcome.session_ended), "kept and ended at once");
        assert!(
            outcome.data.ending.is_none(),
            "a handler never sees a claim"
        );
        Seen {
            kept,
            ended: outcome.session_ended,
            row: self.store.load(&SessionKey::of(&self.id)).await.unwrap(),
        }
    }

    /// One request judged by the world's own registry, which fails closed
    /// when it cannot answer.
    async fn request(&self) -> Seen {
        let registry = SessionRegistryAdapter(self.registry.clone());
        self.load(&registry, UnknownLiveness::Reject).await
    }

    /// The one call the sink got, checked to have been made while the
    /// session's row was still stored, claimed at the clock's instant and
    /// otherwise as it was.
    fn the_call(&self) -> LayerSessionEnded {
        let Told { ended, row } = self.sink.the_call();
        let row = row.expect("the row is still stored when the sink is told");
        let claim = row.ending.expect("claimed before the sink is told");
        assert_eq!(claim.since, self.clock.now(), "claimed by this request");
        assert_eq!(claim.reason, ended.reason, "the claim keeps the reason");
        assert!(row.auth_state.is_authenticated());
        ended
    }

    /// The record of this world's session ending for `reason`.
    fn record(
        &self,
        reason: SessionEndReason,
        impersonator: Option<crate::authn::ids::UserId>,
    ) -> LayerSessionEnded {
        LayerSessionEnded {
            user_id: user(),
            tenant_id: ids::tenant("t"),
            session_id: SessionKey::of(&self.id),
            impersonator,
            reason,
        }
    }
}

/// A session at the age cap to the second stands and nothing is recorded;
/// one second past it the session is ended, its row removed, and the sink
/// told once, with the session, its user, its tenant and the age cap.
#[tokio::test]
async fn a_session_past_the_age_cap_is_recorded_once_as_an_age_cap() {
    let w = World::holding(&authenticated()).await;

    w.clock.advance_secs(3600);
    let at_the_cap = w.request().await;
    assert!(at_the_cap.kept && at_the_cap.row.is_some());
    assert!(w.sink.told().is_empty(), "a kept session is not recorded");

    w.clock.advance_secs(1);
    let past = w.request().await;
    assert!(!past.kept && past.ended && past.row.is_none());
    assert_eq!(w.the_call(), w.record(SessionEndReason::AgeCap, None));

    // The cookie of the ended session now finds no row: a guest, and no
    // second call.
    let after = w.request().await;
    assert!(!after.kept && !after.ended);
    assert_eq!(w.sink.told().len(), 1);
}

/// An impersonation past its own cap, on a session still inside the session
/// cap, is recorded as the impersonation age cap and names the
/// administrator.
#[tokio::test]
async fn an_impersonation_past_its_cap_is_recorded_with_its_administrator() {
    let w = World::holding(&impersonated_since(0)).await;

    w.clock.advance_secs(600);
    assert!(w.request().await.kept);
    assert!(w.sink.told().is_empty());

    w.clock.advance_secs(1);
    let past = w.request().await;
    assert!(!past.kept && past.ended && past.row.is_none());
    assert_eq!(
        w.the_call(),
        w.record(SessionEndReason::ImpersonationAgeCap, Some(admin()))
    );
}

/// A session that carries an impersonation and ends for a reason of its own
/// (here the session's age cap, with the impersonation well inside its own)
/// names the administrator all the same.
#[tokio::test]
async fn an_impersonated_session_past_the_session_cap_names_the_administrator_too() {
    let w = World::holding(&impersonated_since(3500)).await;
    w.clock.advance_secs(3601);
    let past = w.request().await;
    assert!(!past.kept && past.ended && past.row.is_none());
    assert_eq!(
        w.the_call(),
        w.record(SessionEndReason::AgeCap, Some(admin()))
    );
}

/// A session the registry no longer holds is ended and recorded as not
/// registered.
#[tokio::test]
async fn a_session_the_registry_dropped_is_recorded_as_not_registered() {
    let w = World::holding(&authenticated()).await;
    assert!(w.request().await.kept);

    w.registry.invalidate_user(&user()).await.unwrap();
    let dropped = w.request().await;
    assert!(!dropped.kept && dropped.ended && dropped.row.is_none());
    assert_eq!(
        w.the_call(),
        w.record(SessionEndReason::NotRegistered, None)
    );
}

/// An impersonation whose administrator's sessions were ended is ended with
/// them, though the registry still holds the session itself, and recorded
/// as the impersonation's entry being gone, with the administrator.
#[tokio::test]
async fn an_impersonation_whose_administrator_was_ended_is_recorded_by_that_reason() {
    let w = World::holding(&impersonated_since(0)).await;
    assert!(w.request().await.kept);

    w.registry.invalidate_user(&admin()).await.unwrap();
    assert!(
        w.registry
            .is_valid(&user(), &SessionKey::of(&w.id))
            .await
            .unwrap()
    );
    let dropped = w.request().await;
    assert!(!dropped.kept && dropped.ended && dropped.row.is_none());
    assert_eq!(
        w.the_call(),
        w.record(SessionEndReason::ImpersonationNotRegistered, Some(admin()))
    );
}

/// A sink that fails leaves the session unended: the request is a guest's,
/// its cookie is not replaced, and the row stands as it was stored, without
/// the claim. Every request that presents the session tries again, and the
/// one that finds the sink working ends it.
#[tokio::test]
async fn a_sink_that_fails_leaves_the_session_stored_and_refused() {
    let w = World::holding_with(&authenticated(), |store| Sink::on(store).failing()).await;
    w.clock.advance_secs(3601);

    for attempt in 1..=2 {
        let refused = w.request().await;
        assert!(!refused.kept, "an over-age session is never served");
        assert!(!refused.ended, "nothing was ended without its row");
        let row = refused.row.expect("the row stays");
        assert!(row.auth_state.is_authenticated());
        assert_eq!(row.ending, None, "the claim is released");
        assert_eq!(w.sink.told().len(), attempt, "each request tries again");
    }

    w.sink.failing.store(false, Ordering::SeqCst);
    let ended = w.request().await;
    assert!(!ended.kept && ended.ended && ended.row.is_none());
    assert_eq!(w.sink.told().len(), 3);
}

/// A registry that cannot answer ends nothing, under either policy: the row
/// stays exactly as it was and the sink is told nothing. `Reject` runs the
/// request as a guest; `Accept` runs it as the session's user.
#[tokio::test]
async fn a_session_the_registry_cannot_answer_for_is_neither_ended_nor_recorded() {
    for (unknown, kept) in [
        (UnknownLiveness::Reject, false),
        (UnknownLiveness::Accept, true),
    ] {
        let w = World::holding(&authenticated()).await;
        let before = w.store.load(&SessionKey::of(&w.id)).await.unwrap();

        let seen = w.load(&*unanswering(), unknown).await;

        assert_eq!(seen.kept, kept, "{unknown:?}");
        assert!(
            !seen.ended,
            "{unknown:?}: a distrusted session is not ended"
        );
        assert_eq!(
            stored(&seen.row),
            stored(&before),
            "{unknown:?}: the row is untouched"
        );
        assert!(w.sink.told().is_empty(), "{unknown:?}: nothing is recorded");
    }
}

/// Two requests that both load an over-age session before either ends it
/// record one ending: one of them wins the claim, and the other is refused
/// the session and ends nothing.
#[tokio::test]
async fn two_requests_that_load_one_ended_session_record_one_ending() {
    let w = World::holding(&authenticated()).await;
    w.clock.advance_secs(3601);

    let (first, second) = tokio::join!(w.request(), w.request());

    assert!(!first.kept && !second.kept);
    assert_eq!(
        [first.ended, second.ended].iter().filter(|e| **e).count(),
        1,
        "one request ended the session"
    );
    assert_eq!(w.the_call(), w.record(SessionEndReason::AgeCap, None));
    assert!(
        w.store
            .load(&SessionKey::of(&w.id))
            .await
            .unwrap()
            .is_none()
    );
}

/// A request that arrives while another is ending the session (the claim is
/// written, the sink has not answered) is refused the session and records
/// nothing; the ending is the first request's, and is recorded once. The
/// second request is answered at once: it does not reach the sink, which
/// is held shut here and would keep it waiting.
#[tokio::test]
async fn a_request_that_meets_a_session_being_ended_records_nothing() {
    let w = Arc::new(World::holding_with(&authenticated(), |store| Sink::on(store).gated()).await);
    w.clock.advance_secs(3601);

    let ending = tokio::spawn({
        let w = w.clone();
        async move { w.request().await }
    });
    w.sink.entered.notified().await;

    let meanwhile = tokio::time::timeout(std::time::Duration::from_secs(5), w.request())
        .await
        .expect("refused without waiting for the sink");
    assert!(!meanwhile.kept && !meanwhile.ended);
    assert!(
        meanwhile.row.is_some(),
        "the row is the first request's to end"
    );
    assert_eq!(w.sink.told().len(), 1, "the second request told nothing");

    w.sink.open();
    let first = ending.await.unwrap();
    assert!(first.ended && first.row.is_none());
    assert_eq!(w.the_call(), w.record(SessionEndReason::AgeCap, None));
}

/// A request that is dropped while the sink is writing the row does not
/// stop the ending: the row is written and the session removed without it.
#[tokio::test]
async fn a_dropped_request_loses_neither_the_row_nor_the_ending() {
    let w = Arc::new(World::holding_with(&authenticated(), |store| Sink::on(store).gated()).await);
    w.clock.advance_secs(3601);

    {
        let request = Box::pin(w.request());
        tokio::select! {
            biased;
            _ = request => panic!("the gate is closed"),
            () = w.sink.entered.notified() => {}
        }
        // The request future is dropped here, with the sink still waiting.
    }
    assert!(
        w.store
            .load(&SessionKey::of(&w.id))
            .await
            .unwrap()
            .is_some()
    );

    w.sink.open();
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    assert!(
        w.store
            .load(&SessionKey::of(&w.id))
            .await
            .unwrap()
            .is_none(),
        "the ending went on without the request"
    );
    assert_eq!(w.the_call(), w.record(SessionEndReason::AgeCap, None));
}

/// The session's row as the store holds it, with a claim stamped now for
/// `reason`, as a request that began the ending and stopped leaves it.
async fn claim_now(w: &World, reason: SessionEndReason) -> SessionData {
    let mut claimed = w.store.load(&SessionKey::of(&w.id)).await.unwrap().unwrap();
    claimed.ending = Some(EndingClaim {
        since: w.clock.now(),
        reason,
    });
    w.store
        .save(&SessionKey::of(&w.id), &claimed, w.cfg.ttl)
        .await
        .unwrap();
    claimed
}

/// A session carrying a claim younger than the lease is refused and left
/// alone, whoever claimed it; once the claim is a lease old, the request
/// that meets it finishes the ending and records it.
#[tokio::test]
async fn a_claim_holds_for_its_lease_and_is_then_taken_over() {
    let lease = i64::try_from(ENDING_CLAIM_LEASE.as_secs()).unwrap();
    let w = World::holding(&authenticated()).await;
    w.clock.advance_secs(3601);
    let claimed = claim_now(&w, SessionEndReason::AgeCap).await;

    w.clock.advance_secs(lease - 1);
    let held = w.request().await;
    assert!(!held.kept && !held.ended);
    assert_eq!(
        stored(&held.row),
        stored(&Some(claimed)),
        "a claimed row is left alone"
    );
    assert!(w.sink.told().is_empty());

    w.clock.advance_secs(1);
    let taken = w.request().await;
    assert!(!taken.kept && taken.ended && taken.row.is_none());
    assert_eq!(w.the_call(), w.record(SessionEndReason::AgeCap, None));
}

/// A claim is the decision to end the session, and it outlives the request
/// that made it. This session is inside its caps and the registry holds it,
/// so the checks would keep it; it carries a claim older than the lease,
/// left by a request that began to end it for a registry entry that was
/// gone. The request that meets it does not judge it again: it finishes the
/// ending, for the reason the claim holds. No session with a lapsed claim
/// is ever handed to a handler.
#[tokio::test]
async fn a_session_with_a_lapsed_claim_is_ended_for_the_claims_reason_not_kept() {
    let lease = i64::try_from(ENDING_CLAIM_LEASE.as_secs()).unwrap();
    let w = World::holding(&authenticated()).await;
    assert!(w.request().await.kept, "the checks keep this session");
    claim_now(&w, SessionEndReason::NotRegistered).await;

    let held = w.request().await;
    assert!(!held.kept && !held.ended, "refused while the claim holds");
    assert!(w.sink.told().is_empty());

    w.clock.advance_secs(lease);
    assert!(
        w.registry
            .is_valid(&user(), &SessionKey::of(&w.id))
            .await
            .unwrap(),
        "the registry still holds the session"
    );
    let finished = w.request().await;
    assert!(!finished.kept && finished.ended && finished.row.is_none());
    assert_eq!(
        w.the_call(),
        w.record(SessionEndReason::NotRegistered, None)
    );
}

/// An ending that is finished for an earlier request is not taken back when
/// the sink fails: its audit row may already be written, so the session
/// stays claimed, is refused, and is finished by a later request.
#[tokio::test]
async fn an_ending_finished_for_an_earlier_request_is_not_taken_back() {
    let lease = i64::try_from(ENDING_CLAIM_LEASE.as_secs()).unwrap();
    let w = World::holding_with(&authenticated(), |store| Sink::on(store).failing()).await;
    claim_now(&w, SessionEndReason::NotRegistered).await;
    w.clock.advance_secs(lease);

    let refused = w.request().await;
    assert!(!refused.kept && !refused.ended);
    assert_eq!(w.sink.told().len(), 1, "the sink was asked");
    let claim = refused.row.expect("the row stays").ending;
    assert_eq!(
        claim,
        Some(EndingClaim {
            since: w.clock.now(),
            reason: SessionEndReason::NotRegistered,
        }),
        "the claim stands, stamped by the request that tried"
    );

    w.sink.failing.store(false, Ordering::SeqCst);
    let held = w.request().await;
    assert!(
        !held.kept && !held.ended,
        "refused while the new claim holds"
    );
    w.clock.advance_secs(lease);
    let finished = w.request().await;
    assert!(!finished.kept && finished.ended && finished.row.is_none());
    let told = w.sink.told();
    assert_eq!(told.len(), 2);
    assert_eq!(told[0].ended, told[1].ended, "the same ending both times");
    assert_eq!(
        told[1].ended,
        w.record(SessionEndReason::NotRegistered, None)
    );
}

/// With the sink that records nothing the session is ended all the same.
#[tokio::test]
async fn the_sink_that_records_nothing_lets_the_ending_go_ahead() {
    let w = World::holding(&authenticated()).await;
    w.clock.advance_secs(3601);
    let audit: Arc<dyn SessionEndAudit> = Arc::new(UnrecordedSessionEnds);
    let registry = SessionRegistryAdapter(w.registry.clone());
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        axum::http::HeaderValue::from_str(&format!(
            "{}={}",
            w.cfg.cookie_name.as_ref(),
            w.keys.sign_cookie(&CookieSession::of_id(w.id))
        ))
        .unwrap(),
    );

    let outcome = load_session(
        &w.store,
        &w.keys,
        &w.cfg,
        &headers,
        Fingerprints::default(),
        &MockRng::new(1),
        &LoadPolicy {
            registry: Some(&registry),
            unknown: UnknownLiveness::Reject,
            clock: &w.clock,
            metrics: None,
            audit: &audit,
        },
    )
    .await;

    assert!(outcome.session_ended);
    assert!(
        w.store
            .load(&SessionKey::of(&w.id))
            .await
            .unwrap()
            .is_none()
    );
    assert!(w.sink.told().is_empty());
}

/// A session the load ends leaves the registry: its own entry and, for an
/// impersonation, the entry its administrator holds it by.
#[tokio::test]
async fn a_session_the_load_ends_leaves_the_registry() {
    let data = impersonated_since(0);
    let w = World::holding(&data).await;
    let anchor = match &data.auth_state {
        AuthState::Authenticated {
            impersonator: Some(imp),
            ..
        } => imp.registry_anchor(&user()),
        _ => unreachable!("an impersonated session"),
    };
    assert!(w.registry.is_valid(&admin(), &anchor).await.unwrap());

    w.clock.advance_secs(601);
    assert!(w.request().await.ended);

    assert!(
        !w.registry
            .is_valid(&user(), &SessionKey::of(&w.id))
            .await
            .unwrap(),
        "the session's own entry goes"
    );
    assert!(
        !w.registry.is_valid(&admin(), &anchor).await.unwrap(),
        "the administrator's anchor goes"
    );
}

/// The tag and the expiry of every reason the layer ends a session for. One
/// list of rows makes both an exhaustive `match` and the list the test
/// walks, so a reason added to the enum without a row here does not
/// compile, and none can be left out of the walk.
macro_rules! tag_rows {
    ($($reason:ident => $tag:literal, $expiry:literal),* $(,)?) => {
        fn tag_row(reason: SessionEndReason) -> (&'static str, bool) {
            match reason {
                $(SessionEndReason::$reason => ($tag, $expiry),)*
            }
        }

        const EVERY_REASON: &[SessionEndReason] = &[$(SessionEndReason::$reason),*];
    };
}

tag_rows! {
    AgeCap => "session_age_cap", true,
    ImpersonationAgeCap => "impersonation_age_cap", true,
    NotRegistered => "session_not_registered", false,
    ImpersonationNotRegistered => "impersonation_not_registered", false,
    RevokedDuringRotation => "session_revoked_during_rotation", false,
    NotTracked => "session_not_tracked", false,
    RotationFailed => "session_rotation_failed", false,
    KeyBindingRequired => "key_binding_required", false,
    TenantNotConfirmed => "session_tenant_not_confirmed", false,
}

/// Each reason has a tag of its own, and only the age caps are expiries.
#[test]
fn every_reason_has_its_own_tag() {
    let distinct: std::collections::BTreeSet<_> = EVERY_REASON
        .iter()
        .map(|reason| tag_row(*reason).0)
        .collect();
    assert_eq!(distinct.len(), EVERY_REASON.len());
    for reason in EVERY_REASON {
        let (tag, expiry) = tag_row(*reason);
        assert_eq!(reason.as_str(), tag);
        assert_eq!(reason.is_expiry(), expiry, "{tag}");
    }
}
