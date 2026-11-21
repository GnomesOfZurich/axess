//! The audit sink at the finish of a request: a session the layer ends
//! while its key rotates (revoked meanwhile, not tracked by the registry,
//! not movable by the store) is claimed and recorded before its row is
//! removed, and is not ended when it cannot be recorded.

use super::audit_support::{
    Faulty, Sink, admin, authenticated, impersonated_since, memory_store, stored, user,
};
use super::concurrency_tests::{TTL, finalize_telling, request_holding};
use super::*;
use crate::authn::ids::testing as ids;
use crate::session::data::{EndingClaim, SessionData};
use crate::session::id::{SessionId, SessionKey};
use crate::session::layer::UnknownLiveness;
use crate::session::layer::audit::LayerSessionEnded;
use crate::session::store::{MAX_MOVE_RECORDS_PER_USER, MemorySessionStore, SessionRegistry};
use crate::testing::mock_random::MockRng;
use crate::testing::registry_double::{RegistryCall, RegistryDouble, RegistryOp, Step};
use axess_clock::testing::MockClock;
use axess_clock::testing::Shift;
use std::sync::atomic::Ordering;

fn ids_of_rotation() -> (SessionId, SessionId) {
    (
        SessionId::new(&MockRng::new(41)),
        SessionId::new(&MockRng::new(42)),
    )
}

/// What a test scripts a registry to answer.
#[derive(Default)]
struct Scripted {
    held: Vec<SessionId>,
    /// Ids the registry cannot answer for.
    unanswered: Vec<SessionId>,
    /// Every move fails.
    move_fails: bool,
    /// The user's move records are at their bound, each the first former
    /// key of a session of its own, so a move answers `Full`.
    full: bool,
}

impl Scripted {
    fn holding(ids: &[SessionId]) -> Self {
        Self {
            held: ids.to_vec(),
            ..Self::default()
        }
    }

    fn unanswering_for(mut self, id: SessionId) -> Self {
        self.unanswered.push(id);
        self
    }

    /// The registry that answers as scripted, holding `held` for `user()`.
    async fn registry(self) -> RegistryDouble {
        let unanswered: Vec<SessionKey> = self.unanswered.iter().map(SessionKey::of).collect();
        let move_fails = self.move_fails;
        let registry = RegistryDouble::new().before(move |call, _| {
            let fails = match &call {
                RegistryCall::IsValid { session, .. } => unanswered.contains(session),
                RegistryCall::MoveSession { .. } => move_fails,
                _ => false,
            };
            async move {
                if fails {
                    Step::Fail("the registry does not answer")
                } else {
                    Step::Forward
                }
            }
        });
        if self.full {
            fill_move_records(registry.inner()).await;
        }
        for id in &self.held {
            registry
                .inner()
                .register(&user(), &SessionKey::of(id))
                .await
                .unwrap();
        }
        registry
    }
}

/// Bring `user()`'s move records to their bound, each the first former key
/// of a session of its own, which a move never gives up.
async fn fill_move_records(registry: &crate::session::store::MemorySessionRegistry) {
    for i in 0..MAX_MOVE_RECORDS_PER_USER {
        let key = |half: u8| {
            let mut bytes = [half; 32];
            bytes[..8].copy_from_slice(&(i as u64).to_be_bytes());
            SessionKey::from_bytes(bytes)
        };
        registry.register(&user(), &key(0xA0)).await.unwrap();
        assert_eq!(
            registry
                .move_session(&user(), &key(0xA0), &key(0xB0))
                .await
                .unwrap(),
            crate::session::store::MoveOutcome::Moved
        );
    }
}

/// Whether `registry` holds `id` for `user()`.
async fn holds(registry: &RegistryDouble, id: &SessionId) -> bool {
    registry
        .inner()
        .is_valid(&user(), &SessionKey::of(id))
        .await
        .unwrap()
}

/// What a request knows the registry holds, as `Rotation::held`.
#[derive(Clone, Copy)]
enum Known {
    /// The key the request arrived with (a rotation, a step-up).
    Arrived,
    /// The new key, which a handler registered (a login).
    New,
    /// Nothing for this user.
    Nothing,
}

/// One way the registry makes the layer end a rotated session.
struct Case {
    name: &'static str,
    registry: fn(SessionId, SessionId) -> Scripted,
    known: Known,
    reason: SessionEndReason,
    /// `UnknownLiveness::Accept` keeps the session: the registry could not
    /// say whether it holds the key the cookie is to carry.
    accept_keeps: bool,
}

/// Every arm of the registry settlement that ends the session, with the
/// reason it is recorded for.
fn cases() -> Vec<Case> {
    use SessionEndReason::{NotTracked, RevokedDuringRotation};
    vec![
        Case {
            name: "the registry no longer holds the key the session rotated from",
            registry: |_, _| Scripted::holding(&[]),
            known: Known::Arrived,
            reason: RevokedDuringRotation,
            accept_keeps: false,
        },
        Case {
            name: "the move errs",
            registry: |old, _| Scripted {
                move_fails: true,
                ..Scripted::holding(&[old])
            },
            known: Known::Arrived,
            reason: NotTracked,
            accept_keeps: false,
        },
        Case {
            name: "the registry is full",
            registry: |old, _| Scripted {
                full: true,
                ..Scripted::holding(&[old])
            },
            known: Known::Arrived,
            reason: NotTracked,
            accept_keeps: false,
        },
        Case {
            name: "the registry no longer holds the key the handler registered",
            registry: |_, _| Scripted::holding(&[]),
            known: Known::New,
            reason: RevokedDuringRotation,
            accept_keeps: false,
        },
        Case {
            name: "the registry cannot confirm the key the handler registered",
            registry: |_, new| Scripted::holding(&[new]).unanswering_for(new),
            known: Known::New,
            reason: NotTracked,
            accept_keeps: true,
        },
        Case {
            name: "nothing is known and the registry holds neither key",
            registry: |_, _| Scripted::holding(&[]),
            known: Known::Nothing,
            reason: RevokedDuringRotation,
            accept_keeps: false,
        },
        Case {
            name: "nothing is known and the registry cannot confirm the new key",
            registry: |_, new| Scripted::holding(&[]).unanswering_for(new),
            known: Known::Nothing,
            reason: NotTracked,
            accept_keeps: true,
        },
        Case {
            name: "nothing is known and the move of the key the request arrived with errs",
            registry: |old, _| Scripted {
                move_fails: true,
                ..Scripted::holding(&[old])
            },
            known: Known::Nothing,
            reason: NotTracked,
            accept_keeps: false,
        },
    ]
}

/// A rotated session of `user()` impersonated by `admin()`, its row stored
/// under the new key, as the registry settlement finds it.
struct Rotated {
    store: MemorySessionStore,
    sink: Sink,
    old: SessionId,
    new: SessionId,
}

impl Rotated {
    async fn new() -> Self {
        let store = memory_store();
        let (old, new) = ids_of_rotation();
        store
            .save(&SessionKey::of(&new), &impersonated_since(0), TTL)
            .await
            .unwrap();
        Self {
            sink: Sink::on(&store),
            store,
            old,
            new,
        }
    }

    /// Settle the rotation in `registry`, `store` holding the row: whether
    /// the response sets the cookie of the new key.
    async fn settle_in<S>(
        &self,
        store: &S,
        registry: &RegistryDouble,
        known: Known,
        unknown: UnknownLiveness,
    ) -> bool
    where
        S: SessionStore + Send + Sync + 'static,
        S::Error: std::fmt::Display + Send + Sync + 'static,
    {
        let held = match known {
            Known::Arrived => Some(SessionKey::of(&self.old)),
            Known::New => Some(SessionKey::of(&self.new)),
            Known::Nothing => None,
        };
        let outcome = FinalizeOutcome {
            session: CookieSession::of_id(self.new),
            session_changed: true,
            rotation: Some(Rotation {
                user_id: user(),
                tenant_id: ids::tenant("t"),
                impersonator: Some(admin()),
                arrived: SessionKey::of(&self.old),
                new: SessionKey::of(&self.new),
                held,
                anchor: None,
            }),
            released: Vec::new(),
        };
        let handle = registry.clone().handle();
        settle_registry(
            store,
            Some(&*handle),
            (unknown, &self.sink),
            (MockClock::reference_time(), TTL),
            &outcome,
        )
        .await
    }

    async fn settle(
        &self,
        registry: &RegistryDouble,
        known: Known,
        unknown: UnknownLiveness,
    ) -> bool {
        self.settle_in(&self.store, registry, known, unknown).await
    }

    fn record(&self, reason: SessionEndReason) -> LayerSessionEnded {
        LayerSessionEnded {
            user_id: user(),
            tenant_id: ids::tenant("t"),
            session_id: SessionKey::of(&self.new),
            impersonator: Some(admin()),
            reason,
        }
    }

    async fn row(&self) -> Option<SessionData> {
        self.store.load(&SessionKey::of(&self.new)).await.unwrap()
    }
}

/// Every ending the registry settlement makes is claimed on the row, then
/// recorded once, with the session under its new key, its user, its
/// tenant, its administrator and the reason; then the row is removed, the
/// registry holds neither key, and no cookie is set.
#[tokio::test]
async fn a_session_ended_while_its_key_rotated_is_claimed_and_recorded_before_its_row_goes() {
    for case in cases() {
        let name = case.name;
        let rotated = Rotated::new().await;
        let registry = (case.registry)(rotated.old, rotated.new).registry().await;

        let cookie = rotated
            .settle(&registry, case.known, UnknownLiveness::Reject)
            .await;

        assert!(!cookie, "{name}: an ended session gets no cookie");
        let told = rotated.sink.the_call();
        assert_eq!(told.ended, rotated.record(case.reason), "{name}");
        let seen = told
            .row
            .unwrap_or_else(|| panic!("{name}: the row is stored when told"));
        assert_eq!(
            seen.ending.map(|claim| claim.reason),
            Some(case.reason),
            "{name}: the row is claimed for its reason before the sink is told"
        );
        assert!(rotated.row().await.is_none(), "{name}: the row is removed");
        assert!(
            !holds(&registry, &rotated.new).await,
            "{name}: the new key is not registered"
        );
        assert!(
            !holds(&registry, &rotated.old).await,
            "{name}: the old key is not registered"
        );
    }
}

/// When the sink fails, none of those endings is performed: the claim is
/// taken back, the row stays as it was stored and the cookie of the new key
/// is set, so the next request presents the session to the load. The
/// registry does not hold it, which is what ends it there.
#[tokio::test]
async fn a_rotation_ending_that_cannot_be_recorded_is_not_performed() {
    for case in cases() {
        let name = case.name;
        let rotated = Rotated::new().await;
        rotated.sink.failing.store(true, Ordering::SeqCst);
        let before = rotated.row().await;
        let registry = (case.registry)(rotated.old, rotated.new).registry().await;

        let cookie = rotated
            .settle(&registry, case.known, UnknownLiveness::Reject)
            .await;

        assert!(cookie, "{name}: the session keeps its cookie");
        assert_eq!(rotated.sink.told().len(), 1, "{name}: the sink was asked");
        let mut after = rotated.row().await.expect("the row stands");
        assert_eq!(after.ending, None, "{name}: the claim is taken back");
        after.revision = before.as_ref().unwrap().revision;
        assert_eq!(
            stored(&Some(after)),
            stored(&before),
            "{name}: the row stands as it was"
        );
        assert!(
            !holds(&registry, &rotated.new).await,
            "{name}: not registered"
        );
    }
}

/// A session left stored because its ending could not be recorded is ended
/// by the next request that presents it, with its row: the registry does
/// not hold it, so the load refuses it, records it and removes it.
#[tokio::test]
async fn the_next_request_ends_a_session_whose_ending_could_not_be_recorded() {
    let rotated = Rotated::new().await;
    rotated.sink.failing.store(true, Ordering::SeqCst);
    let registry = Scripted::holding(&[]).registry().await;
    assert!(
        rotated
            .settle(&registry, Known::Arrived, UnknownLiveness::Reject)
            .await
    );
    rotated.sink.failing.store(false, Ordering::SeqCst);

    let (store, sink, new) = (rotated.store, rotated.sink, rotated.new);
    let sink = std::sync::Arc::new(sink);
    let told = present(&store, &registry, &sink, new).await;

    assert_eq!(told.len(), 2);
    assert_eq!(told[1].ended.reason, SessionEndReason::NotRegistered);
    assert_eq!(told[1].ended.session_id, SessionKey::of(&new));
}

/// Present the cookie of `id` to the load, with `registry` and `sink`:
/// what the sink has been told by then. The session is ended there.
async fn present(
    store: &MemorySessionStore,
    registry: &RegistryDouble,
    sink: &std::sync::Arc<Sink>,
    id: SessionId,
) -> Vec<super::audit_support::Told> {
    let keys = SigningKeyRing::from_master(&[0xCC; 32]);
    let cfg = SessionConfig::builder().ttl(TTL).build();
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
    let audit: std::sync::Arc<dyn SessionEndAudit> = sink.clone();
    let outcome = load_session(
        store,
        &keys,
        &cfg,
        &headers,
        Fingerprints::default(),
        &MockRng::new(1),
        &LoadPolicy {
            registry: Some(&*registry.clone().handle()),
            unknown: UnknownLiveness::Reject,
            // Past the lease of any claim the settlement left.
            clock: &MockClock::at(
                MockClock::reference_time().plus(axess_clock::SignedDuration::hours(1)),
            ),
            metrics: None,
            audit: &audit,
        },
    )
    .await;
    assert!(outcome.session_ended, "the load ends the session");
    assert!(!outcome.data.auth_state.is_authenticated());
    assert!(store.load(&SessionKey::of(&id)).await.unwrap().is_none());
    sink.told()
}

/// A store that fails the removal after the sink answered leaves the row
/// under the new key claimed with its reason; the request that presents it
/// later finishes the ending for the SAME reason, and the row goes.
#[tokio::test]
async fn a_settlement_ending_whose_removal_fails_is_finished_for_the_same_reason() {
    let rotated = Rotated::new().await;
    let faulty = Faulty::over(&rotated.store);
    faulty.faults.deletes.store(usize::MAX, Ordering::SeqCst);
    let registry = Scripted::holding(&[]).registry().await;

    let cookie = rotated
        .settle_in(&faulty, &registry, Known::Arrived, UnknownLiveness::Reject)
        .await;

    assert!(!cookie);
    let claimed = rotated.row().await.expect("the row is left claimed");
    assert_eq!(
        claimed.ending.map(|claim| claim.reason),
        Some(SessionEndReason::RevokedDuringRotation)
    );
    // The registry holds the new key from here on, so only the claim can
    // make the later request end the session, and for the claim's reason.
    registry
        .inner()
        .register(&user(), &SessionKey::of(&rotated.new))
        .await
        .unwrap();

    let (store, sink, new) = (rotated.store, rotated.sink, rotated.new);
    let sink = std::sync::Arc::new(sink);
    let told = present(&store, &registry, &sink, new).await;
    let reasons: Vec<_> = told.iter().map(|t| t.ended.reason).collect();
    assert_eq!(
        reasons,
        vec![SessionEndReason::RevokedDuringRotation; 2],
        "the later request records the reason the claim keeps"
    );
}

/// A registry that cannot say whether it holds the key the cookie is to
/// carry ends nothing when the layer accepts that: the session keeps its
/// row and its cookie, and nothing is recorded. A registry that could not
/// move the entry, or is full, ends the session under `Accept` as well:
/// the cookie would name a key the registry does not hold.
#[tokio::test]
async fn under_accept_only_an_unanswered_check_keeps_the_session() {
    for case in cases() {
        if case.reason != SessionEndReason::NotTracked {
            continue;
        }
        let name = case.name;
        let rotated = Rotated::new().await;
        let registry = (case.registry)(rotated.old, rotated.new).registry().await;

        let cookie = rotated
            .settle(&registry, case.known, UnknownLiveness::Accept)
            .await;

        if case.accept_keeps {
            assert!(cookie, "{name}");
            assert!(rotated.sink.told().is_empty(), "{name}");
            assert!(rotated.row().await.is_some(), "{name}");
        } else {
            assert!(!cookie, "{name}: ended under Accept as well");
            assert_eq!(
                rotated.sink.the_call().ended,
                rotated.record(SessionEndReason::NotTracked),
                "{name}"
            );
            assert!(rotated.row().await.is_none(), "{name}");
        }
    }
}

/// A rotation the registry tracks is one move and nothing else: nothing is
/// ended or recorded, and the registry holds the new key in place of the
/// old.
#[tokio::test]
async fn a_tracked_rotation_is_one_move_and_is_not_recorded() {
    let rotated = Rotated::new().await;
    let registry = Scripted::holding(&[rotated.old]).registry().await;

    assert!(
        rotated
            .settle(&registry, Known::Arrived, UnknownLiveness::Reject)
            .await
    );

    assert!(rotated.sink.told().is_empty());
    assert_eq!(
        registry.calls(),
        vec![RegistryCall::MoveSession {
            user: user(),
            old: SessionKey::of(&rotated.old),
            new: SessionKey::of(&rotated.new),
        }],
        "one move, and no other registry call"
    );
    assert!(holds(&registry, &rotated.new).await && !holds(&registry, &rotated.old).await);
    assert!(rotated.row().await.is_some());
    assert_eq!(registry.count(RegistryOp::Register), 0);
}

/// The rotation the finalize stage hands the registry settlement carries
/// what the record needs from the session (its tenant and its
/// administrator) and what the request knows the registry holds: the key
/// it arrived with, for a session loaded signed in.
#[tokio::test]
async fn a_rotation_carries_the_tenant_the_administrator_and_the_key_the_registry_holds() {
    let store = memory_store();
    let (old, new) = ids_of_rotation();
    let row = impersonated_since(0);
    store.save(&SessionKey::of(&old), &row, TTL).await.unwrap();
    let mut inner = request_holding(&store, new, &row);
    inner.regenerate = true;
    inner.pre_cycle = Some(SessionKey::of(&old));
    inner.registered = Some((user(), SessionKey::of(&old)));

    let outcome = finalize_telling(&store, inner, Some(old), &Sink::on(&store)).await;

    let rotation = outcome.rotation.expect("an authenticated session rotated");
    assert_eq!(rotation.user_id, user());
    assert_eq!(rotation.tenant_id, ids::tenant("t"));
    assert_eq!(rotation.impersonator, Some(admin()));
    assert_eq!(
        (rotation.arrived, rotation.new, rotation.held),
        (
            SessionKey::of(&old),
            SessionKey::of(&new),
            Some(SessionKey::of(&old))
        )
    );
}

/// An impersonation the settlement ends loses the entry its administrator
/// holds it by.
#[tokio::test]
async fn an_impersonation_the_settlement_ends_loses_its_administrators_entry() {
    let rotated = Rotated::new().await;
    let anchor = SessionKey::of(&SessionId::new(&MockRng::new(43)));
    let registry = Scripted::holding(&[]).registry().await;
    registry.inner().register(&admin(), &anchor).await.unwrap();
    let outcome = FinalizeOutcome {
        session: CookieSession::of_id(rotated.new),
        session_changed: true,
        rotation: Some(Rotation {
            user_id: user(),
            tenant_id: ids::tenant("t"),
            impersonator: Some(admin()),
            arrived: SessionKey::of(&rotated.old),
            new: SessionKey::of(&rotated.new),
            held: Some(SessionKey::of(&rotated.old)),
            anchor: Some((admin(), anchor)),
        }),
        released: Vec::new(),
    };
    let handle = registry.clone().handle();

    let cookie = settle_registry(
        &rotated.store,
        Some(&*handle),
        (UnknownLiveness::Reject, &rotated.sink),
        (MockClock::reference_time(), TTL),
        &outcome,
    )
    .await;

    assert!(!cookie);
    assert!(!registry.inner().is_valid(&admin(), &anchor).await.unwrap());
}

/// An entry the request knows of for another user than the one the
/// response names is not the session's: the rotation knows nothing.
#[tokio::test]
async fn an_entry_of_another_user_is_not_what_the_registry_holds_for_the_session() {
    let store = memory_store();
    let (old, new) = ids_of_rotation();
    let row = authenticated();
    store.save(&SessionKey::of(&old), &row, TTL).await.unwrap();
    let mut inner = request_holding(&store, new, &row);
    inner.regenerate = true;
    inner.pre_cycle = Some(SessionKey::of(&old));
    inner.registered = Some((admin(), SessionKey::of(&old)));

    let outcome = finalize_telling(&store, inner, Some(old), &Sink::on(&store)).await;

    assert_eq!(outcome.rotation.expect("rotated").held, None);
}

// ── a rotation the store cannot make ───────────────────────────────────────

/// A stored session under `old`, a request that rotates it to `new` leaving
/// `left`, and a store that fails or conflicts every rotation.
struct Failing {
    store: Faulty,
    sink: Sink,
    old: SessionId,
    new: SessionId,
    inner: crate::session::layer::handle::SessionInner,
}

impl Failing {
    async fn rotating(loaded: &SessionData, left: &SessionData) -> Self {
        let memory = memory_store();
        let (old, new) = ids_of_rotation();
        memory
            .save(&SessionKey::of(&old), loaded, TTL)
            .await
            .unwrap();
        let mut inner = request_holding(&memory, new, loaded);
        inner.data = left.clone();
        inner.regenerate = true;
        inner.pre_cycle = Some(SessionKey::of(&old));
        let store = Faulty::over(&memory);
        store.faults.cycles.store(true, Ordering::SeqCst);
        Self {
            // The sink reads the row under the old id: the stored session.
            sink: Sink::on(&memory).watching(SessionKey::of(&old)),
            store,
            old,
            new,
            inner,
        }
    }

    async fn finalize(self) -> (FinalizeOutcome, Sink, Faulty) {
        let outcome = finalize_telling(&self.store, self.inner, Some(self.old), &self.sink).await;
        (outcome, self.sink, self.store)
    }
}

fn rotation_failed(
    user_id: crate::authn::ids::UserId,
    session_id: SessionId,
    impersonator: Option<crate::authn::ids::UserId>,
) -> LayerSessionEnded {
    LayerSessionEnded {
        user_id,
        tenant_id: ids::tenant("t"),
        session_id: SessionKey::of(&session_id),
        impersonator,
        reason: SessionEndReason::RotationFailed,
    }
}

/// The same user's session whose rotation the store cannot make (a step-up,
/// a regenerate) ends: it is recorded once, under the id its row holds,
/// while that row is still stored, and then both ids are left without a
/// row and the client's cookie is replaced.
#[tokio::test]
async fn a_session_the_store_cannot_rotate_is_recorded_before_its_row_goes() {
    for conflicting in [false, true] {
        let failing = Failing::rotating(&authenticated(), &authenticated()).await;
        failing
            .store
            .faults
            .cycles
            .store(!conflicting, Ordering::SeqCst);
        failing
            .store
            .faults
            .conflicting_cycles
            .store(conflicting, Ordering::SeqCst);
        let (old, new) = (failing.old, failing.new);

        let (outcome, sink, store) = failing.finalize().await;

        let told = sink.the_call();
        assert_eq!(told.ended, rotation_failed(user(), old, None));
        assert!(
            told.row
                .is_some_and(|row| row.auth_state.signed_in().is_some()),
            "the stored session is still there when the sink is told"
        );
        assert!(
            store
                .inner
                .load(&SessionKey::of(&old))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .inner
                .load(&SessionKey::of(&new))
                .await
                .unwrap()
                .is_none()
        );
        assert!(outcome.session_changed, "the cookie is replaced");
        assert_eq!(
            outcome.released,
            vec![(user(), SessionKey::of(&old))],
            "the ended session's entry is handed to the finish to remove"
        );
        assert_eq!(*outcome.session.key(), SessionKey::of(&new));
        assert!(outcome.rotation.is_none());
    }
}

/// The stored session of a failed rotation is ended as the load ends one:
/// claimed, recorded, removed. When the store then fails the removal too,
/// the session is left claimed, so it is refused and a later request
/// finishes the ending; it is not left to authenticate with a row that
/// says it ended.
#[tokio::test]
async fn a_failed_rotation_whose_removal_fails_leaves_the_session_claimed() {
    let failing = Failing::rotating(&authenticated(), &authenticated()).await;
    failing
        .store
        .faults
        .deletes
        .store(usize::MAX, Ordering::SeqCst);
    let old = failing.old;

    let (outcome, sink, store) = failing.finalize().await;

    let told = sink.the_call();
    assert_eq!(told.ended, rotation_failed(user(), old, None));
    let row = store
        .inner
        .load(&SessionKey::of(&old))
        .await
        .unwrap()
        .expect("the store kept the row");
    assert_eq!(
        row.ending,
        Some(EndingClaim {
            since: MockClock::reference_time(),
            reason: SessionEndReason::RotationFailed,
        }),
        "claimed, so the load refuses it and finishes the ending"
    );
    assert!(outcome.session_changed, "the cookie is replaced");
}

/// When that ending cannot be recorded it is not performed: the stored
/// session is left as it was, and no cookie is set, so the client keeps the
/// session it had.
#[tokio::test]
async fn a_failed_rotation_that_cannot_be_recorded_keeps_the_stored_session() {
    let failing = Failing::rotating(&authenticated(), &authenticated()).await;
    failing.sink.failing.store(true, Ordering::SeqCst);
    let (old, new) = (failing.old, failing.new);
    let before = failing
        .store
        .inner
        .load(&SessionKey::of(&old))
        .await
        .unwrap();

    let (outcome, sink, store) = failing.finalize().await;

    assert_eq!(sink.told().len(), 1, "the sink was asked");
    // As it was stored, two revisions on: the claim and its release.
    let mut kept = before.expect("the session was stored");
    kept.revision += 2;
    assert_eq!(
        stored(&store.inner.load(&SessionKey::of(&old)).await.unwrap()),
        stored(&Some(kept))
    );
    assert!(
        store
            .inner
            .load(&SessionKey::of(&new))
            .await
            .unwrap()
            .is_none()
    );
    assert!(!outcome.session_changed, "the client keeps its cookie");
}

/// A login whose rotation the store cannot make leaves a session the login
/// already recorded and no row ever held: it is recorded under the id it
/// was to get. No stored session ends, so nothing else is told.
#[tokio::test]
async fn a_login_the_store_cannot_keep_is_recorded_under_its_new_id() {
    let failing = Failing::rotating(&SessionData::default(), &authenticated()).await;
    let (old, new) = (failing.old, failing.new);

    let (outcome, sink, store) = failing.finalize().await;

    assert_eq!(sink.the_call().ended, rotation_failed(user(), new, None));
    assert!(
        store
            .inner
            .load(&SessionKey::of(&old))
            .await
            .unwrap()
            .is_none()
    );
    assert!(outcome.session_changed);
}

/// A request that changes who the session is (the start of an
/// impersonation) and cannot rotate ends two sessions: the administrator's
/// own, which was stored, and the impersonation, which never was. Each is
/// recorded, the stored one first.
#[tokio::test]
async fn a_failed_change_of_user_records_the_stored_session_and_the_one_never_stored() {
    let mut as_admin = SessionData::default();
    as_admin
        .auth_state
        .set_authenticated(admin(), ids::tenant("t"), MockClock::reference_time());
    let failing = Failing::rotating(&as_admin, &impersonated_since(0)).await;
    let (old, new) = (failing.old, failing.new);

    let (outcome, sink, store) = failing.finalize().await;

    let told: Vec<_> = sink.told().into_iter().map(|told| told.ended).collect();
    assert_eq!(
        told,
        [
            rotation_failed(admin(), old, None),
            rotation_failed(user(), new, Some(admin())),
        ]
    );
    assert!(
        store
            .inner
            .load(&SessionKey::of(&old))
            .await
            .unwrap()
            .is_none()
    );
    assert!(outcome.session_changed);
}

/// A request that leaves a guest (a logout) ended its session itself: a
/// rotation that fails removes the row, as the logout meant, and the layer
/// records nothing of its own.
#[tokio::test]
async fn a_failed_rotation_of_a_logout_is_not_the_layers_ending() {
    let failing = Failing::rotating(&authenticated(), &SessionData::default()).await;
    let old = failing.old;

    let (outcome, sink, store) = failing.finalize().await;

    assert!(sink.told().is_empty());
    assert!(
        store
            .inner
            .load(&SessionKey::of(&old))
            .await
            .unwrap()
            .is_none()
    );
    assert!(outcome.session_changed);
}

// ── a rotation of a session in a step-up ───────────────────────────────────

/// A session in a step-up of `authenticated()`, impersonated by `admin()`.
fn stepping_up() -> SessionData {
    let mut data = impersonated_since(0);
    assert!(
        data.auth_state
            .begin_step_up(vec![crate::authn::factor::FactorStep::Required(
                crate::authn::factor::FactorKind::Totp
            )])
    );
    assert!(!data.auth_state.is_authenticated(), "a step-up in progress");
    data
}

/// A session in a step-up whose rotation the settlement ends is recorded as
/// the signed-in session it began from: its user, tenant and administrator,
/// under its new key, with the row stored and claimed when the sink is told.
#[tokio::test]
async fn a_step_up_the_settlement_ends_is_recorded_as_the_session_it_began_from() {
    let rotated = Rotated::new().await;
    rotated
        .store
        .save(&SessionKey::of(&rotated.new), &stepping_up(), TTL)
        .await
        .unwrap();
    let registry = Scripted::holding(&[]).registry().await;

    let cookie = rotated
        .settle(&registry, Known::Arrived, UnknownLiveness::Reject)
        .await;

    assert!(!cookie);
    let told = rotated.sink.the_call();
    assert_eq!(
        told.ended,
        rotated.record(SessionEndReason::RevokedDuringRotation)
    );
    let row = told.row.expect("the row is stored when the sink is told");
    assert!(
        row.auth_state.signed_in().is_some(),
        "the signed-in session"
    );
    assert!(row.ending.is_some(), "claimed first");
    assert!(rotated.row().await.is_none());
}

/// A session in a step-up whose rotation the store fails is recorded as the
/// signed-in session it began from, under the key its row holds.
#[tokio::test]
async fn a_step_up_the_store_cannot_rotate_is_recorded_as_the_session_it_began_from() {
    let failing = Failing::rotating(&stepping_up(), &stepping_up()).await;
    let old = failing.old;

    let (outcome, sink, _) = failing.finalize().await;

    let told = sink.the_call();
    assert_eq!(told.ended, rotation_failed(user(), old, Some(admin())));
    assert!(
        told.row
            .is_some_and(|row| row.auth_state.signed_in().is_some()),
        "the stored session is still there when the sink is told"
    );
    assert!(outcome.session_changed, "the cookie is replaced");
}
