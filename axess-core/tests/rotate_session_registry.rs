#![cfg(feature = "testing")]
//! `rotate_session` on a session no layer stands behind moves its registry
//! entry in one step, and only a session the registry holds. A session that
//! was revoked, before the rotation or as it moves, is not registered again
//! under a new key, and a registry that cannot move the session ends the
//! rotation.

use axess_core::session::SessionKey;
use axess_core::testing::fixtures as common;

use axess_core::authn::AuditContext;
use axess_core::authn::error::AuthnError;
use axess_core::authn::service::{AuthnService, RequestAuthnService};
use axess_core::session::AuthSession;
use axess_core::session::store::{CutOff, MemorySessionRegistry, SessionRegistry};
use axess_core::testing::AuthSessionTestExt;
use axess_core::testing::registry_double::{RegistryDouble, RegistryOp, Step};
use axess_core::testing::{
    MockRng,
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session_with_rng,
};
use common::{test_tenant, test_user, tid, uid};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// What another request does as the rotation moves the session: it lands
/// just before the registry's one step.
#[derive(Clone, Copy)]
enum Meanwhile {
    /// Every session of the user is ended.
    EveryoneEnded,
    /// Every session of the user but this one is ended.
    AllButOneEnded(SessionKey),
}

/// A registry over the in-memory one whose move fails while `move_down` is
/// set and which runs `meanwhile` once, right before the next move.
fn hooked(
    inner: MemorySessionRegistry,
    move_down: Arc<AtomicBool>,
    meanwhile: Arc<Mutex<Option<Meanwhile>>>,
) -> RegistryDouble {
    RegistryDouble::over(inner).before(move |call, inner| {
        let moving = call.op() == RegistryOp::MoveSession;
        let down = moving && move_down.load(Ordering::SeqCst);
        let meanwhile = if moving {
            meanwhile.lock().unwrap().take()
        } else {
            None
        };
        async move {
            match meanwhile {
                Some(Meanwhile::EveryoneEnded) => {
                    inner.invalidate_user(call.user()).await.unwrap();
                }
                Some(Meanwhile::AllButOneEnded(keep)) => {
                    let cut = inner
                        .invalidate_other_sessions(call.user(), &keep)
                        .await
                        .unwrap();
                    assert!(matches!(cut, CutOff::KeptOne(_)), "{cut:?}");
                }
                None => {}
            }
            if down {
                Step::Fail("registry down")
            } else {
                Step::Forward
            }
        }
    })
}

struct World {
    svc: RequestAuthnService<MockIdentityStore, MockFactorStore>,
    registry: RegistryDouble,
    move_down: Arc<AtomicBool>,
    meanwhile: Arc<Mutex<Option<Meanwhile>>>,
    /// How many registry calls the world itself made, before the rotation.
    calls_before: usize,
    /// Alice's session that rotates, registered.
    session: AuthSession,
    /// Its id before the rotation.
    old: SessionKey,
    /// Alice's other session, registered.
    other: SessionKey,
}

/// A registered session of Alice, its ids drawn from `seed`.
async fn signed_in(registry: &RegistryDouble, seed: u64) -> AuthSession {
    let session = test_session_with_rng(MockRng::new(seed));
    session
        .set_authenticated(uid("alice"), tid("default"), common::start())
        .await;
    let id = session.session_key().await;
    registry.register(&uid("alice"), &id).await.unwrap();
    session
}

async fn world() -> World {
    let clock = common::test_clock();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("alice", "alice"));
    let (move_down, meanwhile) = (Arc::default(), Arc::default());
    let registry = hooked(
        MemorySessionRegistry::new().with_clock(Arc::new(clock.clone())),
        Arc::clone(&move_down),
        Arc::clone(&meanwhile),
    );
    let svc = AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .with_registry(registry.clone())
        .build()
        .with_audit_context(AuditContext::default());
    let session = signed_in(&registry, 31).await;
    let old = session.session_key().await;
    let other = signed_in(&registry, 32).await.session_key().await;
    // Only what the rotation asks of the registry is counted.
    let calls_before = registry.calls().len();
    World {
        svc,
        registry,
        move_down,
        meanwhile,
        calls_before,
        session,
        old,
        other,
    }
}

impl World {
    /// What the rotation asked of the registry.
    fn rotation_calls(&self) -> Vec<RegistryOp> {
        self.registry.calls()[self.calls_before..]
            .iter()
            .map(|call| call.op())
            .collect()
    }

    async fn held(&self) -> Vec<SessionKey> {
        self.registry
            .inner()
            .active_sessions(&uid("alice"))
            .await
            .unwrap()
    }

    /// The rotation was refused and left no session behind it: the error,
    /// a cleared session, and neither of its ids in the registry.
    async fn assert_rotation_ended<E>(&self, result: Result<(), AuthnError<E>>)
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        assert!(matches!(result, Err(AuthnError::NoFlow)), "{result:?}");
        assert!(!self.session.is_authenticated().await);
        let held = self.held().await;
        assert!(!held.contains(&self.old), "{held:?}");
        assert!(
            !held.contains(&self.session.session_key().await),
            "the id the rotation moved to is registered: {held:?}"
        );
    }
}

/// The control: a session the registry holds moves to its new key, in one
/// call of the registry.
#[tokio::test]
async fn a_session_the_registry_holds_moves_to_its_new_key_in_one_step() {
    let w = world().await;

    w.svc.rotate_session(&w.session).await.unwrap();

    let new = w.session.session_key().await;
    assert_ne!(new, w.old);
    assert_eq!(w.held().await, vec![new, w.other], "in the old key's place");
    assert!(w.session.is_authenticated().await);
    assert_eq!(w.rotation_calls(), vec![RegistryOp::MoveSession]);
    assert_eq!(
        w.session.registered_key().await,
        new,
        "the session knows the key the registry holds now"
    );
}

/// A session that was revoked is not brought back by rotating it: the
/// registry does not hold it, so the move changes nothing.
#[tokio::test]
async fn a_revoked_session_is_not_registered_again() {
    let w = world().await;
    w.registry
        .invalidate_session(&uid("alice"), &w.old)
        .await
        .unwrap();
    let calls_before = w.registry.calls().len();

    let result = w.svc.rotate_session(&w.session).await;

    w.assert_rotation_ended(result).await;
    assert_eq!(w.held().await, vec![w.other]);
    assert_eq!(
        w.registry.calls().len() - calls_before,
        1,
        "one move, nothing else"
    );
}

/// Every session of the user is ended as the rotation moves it: the move
/// finds the old key gone, and the new key is never held.
#[tokio::test]
async fn a_revocation_of_everyone_as_the_rotation_moves_ends_the_session() {
    let w = world().await;
    *w.meanwhile.lock().unwrap() = Some(Meanwhile::EveryoneEnded);

    let result = w.svc.rotate_session(&w.session).await;

    w.assert_rotation_ended(result).await;
    assert_eq!(w.held().await, Vec::<SessionKey>::new());
}

/// Another session ends every session but itself as the rotation moves (a
/// password change on another device): the rotating session is ended and
/// the other one is kept.
#[tokio::test]
async fn a_cut_off_by_another_session_as_the_rotation_moves_ends_the_session() {
    let w = world().await;
    *w.meanwhile.lock().unwrap() = Some(Meanwhile::AllButOneEnded(w.other));

    let result = w.svc.rotate_session(&w.session).await;

    w.assert_rotation_ended(result).await;
    assert_eq!(w.held().await, vec![w.other]);
}

/// A registry that cannot move the session ends the rotation, and lets the
/// old key go: nothing is kept on a guess.
#[tokio::test]
async fn a_registry_that_cannot_move_the_session_ends_the_rotation() {
    let w = world().await;
    w.move_down.store(true, Ordering::SeqCst);

    let result = w.svc.rotate_session(&w.session).await;

    w.assert_rotation_ended(result).await;
    assert_eq!(w.held().await, vec![w.other]);
    assert_eq!(
        w.rotation_calls(),
        vec![RegistryOp::MoveSession, RegistryOp::InvalidateSession]
    );
}
