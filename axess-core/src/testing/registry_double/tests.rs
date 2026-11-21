use super::{RegistryCall, RegistryDouble, RegistryDoubleError, RegistryOp, Step};
use crate::authn::ids::UserId;
use crate::session::id::{SessionId, SessionKey};
use crate::session::store::{CutOff, SessionRegistry};
use axess_rng::testing::MockRng;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

/// How long a test waits for a call it holds before it calls the call
/// unanswered. The runtime's time is paused, so the wait passes at once.
const HELD_FOR: Duration = Duration::from_secs(30);

fn ids() -> (UserId, SessionKey, SessionKey) {
    let rng = MockRng::new(7);
    (
        axess_identity::testing::user("u1"),
        SessionKey::of(&SessionId::new(&rng)),
        SessionKey::of(&SessionId::new(&rng)),
    )
}

#[tokio::test]
async fn every_method_records_its_call_with_its_arguments() {
    let (user, first, second) = ids();
    let double = RegistryDouble::new();

    double.register(&user, &first).await.unwrap();
    double.register(&user, &second).await.unwrap();
    double.is_valid(&user, &first).await.unwrap();
    double.active_sessions(&user).await.unwrap();
    assert_eq!(
        double
            .invalidate_other_sessions(&user, &first)
            .await
            .unwrap(),
        CutOff::KeptOne(vec![second])
    );
    double.invalidate_session(&user, &first).await.unwrap();
    double.invalidate_user(&user).await.unwrap();

    let expected = vec![
        RegistryCall::Register {
            user,
            session: first,
        },
        RegistryCall::Register {
            user,
            session: second,
        },
        RegistryCall::IsValid {
            user,
            session: first,
        },
        RegistryCall::ActiveSessions { user },
        RegistryCall::InvalidateOtherSessions { user, keep: first },
        RegistryCall::InvalidateSession {
            user,
            session: first,
        },
        RegistryCall::InvalidateUser { user },
    ];
    assert_eq!(double.calls(), expected);
    for op in [
        RegistryOp::Register,
        RegistryOp::IsValid,
        RegistryOp::InvalidateUser,
        RegistryOp::InvalidateSession,
        RegistryOp::InvalidateOtherSessions,
        RegistryOp::ActiveSessions,
    ] {
        let seen = expected.iter().filter(|call| call.op() == op).count();
        assert_eq!(double.count(op), seen, "{op:?}");
    }
    assert_eq!(expected[4].session(), Some(&first));
    assert_eq!(expected[6].session(), None);
    assert!(expected.iter().all(|call| call.user() == &user));
}

#[tokio::test]
async fn a_forwarded_call_reaches_the_registry_inside() {
    let (user, first, second) = ids();
    let double = RegistryDouble::new().before(|_, _| async { Step::Forward });

    double.register(&user, &first).await.unwrap();
    double.register(&user, &second).await.unwrap();
    assert!(double.inner().is_valid(&user, &first).await.unwrap());
    assert!(double.is_valid(&user, &second).await.unwrap());
    assert_eq!(
        double.active_sessions(&user).await.unwrap(),
        vec![first, second]
    );
    assert_eq!(
        double
            .invalidate_other_sessions(&user, &first)
            .await
            .unwrap(),
        CutOff::KeptOne(vec![second])
    );
    double.invalidate_session(&user, &first).await.unwrap();
    assert!(!double.inner().is_valid(&user, &first).await.unwrap());
    double.inner().register(&user, &second).await.unwrap();
    double.invalidate_user(&user).await.unwrap();
    assert!(
        double
            .inner()
            .active_sessions(&user)
            .await
            .unwrap()
            .is_empty(),
        "the user's sessions were ended"
    );
}

#[tokio::test]
async fn a_failed_call_answers_the_error_is_recorded_and_does_not_reach_the_registry() {
    let (user, first, _) = ids();
    let double = RegistryDouble::new().before(|call, _| async move {
        match call.op() {
            RegistryOp::Register | RegistryOp::InvalidateUser => Step::Fail("down"),
            _ => Step::Forward,
        }
    });
    double.inner().register(&user, &first).await.unwrap();
    let rng = MockRng::new(70);
    let refused = SessionKey::of(&SessionId::new(&rng));

    assert_eq!(
        double.register(&user, &refused).await,
        Err(RegistryDoubleError("down".to_owned()))
    );
    assert_eq!(
        double.invalidate_user(&user).await.unwrap_err().to_string(),
        "registry double: down"
    );

    assert!(!double.inner().is_valid(&user, &refused).await.unwrap());
    assert!(
        double.inner().is_valid(&user, &first).await.unwrap(),
        "the failed invalidation ended nothing"
    );
    assert_eq!(
        double.calls(),
        vec![
            RegistryCall::Register {
                user,
                session: refused,
            },
            RegistryCall::InvalidateUser { user },
        ],
        "a call that fails is recorded before it fails"
    );
}

#[tokio::test(start_paused = true)]
async fn a_held_call_is_still_pending_after_the_wait() {
    let (user, first, _) = ids();
    let double = RegistryDouble::new().before(|_, _| async { Step::Hang });

    let held = tokio::time::timeout(HELD_FOR, double.register(&user, &first)).await;

    assert!(held.is_err(), "the held call answered: {held:?}");
    assert!(!double.inner().is_valid(&user, &first).await.unwrap());
    assert_eq!(
        double.calls(),
        vec![RegistryCall::Register {
            user,
            session: first,
        }],
        "a held call is recorded"
    );
}

#[tokio::test]
async fn the_before_hook_runs_before_the_call_reaches_the_registry() {
    let (user, first, _) = ids();
    let registered_before = Arc::new(AtomicBool::new(true));
    let seen = registered_before.clone();
    let double = RegistryDouble::new().before(move |call, inner| {
        let seen = seen.clone();
        async move {
            if let RegistryCall::Register { user, session } = call {
                let held = inner.is_valid(&user, &session).await.unwrap();
                seen.store(held, Ordering::SeqCst);
            }
            Step::Forward
        }
    });

    double.register(&user, &first).await.unwrap();

    assert!(
        !registered_before.load(Ordering::SeqCst),
        "the session was registered before the hook ran"
    );
    assert!(double.inner().is_valid(&user, &first).await.unwrap());
}

#[tokio::test(start_paused = true)]
async fn the_after_hook_runs_only_for_a_call_forwarded_and_answered() {
    let (user, first, _) = ids();
    let after = Arc::new(AtomicUsize::new(0));
    let landed = Arc::new(AtomicBool::new(false));
    let (count, seen) = (after.clone(), landed.clone());
    let double = RegistryDouble::new()
        .before(|call, _| async move {
            match call.op() {
                RegistryOp::IsValid => Step::Fail("down"),
                RegistryOp::ActiveSessions => Step::Hang,
                _ => Step::Forward,
            }
        })
        .after(move |call, inner| {
            let (count, seen) = (count.clone(), seen.clone());
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                if let RegistryCall::Register { user, session } = call {
                    seen.store(
                        inner.is_valid(&user, &session).await.unwrap(),
                        Ordering::SeqCst,
                    );
                }
            }
        });

    double.register(&user, &first).await.unwrap();
    assert_eq!(after.load(Ordering::SeqCst), 1);
    assert!(
        landed.load(Ordering::SeqCst),
        "the after hook ran before the call landed"
    );

    assert!(double.is_valid(&user, &first).await.is_err());
    let held = tokio::time::timeout(HELD_FOR, double.active_sessions(&user)).await;
    assert!(held.is_err());
    assert_eq!(
        after.load(Ordering::SeqCst),
        1,
        "the after hook ran for a call that failed or was held"
    );
    assert_eq!(double.calls().len(), 3);
}

#[tokio::test]
async fn a_second_hook_replaces_the_first_and_clones_share_hooks_and_calls() {
    let (user, first, _) = ids();
    let double = RegistryDouble::new().before(|_, _| async { Step::Fail("first") });
    let clone = double.clone();
    let double = double.before(|_, _| async { Step::Fail("second") });

    assert_eq!(
        clone.register(&user, &first).await,
        Err(RegistryDoubleError("second".to_owned())),
        "the clone sees the hook set after it was made"
    );
    assert_eq!(double.count(RegistryOp::Register), 1);
    assert_eq!(double.calls(), clone.calls());
    assert!(format!("{double:?}").contains("calls: 1"));
}

#[tokio::test]
async fn the_handle_carries_the_double() {
    let (user, first, _) = ids();
    let double = RegistryDouble::new().before(|call, _| async move {
        match call.op() {
            RegistryOp::IsValid => Step::Fail("down"),
            _ => Step::Forward,
        }
    });
    let handle = double.clone().handle();

    assert!(handle.register(&user, &first).await);
    assert_eq!(
        handle.liveness(&user, &first).await,
        crate::session::store::SessionLiveness::Unknown
    );
    assert_eq!(double.count(RegistryOp::Register), 1);
    assert!(double.inner().is_valid(&user, &first).await.unwrap());
}

/// The double passes the move and the current key on to the registry inside
/// and records both, and keeps the whole registry contract.
#[tokio::test]
async fn the_double_records_a_move_and_keeps_the_registry_contract() {
    let (user, first, second) = ids();
    let double = RegistryDouble::new();
    double.register(&user, &first).await.unwrap();
    assert_eq!(
        double.move_session(&user, &first, &second).await.unwrap(),
        crate::session::store::MoveOutcome::Moved
    );
    assert_eq!(
        double.current_key(&user, &first).await.unwrap(),
        Some(second)
    );
    assert_eq!(
        double.calls()[1..],
        [
            RegistryCall::MoveSession {
                user,
                old: first,
                new: second
            },
            RegistryCall::CurrentKey {
                user,
                session: first
            },
        ]
    );
    assert_eq!(double.count(RegistryOp::MoveSession), 1);
    assert_eq!(double.count(RegistryOp::CurrentKey), 1);
    assert_eq!(double.calls()[1].session(), Some(&first));

    crate::testing::registry_contract::assert_registry_contract(&RegistryDouble::new()).await;
}
