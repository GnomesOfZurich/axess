//! `RequestAuthnService::rotate_session` and the logins behind a session
//! layer: the handler asks for the rotation, a login registers its key, and
//! the layer moves or checks the entry after the row has moved.

use crate::world::{Browser, Options, World, alice};
use axess_core::session::UnknownLiveness;
use axess_core::testing::registry_double::RegistryOp;
use std::sync::atomic::Ordering;

/// The handler asks for the rotation and the layer moves the entry: the
/// session survives under its new key, in its old key's place, and nothing
/// is recorded as ended.
#[tokio::test]
async fn a_rotation_a_handler_asks_for_keeps_the_session_and_moves_its_entry() {
    let w = World::new();
    let mut b = Browser::default();
    assert_eq!(w.get(&mut b, "/login").await, "Authenticated");
    let before = w.key(&mut b).await;
    assert_eq!(w.held(&alice()).await, vec![before]);

    assert_eq!(w.get(&mut b, "/rotate").await, "rotated");
    assert!(b.cookie_set, "the rotation's response sets the new cookie");
    assert_eq!(
        w.get(&mut b, "/whoami").await,
        "user",
        "the next request with it is signed in"
    );
    let after = w.key(&mut b).await;
    assert_ne!(after, before, "the key rotated");
    assert_eq!(
        w.held(&alice()).await,
        vec![after],
        "the registry holds exactly the new key in the old one's place"
    );
    assert!(w.row(&before).await.is_none(), "the old row is gone");
    assert_eq!(
        w.ends.reasons(),
        Vec::<&str>::new(),
        "the sink was told nothing"
    );
}

/// The registry entry is removed while the handler runs: the layer's move
/// finds the old key gone. No cookie, one record, the row claimed before
/// the sink is told and gone after, and the registry holds neither key.
#[tokio::test]
async fn a_session_revoked_while_it_rotates_is_ended_with_one_record() {
    let w = World::new();
    let mut b = Browser::default();
    w.get(&mut b, "/login").await;
    let before = w.key(&mut b).await;

    assert_eq!(w.get(&mut b, "/rotate-revoked").await, "rotated");

    assert!(!b.cookie_set, "no cookie for the ended session");
    let told = w.ends.told();
    assert_eq!(w.ends.reasons(), vec!["session_revoked_during_rotation"]);
    let (ended, row) = &told[0];
    assert_eq!(ended.user_id, alice());
    assert_eq!(ended.impersonator, None);
    assert!(
        row.as_ref().and_then(|row| row.ending).is_some(),
        "the row is claimed before the sink is told"
    );
    assert!(w.row(&ended.session_id).await.is_none(), "the row is gone");
    assert!(w.held(&alice()).await.is_empty());
    assert!(!w.held(&alice()).await.contains(&before));
    assert_eq!(w.get(&mut b, "/whoami").await, "guest");
}

/// A registry that errs on the move ends the session in the same request,
/// as not tracked, through the claim: under `Reject` and under `Accept`
/// alike, since the cookie would name a key the registry does not hold.
#[tokio::test]
async fn a_registry_that_errs_on_the_move_ends_the_session_under_either_setting() {
    for unknown in [UnknownLiveness::Reject, UnknownLiveness::Accept] {
        let w = World::with(Options {
            unknown,
            ..Options::default()
        });
        let mut b = Browser::default();
        w.get(&mut b, "/login").await;
        w.faults.fail_moves.store(true, Ordering::SeqCst);

        assert_eq!(w.get(&mut b, "/regenerate").await, "regenerated");

        assert!(!b.cookie_set, "{unknown:?}: no cookie");
        assert_eq!(
            w.ends.reasons(),
            vec!["session_not_tracked"],
            "{unknown:?}: one record"
        );
        let (ended, row) = &w.ends.told()[0];
        assert!(
            row.as_ref().and_then(|row| row.ending).is_some(),
            "{unknown:?}: through the claim"
        );
        assert!(w.row(&ended.session_id).await.is_none());
        assert_eq!(w.get(&mut b, "/whoami").await, "guest", "{unknown:?}");
    }
}

/// A guest signs in: the handler registered the new key, the layer made no
/// move, the cookie is set. When the registry no longer holds the key the
/// login registered, the session ends as revoked.
#[tokio::test]
async fn a_login_still_registers_and_the_layer_only_checks_it() {
    let w = World::new();
    let mut b = Browser::default();
    assert_eq!(w.get(&mut b, "/login").await, "Authenticated");
    assert!(b.cookie_set);
    assert_eq!(
        w.count(RegistryOp::MoveSession),
        0,
        "the layer made no move"
    );
    assert_eq!(w.count(RegistryOp::Register), 1);
    let key = w.key(&mut b).await;
    assert_eq!(w.held(&alice()).await, vec![key]);

    let mut revoked = Browser::default();
    w.get(&mut revoked, "/login-revoked").await;
    assert!(!revoked.cookie_set);
    assert_eq!(w.ends.reasons(), vec!["session_revoked_during_rotation"]);
}

/// A handler signs a guest in and then asks for a rotation (or rotates
/// itself) in the same request: the session survives, and the registry
/// holds exactly the final key.
#[tokio::test]
async fn a_login_and_a_rotation_in_one_request_keep_the_session() {
    for path in ["/login-and-rotate", "/login-and-regenerate"] {
        let w = World::new();
        let mut b = Browser::default();
        let answer = w.get(&mut b, path).await;
        assert!(answer.starts_with("Authenticated"), "{path}: {answer}");
        assert!(b.cookie_set, "{path}");
        assert_eq!(w.get(&mut b, "/whoami").await, "user", "{path}");
        let key = w.key(&mut b).await;
        assert_eq!(w.held(&alice()).await, vec![key], "{path}");
        assert!(w.ends.told().is_empty(), "{path}");
    }
}

/// A handler of the adopter's own registers the key a guest session
/// carries and then signs the session in, which rotates it: the layer knows
/// of no entry, finds the new key not held, and moves the key the request
/// arrived with. The session survives, in the first key's place.
#[tokio::test]
async fn a_handler_of_the_adopters_own_that_registered_the_arrived_key_keeps_the_session() {
    let w = World::with(Options {
        service_registry: false,
        ..Options::default()
    });
    let mut b = Browser::default();
    assert_eq!(w.get(&mut b, "/own-sign-in").await, "user");
    assert!(b.cookie_set);
    assert_eq!(w.get(&mut b, "/whoami").await, "user");
    let key = w.key(&mut b).await;
    assert_eq!(w.held(&alice()).await, vec![key]);
    assert_eq!(w.count(RegistryOp::MoveSession), 1);
}

/// Under a layer built without a registry, `rotate_session` and a step-up's
/// completion move the entry in one call of the service, and the validator
/// middleware finds the session valid on the next request.
#[tokio::test]
async fn under_a_layer_without_a_registry_the_service_moves_the_entry() {
    let w = World::with(Options {
        layer_registry: false,
        ..Options::default()
    });
    let mut b = Browser::default();
    w.get(&mut b, "/login").await;
    assert_eq!(w.get(&mut b, "/valid").await, "valid");

    assert_eq!(w.get(&mut b, "/rotate").await, "rotated");
    assert_eq!(w.count(RegistryOp::MoveSession), 1, "one call");
    assert_eq!(w.get(&mut b, "/valid").await, "valid");
    let key = w.key(&mut b).await;
    assert_eq!(w.held(&alice()).await, vec![key]);

    assert_eq!(w.get(&mut b, "/step-up").await, "Authenticated");
    assert_eq!(w.count(RegistryOp::MoveSession), 2, "one more call");
    assert_eq!(w.get(&mut b, "/valid").await, "valid");
    let key = w.key(&mut b).await;
    assert_eq!(w.held(&alice()).await, vec![key]);
}

/// Under a layer with a registry, a registry check later in the handler
/// that asked for the rotation asks for the key the registry still holds:
/// `check_session` is true and `SessionValidator::enforce` leaves the
/// session as it is.
#[tokio::test]
async fn registry_checks_after_a_rotation_ask_for_the_key_the_registry_holds() {
    let w = World::new();
    let mut b = Browser::default();
    w.get(&mut b, "/login").await;

    assert_eq!(
        w.get(&mut b, "/rotate-and-check").await,
        "rotated true true user"
    );
    assert!(b.cookie_set);
    assert_eq!(w.get(&mut b, "/whoami").await, "user");
    assert!(w.ends.told().is_empty());
}
