//! A session the service ends in a request that rotated its key: the
//! registry entry that goes is the one the registry holds, the key the
//! request arrived with, not the key the response would carry.

use crate::world::{Browser, Options, World, alice};
use axess_core::authn::event::AuthEventType;
use axess_core::session::SessionKey;

/// A handler rotates the session's key and then logs out, in one request.
/// Under either layer the user's entry is gone afterwards and the next
/// request is a guest's. A layer without a registry moves nothing on a
/// rotation, so only the service's logout can end the entry there.
#[tokio::test]
async fn a_logout_after_a_rotation_in_the_same_request_ends_the_entry_the_registry_holds() {
    for layer_registry in [false, true] {
        let w = World::with(Options {
            layer_registry,
            ..Options::default()
        });
        let mut b = Browser::default();
        assert_eq!(w.get(&mut b, "/login").await, "Authenticated");
        let arrived = w.key(&mut b).await;
        assert_eq!(w.held(&alice()).await, vec![arrived]);

        assert_eq!(w.get(&mut b, "/regenerate-then-logout").await, "out");

        assert!(
            w.held(&alice()).await.is_empty(),
            "layer with a registry: {layer_registry}: the entry is gone"
        );
        assert_eq!(w.get(&mut b, "/whoami").await, "guest");
    }
}

/// A step-up whose audit row cannot be written, under a layer that moves
/// the entry itself: the service ends the entry the registry holds while
/// the request still runs, so a second request with the same cookie is not
/// let through in the meantime.
#[tokio::test]
async fn a_step_up_that_cannot_be_recorded_ends_the_entry_the_registry_holds_at_once() {
    let w = World::new();
    let mut b = Browser::default();
    assert_eq!(w.get(&mut b, "/login").await, "Authenticated");

    assert_eq!(
        w.get(&mut b, "/step-up-unrecorded").await,
        "refused false",
        "the step-up is refused and the entry is gone before the response"
    );

    assert!(w.held(&alice()).await.is_empty(), "not listed");
    assert_eq!(w.get(&mut b, "/whoami").await, "guest");
}

/// A rotation and then a logout in one request, by `regenerate` behind the
/// layer and by the service's `rotate_session`, under a layer with a
/// registry and under one without: the logout's audit row names the key the
/// registry entry it ended was under, which is the key the request arrived
/// with until a move of the registry's own has followed the rotation.
#[tokio::test]
async fn the_logout_row_names_the_key_whose_registry_entry_the_logout_ended() {
    for layer_registry in [false, true] {
        for path in ["/regenerate-then-logout-keys", "/rotate-then-logout-keys"] {
            let w = World::with(Options {
                layer_registry,
                ..Options::default()
            });
            let mut b = Browser::default();
            assert_eq!(w.get(&mut b, "/login").await, "Authenticated");

            let answer = w.get(&mut b, path).await;
            let keys: Vec<SessionKey> = answer
                .split(' ')
                .map(|k| k.parse().unwrap_or_else(|_| panic!("{path}: {answer}")))
                .collect();
            let [held, own] = keys.as_slice() else {
                panic!("{path}: {answer}");
            };

            assert!(
                w.held(&alice()).await.is_empty(),
                "layer with a registry: {layer_registry}, {path}: the entry is gone"
            );
            let rows: Vec<_> = w
                .identity
                .events()
                .into_iter()
                .filter(|e| e.event_type == AuthEventType::LogoutAttempt)
                .collect();
            let [row] = rows.as_slice() else {
                panic!("{path}: one logout row, got {}", rows.len());
            };
            assert_eq!(
                row.session_id.as_ref(),
                Some(held),
                "layer with a registry: {layer_registry}, {path}: the row names the key the \
                 registry entry was under (the session carried {own})"
            );
        }
    }
}
