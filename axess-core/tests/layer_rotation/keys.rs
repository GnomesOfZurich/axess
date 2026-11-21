//! `AuthSession::registered_key` and the cut-off of a user's other
//! sessions: within one request the registered key is the key the registry
//! holds, before and after the request's own rotations, and a key the
//! session held before a rotation another request made ends everything.

use crate::world::{Browser, Options, World, alice};

/// Before and after `regenerate` in one handler, and after a login in the
/// same handler, `registered_key` is the key the registry holds.
#[tokio::test]
async fn the_registered_key_is_the_key_the_registry_holds() {
    let w = World::new();
    let mut b = Browser::default();
    assert_eq!(w.get(&mut b, "/login-then-keys").await, "true true");
    w.get(&mut b, "/whoami").await;
    assert_eq!(
        w.get(&mut b, "/keys-around-regenerate").await,
        "true true true"
    );
    assert_eq!(w.get(&mut b, "/whoami").await, "user");
}

/// A cut-off keeping `registered_key` after `regenerate` keeps the caller,
/// ends the others and answers `Ok(())`: the caller's own request holds the
/// current key.
#[tokio::test]
async fn a_cut_off_keeping_the_registered_key_keeps_the_caller() {
    let w = World::new();
    let (mut me, mut other) = (Browser::default(), Browser::default());
    w.get(&mut me, "/login").await;
    w.get(&mut other, "/login").await;

    assert_eq!(w.get(&mut me, "/regenerate-then-cut").await, "kept");

    assert_eq!(w.get(&mut me, "/whoami").await, "user");
    assert_eq!(w.get(&mut other, "/whoami").await, "guest");
    let mine = w.key(&mut me).await;
    assert_eq!(w.held(&alice()).await, vec![mine]);
}

/// A cut-off keeping `session_key` after `regenerate`, under a layer with a
/// registry, names a key the registry does not hold yet: it is refused and
/// nothing is ended.
#[tokio::test]
async fn a_cut_off_keeping_the_new_key_before_the_move_is_refused() {
    let w = World::new();
    let (mut me, mut other) = (Browser::default(), Browser::default());
    w.get(&mut me, "/login").await;
    w.get(&mut other, "/login").await;

    let answer = w.get(&mut me, "/regenerate-then-cut-own-key").await;

    assert!(answer.starts_with("refused"), "{answer}");
    assert_eq!(w.get(&mut me, "/whoami").await, "user");
    assert_eq!(w.get(&mut other, "/whoami").await, "user");
    assert_eq!(w.held(&alice()).await.len(), 2);
}

/// Under a layer without a registry `rotate_session` moves the entry at
/// once, so a cut-off keeping the key read before it names a former key:
/// every session of the user ends, the caller's included, and the answer
/// says so.
#[tokio::test]
async fn a_cut_off_keeping_a_key_from_before_the_rotation_ends_every_session() {
    let w = World::with(Options {
        layer_registry: false,
        ..Options::default()
    });
    let (mut me, mut other) = (Browser::default(), Browser::default());
    w.get(&mut me, "/login").await;
    w.get(&mut other, "/login").await;

    assert_eq!(
        w.get(&mut me, "/rotate-then-cut-earlier-key").await,
        "caller-ended"
    );

    assert!(w.held(&alice()).await.is_empty());
    assert_eq!(w.get(&mut other, "/whoami").await, "guest");
}

/// Two requests carry one cookie. The first loads the session and waits;
/// the second completes a step-up and its response is written, so the
/// layer moved the entry. The first then cuts off the other sessions
/// keeping the key it arrived with: every session of the user ends, the
/// moved one included, every row goes, and either cookie is a guest's.
#[tokio::test]
async fn a_keep_another_request_rotated_ends_every_session_of_the_user() {
    let w = std::sync::Arc::new(World::new());
    let mut me = Browser::default();
    w.get(&mut me, "/login").await;
    let mut other = Browser::default();
    w.get(&mut other, "/login").await;
    let arrived = w.key(&mut me).await;

    let first = {
        let (w, mut tab) = (w.clone(), me.clone());
        tokio::spawn(async move {
            let answer = w.get(&mut tab, "/wait-then-cut").await;
            (answer, tab)
        })
    };
    w.gate.entered.notified().await;
    let mut second = me.clone();
    assert_eq!(w.get(&mut second, "/step-up").await, "Authenticated");
    assert!(second.cookie_set, "the second request moved the session");
    let moved = w.key(&mut second).await;
    assert!(w.held(&alice()).await.contains(&moved));
    w.gate.open.notify_one();
    let (answer, mut first_tab) = first.await.unwrap();

    assert_eq!(answer, "caller-ended");
    assert!(
        w.held(&alice()).await.is_empty(),
        "nothing of the user is held"
    );
    assert!(w.row(&arrived).await.is_none());
    assert!(
        w.row(&moved).await.is_none(),
        "the moved session's row goes"
    );
    assert_eq!(w.get(&mut first_tab, "/whoami").await, "guest");
    assert_eq!(w.get(&mut second, "/whoami").await, "guest");
    assert_eq!(w.get(&mut other, "/whoami").await, "guest");
}
