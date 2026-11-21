//! A step-up's completion is the session it began from: it registers
//! nothing, so it does not count against the session limit, and a person
//! who signs in on a session another person was signed in on takes the
//! session's entry away from them.

use crate::world::{Browser, Options, World, alice, bob};
use axess_core::testing::registry_double::RegistryOp;

/// A user at the session limit completes a step-up: nobody is evicted, and
/// the session survives under its new key in its old place.
#[tokio::test]
async fn a_step_up_at_the_session_limit_evicts_nobody() {
    let w = World::with(Options {
        max_sessions: Some(2),
        ..Options::default()
    });
    let (mut oldest, mut me) = (Browser::default(), Browser::default());
    w.get(&mut oldest, "/login").await;
    w.get(&mut me, "/login").await;
    let first = w.key(&mut oldest).await;
    let registrations = w.count(RegistryOp::Register);

    assert_eq!(w.get(&mut me, "/step-up").await, "Authenticated");

    assert_eq!(
        w.count(RegistryOp::Register),
        registrations,
        "nothing registered"
    );
    assert_eq!(
        w.get(&mut oldest, "/whoami").await,
        "user",
        "nobody evicted"
    );
    assert_eq!(w.get(&mut me, "/whoami").await, "user");
    let mine = w.key(&mut me).await;
    assert_eq!(
        w.held(&alice()).await,
        vec![first, mine],
        "in its old place"
    );
}

/// A is signed in; A signs out and B signs in on the same session in one
/// request:
/// afterwards A's sessions do not list it, and B's list exactly the final
/// key.
#[tokio::test]
async fn a_second_person_in_one_request_takes_the_entry_from_the_first() {
    let w = World::new();
    let mut b = Browser::default();
    w.get(&mut b, "/login").await;

    assert_eq!(w.get(&mut b, "/switch-to-bob").await, "Authenticated");

    assert!(w.held(&alice()).await.is_empty(), "not listed for A");
    let key = w.key(&mut b).await;
    assert_eq!(w.held(&bob()).await, vec![key], "listed for B");
    assert_eq!(w.get(&mut b, "/whoami").await, "user");
}
