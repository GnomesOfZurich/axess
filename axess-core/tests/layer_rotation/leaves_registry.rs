//! A session that ended leaves the registry: it is no longer listed by
//! `active_sessions` nor valid there, whichever way it ended, so the session
//! limit does not count it and a socket that watches it is told.

use crate::world::{Browser, Options, World, alice};
use axess_core::session::store::SessionRegistry;
use axum::http::StatusCode;

/// The absolute age cap ends a session at the load: its entry goes with it.
#[tokio::test]
async fn a_session_ended_at_its_age_cap_leaves_the_registry() {
    let w = World::with(Options {
        max_age: Some(std::time::Duration::from_secs(600)),
        ..Options::default()
    });
    let mut b = Browser::default();
    w.get(&mut b, "/login").await;
    let key = w.key(&mut b).await;
    assert_eq!(w.held(&alice()).await, vec![key]);

    w.clock.advance_secs(601);
    assert_eq!(w.get(&mut b, "/whoami").await, "guest");

    assert_eq!(w.ends.reasons(), vec!["session_age_cap"]);
    assert!(w.held(&alice()).await.is_empty(), "not listed");
    assert!(!w.registry.inner().is_valid(&alice(), &key).await.unwrap());
}

/// A request that leaves the session signed out without asking the registry
/// anything: the layer removes the entry the request knew of.
#[tokio::test]
async fn a_request_that_signs_the_session_out_removes_its_entry() {
    let w = World::new();
    let mut b = Browser::default();
    w.get(&mut b, "/login").await;
    let key = w.key(&mut b).await;

    assert_eq!(w.get(&mut b, "/sign-out-quietly").await, "out");

    assert!(w.held(&alice()).await.is_empty(), "not listed");
    assert!(!w.registry.inner().is_valid(&alice(), &key).await.unwrap());
}

/// Two requests carry one cookie under a layer with a registry. The second
/// rotates the session and its response is written. The first then passes
/// the validator, which finds the key it holds gone from the registry: the
/// answer is 401, this request records nothing and sets no cookie, since
/// the row it would end was moved by the other request. The entry the
/// first request knew of goes, and the move's record takes the moved
/// session with it: the next request with the second request's cookie is
/// ended at the load, with exactly one record.
#[tokio::test]
async fn an_ending_asked_for_a_row_another_request_moved_records_nothing() {
    let w = std::sync::Arc::new(World::new());
    let mut b = Browser::default();
    w.get(&mut b, "/login").await;

    let first = {
        let (w, mut tab) = (w.clone(), b.clone());
        tokio::spawn(async move {
            w.get(&mut tab, "/wait-then-validate").await;
            tab
        })
    };
    w.gate.entered.notified().await;
    let mut second = b.clone();
    assert_eq!(w.get(&mut second, "/regenerate").await, "regenerated");
    assert!(second.cookie_set);
    w.gate.open.notify_one();
    let first_tab = first.await.unwrap();

    assert_eq!(first_tab.status, Some(StatusCode::UNAUTHORIZED));
    assert!(
        !first_tab.cookie_set,
        "no cookie for a row this request did not end"
    );
    assert!(w.ends.told().is_empty(), "this request records nothing");

    assert_eq!(w.get(&mut second, "/whoami").await, "guest");
    assert_eq!(w.ends.reasons(), vec!["session_not_registered"]);
}
