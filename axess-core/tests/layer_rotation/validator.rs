//! A session the validator middleware finds revoked is ended through the
//! ending protocol: claimed, recorded once, removed, and the 401 replaces
//! the cookie.

use crate::world::{Browser, Options, World, alice};
use axum::http::StatusCode;

/// Under a layer built without a registry, with a validator that has one:
/// the session's entry is removed, and its next request through
/// `require_valid_session` is refused and ended with one record.
#[tokio::test]
async fn the_validators_ending_is_recorded_under_a_layer_without_a_registry() {
    let w = World::with(Options {
        layer_registry: false,
        ..Options::default()
    });
    let mut b = Browser::default();
    w.get(&mut b, "/login").await;
    let key = w.key(&mut b).await;
    {
        use axess_core::session::store::SessionRegistry as _;
        w.registry.inner().invalidate_user(&alice()).await.unwrap();
    }

    w.get(&mut b, "/valid").await;

    assert_eq!(b.status, Some(StatusCode::UNAUTHORIZED));
    assert_eq!(w.ends.reasons(), vec!["session_not_registered"]);
    let (ended, row) = &w.ends.told()[0];
    assert_eq!(ended.session_id, key);
    assert!(
        row.as_ref().and_then(|row| row.ending).is_some(),
        "the row is claimed before the sink is told"
    );
    assert!(w.row(&key).await.is_none(), "the row is removed");
    assert!(b.cookie_set, "the response replaces the cookie");
    assert_eq!(w.get(&mut b, "/whoami").await, "guest");
}

/// Under a layer with a registry, the entry removed between the load and
/// the middleware: the same, once.
#[tokio::test]
async fn the_validators_ending_is_recorded_under_a_layer_with_a_registry() {
    let w = World::new();
    let mut b = Browser::default();
    w.get(&mut b, "/login").await;
    let key = w.key(&mut b).await;
    // The load asks once; the validator's question is the next one.
    *w.faults.revoke_at_check.lock().unwrap() = Some(1);

    w.get(&mut b, "/valid").await;

    assert_eq!(b.status, Some(StatusCode::UNAUTHORIZED));
    assert_eq!(w.ends.reasons(), vec!["session_not_registered"]);
    assert!(
        w.ends.told()[0]
            .1
            .as_ref()
            .and_then(|row| row.ending)
            .is_some()
    );
    assert!(w.row(&key).await.is_none());
    assert!(b.cookie_set);
    assert_eq!(w.get(&mut b, "/whoami").await, "guest");
    assert_eq!(w.ends.told().len(), 1, "recorded once");
}
