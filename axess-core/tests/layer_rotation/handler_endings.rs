//! A session a handler finds revoked (the service's rotation or a step-up's
//! completion, under a layer that does not move the entry) is ended through
//! the layer's ending protocol: claimed, recorded once, removed, and the
//! response replaces the cookie. With no layer behind the handle, the
//! service's own sink is told.

use crate::world::{Browser, Options, World, alice};
use axess_core::authn::event::AuthEventType;
use axess_core::testing::fixtures as common;
use axess_core::testing::{AuthSessionTestExt, MockRng, test_session_with_rng};

fn without_layer_registry() -> World {
    World::with(Options {
        layer_registry: false,
        ..Options::default()
    })
}

/// `rotate_session` whose key was revoked while its request ran, under a
/// layer without a registry: refused, one record, the row claimed before it
/// goes, and the response replaces the cookie.
#[tokio::test]
async fn a_rotation_the_service_finds_revoked_is_ended_through_the_layer() {
    let w = without_layer_registry();
    let mut b = Browser::default();
    w.get(&mut b, "/login").await;
    let arrived = w.key(&mut b).await;

    let answer = w.get(&mut b, "/rotate-revoked").await;

    assert!(answer.starts_with("refused"), "{answer}");
    assert_eq!(w.ends.reasons(), vec!["session_revoked_during_rotation"]);
    let (ended, row) = &w.ends.told()[0];
    assert_eq!(ended.session_id, arrived, "named by the key of its row");
    assert!(
        row.as_ref().and_then(|row| row.ending).is_some(),
        "the row is claimed before the sink is told"
    );
    assert!(w.row(&arrived).await.is_none(), "the row is removed");
    assert!(b.cookie_set, "the response replaces the cookie");
    assert_eq!(w.get(&mut b, "/whoami").await, "guest");
}

/// The same for a step-up's completion that finds the session revoked.
#[tokio::test]
async fn a_step_up_the_service_finds_revoked_is_ended_through_the_layer() {
    let w = without_layer_registry();
    let mut b = Browser::default();
    w.get(&mut b, "/login").await;
    let arrived = w.key(&mut b).await;

    let answer = w.get(&mut b, "/step-up-revoked").await;

    assert!(answer.starts_with("refused"), "{answer}");
    assert_eq!(w.ends.reasons(), vec!["session_revoked_during_rotation"]);
    let (ended, row) = &w.ends.told()[0];
    assert_eq!(ended.session_id, arrived);
    assert!(row.as_ref().and_then(|row| row.ending).is_some());
    assert!(w.row(&arrived).await.is_none());
    assert!(b.cookie_set);
    assert_eq!(w.get(&mut b, "/whoami").await, "guest");
}

/// On a handle no layer stands behind, the service's own sink is told once,
/// one `SessionInvalidated` row with the reason.
#[tokio::test]
async fn with_no_layer_the_services_sink_is_told_once() {
    let w = World::new();
    let session = test_session_with_rng(MockRng::new(77));
    session
        .set_authenticated(alice(), common::tid("t1"), common::start())
        .await;
    let key = session.session_key().await;
    {
        use axess_core::session::store::SessionRegistry as _;
        w.registry.inner().register(&alice(), &key).await.unwrap();
        w.registry.inner().invalidate_user(&alice()).await.unwrap();
    }

    let result = w.svc.rotate_session(&session).await;

    assert!(result.is_err(), "{result:?}");
    assert!(!session.is_authenticated().await);
    let rows: Vec<_> = w
        .identity
        .events()
        .into_iter()
        .filter(|e| e.event_type == AuthEventType::SessionInvalidated)
        .collect();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].session_id, Some(key));
    assert_eq!(
        rows[0].error.as_ref().map(ToString::to_string).as_deref(),
        Some("session_revoked_during_rotation")
    );
    assert!(w.ends.told().is_empty(), "the layer's sink is not this one");
}
