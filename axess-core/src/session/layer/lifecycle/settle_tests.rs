//! The rows of the registry settlement that keep a rotated session: what
//! the request knows the registry holds decides whether the layer moves the
//! entry, and from which key, or only asks whether the new key is held. The
//! rows that end the session are in `rotation_audit_tests`.

use super::audit_support::{Sink, authenticated, memory_store, user};
use super::concurrency_tests::TTL;
use super::*;
use crate::authn::ids::testing as ids;
use crate::session::id::{SessionId, SessionKey};
use crate::session::layer::UnknownLiveness;
use crate::session::store::{MemorySessionStore, SessionRegistry};
use crate::testing::mock_random::MockRng;
use crate::testing::registry_double::{RegistryCall, RegistryDouble, RegistryOp};
use axess_clock::testing::MockClock;

/// The keys of one rotation: the one the request arrived with, a key a
/// login in the request registered, and the one the response carries.
struct Keys {
    arrived: SessionKey,
    login: SessionKey,
    new: SessionKey,
}

fn keys() -> Keys {
    let key = |seed| SessionKey::of(&SessionId::new(&MockRng::new(seed)));
    Keys {
        arrived: key(51),
        login: key(52),
        new: key(53),
    }
}

/// Settle a rotation of `user()` to `keys.new` with `held` known, the row
/// stored under the new key; whether the cookie is set, and what the sink
/// was told.
async fn settle(
    registry: &RegistryDouble,
    keys: &Keys,
    held: Option<SessionKey>,
) -> (bool, Sink, MemorySessionStore) {
    let store = memory_store();
    store.save(&keys.new, &authenticated(), TTL).await.unwrap();
    let sink = Sink::on(&store);
    let outcome = FinalizeOutcome {
        session: CookieSession::mint(&MockRng::new(54)),
        session_changed: true,
        rotation: Some(Rotation {
            user_id: user(),
            tenant_id: ids::tenant("t"),
            impersonator: None,
            arrived: keys.arrived,
            new: keys.new,
            held,
            anchor: None,
        }),
        released: Vec::new(),
    };
    let handle = registry.clone().handle();
    let cookie = settle_registry(
        &store,
        Some(&*handle),
        (UnknownLiveness::Reject, &sink),
        (MockClock::reference_time(), TTL),
        &outcome,
    )
    .await;
    (cookie, sink, store)
}

async fn registry_holding(held: &[SessionKey]) -> RegistryDouble {
    let registry = RegistryDouble::new();
    for key in held {
        registry.inner().register(&user(), key).await.unwrap();
    }
    registry
}

async fn held(registry: &RegistryDouble) -> Vec<SessionKey> {
    registry.inner().active_sessions(&user()).await.unwrap()
}

/// A handler registered the final key itself (a login): the layer only asks
/// whether it is still held, and moves nothing.
#[tokio::test]
async fn a_key_the_handler_registered_is_asked_for_and_not_moved() {
    let keys = keys();
    let registry = registry_holding(&[keys.new]).await;

    let (cookie, sink, _) = settle(&registry, &keys, Some(keys.new)).await;

    assert!(cookie);
    assert!(sink.told().is_empty());
    assert_eq!(registry.count(RegistryOp::MoveSession), 0);
    assert_eq!(held(&registry).await, vec![keys.new]);
}

/// A login, then a rotation in the same request: the registry holds the key
/// the login registered, and the layer moves it, not the key the request
/// arrived with.
#[tokio::test]
async fn a_rotation_after_a_login_moves_the_key_the_login_registered() {
    let keys = keys();
    let other = SessionKey::of(&SessionId::new(&MockRng::new(55)));
    let registry = registry_holding(&[other, keys.login]).await;

    let (cookie, sink, _) = settle(&registry, &keys, Some(keys.login)).await;

    assert!(cookie, "the session survives");
    assert!(sink.told().is_empty());
    assert_eq!(
        registry.calls(),
        vec![RegistryCall::MoveSession {
            user: user(),
            old: keys.login,
            new: keys.new,
        }]
    );
    assert_eq!(
        held(&registry).await,
        vec![other, keys.new],
        "the final key in the login key's place"
    );
}

/// Nothing known for the user, and a handler of the adopter's own
/// registered the final key: it is held, and nothing moves.
#[tokio::test]
async fn nothing_known_and_the_new_key_held_keeps_the_session() {
    let keys = keys();
    let registry = registry_holding(&[keys.new]).await;

    let (cookie, sink, _) = settle(&registry, &keys, None).await;

    assert!(cookie);
    assert!(sink.told().is_empty());
    assert_eq!(registry.count(RegistryOp::MoveSession), 0);
}

/// Nothing known for the user, and a handler of the adopter's own
/// registered the key the request arrived with, then the session rotated:
/// the layer moves that key to the new one.
#[tokio::test]
async fn nothing_known_and_the_arrived_key_held_moves_it() {
    let keys = keys();
    let registry = registry_holding(&[keys.arrived]).await;

    let (cookie, sink, _) = settle(&registry, &keys, None).await;

    assert!(cookie);
    assert!(sink.told().is_empty());
    assert_eq!(held(&registry).await, vec![keys.new]);
    assert_eq!(registry.count(RegistryOp::MoveSession), 1);
}

/// The settlement moves the key it knows of, whatever else the user holds:
/// the record of the move leads from the former key to the new one.
#[tokio::test]
async fn a_moved_entry_answers_for_its_former_key() {
    let keys = keys();
    let registry = registry_holding(&[keys.arrived]).await;

    let (cookie, _, store) = settle(&registry, &keys, Some(keys.arrived)).await;

    assert!(cookie);
    assert!(store.load(&keys.new).await.unwrap().is_some());
    assert_eq!(
        registry
            .inner()
            .current_key(&user(), &keys.arrived)
            .await
            .unwrap(),
        Some(keys.new)
    );
}
