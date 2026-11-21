#![cfg(feature = "testing")]
//! A session in a log line is the first eight characters of its key, never
//! the whole key and never any form of its id, which is a credential: in the
//! refusal of a session kick, and in the eviction of the oldest session
//! under the per-user cap. Its own test binary: the assertions read a
//! thread-scoped tracing capture, which sibling tests in a shared binary can
//! disturb.

use axess_core::testing::fixtures as common;

use axess_core::authn::AuditContext;
use axess_core::authn::factor::{FactorCredential, ZeroizedString};
use axess_core::authn::service::{Actor, AuthnService, FactorOutcome};
use axess_core::session::store::{MemorySessionRegistry, SessionRegistry};
use axess_core::session::{SessionId, SessionKey};
use axess_core::testing::AuthSessionTestExt;
use axess_core::testing::{
    MockRng,
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session_with_rng,
};
use axess_testing::mock_tracing::{CapturedEvent, TracingCapture};
use common::{password_config, password_method, test_tenant, test_user, tid, uid, user_scope};

/// The id behind `key`, among the ids a session drawing from a
/// `MockRng::new(seed)` can have minted. A handler reads only the key; the
/// test knows the bearer value by drawing the same sequence again, starting
/// at every eight-byte step the generator takes, so draws of other lengths
/// in between do not hide it.
fn id_behind(key: &SessionKey, seed: u64) -> SessionId {
    use axess_rng::SecureRng as _;
    (0..64)
        .map(|skipped| {
            let rng = MockRng::new(seed);
            for _ in 0..skipped {
                rng.fill_bytes(&mut [0u8; 8]);
            }
            SessionId::new(&rng)
        })
        .find(|id| SessionKey::of(id) == *key)
        .expect("the key is of an id the seeded generator drew")
}

/// `event` names `key` by its log form and holds neither the whole key nor
/// the id in its hyphenated or its simple form, nor the id's first eight
/// characters.
fn names_only_the_prefix(event: &CapturedEvent, key: &SessionKey, id: &SessionId) {
    let prefix = key.prefix().to_string();
    assert_eq!(prefix.len(), 11, "eight characters and three dots");
    assert!(event.message.contains(&prefix), "{event}");
    let hyphenated = id.to_string();
    for text in [
        key.to_string(),
        hyphenated.clone(),
        hyphenated.replace('-', ""),
        hyphenated[..8].to_owned(),
    ] {
        assert!(!event.message.contains(&text), "{text} is logged: {event}");
    }
}

/// No line holds the whole key or any form of the id.
fn no_line_holds(events: &[CapturedEvent], key: &SessionKey, id: &SessionId) {
    let hyphenated = id.to_string();
    for text in [
        key.to_string(),
        hyphenated.clone(),
        hyphenated.replace('-', ""),
    ] {
        assert!(
            events.iter().all(|event| !event.message.contains(&text)),
            "{text} is logged: {events:?}"
        );
    }
}

/// The refusals of both kicks, for a session the registry holds for another
/// user: each is logged, with the first eight characters of the key and
/// nothing more of it or of the id.
#[tokio::test]
async fn a_refused_kick_names_the_session_by_a_prefix_only() {
    let capture = TracingCapture::install();
    let clock = common::test_clock();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("alice", "alice"))
        .with_user(test_user("bob", "bob"));
    let registry = MemorySessionRegistry::new().with_clock(std::sync::Arc::new(clock.clone()));
    let svc = AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .with_registry(registry.clone())
        .build()
        .with_audit_context(AuditContext::default());
    let mut sessions = Vec::new();
    for (who, seed) in [("alice", 11), ("bob", 22)] {
        let session = test_session_with_rng(MockRng::new(seed));
        session
            .set_authenticated(uid(who), tid("default"), common::start())
            .await;
        let key = session.session_key().await;
        registry.register(&uid(who), &key).await.unwrap();
        sessions.push((key, id_behind(&key, seed)));
    }
    let (bobs, bobs_id) = sessions[1];

    assert!(
        svc.invalidate_session(&uid("alice"), &bobs, Actor::System)
            .await
            .is_err()
    );
    assert!(
        svc.invalidate_other_sessions(&uid("alice"), &bobs, Actor::System)
            .await
            .is_err()
    );

    let events = capture.events();
    let refusals: Vec<_> = events
        .iter()
        .filter(|event| event.message.contains("refused"))
        .collect();
    assert_eq!(refusals.len(), 2, "{events:?}");
    for refusal in refusals {
        names_only_the_prefix(refusal, &bobs, &bobs_id);
    }
    no_line_holds(&events, &bobs, &bobs_id);
}

/// A second sign-in under a cap of one session evicts the first, and the
/// line that says so names the evicted session by its key's prefix.
#[tokio::test]
async fn an_evicted_session_is_named_by_a_prefix_only() {
    let capture = TracingCapture::install();
    let clock = common::test_clock();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Sample2+"))
        .with_method(&uid("u1"), password_method());
    let registry = MemorySessionRegistry::new().with_clock(std::sync::Arc::new(clock.clone()));
    let svc = AuthnService::builder(identity, factors)
        .with_clock(clock.clone())
        .with_registry(registry.clone())
        .with_max_sessions_per_user(std::num::NonZeroUsize::new(1).expect("one"))
        .build()
        .with_audit_context(AuditContext::default());
    let mut sessions = Vec::new();
    for seed in [41, 42] {
        let session = test_session_with_rng(MockRng::new(seed));
        svc.begin_login("alice", "default", &session).await.unwrap();
        let outcome = svc
            .verify_factor(
                &FactorCredential::Password(ZeroizedString::new("Sample2+")),
                &session,
            )
            .await
            .unwrap();
        assert!(
            matches!(outcome, FactorOutcome::Authenticated),
            "{outcome:?}"
        );
        let key = session.session_key().await;
        sessions.push((key, id_behind(&key, seed)));
    }
    assert_eq!(
        registry.active_sessions(&uid("u1")).await.unwrap(),
        vec![sessions[1].0],
        "the first session was evicted"
    );

    let (evicted, evicted_id) = sessions[0];
    let events = capture.events();
    let evictions: Vec<_> = events
        .iter()
        .filter(|event| event.message.contains("evicting oldest session"))
        .collect();
    assert_eq!(evictions.len(), 1, "{events:?}");
    names_only_the_prefix(evictions[0], &evicted, &evicted_id);
    no_line_holds(&events, &evicted, &evicted_id);
}
