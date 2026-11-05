//! Registry behaviours that need care with time and randomness.

use super::registry::ValkeySessionRegistry;
use crate::authn::ids::UserId;
use crate::session::id::SessionId;
use crate::session::store::SessionRegistry;
use crate::testing::MockRng;
use axess_clock::Clock;
use axess_clock::testing::MockClock;
use axess_rng::SystemRng;
use chrono::{DateTime, Utc};
use fred::prelude::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn offline_registry() -> ValkeySessionRegistry {
    ValkeySessionRegistry::new(Client::new(Config::default(), None, None, None))
}

/// The recheck delay is drawn from the injected random source and stays in
/// `0..=250` ms: a zero draw is no delay, draws differ, and none exceeds the
/// window.
#[test]
fn recheck_delay_is_drawn_from_the_injected_rng_within_the_window() {
    let registry = offline_registry().with_rng(Arc::new(MockRng::new(11)));
    let delays: Vec<Duration> = (0..64).map(|_| registry.recheck_delay()).collect();
    assert!(delays.iter().all(|d| *d <= Duration::from_millis(250)));
    let distinct = delays
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    assert!(
        distinct > 8,
        "the delays spread over the window: {distinct} distinct"
    );

    let again = offline_registry().with_rng(Arc::new(MockRng::new(11)));
    let replay: Vec<Duration> = (0..64).map(|_| again.recheck_delay()).collect();
    assert_eq!(delays, replay, "the same seed gives the same delays");
}

/// Each degraded poll's wait is drawn from the injected random source and
/// stays within the quarter interval on either side of the base: the draws
/// differ, so watchers that lost one connection together do not poll in
/// lockstep.
#[test]
fn degraded_poll_delay_is_drawn_from_the_injected_rng_within_the_window() {
    let registry = offline_registry().with_rng(Arc::new(MockRng::new(7)));
    let delays: Vec<Duration> = (0..64).map(|_| registry.degraded_poll_delay(0)).collect();
    assert!(
        delays
            .iter()
            .all(|d| (Duration::from_millis(3_750)..=Duration::from_millis(6_250)).contains(d)),
        "{delays:?}"
    );
    let distinct = delays
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    assert!(
        distinct > 8,
        "the delays spread over the window: {distinct} distinct"
    );
}

/// A clock that runs a closure once, on its first reading, then reports a
/// fixed instant. `is_valid` reads the clock between its `ZSCORE` and its
/// removal of an expired member, so the closure is a write landing exactly
/// there.
struct InterleavingClock {
    at: DateTime<Utc>,
    once: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Clock for InterleavingClock {
    fn now(&self) -> DateTime<Utc> {
        let action = self.once.lock().unwrap().take();
        if let Some(action) = action {
            action();
        }
        self.at
    }
}

fn live_url() -> String {
    std::env::var("VALKEY_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into())
}

async fn connect() -> Client {
    let client = Client::new(Config::from_url(&live_url()).unwrap(), None, None, None);
    client.init().await.expect("connect");
    client
}

/// An expired member is pruned by `is_valid`, but a session registered again
/// between the read and the prune keeps its fresh registration. Before, the
/// prune removed the member by name and took the fresh score with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_is_valid_prune_spares_a_session_registered_again_meanwhile() {
    let prefix = format!("axt_prune_{}", UserId::new(&SystemRng));
    let ttl = Duration::from_secs(10);
    let t0 = Utc::now();
    let t_later = t0 + chrono::Duration::seconds(20);
    let user = UserId::new(&SystemRng);
    let session = SessionId::new(&SystemRng);

    let first = ValkeySessionRegistry::with_options(connect().await, prefix.clone(), ttl)
        .with_clock(Arc::new(MockClock::at(t0)));
    first.register(&user, &session).await.unwrap();

    let fresh = ValkeySessionRegistry::with_options(connect().await, prefix.clone(), ttl)
        .with_clock(Arc::new(MockClock::at(t_later)));
    let reregister = {
        let (fresh, user, session) = (fresh.clone(), user, session);
        let runtime = tokio::runtime::Handle::current();
        Box::new(move || {
            tokio::task::block_in_place(|| {
                runtime.block_on(fresh.register(&user, &session)).unwrap();
            });
        }) as Box<dyn FnOnce() + Send>
    };
    let checker = ValkeySessionRegistry::with_options(connect().await, prefix, ttl).with_clock(
        Arc::new(InterleavingClock {
            at: t_later,
            once: Mutex::new(Some(reregister)),
        }),
    );

    assert!(
        !checker.is_valid(&user, &session).await.unwrap(),
        "the member the checker read was expired"
    );
    assert!(
        fresh.is_valid(&user, &session).await.unwrap(),
        "the fresh registration must survive the prune"
    );
}

/// A session that stays active outlives the registry's lifetime: its member
/// is kept alive by the requests that find it live, as the session's own
/// sliding lifetime is. Before, the member expired a fixed `ttl` after
/// `register` and an active user was logged out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_registry_member_of_an_active_session_does_not_expire() {
    let prefix = format!("axt_active_{}", UserId::new(&SystemRng));
    let ttl = Duration::from_secs(10);
    let t0 = Utc::now();
    let user = UserId::new(&SystemRng);
    let session = SessionId::new(&SystemRng);
    let at = |secs: i64| {
        ValkeySessionRegistry::with_options(
            // One client per instant: the clocks differ, the rows are shared.
            Client::new(Config::from_url(&live_url()).unwrap(), None, None, None),
            prefix.clone(),
            ttl,
        )
        .with_clock(Arc::new(MockClock::at(
            t0 + chrono::Duration::seconds(secs),
        )))
    };
    let (r0, r8, r16) = (at(0), at(8), at(16));
    for r in [&r0, &r8, &r16] {
        r.client.init().await.unwrap();
    }
    r0.register(&user, &session).await.unwrap();
    assert!(r8.is_valid(&user, &session).await.unwrap());
    assert!(
        r16.is_valid(&user, &session).await.unwrap(),
        "the session was active at 8 s: its registry member must still be live at 16 s"
    );
}

/// A session nothing touches still lapses a `ttl` after its last activity.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_registry_member_of_an_idle_session_still_expires() {
    let prefix = format!("axt_idle_{}", UserId::new(&SystemRng));
    let ttl = Duration::from_secs(10);
    let t0 = Utc::now();
    let user = UserId::new(&SystemRng);
    let session = SessionId::new(&SystemRng);
    let registry = |secs: i64| {
        ValkeySessionRegistry::with_options(
            Client::new(Config::from_url(&live_url()).unwrap(), None, None, None),
            prefix.clone(),
            ttl,
        )
        .with_clock(Arc::new(MockClock::at(
            t0 + chrono::Duration::seconds(secs),
        )))
    };
    let (r0, r20) = (registry(0), registry(20));
    r0.client.init().await.unwrap();
    r20.client.init().await.unwrap();
    r0.register(&user, &session).await.unwrap();
    assert!(!r20.is_valid(&user, &session).await.unwrap());
}
