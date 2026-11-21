//! Registry behaviours that need care with time and randomness.

use super::internal::{revocation_session_channel, user_keys};
use super::registry::ValkeySessionRegistry;
use super::subscriber::connection_name;
use super::watch_tests::{eventually, subscriber_connections};
use crate::authn::ids::UserId;
use crate::session::id::{SessionId, SessionKey};
use crate::session::store::SessionRegistry;
use crate::testing::MockRng;
use crate::testing::valkey_server::AclUser;
use axess_clock::Clock;
use axess_clock::Timestamp;
use axess_clock::testing::MockClock;
use axess_clock::testing::Shift;
use axess_rng::SystemRng;
use fred::prelude::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A registry on a client that is never connected, built past the
/// constructors' checks: what these tests read is drawn locally.
fn offline_registry() -> ValkeySessionRegistry {
    ValkeySessionRegistry::assembled(
        Client::new(Config::default(), None, None, None),
        "axess".into(),
        Duration::from_secs(60),
    )
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
    at: Timestamp,
    once: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Clock for InterleavingClock {
    fn now(&self) -> Timestamp {
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

pub(super) async fn connect() -> Client {
    let client = Client::new(Config::from_url(&live_url()).unwrap(), None, None, None);
    client.init().await.expect("connect");
    client
}

/// A registry built by its constructor on `client`, under `prefix`.
async fn registry_on(client: Client, prefix: &str, ttl: Duration) -> ValkeySessionRegistry {
    ValkeySessionRegistry::with_options(client, prefix, ttl)
        .await
        .expect("a registry")
}

/// A registry on a client of its own whose clock reads `at`: the clocks of
/// the registries of one test differ, the rows are shared.
async fn registry_at(prefix: &str, ttl: Duration, at: Timestamp) -> ValkeySessionRegistry {
    registry_on(connect().await, prefix, ttl)
        .await
        .with_clock(Arc::new(MockClock::at(at)))
}

/// An expired member is pruned by `is_valid`, but a session registered again
/// between the read and the prune keeps its fresh registration. Before, the
/// prune removed the member by name and took the fresh score with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_is_valid_prune_spares_a_session_registered_again_meanwhile() {
    let sweep = crate::testing::valkey_sweep::on_node("prune");
    let prefix = sweep.prefix().to_owned();
    let ttl = Duration::from_secs(10);
    let t0 = axess_clock::testing::MockClock::reference_time();
    let t_later = t0.plus(axess_clock::SignedDuration::seconds(20));
    let user = UserId::new(&SystemRng);
    let session = SessionKey::of(&SessionId::new(&SystemRng));

    let first = registry_on(connect().await, &prefix, ttl)
        .await
        .with_clock(Arc::new(MockClock::at(t0)));
    first.register(&user, &session).await.unwrap();

    let fresh = registry_on(connect().await, &prefix, ttl)
        .await
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
    let checker = registry_on(connect().await, &prefix, ttl)
        .await
        .with_clock(Arc::new(InterleavingClock {
            at: t_later,
            once: Mutex::new(Some(reregister)),
        }));

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
    let sweep = crate::testing::valkey_sweep::on_node("active");
    let prefix = sweep.prefix().to_owned();
    let ttl = Duration::from_secs(10);
    let t0 = axess_clock::testing::MockClock::reference_time();
    let user = UserId::new(&SystemRng);
    let session = SessionKey::of(&SessionId::new(&SystemRng));
    let at = |secs: i64| {
        registry_at(
            &prefix,
            ttl,
            t0.plus(axess_clock::SignedDuration::seconds(secs)),
        )
    };
    let (r0, r8, r16) = (at(0).await, at(8).await, at(16).await);
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
    let sweep = crate::testing::valkey_sweep::on_node("idle");
    let prefix = sweep.prefix().to_owned();
    let ttl = Duration::from_secs(10);
    let t0 = axess_clock::testing::MockClock::reference_time();
    let user = UserId::new(&SystemRng);
    let session = SessionKey::of(&SessionId::new(&SystemRng));
    let registry = |secs: i64| {
        registry_at(
            &prefix,
            ttl,
            t0.plus(axess_clock::SignedDuration::seconds(secs)),
        )
    };
    let (r0, r20) = (registry(0).await, registry(20).await);
    r0.register(&user, &session).await.unwrap();
    assert!(!r20.is_valid(&user, &session).await.unwrap());
}

/// How long a test waits for a watcher that a message it published by hand
/// should end.
const TOLD_WITHIN: Duration = Duration::from_secs(5);

/// The background watcher only reads: its checks do not move the member's
/// score, so a session nobody uses still lapses a `ttl` after its last
/// request even while a watcher polls the registry for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_watcher_checks_do_not_keep_an_idle_session_alive() {
    let serial = super::SUBSCRIBER_TESTS.lock().await;
    let sweep = crate::testing::valkey_sweep::on_node("watchread");
    let prefix = sweep.prefix().to_owned();
    let ttl = Duration::from_secs(10);
    let t0 = axess_clock::testing::MockClock::reference_time();
    let user = UserId::new(&SystemRng);
    let session = SessionKey::of(&SessionId::new(&SystemRng));
    let at = |secs: i64| {
        registry_at(
            &prefix,
            ttl,
            t0.plus(axess_clock::SignedDuration::seconds(secs)),
        )
    };
    let (r0, r7) = (at(0).await, at(7).await);
    r0.register(&user, &session).await.unwrap();
    let key = user_keys(&prefix, &user).expect("one slot").registry;
    let score = |c: Client| {
        let (key, session) = (key.clone(), session.to_string());
        async move { c.zscore::<Option<f64>, _, _>(key, session).await.unwrap() }
    };
    let before = score(connect().await).await;

    // 7 s into a 10 s lifetime: past the half at which a request would slide.
    let watcher = {
        let (r7, user) = (r7.clone(), user);
        tokio::spawn(async move { r7.watch_revocation(&user, &session).await })
    };
    // The watcher holds its place, then its connection subscribes: a
    // message published before the subscription would be lost.
    let admin = connect().await;
    let connection = connection_name(&prefix);
    eventually("the watcher joined", || async {
        r7.subscriber.watcher_count() == 1
    })
    .await;
    eventually("the watcher's connection is subscribed", || async {
        subscriber_connections(&admin, &connection).await == 1
    })
    .await;
    // The watcher returns from a routed message only after its first check
    // returned, and a sliding check awaits its own write before it returns:
    // once the task has ended, a slide would be in the score.
    let _: i64 = admin
        .publish(
            revocation_session_channel(&prefix, &session.to_string()),
            "1",
        )
        .await
        .expect("PUBLISH");
    tokio::time::timeout(TOLD_WITHIN, watcher)
        .await
        .expect("the watcher is told")
        .unwrap();
    assert_eq!(
        score(connect().await).await,
        before,
        "the watcher's own check moved the member's score"
    );
    drop(serial);
}

/// A Valkey user that may do everything except PUBLISH, and a client of it.
async fn client_without_publish(admin: &Client, name: &str) -> (AclUser, Client) {
    client_denied(admin, name, "-publish").await
}

/// A Valkey user named `name` that may do everything except what `denied`
/// takes away (an ACL rule such as `-publish` or `-@scripting`), and a
/// client signed in as it. The user is removed when its guard is dropped,
/// also when the test fails, and also when the client cannot connect.
pub(super) async fn client_denied(admin: &Client, name: &str, denied: &str) -> (AclUser, Client) {
    let user = AclUser::make(admin, name, &["on", ">pw", "~*", "&*", "+@all", denied]).await;
    let url = live_url().replacen("redis://", &format!("redis://{name}:pw@"), 1);
    let client = Client::new(Config::from_url(&url).unwrap(), None, None, None);
    client.init().await.expect("connect as the restricted user");
    (user, client)
}

/// A revocation whose push to the other nodes failed is reported: the
/// registry entry is gone, but the watchers elsewhere were not told, and the
/// caller must not read that as a complete revocation. The user that may
/// not publish is removed when the test ends, also when it fails.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_revocation_reports_a_failed_publish() {
    let admin = connect().await;
    let name = format!(
        "nopub{}",
        UserId::new(&SystemRng).to_string().replace('-', "")
    );
    let (nopub, restricted) = client_without_publish(&admin, &name).await;
    let sweep = crate::testing::valkey_sweep::on_node("pub");
    let registry = registry_on(restricted, sweep.prefix(), Duration::from_secs(60)).await;
    let (user, session) = (
        UserId::new(&SystemRng),
        SessionKey::of(&SessionId::new(&SystemRng)),
    );
    registry.register(&user, &session).await.unwrap();
    let one = registry.invalidate_session(&user, &session).await;
    registry.register(&user, &session).await.unwrap();
    let all = registry.invalidate_user(&user).await;
    nopub.remove(&admin).await;
    assert!(one.is_err(), "invalidate_session hid the failed publish");
    assert!(all.is_err(), "invalidate_user hid the failed publish");
}

/// A lifetime too long for the server's expiry range still registers: the
/// key's expiry is capped instead of being rejected as an invalid expire time.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_registry_with_an_enormous_ttl_still_registers() {
    let sweep = crate::testing::valkey_sweep::on_node("huge");
    let registry = registry_on(connect().await, sweep.prefix(), Duration::MAX).await;
    let (user, session) = (
        UserId::new(&SystemRng),
        SessionKey::of(&SessionId::new(&SystemRng)),
    );
    registry.register(&user, &session).await.unwrap();
    assert!(registry.is_valid(&user, &session).await.unwrap());
}

/// Without an injected clock the score is the Valkey server's time, not the
/// app node's.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_registry_scores_with_the_servers_clock() {
    let admin = connect().await;
    let sweep = crate::testing::valkey_sweep::on_node("server_clock");
    let prefix = sweep.prefix().to_owned();
    let registry = registry_on(connect().await, &prefix, Duration::from_secs(60)).await;
    let (user, session) = (
        UserId::new(&SystemRng),
        SessionKey::of(&SessionId::new(&SystemRng)),
    );
    registry.register(&user, &session).await.unwrap();

    let command =
        fred::types::CustomCommand::new_static("TIME", fred::types::ClusterHash::FirstKey, false);
    let time: Vec<String> = admin.custom(command, Vec::<String>::new()).await.unwrap();
    let server_ms = time[0].parse::<i64>().unwrap() * 1000 + time[1].parse::<i64>().unwrap() / 1000;
    let score: Option<f64> = admin
        .zscore(
            user_keys(&prefix, &user).expect("one slot").registry,
            session.to_string(),
        )
        .await
        .unwrap();
    let skew = (score.unwrap() - server_ms as f64).abs();
    assert!(skew < 1500.0, "score is {skew} ms from the server's clock");
}

/// The cap evicts the oldest registration. A session used since it was
/// registered keeps its place in the order: before, its score moved forward
/// with each use and the newer session sorted ahead of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_active_sessions_stays_oldest_first_after_is_valid_bump() {
    let sweep = crate::testing::valkey_sweep::on_node("order");
    let prefix = sweep.prefix().to_owned();
    let ttl = Duration::from_secs(10);
    let t0 = axess_clock::testing::MockClock::reference_time();
    let user = UserId::new(&SystemRng);
    let (older, newer) = (
        SessionKey::of(&SessionId::new(&SystemRng)),
        SessionKey::of(&SessionId::new(&SystemRng)),
    );
    let at = |secs: i64| {
        registry_at(
            &prefix,
            ttl,
            t0.plus(axess_clock::SignedDuration::seconds(secs)),
        )
    };
    let (r0, r1, r7, r8) = (at(0).await, at(1).await, at(7).await, at(8).await);
    r0.register(&user, &older).await.unwrap();
    r1.register(&user, &newer).await.unwrap();
    // Past half the lifetime, so the check moves the score forward.
    assert!(r7.is_valid(&user, &older).await.unwrap());
    assert_eq!(
        r8.active_sessions(&user).await.unwrap(),
        vec![older, newer],
        "the cap would evict the newer session instead of the oldest"
    );
}

/// A forced logout of one session and of the whole user leaves no
/// registration time behind to be counted or ordered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_invalidation_removes_the_registration_times() {
    let sweep = crate::testing::valkey_sweep::on_node("orderdel");
    let prefix = sweep.prefix().to_owned();
    let user = UserId::new(&SystemRng);
    let (a, b) = (
        SessionKey::of(&SessionId::new(&SystemRng)),
        SessionKey::of(&SessionId::new(&SystemRng)),
    );
    let registry = registry_on(connect().await, &prefix, Duration::from_secs(60)).await;
    registry.register(&user, &a).await.unwrap();
    registry.register(&user, &b).await.unwrap();
    registry.invalidate_session(&user, &a).await.unwrap();
    assert_eq!(registry.active_sessions(&user).await.unwrap(), vec![b]);
    registry.invalidate_user(&user).await.unwrap();
    assert!(registry.active_sessions(&user).await.unwrap().is_empty());
    registry.register(&user, &a).await.unwrap();
    assert_eq!(registry.active_sessions(&user).await.unwrap(), vec![a]);
}

/// A session registered while `active_sessions` runs, after it read the live
/// members and before it dropped the orphaned registration times, keeps its
/// registration time; a session that is gone from the registry loses its.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_session_registered_during_active_sessions_keeps_its_registration_time() {
    let sweep = crate::testing::valkey_sweep::on_node("orphan");
    let prefix = sweep.prefix().to_owned();
    let user = UserId::new(&SystemRng);
    let (gone, kept, late) = (
        SessionKey::of(&SessionId::new(&SystemRng)),
        SessionKey::of(&SessionId::new(&SystemRng)),
        SessionKey::of(&SessionId::new(&SystemRng)),
    );
    let registry = registry_on(connect().await, &prefix, Duration::from_secs(60)).await;
    let keys = user_keys(&prefix, &user).expect("one slot");
    registry.register(&user, &gone).await.unwrap();
    registry.register(&user, &kept).await.unwrap();
    // After `active_sessions` read the live members: one session expires
    // out of the registry and another is registered. The orphan step reads
    // no snapshot, so it cannot be stale against either.
    registry
        .client
        .zrem::<(), _, _>(&keys.registry, gone.to_string())
        .await
        .unwrap();
    registry.register(&user, &late).await.unwrap();

    registry.drop_orphan_registrations(&keys).await.unwrap();

    let at = |sid: &SessionKey| {
        let registered_key = keys.registered_at.clone();
        let client = registry.client.clone();
        let sid = sid.to_string();
        async move {
            client
                .zscore::<Option<f64>, _, _>(&registered_key, sid)
                .await
                .unwrap()
        }
    };
    assert!(
        at(&late).await.is_some(),
        "the session registered meanwhile lost its registration time"
    );
    assert!(at(&kept).await.is_some());
    assert!(at(&gone).await.is_none(), "the gone session kept its time");
}

/// Registering a session id again keeps its first registration time, so the
/// eviction order does not move for a session that re-registers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_registering_a_session_again_keeps_its_first_registration_time() {
    let sweep = crate::testing::valkey_sweep::on_node("again");
    let prefix = sweep.prefix().to_owned();
    let t0 = Timestamp::from_unix_seconds(1_800_000_000).expect("a valid instant");
    let user = UserId::new(&SystemRng);
    let sid = SessionKey::of(&SessionId::new(&SystemRng));
    let at = |secs: i64| {
        registry_at(
            &prefix,
            Duration::from_secs(60),
            t0.plus(axess_clock::SignedDuration::seconds(secs)),
        )
    };
    let (r0, r5) = (at(0).await, at(5).await);
    r0.register(&user, &sid).await.unwrap();
    r5.register(&user, &sid).await.unwrap();

    let registered: Option<f64> = r5
        .client
        .zscore(
            user_keys(&prefix, &user).expect("one slot").registered_at,
            sid.to_string(),
        )
        .await
        .unwrap();
    assert_eq!(
        registered,
        Some(t0.unix_millis() as f64),
        "the second registration moved the registration time"
    );
}
