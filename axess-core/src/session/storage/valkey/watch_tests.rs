//! Revocation watchers against a live Valkey: they share one subscriber
//! connection and leave none behind. Each test counts, and kills, only the
//! connection that carries its own registry's name, so what else holds a
//! pub/sub connection on the server neither moves a count nor is killed.
//!
//! Run with `VALKEY_URL=redis://127.0.0.1:6399 cargo test --features valkey
//! -- --ignored valkey_watch`.

use super::registry::ValkeySessionRegistry;
use super::subscriber::connection_name;
use crate::authn::ids::UserId;
use crate::session::id::{SessionId, SessionKey};
use crate::session::store::SessionRegistry;
use axess_rng::SystemRng;
use fred::prelude::*;
use fred::types::{ClusterHash, CustomCommand};
use std::time::Duration;
use tokio::task::JoinHandle;

use super::SUBSCRIBER_TESTS;

pub(super) async fn connect() -> Client {
    let url = std::env::var("VALKEY_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let client = Client::new(Config::from_url(&url).unwrap(), None, None, None);
    client.init().await.expect("connect");
    client
}

/// The server's ids of the connections in pub/sub mode that are called
/// `name`: the lines of `CLIENT LIST TYPE pubsub` with that `name=` field.
async fn subscribers_named(admin: &Client, name: &str) -> Vec<String> {
    let wanted = format!("name={name}");
    let command = CustomCommand::new_static("CLIENT", ClusterHash::FirstKey, false);
    let listing: String = admin
        .custom(command, vec!["LIST", "TYPE", "pubsub"])
        .await
        .expect("CLIENT LIST");
    listing
        .lines()
        .filter(|line| line.split(' ').any(|field| field == wanted))
        .filter_map(|line| line.split(' ').find_map(|field| field.strip_prefix("id=")))
        .map(str::to_owned)
        .collect()
}

/// Connections currently in pub/sub mode under `name`, the name a registry
/// gives its subscriber connection, as the server lists them. A watcher
/// counts in `watcher_count` from the moment it registers, before its join
/// has opened and subscribed the connection, so a count that a join raises is
/// waited for, never read straight after the watcher count.
pub(super) async fn subscriber_connections(admin: &Client, name: &str) -> usize {
    subscribers_named(admin, name).await.len()
}

/// Kill the pub/sub connections called `name`, and no other client's.
async fn kill_subscribers(admin: &Client, name: &str) {
    for id in subscribers_named(admin, name).await {
        let kill = CustomCommand::new_static("CLIENT", ClusterHash::FirstKey, false);
        let _: i64 = admin
            .custom(kill, vec!["KILL", "ID", id.as_str()])
            .await
            .expect("CLIENT KILL");
    }
}

pub(super) async fn eventually<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..100 {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}

fn user() -> UserId {
    UserId::new(&SystemRng)
}

fn watch(registry: &ValkeySessionRegistry, user: UserId, session: SessionKey) -> JoinHandle<()> {
    let registry = registry.clone();
    tokio::spawn(async move { registry.watch_revocation(&user, &session).await })
}

async fn registered(registry: &ValkeySessionRegistry, user: &UserId) -> SessionKey {
    let session = SessionKey::of(&SessionId::new(&SystemRng));
    registry.register(user, &session).await.unwrap();
    session
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_watch_two_watchers_share_one_connection_and_both_wake() {
    let serial = SUBSCRIBER_TESTS.lock().await;
    let admin = connect().await;
    let sweep = crate::testing::valkey_sweep::on_node("watch_a");
    let prefix = sweep.prefix().to_owned();
    let name = connection_name(&prefix);
    let registry =
        ValkeySessionRegistry::with_options(connect().await, prefix, Duration::from_secs(60))
            .await
            .expect("a registry");
    let before = subscriber_connections(&admin, &name).await;

    let u = user();
    let (s1, s2) = (
        registered(&registry, &u).await,
        registered(&registry, &u).await,
    );
    let (w1, w2) = (watch(&registry, u, s1), watch(&registry, u, s2));
    eventually("both watchers joined", || async {
        registry.subscriber.watcher_count() == 2
    })
    .await;

    eventually("two watchers, one subscriber connection", || async {
        subscriber_connections(&admin, &name).await == before + 1
    })
    .await;

    registry.invalidate_user(&u).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        w1.await.unwrap();
        w2.await.unwrap();
    })
    .await
    .expect("both watchers receive the revocation");

    eventually("connection closed after the last watcher", || async {
        subscriber_connections(&admin, &name).await == before
    })
    .await;
    drop(serial);
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_watch_aborting_one_leaves_the_other_and_aborting_both_closes() {
    let serial = SUBSCRIBER_TESTS.lock().await;
    let admin = connect().await;
    let sweep = crate::testing::valkey_sweep::on_node("watch_b");
    let prefix = sweep.prefix().to_owned();
    let name = connection_name(&prefix);
    let registry =
        ValkeySessionRegistry::with_options(connect().await, prefix, Duration::from_secs(60))
            .await
            .expect("a registry");
    let before = subscriber_connections(&admin, &name).await;

    let (u1, u2) = (user(), user());
    let (s1, s2) = (
        registered(&registry, &u1).await,
        registered(&registry, &u2).await,
    );
    let (w1, w2) = (watch(&registry, u1, s1), watch(&registry, u2, s2));
    eventually("both watchers joined", || async {
        registry.subscriber.watcher_count() == 2
    })
    .await;
    eventually("one subscriber connection is open", || async {
        subscriber_connections(&admin, &name).await == before + 1
    })
    .await;

    // Aborted before it could quit anything itself.
    w1.abort();
    let _ = w1.await;
    eventually("one hold released", || async {
        registry.subscriber.watcher_count() == 1
    })
    .await;
    assert_eq!(
        subscriber_connections(&admin, &name).await,
        before + 1,
        "the other watcher keeps the connection"
    );

    registry.invalidate_session(&u2, &s2).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), w2)
        .await
        .expect("the remaining watcher still receives its revocation")
        .unwrap();
    eventually("connection closed after the last watcher", || async {
        subscriber_connections(&admin, &name).await == before
    })
    .await;

    // Both aborted: nothing is left behind.
    let (u3, u4) = (user(), user());
    let (s3, s4) = (
        registered(&registry, &u3).await,
        registered(&registry, &u4).await,
    );
    let (w3, w4) = (watch(&registry, u3, s3), watch(&registry, u4, s4));
    eventually("watchers joined", || async {
        registry.subscriber.watcher_count() == 2
    })
    .await;
    w3.abort();
    w4.abort();
    let _ = (w3.await, w4.await);
    eventually("aborted watchers leave no connection", || async {
        subscriber_connections(&admin, &name).await == before
    })
    .await;
    drop(serial);
}

/// A subscriber connection that died is not reused: the next watcher opens a
/// new one and is woken by its revocation. Before, the dead client was kept
/// while any watcher held it and every later watcher waited forever.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_watch_replaces_a_dead_subscriber_connection() {
    let serial = SUBSCRIBER_TESTS.lock().await;
    let admin = connect().await;
    let sweep = crate::testing::valkey_sweep::on_node("watch_c");
    let prefix = sweep.prefix().to_owned();
    let name = connection_name(&prefix);
    let registry =
        ValkeySessionRegistry::with_options(connect().await, prefix, Duration::from_secs(60))
            .await
            .expect("a registry");
    let before = subscriber_connections(&admin, &name).await;

    let (u1, u2) = (user(), user());
    let (s1, s2) = (
        registered(&registry, &u1).await,
        registered(&registry, &u2).await,
    );
    let w1 = watch(&registry, u1, s1);
    eventually("first watcher joined", || async {
        registry.subscriber.watcher_count() == 1
    })
    .await;
    eventually("the subscriber connection is open", || async {
        subscriber_connections(&admin, &name).await == before + 1
    })
    .await;

    kill_subscribers(&admin, &name).await;
    eventually("the subscriber connection is gone", || async {
        subscriber_connections(&admin, &name).await == before
    })
    .await;

    let w2 = watch(&registry, u2, s2);
    eventually("second watcher joined", || async {
        registry.subscriber.watcher_count() == 2
    })
    .await;
    eventually("a new subscriber connection is open", || async {
        subscriber_connections(&admin, &name).await == before + 1
    })
    .await;

    registry.invalidate_session(&u2, &s2).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), w2)
        .await
        .expect("the new watcher receives its revocation")
        .unwrap();
    registry.invalidate_session(&u1, &s1).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), w1)
        .await
        .expect("the first watcher is served by the replacement connection")
        .unwrap();
    drop(serial);
}

/// A revocation published while the subscriber connection was dead is not
/// lost: the dispatcher forgets the dead connection on `Closed`, and the next
/// join that reconnects still flags the waiting watcher for a recheck. The
/// wait is shorter than the degraded poll interval, so the poll cannot be
/// what wakes it.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_watch_rechecks_waiting_watchers_after_a_closed_connection() {
    let serial = SUBSCRIBER_TESTS.lock().await;
    let admin = connect().await;
    let sweep = crate::testing::valkey_sweep::on_node("watch_d");
    let prefix = sweep.prefix().to_owned();
    let name = connection_name(&prefix);
    let registry =
        ValkeySessionRegistry::with_options(connect().await, prefix, Duration::from_secs(60))
            .await
            .expect("a registry");
    let before = subscriber_connections(&admin, &name).await;
    let (u1, u2) = (user(), user());
    let (s1, s2) = (
        registered(&registry, &u1).await,
        registered(&registry, &u2).await,
    );
    let w1 = watch(&registry, u1, s1);
    eventually("first watcher joined", || async {
        registry.subscriber.watcher_count() == 1
    })
    .await;
    eventually("the subscriber connection is open", || async {
        subscriber_connections(&admin, &name).await == before + 1
    })
    .await;

    kill_subscribers(&admin, &name).await;
    eventually("the subscriber connection is gone", || async {
        subscriber_connections(&admin, &name).await == before
    })
    .await;

    // Published while there is no connection: no watcher can hear it.
    registry.invalidate_session(&u1, &s1).await.unwrap();

    let w2 = watch(&registry, u2, s2);
    tokio::time::timeout(Duration::from_secs(3), w1)
        .await
        .expect("the waiting watcher rechecks after the reconnect")
        .unwrap();
    w2.abort();
    drop(serial);
}

/// A client that reconnects on its own after the server drops it.
async fn connect_reconnecting(delay_ms: u32) -> Client {
    let url = std::env::var("VALKEY_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let policy = ReconnectPolicy::new_constant(0, delay_ms);
    let client = Client::new(Config::from_url(&url).unwrap(), None, None, Some(policy));
    client.init().await.expect("connect");
    client
}

/// The subscriber connection drops and the client reconnects by itself while
/// a revocation is published: the broadcast never closes and never lags, yet
/// the waiting watcher still learns of the revocation, because the
/// reconnect resubscribes and flags a recheck.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_watch_rechecks_after_the_client_reconnects_by_itself() {
    let serial = SUBSCRIBER_TESTS.lock().await;
    let admin = connect().await;
    let sweep = crate::testing::valkey_sweep::on_node("watch_e");
    let prefix = sweep.prefix().to_owned();
    let name = connection_name(&prefix);
    let registry = ValkeySessionRegistry::with_options(
        connect_reconnecting(1500).await,
        prefix,
        Duration::from_secs(60),
    )
    .await
    .expect("a registry");
    let before = subscriber_connections(&admin, &name).await;
    let (u1, u2) = (user(), user());
    let (s1, s2) = (
        registered(&registry, &u1).await,
        registered(&registry, &u2).await,
    );
    let (w1, w2) = (watch(&registry, u1, s1), watch(&registry, u2, s2));
    eventually("the subscriber connection is open", || async {
        subscriber_connections(&admin, &name).await == before + 1
    })
    .await;

    kill_subscribers(&admin, &name).await;
    eventually("the subscriber connection is gone", || async {
        subscriber_connections(&admin, &name).await == before
    })
    .await;

    // Published while the client is between connections.
    registry.invalidate_session(&u1, &s1).await.unwrap();

    tokio::time::timeout(Duration::from_secs(6), w1)
        .await
        .expect("the watcher learns of the revocation after the reconnect")
        .unwrap();

    // The other watcher still holds the connection the client reopened,
    // and that connection is named as the first one was.
    eventually("the reopened connection carries the name", || async {
        subscriber_connections(&admin, &name).await == before + 1
    })
    .await;
    w2.abort();
    let _ = w2.await;
    drop(serial);
}

/// The counts are of the registry's own connection. Another client of the
/// same server holds a subscription while the count is first read and
/// closes it before the watcher's connection is counted: a count of every
/// pub/sub connection on the server would then never rise by one.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_watch_counts_are_not_moved_by_another_clients_subscription() {
    let serial = SUBSCRIBER_TESTS.lock().await;
    let admin = connect().await;
    let sweep = crate::testing::valkey_sweep::on_node("watch_f");
    let prefix = sweep.prefix().to_owned();
    let name = connection_name(&prefix);
    let registry =
        ValkeySessionRegistry::with_options(connect().await, prefix, Duration::from_secs(60))
            .await
            .expect("a registry");

    let other = connect().await;
    let other_name = format!("axt-watch-other-{}", user());
    let set_name = CustomCommand::new_static("CLIENT", ClusterHash::FirstKey, false);
    let _: String = other
        .custom(set_name, vec!["SETNAME", other_name.as_str()])
        .await
        .expect("CLIENT SETNAME");
    other.subscribe("axt_watch_other").await.expect("subscribe");
    eventually("the other client's subscription is open", || async {
        subscriber_connections(&admin, &other_name).await == 1
    })
    .await;

    let before = subscriber_connections(&admin, &name).await;
    let u = user();
    let s = registered(&registry, &u).await;
    let w = watch(&registry, u, s);
    eventually("the watcher joined", || async {
        registry.subscriber.watcher_count() == 1
    })
    .await;
    other.quit().await.expect("quit");
    eventually("the other client's subscription is closed", || async {
        subscriber_connections(&admin, &other_name).await == 0
    })
    .await;
    eventually("one subscriber connection is open", || async {
        subscriber_connections(&admin, &name).await == before + 1
    })
    .await;

    w.abort();
    let _ = w.await;
    eventually("connection closed after the last watcher", || async {
        subscriber_connections(&admin, &name).await == before
    })
    .await;
    drop(serial);
}
