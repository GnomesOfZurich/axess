//! Revocation watchers against a live Valkey: they share one subscriber
//! connection and leave none behind.
//!
//! Run with `VALKEY_URL=redis://127.0.0.1:6399 cargo test --features valkey
//! -- --ignored valkey_watch`.

use super::registry::ValkeySessionRegistry;
use crate::authn::ids::UserId;
use crate::session::id::SessionId;
use crate::session::store::SessionRegistry;
use axess_rng::SystemRng;
use fred::prelude::*;
use fred::types::{ClusterHash, CustomCommand};
use std::time::Duration;
use tokio::task::JoinHandle;

/// The tests count the server's subscriber connections, so they run one at a
/// time.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn connect() -> Client {
    let url = std::env::var("VALKEY_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let client = Client::new(Config::from_url(&url).unwrap(), None, None, None);
    client.init().await.expect("connect");
    client
}

/// Connections currently in pub/sub mode, as the server lists them.
async fn subscriber_connections(admin: &Client) -> usize {
    let command = CustomCommand::new_static("CLIENT", ClusterHash::FirstKey, false);
    let listing: String = admin
        .custom(command, vec!["LIST", "TYPE", "pubsub"])
        .await
        .expect("CLIENT LIST");
    listing.lines().filter(|l| !l.trim().is_empty()).count()
}

async fn eventually<F, Fut>(what: &str, mut check: F)
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

fn watch(registry: &ValkeySessionRegistry, user: UserId, session: SessionId) -> JoinHandle<()> {
    let registry = registry.clone();
    tokio::spawn(async move { registry.watch_revocation(&user, &session).await })
}

async fn registered(registry: &ValkeySessionRegistry, user: &UserId) -> SessionId {
    let session = SessionId::new(&SystemRng);
    registry.register(user, &session).await.unwrap();
    session
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_watch_two_watchers_share_one_connection_and_both_wake() {
    let _serial = ONE_AT_A_TIME.lock().await;
    let admin = connect().await;
    let registry = ValkeySessionRegistry::with_options(
        connect().await,
        format!("axt_watch_a_{}", user()),
        Duration::from_secs(60),
    );
    let before = subscriber_connections(&admin).await;

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

    assert_eq!(
        subscriber_connections(&admin).await,
        before + 1,
        "two watchers, one subscriber connection"
    );

    registry.invalidate_user(&u).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        w1.await.unwrap();
        w2.await.unwrap();
    })
    .await
    .expect("both watchers receive the revocation");

    eventually("connection closed after the last watcher", || async {
        subscriber_connections(&admin).await == before
    })
    .await;
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_watch_aborting_one_leaves_the_other_and_aborting_both_closes() {
    let _serial = ONE_AT_A_TIME.lock().await;
    let admin = connect().await;
    let registry = ValkeySessionRegistry::with_options(
        connect().await,
        format!("axt_watch_b_{}", user()),
        Duration::from_secs(60),
    );
    let before = subscriber_connections(&admin).await;

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
    assert_eq!(subscriber_connections(&admin).await, before + 1);

    // Aborted before it could quit anything itself.
    w1.abort();
    let _ = w1.await;
    eventually("one hold released", || async {
        registry.subscriber.watcher_count() == 1
    })
    .await;
    assert_eq!(
        subscriber_connections(&admin).await,
        before + 1,
        "the other watcher keeps the connection"
    );

    registry.invalidate_session(&u2, &s2).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), w2)
        .await
        .expect("the remaining watcher still receives its revocation")
        .unwrap();
    eventually("connection closed after the last watcher", || async {
        subscriber_connections(&admin).await == before
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
        subscriber_connections(&admin).await == before
    })
    .await;
}
