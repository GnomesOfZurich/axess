//! On a cluster whose prefix has no hash tag the cache stores nothing and
//! sends no command: a load goes to the provider, the cache says so once,
//! and an invalidation has nothing to look for. The client is clustered and
//! never connected, so a command sent to it fails the test.

use super::*;
use crate::authz::cache::test_support::{CountingProvider, guest_session, uid};
use axess_testing::mock_tracing::TracingCapture;
use std::sync::atomic::AtomicUsize;
use tracing::Level;

/// A cache over a clustered client that is never connected, and the count
/// of its provider's builds.
fn untagged_on_a_cluster() -> (ValkeyEntityCache<CountingProvider>, Arc<AtomicUsize>) {
    let config = Config::from_url("redis-cluster://127.0.0.1:1").expect("a cluster URL");
    let client = Client::new(config, None, None, None);
    assert!(client.is_clustered());
    let builds = Arc::new(AtomicUsize::new(0));
    let cache = ValkeyEntityCache::with_options(
        CountingProvider {
            calls: builds.clone(),
        },
        client,
        "axess",
        Duration::from_secs(60),
    );
    (cache, builds)
}

/// The warnings saying that nothing is cached.
fn nothing_cached_warnings(capture: &TracingCapture) -> usize {
    capture
        .events()
        .iter()
        .filter(|e| e.level == Level::WARN && e.message.contains("nothing is cached"))
        .count()
}

/// Every load is built by the provider, and the first load says that
/// nothing is cached, once.
#[tokio::test]
async fn an_untagged_cluster_cache_builds_every_load_and_says_so_once() {
    let (cache, builds) = untagged_on_a_cluster();
    let capture = TracingCapture::install();
    let s = guest_session();
    let (p, r, a) = (
        uid("App::User::\"alice\""),
        uid("App::Doc::\"d1\""),
        uid("App::Action::\"View\""),
    );

    let first = tokio::time::timeout(Duration::from_secs(5), cache.entities_for(&s, &p, &r, &a))
        .await
        .expect("the load sends no command");
    first.expect("the provider's set");
    assert_eq!(
        nothing_cached_warnings(&capture),
        1,
        "said on the first load"
    );
    for _ in 0..2 {
        tokio::time::timeout(Duration::from_secs(5), cache.entities_for(&s, &p, &r, &a))
            .await
            .expect("the load sends no command")
            .expect("the provider's set");
    }

    assert_eq!(builds.load(AtomicOrdering::SeqCst), 3);
    assert_eq!(nothing_cached_warnings(&capture), 1, "said once");
}

/// `invalidation` returns `Ok` within a few seconds, which a command sent
/// to the never-connected client does not.
async fn answers_at_once(
    label: &str,
    invalidation: impl std::future::Future<Output = Result<(), fred::error::Error>>,
) {
    match tokio::time::timeout(Duration::from_secs(5), invalidation).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("{label} sent a command, which failed: {e}"),
        Err(_) => panic!("{label} sent a command, which did not answer"),
    }
}

/// An invalidation of every scope returns at once without a command.
#[tokio::test]
async fn an_untagged_cluster_cache_invalidates_without_a_command() {
    let (cache, _) = untagged_on_a_cluster();
    let (p, r, a) = (
        uid("App::User::\"alice\""),
        uid("App::Doc::\"d1\""),
        uid("App::Action::\"View\""),
    );
    answers_at_once("invalidate", cache.invalidate(&p, None, &r, &a)).await;
    answers_at_once("invalidate_principal", cache.invalidate_principal(&p)).await;
    answers_at_once("invalidate_resource", cache.invalidate_resource(&r)).await;
    answers_at_once("invalidate_tenant", cache.invalidate_tenant("t1")).await;
    answers_at_once("invalidate_all", cache.invalidate_all()).await;
}
