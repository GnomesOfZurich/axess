//! What each invalidation drops, and what it leaves, against a running
//! Valkey (`VALKEY_URL`): ignored by default, run by
//! `scripts/check-live-stores.sh`. Each test removes what it wrote, also
//! when it fails.

use super::live_tests::live_client;
use super::*;
use crate::authz::cache::test_support::{guest_session, uid};
use crate::testing::valkey_sweep::Swept;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// A provider that records every build as `principal resource action`.
#[derive(Default)]
struct RecordingProvider {
    builds: Arc<Mutex<Vec<String>>>,
}

impl RequestEntityProvider for RecordingProvider {
    fn entities_for<'a>(
        &'a self,
        _: &'a AuthSession,
        principal: &'a EntityUid,
        resource: &'a EntityUid,
        action: &'a EntityUid,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Entities, AuthzError>> + Send + 'a>,
    > {
        // The log names the request; the session is not part of it.
        Box::pin(async move {
            self.builds
                .lock()
                .expect("the build log")
                .push(format!("{principal} {resource} {action}"));
            let entity = |uid: &EntityUid| {
                cedar_policy::Entity::new(uid.clone(), HashMap::new(), HashSet::new())
                    .expect("an entity")
            };
            Ok(
                Entities::from_entities(vec![entity(principal), entity(resource)], None)
                    .expect("the entities"),
            )
        })
    }
}

/// A session authenticated in `tenant`, or a guest's for `None`.
async fn session(tenant: Option<&str>) -> AuthSession {
    let session = guest_session();
    if let Some(tenant) = tenant {
        session
            .set_authenticated(
                axess_identity::testing::user("cache-user"),
                axess_identity::testing::tenant(tenant),
                axess_clock::testing::MockClock::reference_time(),
            )
            .await;
    }
    session
}

/// A cache over a fresh prefix, held with the sweep that removes its keys
/// when the test ends, also when it fails, and the log of the provider's
/// builds.
async fn fresh_cache() -> (
    Swept<ValkeyEntityCache<RecordingProvider>>,
    Arc<Mutex<Vec<String>>>,
) {
    let provider = RecordingProvider::default();
    let builds = provider.builds.clone();
    let sweep = crate::testing::valkey_sweep::on_node("scope");
    let cache = ValkeyEntityCache::with_options(
        provider,
        live_client().await,
        sweep.prefix(),
        Duration::from_secs(60),
    );
    (sweep.hold(cache), builds)
}

/// The builds logged since `seen`, sorted, and `seen` moved past them.
fn new_builds(builds: &Mutex<Vec<String>>, seen: &mut usize) -> Vec<String> {
    let log = builds.lock().expect("the build log");
    let mut fresh = log[*seen..].to_vec();
    *seen = log.len();
    fresh.sort();
    fresh
}

/// The requests the tests load: two principals, two resources, two actions.
struct World {
    alice: EntityUid,
    bob: EntityUid,
    d1: EntityUid,
    d2: EntityUid,
    view: EntityUid,
    edit: EntityUid,
}

fn world() -> World {
    World {
        alice: uid("App::User::\"alice\""),
        bob: uid("App::User::\"bob\""),
        d1: uid("App::Doc::\"d1\""),
        d2: uid("App::Doc::\"d2\""),
        view: uid("App::Action::\"View\""),
        edit: uid("App::Action::\"Edit\""),
    }
}

impl World {
    /// Every request of the world, loaded once through `cache` by `session`.
    async fn load_all(&self, cache: &ValkeyEntityCache<RecordingProvider>, s: &AuthSession) {
        for p in [&self.alice, &self.bob] {
            for r in [&self.d1, &self.d2] {
                for a in [&self.view, &self.edit] {
                    cache.entities_for(s, p, r, a).await.expect("a load");
                }
            }
        }
    }
}

/// Every request is stored under a key of its own, for the configured TTL,
/// and a second load of each is served from Valkey.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_each_request_is_stored_once_under_its_own_key_for_the_ttl() {
    let (cache, builds) = fresh_cache().await;
    let w = world();
    let s = session(None).await;
    let mut seen = 0;

    w.load_all(&cache, &s).await;
    assert_eq!(
        new_builds(&builds, &mut seen).len(),
        8,
        "every request is built once"
    );
    w.load_all(&cache, &s).await;
    assert_eq!(
        new_builds(&builds, &mut seen),
        Vec::<String>::new(),
        "the second load of every request is served from the cache"
    );

    let key = cache.cache_key(&w.alice, None, &w.d1, &w.view, None);
    let entry_ttl: i64 = cache.client.pttl(&key).await.expect("PTTL");
    assert!(
        (30_000..=60_000).contains(&entry_ttl),
        "the entry lives the configured TTL, not {entry_ttl} ms"
    );
    let index_ttl: i64 = cache
        .client
        .pttl(cache.index_key(&w.d1))
        .await
        .expect("PTTL");
    assert!(
        (30_000..=60_000).contains(&index_ttl),
        "the index lives the configured TTL, not {index_ttl} ms"
    );
}

/// Invalidating one request drops its entry and no other.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_invalidating_a_request_drops_that_entry_alone() {
    let (cache, builds) = fresh_cache().await;
    let w = world();
    let s = session(None).await;
    let mut seen = 0;
    w.load_all(&cache, &s).await;
    new_builds(&builds, &mut seen);

    cache
        .invalidate(&w.alice, None, &w.d1, &w.view)
        .await
        .expect("the invalidation");
    w.load_all(&cache, &s).await;

    assert_eq!(
        new_builds(&builds, &mut seen),
        vec![format!("{} {} {}", w.alice, w.d1, w.view)]
    );
}

/// Invalidating a principal drops its entries and leaves another's.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_invalidating_a_principal_drops_its_entries_alone() {
    let (cache, builds) = fresh_cache().await;
    let w = world();
    let s = session(None).await;
    let mut seen = 0;
    w.load_all(&cache, &s).await;
    new_builds(&builds, &mut seen);

    cache
        .invalidate_principal(&w.alice)
        .await
        .expect("the invalidation");
    w.load_all(&cache, &s).await;

    let rebuilt = new_builds(&builds, &mut seen);
    assert_eq!(rebuilt.len(), 4, "{rebuilt:?}");
    assert!(
        rebuilt.iter().all(|b| b.starts_with(&w.alice.to_string())),
        "{rebuilt:?}"
    );
}

/// Invalidating a resource drops its entries for every principal and leaves
/// another resource's.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_invalidating_a_resource_drops_its_entries_alone() {
    let (cache, builds) = fresh_cache().await;
    let w = world();
    let s = session(None).await;
    let mut seen = 0;
    w.load_all(&cache, &s).await;
    new_builds(&builds, &mut seen);

    cache
        .invalidate_resource(&w.d2)
        .await
        .expect("the invalidation");
    w.load_all(&cache, &s).await;

    let rebuilt = new_builds(&builds, &mut seen);
    assert_eq!(rebuilt.len(), 4, "{rebuilt:?}");
    let d2 = format!(" {} ", w.d2);
    assert!(rebuilt.iter().all(|b| b.contains(&d2)), "{rebuilt:?}");
}

/// Invalidating a tenant drops the entries loaded in it and leaves another
/// tenant's and a guest's.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_invalidating_a_tenant_drops_its_entries_alone() {
    let (cache, builds) = fresh_cache().await;
    let w = world();
    let (home, away, guest) = (
        session(Some("cache-home")).await,
        session(Some("cache-away")).await,
        session(None).await,
    );
    let mut seen = 0;
    for s in [&home, &away, &guest] {
        w.load_all(&cache, s).await;
    }
    assert_eq!(
        new_builds(&builds, &mut seen).len(),
        24,
        "each tenant's requests are entries of their own"
    );

    let tenant = axess_identity::testing::tenant("cache-home").to_string();
    cache
        .invalidate_tenant(&tenant)
        .await
        .expect("the invalidation");
    for s in [&away, &guest] {
        w.load_all(&cache, s).await;
    }
    assert_eq!(
        new_builds(&builds, &mut seen),
        Vec::<String>::new(),
        "another tenant's and a guest's entries stay"
    );
    w.load_all(&cache, &home).await;
    assert_eq!(
        new_builds(&builds, &mut seen).len(),
        8,
        "the tenant's entries are dropped"
    );
}
