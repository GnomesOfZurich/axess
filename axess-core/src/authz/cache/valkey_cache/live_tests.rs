//! The cache against a running Valkey (`VALKEY_URL`): ignored by default,
//! run by `scripts/check-live-stores.sh`. Each test removes what it wrote,
//! also when it fails.

use super::*;
use crate::authz::cache::test_support::guest_session;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A provider whose resource sits in a folder: the folder is part of
/// every entity set it builds, as the resource's parent.
struct FolderedProvider {
    calls: Arc<AtomicUsize>,
    folder: EntityUid,
}

impl RequestEntityProvider for FolderedProvider {
    fn entities_for<'a>(
        &'a self,
        _: &'a AuthSession,
        principal: &'a EntityUid,
        resource: &'a EntityUid,
        _: &'a EntityUid,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Entities, AuthzError>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let entity = |uid: &EntityUid, parents: HashSet<EntityUid>| {
                cedar_policy::Entity::new(uid.clone(), HashMap::new(), parents).unwrap()
            };
            Ok(Entities::from_entities(
                vec![
                    entity(principal, HashSet::new()),
                    entity(&self.folder, HashSet::new()),
                    entity(resource, HashSet::from([self.folder.clone()])),
                ],
                None,
            )
            .unwrap())
        })
    }
}

pub(super) async fn live_client() -> Client {
    let url = std::env::var("VALKEY_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let client = Client::new(Config::from_url(&url).expect("url"), None, None, None);
    client.init().await.expect("connect");
    client
}

/// Invalidating a folder drops the entries of the documents in it, on
/// the shared tier as on the in-process one: the folder is in their
/// entity sets, not in their keys.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn invalidating_a_folder_drops_the_entries_of_the_documents_in_it() {
    let calls = Arc::new(AtomicUsize::new(0));
    let folder = EntityUid::from_str("App::Folder::\"f1\"").unwrap();
    let sweep = crate::testing::valkey_sweep::on_node("folder");
    let cached = ValkeyEntityCache::with_options(
        FolderedProvider {
            calls: calls.clone(),
            folder: folder.clone(),
        },
        live_client().await,
        sweep.prefix(),
        Duration::from_secs(60),
    );
    let s = guest_session();
    let p = EntityUid::from_str("App::User::\"alice\"").unwrap();
    let a = EntityUid::from_str("App::Action::\"View\"").unwrap();
    let docs = [
        EntityUid::from_str("App::Doc::\"d1\"").unwrap(),
        EntityUid::from_str("App::Doc::\"d2\"").unwrap(),
    ];
    cached.invalidate_all().await.unwrap();
    for res in &docs {
        cached.entities_for(&s, &p, res, &a).await.unwrap();
    }
    cached.invalidate_resource(&folder).await.unwrap();
    for res in &docs {
        cached.entities_for(&s, &p, res, &a).await.unwrap();
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        4,
        "both documents are rebuilt after their folder changed"
    );
}

/// Load `docs` for `principal` through `cached`, then invalidate the
/// principal and load them again: the number of provider builds.
async fn builds_around_an_invalidation(
    cached: &ValkeyEntityCache<FolderedProvider>,
    calls: &AtomicUsize,
    docs: &[EntityUid],
) -> (usize, usize) {
    let s = guest_session();
    let p = EntityUid::from_str("App::User::\"alice\"").unwrap();
    let a = EntityUid::from_str("App::Action::\"View\"").unwrap();
    for res in docs {
        cached.entities_for(&s, &p, res, &a).await.unwrap();
    }
    for res in docs {
        cached.entities_for(&s, &p, res, &a).await.unwrap();
    }
    let before = calls.load(Ordering::SeqCst);
    cached
        .invalidate_principal(&p)
        .await
        .expect("the invalidation");
    for res in docs {
        cached.entities_for(&s, &p, res, &a).await.unwrap();
    }
    (before, calls.load(Ordering::SeqCst))
}

/// Documents enough to land entries on every node of a cluster.
fn many_docs() -> Vec<EntityUid> {
    (0..48)
        .map(|n| EntityUid::from_str(&format!("App::Doc::\"d{n}\"")).unwrap())
        .collect()
}

/// The tests that need a cluster. `valkey_cluster` is the name a run
/// leaves them out by (`--skip valkey_cluster`); the module inside is the
/// authorization cache's own, the name the live-store gate counts this
/// suite by, apart from the session store's and the device store's.
mod valkey_cluster {
    use super::*;

    mod authz_cluster {
        use super::*;

        /// On a cluster, a prefix without a hash tag spreads the entries over every
        /// node, where one SCAN cannot find them all: no entry is kept, so an
        /// invalidated principal is rebuilt everywhere.
        #[tokio::test]
        #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
        async fn an_untagged_prefix_leaves_no_entry_an_invalidation_misses() {
            let counting = crate::testing::valkey_cluster::refused_scripts_ledger().await;
            let calls = Arc::new(AtomicUsize::new(0));
            let sweep = crate::testing::valkey_sweep::on_cluster("authz");
            let cached = ValkeyEntityCache::with_options(
                FolderedProvider {
                    calls: calls.clone(),
                    folder: EntityUid::from_str("App::Folder::\"f1\"").unwrap(),
                },
                crate::testing::valkey_cluster::cluster_client().await,
                sweep.prefix(),
                Duration::from_secs(60),
            );
            let docs = many_docs();

            let (before, after) = builds_around_an_invalidation(&cached, &calls, &docs).await;

            assert_eq!(
                after - before,
                docs.len(),
                "an entry outlived the invalidation of its principal"
            );
            counting.release().await;
        }

        /// On a cluster, a hash-tag prefix keeps every entry in one slot: the
        /// entries are shared, and an invalidation drops all of them.
        #[tokio::test]
        #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
        async fn a_tagged_prefix_caches_and_invalidates_whole() {
            let counting = crate::testing::valkey_cluster::refused_scripts_ledger().await;
            let calls = Arc::new(AtomicUsize::new(0));
            let sweep = crate::testing::valkey_sweep::on_cluster("authz");
            let cached = ValkeyEntityCache::with_options(
                FolderedProvider {
                    calls: calls.clone(),
                    folder: EntityUid::from_str("App::Folder::\"f1\"").unwrap(),
                },
                crate::testing::valkey_cluster::cluster_client().await,
                format!("{{{}}}", sweep.prefix()),
                Duration::from_secs(60),
            );
            let docs = many_docs();

            let (before, after) = builds_around_an_invalidation(&cached, &calls, &docs).await;

            assert_eq!(
                before,
                docs.len(),
                "the second load was served from the cache"
            );
            assert_eq!(after - before, docs.len(), "every entry was dropped");
            counting.release().await;
        }
    }
}
