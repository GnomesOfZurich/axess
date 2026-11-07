#![cfg(all(feature = "testing", feature = "authz"))]
//! The reload follower and the reload steps are bounded in time, a failing
//! source is counted, a panicking source does not end the follower, and a
//! follower never goes back to an older bundle.

use axess_core::authz::{
    AuthzEntityProvider, AuthzError, AuthzStore, PolicyStore,
    cache::CacheInvalidator,
    make_entity_uid,
    reload::{
        CoordinationError, InProcessCoordinator, PolicyBundle, PolicySource, ReloadCoordinator,
        ReloadFuture, ReloadReceiver, ReloadTimeouts, VersionedBundle,
    },
};
use axess_core::metrics::{AuthzCacheMetrics, MetricSinks};
use cedar_policy::{Entities, EntityUid, Schema};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const SCHEMA: &str = r#"{
    "App": {
        "entityTypes": {
            "User": { "memberOfTypes": [] },
            "Resource": { "memberOfTypes": [] }
        },
        "actions": {
            "View": {
                "appliesTo": {
                    "principalTypes": ["User"],
                    "resourceTypes": ["Resource"]
                }
            }
        }
    }
}"#;

fn permit(doc: &str) -> String {
    format!(
        r#"permit(principal == App::User::"alice", action == App::Action::"View", resource == App::Resource::"{doc}");"#
    )
}

fn bundle(doc: &str) -> PolicyBundle {
    PolicyBundle {
        policy_text: permit(doc),
        schema_json: SCHEMA.to_string(),
    }
}

fn digest_of(doc: &str) -> String {
    bundle(doc).digest()
}

struct Provider;

impl AuthzEntityProvider for Provider {
    type ResourceId = String;
    type Error = std::convert::Infallible;

    async fn entities_for(
        &self,
        _: &EntityUid,
        _: &String,
        _: &EntityUid,
    ) -> Result<Entities, Self::Error> {
        Ok(Entities::empty())
    }

    async fn entities_for_tenant(
        &self,
        _: &EntityUid,
        _: Option<&str>,
        _: &String,
        _: &EntityUid,
    ) -> Result<Entities, Self::Error> {
        Ok(Entities::empty())
    }

    fn resource_uid(&self, id: &String) -> Result<EntityUid, AuthzError> {
        make_entity_uid("App", "Resource", id)
    }

    fn validate_schema(&self, _: &Schema) -> Result<(), AuthzError> {
        Ok(())
    }
}

#[derive(Default)]
struct Counting {
    refused: AtomicUsize,
}

impl AuthzCacheMetrics for Counting {
    fn authz_policy_reload_refused(&self) {
        self.refused.fetch_add(1, Ordering::SeqCst);
    }
}

fn bus() -> Arc<InProcessCoordinator> {
    Arc::new(InProcessCoordinator::new(NonZeroUsize::new(16).unwrap()))
}

fn fast() -> ReloadTimeouts {
    ReloadTimeouts {
        source_read: Duration::from_millis(100),
        hook: Duration::from_millis(100),
        announce: Duration::from_millis(100),
    }
}

fn store(doc: &str, metrics: &Arc<Counting>) -> AuthzStore<Provider> {
    let evaluator = Arc::new(PolicyStore::from_text(&permit(doc), SCHEMA).unwrap());
    AuthzStore::try_new(evaluator, Arc::new(Provider), "App")
        .unwrap()
        .with_reload_timeouts(fast())
        .with_metrics(MetricSinks::noop().with_authz_cache(metrics.clone()))
}

/// Poll `check` for at most 3 s.
async fn eventually(what: &str, mut check: impl FnMut() -> bool) {
    for _ in 0..300 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("did not happen within 3s: {what}");
}

/// What the source does on each read, in order; the last entry repeats.
enum Step {
    Hang,
    Fail,
    Panic,
    Serve(VersionedBundle),
}

struct ScriptedSource {
    steps: Mutex<Vec<Step>>,
    reads: AtomicUsize,
}

impl ScriptedSource {
    fn new(steps: Vec<Step>) -> Arc<Self> {
        Arc::new(Self {
            steps: Mutex::new(steps),
            reads: AtomicUsize::new(0),
        })
    }
    fn replace(&self, steps: Vec<Step>) {
        *self.steps.lock().unwrap() = steps;
    }
}

impl PolicySource for ScriptedSource {
    fn load(&self) -> ReloadFuture<'_, Result<PolicyBundle, AuthzError>> {
        Box::pin(async move {
            Err(AuthzError::PolicyParse(
                "scripted source is read through load_versioned".into(),
            ))
        })
    }

    fn load_versioned(&self) -> ReloadFuture<'_, Result<VersionedBundle, AuthzError>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let step = {
            let mut steps = self.steps.lock().unwrap();
            if steps.len() > 1 {
                steps.remove(0)
            } else {
                match steps.first() {
                    Some(Step::Hang) => Step::Hang,
                    Some(Step::Fail) => Step::Fail,
                    Some(Step::Panic) => Step::Panic,
                    Some(Step::Serve(b)) => Step::Serve(b.clone()),
                    None => Step::Hang,
                }
            }
        };
        Box::pin(async move {
            match step {
                Step::Hang => std::future::pending().await,
                Step::Fail => Err(AuthzError::PolicyParse("source down".into())),
                Step::Panic => panic!("source blew up"),
                Step::Serve(b) => Ok(b),
            }
        })
    }
}

fn gen_bundle(doc: &str, generation: u64) -> VersionedBundle {
    VersionedBundle::new(bundle(doc)).with_generation(generation)
}

#[tokio::test]
async fn a_source_that_hangs_is_cut_off_and_counted() {
    let metrics = Arc::new(Counting::default());
    let a = Arc::new(store("doc1", &metrics).with_coordinator(bus()));
    let source = ScriptedSource::new(vec![Step::Hang]);
    let _follower = a
        .follow_reloads(source.clone(), Duration::from_millis(50))
        .await
        .unwrap();

    eventually("a hung read is counted", || {
        metrics.refused.load(Ordering::SeqCst) >= 1
    })
    .await;
    // The follower is still reading: the hung read did not stall it.
    eventually("a second read starts", || {
        source.reads.load(Ordering::SeqCst) >= 2
    })
    .await;
}

#[tokio::test]
async fn a_source_that_fails_is_counted_and_the_set_holds() {
    let metrics = Arc::new(Counting::default());
    let a = Arc::new(store("doc1", &metrics).with_coordinator(bus()));
    let source = ScriptedSource::new(vec![Step::Fail]);
    let _follower = a
        .follow_reloads(source, Duration::from_millis(50))
        .await
        .unwrap();

    eventually("a failed read is counted", || {
        metrics.refused.load(Ordering::SeqCst) >= 1
    })
    .await;
    assert_eq!(a.policy_digest(), Some(digest_of("doc1")));
}

#[tokio::test]
async fn a_source_that_panics_does_not_end_the_follower() {
    let metrics = Arc::new(Counting::default());
    let a = Arc::new(store("doc1", &metrics).with_coordinator(bus()));
    let source = ScriptedSource::new(vec![Step::Panic, Step::Serve(gen_bundle("doc2", 1))]);
    let follower = a
        .follow_reloads(source, Duration::from_millis(50))
        .await
        .unwrap();

    eventually("the panic is counted", || {
        metrics.refused.load(Ordering::SeqCst) >= 1
    })
    .await;
    eventually("the next read converges", || {
        a.policy_digest() == Some(digest_of("doc2"))
    })
    .await;
    assert!(!follower.is_finished());
}

#[derive(Default)]
struct HangingCache;

#[derive(Debug, thiserror::Error)]
#[error("never")]
struct Never;

impl CacheInvalidator for HangingCache {
    type Error = Never;
    async fn invalidate_principal(&self, _: &EntityUid) -> Result<(), Never> {
        Ok(())
    }
    async fn invalidate_tenant(&self, _: &str) -> Result<(), Never> {
        Ok(())
    }
    async fn invalidate_all(&self) -> Result<(), Never> {
        std::future::pending().await
    }
}

#[tokio::test]
async fn a_hung_cache_does_not_hold_the_reload_lock() {
    let metrics = Arc::new(Counting::default());
    let a = store("doc1", &metrics).with_cache_invalidator(Arc::new(HangingCache));

    let first = tokio::time::timeout(
        Duration::from_secs(3),
        a.reload_policies(&permit("doc2"), SCHEMA),
    )
    .await
    .expect("the first reload returns")
    .unwrap();
    assert!(!first.cache_invalidated);

    // An emergency reload behind it is not queued forever.
    let second = tokio::time::timeout(
        Duration::from_secs(3),
        a.reload_policies(&permit("doc3"), SCHEMA),
    )
    .await
    .expect("the second reload returns")
    .unwrap();
    assert_eq!(second.digest, digest_of("doc3"));
}

struct HangingAnnounce;

impl ReloadCoordinator for HangingAnnounce {
    fn announce<'a>(&'a self, _: &'a str) -> ReloadFuture<'a, Result<(), CoordinationError>> {
        Box::pin(std::future::pending())
    }
    fn subscribe(&self) -> ReloadFuture<'_, Result<ReloadReceiver, CoordinationError>> {
        Box::pin(std::future::pending())
    }
}

#[tokio::test]
async fn a_hung_announce_is_cut_off_and_reported_as_not_announced() {
    let metrics = Arc::new(Counting::default());
    let a = store("doc1", &metrics).with_coordinator(Arc::new(HangingAnnounce));

    let reloaded = tokio::time::timeout(
        Duration::from_secs(3),
        a.reload_policies(&permit("doc2"), SCHEMA),
    )
    .await
    .expect("the reload returns")
    .unwrap();

    assert!(!reloaded.announced);
    assert_eq!(a.policy_digest(), Some(digest_of("doc2")));
}

#[tokio::test]
async fn a_follower_does_not_go_back_to_an_older_bundle() {
    let metrics = Arc::new(Counting::default());
    let b = Arc::new(store("doc1", &metrics).with_coordinator(bus()));
    let source = ScriptedSource::new(vec![Step::Serve(gen_bundle("doc2", 2))]);
    let _follower = b
        .follow_reloads(source.clone(), Duration::from_millis(50))
        .await
        .unwrap();
    eventually("generation 2 is applied", || {
        b.policy_digest() == Some(digest_of("doc2"))
    })
    .await;

    // A stale replica answers with generation 1.
    source.replace(vec![Step::Serve(gen_bundle("doc1", 1))]);
    let before = source.reads.load(Ordering::SeqCst);
    eventually("the stale bundle is read", || {
        source.reads.load(Ordering::SeqCst) >= before + 3
    })
    .await;
    assert_eq!(b.policy_digest(), Some(digest_of("doc2")));
    assert!(metrics.refused.load(Ordering::SeqCst) >= 1);

    // A newer generation still applies.
    source.replace(vec![Step::Serve(gen_bundle("doc3", 3))]);
    eventually("generation 3 is applied", || {
        b.policy_digest() == Some(digest_of("doc3"))
    })
    .await;
}

#[tokio::test]
async fn an_unversioned_bundle_is_applied_whatever_came_before() {
    let metrics = Arc::new(Counting::default());
    let b = Arc::new(store("doc1", &metrics).with_coordinator(bus()));
    let source = ScriptedSource::new(vec![Step::Serve(gen_bundle("doc2", 5))]);
    let _follower = b
        .follow_reloads(source.clone(), Duration::from_millis(50))
        .await
        .unwrap();
    eventually("generation 5 is applied", || {
        b.policy_digest() == Some(digest_of("doc2"))
    })
    .await;

    source.replace(vec![Step::Serve(VersionedBundle::new(bundle("doc1")))]);
    eventually("an unversioned bundle is applied", || {
        b.policy_digest() == Some(digest_of("doc1"))
    })
    .await;
}

#[tokio::test]
async fn a_local_reload_not_written_to_the_source_is_replaced_by_the_sources_bundle() {
    let metrics = Arc::new(Counting::default());
    let b = Arc::new(store("doc1", &metrics).with_coordinator(bus()));
    let source = ScriptedSource::new(vec![Step::Serve(VersionedBundle::new(bundle("doc1")))]);
    let _follower = b
        .follow_reloads(source, Duration::from_millis(50))
        .await
        .unwrap();

    b.reload_policies(&permit("doc2"), SCHEMA).await.unwrap();

    // The source is the truth a follower converges on, so the local set
    // lasts until the next read.
    eventually("the source's bundle comes back", || {
        b.policy_digest() == Some(digest_of("doc1"))
    })
    .await;
}
