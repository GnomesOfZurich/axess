#![cfg(all(feature = "testing", feature = "authz"))]
//! Live policy reload: a refused reload leaves the previous set in force, an
//! accepted one decides the next request, caches are dropped, and followers
//! converge from their source.

use axess_core::authz::{
    AuthzEntityProvider, AuthzError, AuthzStore, PolicyStore,
    cache::CacheInvalidator,
    make_entity_uid,
    reload::{InProcessCoordinator, PolicyBundle, PolicySource, ReloadCoordinator, ReloadFuture},
};
use axess_core::metrics::{AuthzCacheMetrics, MetricSinks};
use cedar_policy::{Entities, EntityUid, Schema};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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

/// The same schema without the `Resource` type.
const SCHEMA_WITHOUT_RESOURCE: &str = r#"{
    "App": {
        "entityTypes": { "User": { "memberOfTypes": [] } },
        "actions": {}
    }
}"#;

fn permit(doc: &str) -> String {
    format!(
        r#"permit(principal == App::User::"alice", action == App::Action::"View", resource == App::Resource::"{doc}");"#
    )
}

/// A provider with no entities of its own; it refuses a schema that lacks
/// the `Resource` type, the way a provider built for the old schema would.
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

    fn validate_schema(&self, schema: &Schema) -> Result<(), AuthzError> {
        if schema
            .entity_types()
            .any(|t| AsRef::<str>::as_ref(t.basename()) == "Resource")
        {
            Ok(())
        } else {
            Err(AuthzError::SchemaParse(
                "the provider builds Resource entities; the schema declares none".into(),
            ))
        }
    }
}

fn store_with(policy: &str) -> AuthzStore<Provider> {
    let evaluator = Arc::new(PolicyStore::from_text(policy, SCHEMA).expect("policy"));
    AuthzStore::try_new(evaluator, Arc::new(Provider), "App").expect("store")
}

async fn allowed(store: &Arc<AuthzStore<Provider>>, doc: &str) -> bool {
    store
        .for_user_id("alice")
        .expect("session")
        .is_permitted("View", &doc.to_string())
        .await
}

#[derive(Default)]
struct CountingCache {
    dropped: AtomicUsize,
    fail: AtomicBool,
}

#[derive(Debug, thiserror::Error)]
#[error("cache down")]
struct CacheDown;

impl CacheInvalidator for CountingCache {
    type Error = CacheDown;
    async fn invalidate_principal(&self, _: &EntityUid) -> Result<(), CacheDown> {
        Ok(())
    }
    async fn invalidate_tenant(&self, _: &str) -> Result<(), CacheDown> {
        Ok(())
    }
    async fn invalidate_all(&self) -> Result<(), CacheDown> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(CacheDown);
        }
        self.dropped.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Default)]
struct CountingMetrics {
    reloaded: AtomicUsize,
    refused: AtomicUsize,
}

impl AuthzCacheMetrics for CountingMetrics {
    fn authz_policy_reloaded(&self) {
        self.reloaded.fetch_add(1, Ordering::SeqCst);
    }
    fn authz_policy_reload_refused(&self) {
        self.refused.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn a_reload_with_text_that_does_not_parse_is_refused_and_the_old_set_holds() {
    let store = Arc::new(store_with(&permit("doc1")));
    let before = store.policy_digest();

    let refused = store
        .reload_policies("permit(this is not cedar", SCHEMA)
        .await;

    assert!(
        matches!(refused, Err(AuthzError::PolicyParse(_))),
        "{refused:?}"
    );
    assert!(
        allowed(&store, "doc1").await,
        "the previous set still decides"
    );
    assert_eq!(store.policy_digest(), before);
}

#[tokio::test]
async fn a_reload_that_fails_validation_is_refused_and_the_old_set_holds() {
    let store = Arc::new(store_with(&permit("doc1")));
    // Parses, but names an action the schema does not declare.
    let unknown_action = r#"permit(principal, action == App::Action::"Erase", resource);"#;

    let refused = store.reload_policies(unknown_action, SCHEMA).await;

    assert!(
        matches!(refused, Err(AuthzError::PolicyValidation(_))),
        "{refused:?}"
    );
    assert!(allowed(&store, "doc1").await);
}

#[tokio::test]
async fn a_reload_with_a_schema_the_provider_does_not_fit_is_refused() {
    let store = Arc::new(store_with(&permit("doc1")));

    let refused = store.reload_policies("", SCHEMA_WITHOUT_RESOURCE).await;

    assert!(
        matches!(refused, Err(AuthzError::SchemaParse(_))),
        "{refused:?}"
    );
    assert!(allowed(&store, "doc1").await, "the old set and schema hold");
}

#[tokio::test]
async fn a_reload_with_valid_text_changes_the_next_decision() {
    let store = Arc::new(store_with(&permit("doc1")));
    assert!(allowed(&store, "doc1").await);
    assert!(!allowed(&store, "doc2").await);

    let reloaded = store
        .reload_policies(&permit("doc2"), SCHEMA)
        .await
        .expect("valid set");

    assert!(!allowed(&store, "doc1").await, "the retired grant is gone");
    assert!(allowed(&store, "doc2").await);
    assert_eq!(
        store.policy_digest().as_deref(),
        Some(reloaded.digest.as_str())
    );
    assert!(!reloaded.announced, "no coordinator is set");
}

#[tokio::test]
async fn a_reload_drops_the_registered_caches_and_a_refusal_does_not() {
    let cache = Arc::new(CountingCache::default());
    let metrics = Arc::new(CountingMetrics::default());
    let store = Arc::new(
        store_with(&permit("doc1"))
            .with_cache_invalidator(Arc::clone(&cache))
            .with_metrics(MetricSinks::noop().with_authz_cache(metrics.clone())),
    );

    let ok = store
        .reload_policies(&permit("doc2"), SCHEMA)
        .await
        .unwrap();
    assert!(ok.cache_invalidated);
    assert_eq!(cache.dropped.load(Ordering::SeqCst), 1);

    store
        .reload_policies("garbage (", SCHEMA)
        .await
        .unwrap_err();
    assert_eq!(
        cache.dropped.load(Ordering::SeqCst),
        1,
        "a refusal drops nothing"
    );

    cache.fail.store(true, Ordering::SeqCst);
    let degraded = store
        .reload_policies(&permit("doc3"), SCHEMA)
        .await
        .unwrap();
    assert!(
        !degraded.cache_invalidated,
        "the swap stands, the outcome says so"
    );
    assert!(allowed(&store, "doc3").await);

    assert_eq!(metrics.reloaded.load(Ordering::SeqCst), 2);
    assert_eq!(metrics.refused.load(Ordering::SeqCst), 1);
}

struct FixedSource(Mutex<PolicyBundle>);

impl FixedSource {
    fn new(doc: &str) -> Arc<Self> {
        Arc::new(Self(Mutex::new(bundle(&permit(doc)))))
    }
    fn set(&self, policy: &str) {
        *self.0.lock().unwrap() = bundle(policy);
    }
}

fn bundle(policy: &str) -> PolicyBundle {
    PolicyBundle {
        policy_text: policy.to_string(),
        schema_json: SCHEMA.to_string(),
    }
}

impl PolicySource for FixedSource {
    fn load(&self) -> ReloadFuture<'_, Result<PolicyBundle, AuthzError>> {
        Box::pin(async move { Ok(self.0.lock().unwrap().clone()) })
    }
}

async fn eventually(what: &str, mut check: impl AsyncFnMut() -> bool) {
    for _ in 0..200 {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("did not happen within 2s: {what}");
}

fn coordinator() -> Arc<InProcessCoordinator> {
    Arc::new(InProcessCoordinator::new(NonZeroUsize::new(16).unwrap()))
}

#[tokio::test]
async fn a_notice_makes_a_second_store_re_read_its_source() {
    let bus = coordinator();
    let source = FixedSource::new("doc1");
    let a = Arc::new(store_with(&permit("doc1")).with_coordinator(bus.clone()));
    let b = Arc::new(store_with(&permit("doc1")).with_coordinator(bus.clone()));
    let _follower = b
        .follow_reloads(source.clone(), Duration::from_secs(3600))
        .await
        .expect("follow");

    // The adopter updates the source, then reloads one instance.
    source.set(&permit("doc2"));
    let reloaded = a.reload_policies(&permit("doc2"), SCHEMA).await.unwrap();
    assert!(reloaded.announced);

    eventually("B follows A", async || allowed(&b, "doc2").await).await;
    assert!(!allowed(&b, "doc1").await);
    assert_eq!(b.policy_digest(), a.policy_digest());
}

#[tokio::test]
async fn a_notice_cannot_inject_policy_the_source_does_not_hold() {
    let bus = coordinator();
    let source = FixedSource::new("doc1");
    let b = Arc::new(store_with(&permit("doc1")).with_coordinator(bus.clone()));
    let _follower = b
        .follow_reloads(source.clone(), Duration::from_secs(3600))
        .await
        .unwrap();

    // A notice with a digest nobody holds: the source still says doc1.
    bus.announce("deadbeef").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(allowed(&b, "doc1").await);
    assert!(!allowed(&b, "doc2").await);
}

#[tokio::test]
async fn a_follower_refuses_a_bad_bundle_from_its_source_and_keeps_its_set() {
    let bus = coordinator();
    let source = FixedSource::new("doc1");
    let metrics = Arc::new(CountingMetrics::default());
    let b = Arc::new(
        store_with(&permit("doc1"))
            .with_coordinator(bus.clone())
            .with_metrics(MetricSinks::noop().with_authz_cache(metrics.clone())),
    );
    let _follower = b
        .follow_reloads(source.clone(), Duration::from_secs(3600))
        .await
        .unwrap();

    source.set("permit(broken");
    bus.announce("any").await.unwrap();

    eventually("the refusal is counted", async || {
        metrics.refused.load(Ordering::SeqCst) >= 1
    })
    .await;
    assert!(allowed(&b, "doc1").await);
}

/// A source that counts how often it was read.
struct CountingSource {
    inner: Arc<FixedSource>,
    loads: AtomicUsize,
}

impl PolicySource for CountingSource {
    fn load(&self) -> ReloadFuture<'_, Result<PolicyBundle, AuthzError>> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        self.inner.load()
    }
}

#[tokio::test]
async fn a_follower_whose_receiver_lagged_converges_on_the_source() {
    // Capacity 2; the test runtime is single-threaded, so the follower does
    // not run between the announcements below and its receiver must lag.
    let bus = Arc::new(InProcessCoordinator::new(NonZeroUsize::new(2).unwrap()));
    let fixed = FixedSource::new("doc1");
    let source = Arc::new(CountingSource {
        inner: fixed.clone(),
        loads: AtomicUsize::new(0),
    });
    let b = Arc::new(store_with(&permit("doc1")).with_coordinator(bus.clone()));
    // The poll is an hour away: only a notice can make the follower read again.
    let _follower = b
        .follow_reloads(source.clone(), Duration::from_secs(3600))
        .await
        .unwrap();
    eventually("the follower read the source at start", async || {
        source.loads.load(Ordering::SeqCst) >= 1
    })
    .await;
    let loads_before = source.loads.load(Ordering::SeqCst);

    // A probe subscriber that never reads shows the channel did overflow.
    let mut probe = bus.subscribe().await.unwrap();
    fixed.set(&permit("doc2"));
    for i in 0..8 {
        bus.announce(&format!("notice-{i}")).await.unwrap();
    }
    assert!(
        matches!(
            probe.recv().await,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_))
        ),
        "eight notices into a channel of two must lag a reader that is behind"
    );

    eventually("the lagged follower re-reads and converges", async || {
        allowed(&b, "doc2").await
    })
    .await;
    assert!(!allowed(&b, "doc1").await);
    assert!(source.loads.load(Ordering::SeqCst) > loads_before);
    assert_eq!(b.policy_digest(), Some(bundle(&permit("doc2")).digest()));
}

#[tokio::test]
async fn a_follower_that_missed_the_notice_catches_up_by_its_poll() {
    let bus = coordinator();
    let source = FixedSource::new("doc1");
    let b = Arc::new(store_with(&permit("doc1")).with_coordinator(bus.clone()));
    let _follower = b
        .follow_reloads(source.clone(), Duration::from_millis(50))
        .await
        .unwrap();

    // No announce at all: the notice is lost.
    source.set(&permit("doc2"));

    eventually("the poll applies the source", async || {
        allowed(&b, "doc2").await
    })
    .await;
}

#[tokio::test]
async fn following_without_a_coordinator_or_with_a_zero_poll_is_refused_by_name() {
    let source = FixedSource::new("doc1");
    let bare = Arc::new(store_with(&permit("doc1")));
    let err = bare
        .follow_reloads(source.clone(), Duration::from_secs(1))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("coordinator"), "{err}");

    let wired = Arc::new(store_with(&permit("doc1")).with_coordinator(coordinator()));
    let err = wired
        .follow_reloads(source, Duration::ZERO)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("poll_every"), "{err}");
}

/// Bound: 6 deciding tasks, 4 reloading rounds of 25 swaps between two sets
/// (plus a refused text each round), 500 ms of decisions at least. The
/// document both sets permit is allowed in every decision (a swap that
/// momentarily held no set would deny it), the document neither permits is
/// denied in every decision (a refused or half-built set never decides), and
/// nothing panics.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reloads_racing_decisions_never_expose_a_missing_or_bad_set() {
    let both = |extra: &str| format!("{}\n{}", permit("shared"), permit(extra));
    let store = Arc::new(store_with(&both("only_a")));
    let stop = Arc::new(AtomicBool::new(false));

    let mut deciders = Vec::new();
    for _ in 0..6 {
        let store = Arc::clone(&store);
        let stop = Arc::clone(&stop);
        deciders.push(tokio::spawn(async move {
            let mut decisions = 0u64;
            while !stop.load(Ordering::Relaxed) {
                assert!(
                    allowed(&store, "shared").await,
                    "the shared grant flickered"
                );
                assert!(!allowed(&store, "neither").await, "a grant nobody wrote");
                decisions += 2;
                // Decisions never suspend on their own; without this the
                // deciders would starve the reloading task.
                tokio::task::yield_now().await;
            }
            decisions
        }));
    }

    for _ in 0..4 {
        for i in 0..25 {
            let doc = if i % 2 == 0 { "only_b" } else { "only_a" };
            store
                .reload_policies(&both(doc), SCHEMA)
                .await
                .expect("valid");
        }
        store.reload_policies("permit(", SCHEMA).await.unwrap_err();
        tokio::time::sleep(Duration::from_millis(125)).await;
    }

    stop.store(true, Ordering::Relaxed);
    let mut total = 0;
    for decider in deciders {
        total += decider.await.expect("a decider panicked");
    }
    assert!(total > 0);
    assert!(allowed(&store, "shared").await);
}
