//! `tests`: extracted from `entity_cache.rs` per the
//! 200-LoC inline-test rule in AGENTS.md.

use super::*;
use axess_clock::testing::MockClock;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Counts inner-provider calls so the test can verify cache hits/misses.
struct CountingProvider {
    calls: Arc<AtomicUsize>,
}

impl RequestEntityProvider for CountingProvider {
    fn entities_for<'a>(
        &'a self,
        session: &'a AuthSession,
        principal: &'a EntityUid,
        resource: &'a EntityUid,
        action: &'a EntityUid,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Entities, AuthzError>> + Send + 'a>,
    > {
        // Synthetic counting fixture; doesn't need session/action; explicit
        // acknowledgment per the axess no-`_`-prefix convention.
        let _ = (session, action);
        let calls = self.calls.clone();
        let principal = principal.clone();
        let resource = resource.clone();
        Box::pin(async move {
            calls.fetch_add(1, Ordering::SeqCst);
            let p = cedar_policy::Entity::new(
                principal,
                std::collections::HashMap::new(),
                HashSet::new(),
            )
            .unwrap();
            let r = cedar_policy::Entity::new(
                resource,
                std::collections::HashMap::new(),
                HashSet::new(),
            )
            .unwrap();
            Ok(Entities::from_entities(vec![p, r], None).unwrap())
        })
    }
}

/// Construct a guest (unauthenticated) `AuthSession` for unit tests.
/// Reaches into `pub(crate)` `SessionInner` / `SessionHandle`: usable
/// only from inside axess-core; mirrors the pattern in
/// `session::extractor::tests::make_session`.
fn guest_session() -> AuthSession {
    use crate::session::SessionData;
    use crate::session::id::SessionId;
    use crate::session::layer::{SessionHandle, SessionInner};
    use tokio::sync::RwLock;

    let inner = SessionInner {
        id: SessionId::new(&axess_rng::SystemRng),
        data: SessionData::default(),
        modified: false,
        needs_persist: false,
        regenerate: false,
        pre_cycle_id: None,
        rng: std::sync::Arc::new(axess_rng::SystemRng),
        pending_fingerprint: None,
        max_custom_bytes: 64 * 1024,
        consume: None,
    };
    AuthSession(SessionHandle(Arc::new(RwLock::new(inner))))
}

fn principal() -> EntityUid {
    EntityUid::from_str("App::User::\"alice\"").unwrap()
}
fn action() -> EntityUid {
    EntityUid::from_str("App::Action::\"View\"").unwrap()
}
fn doc(id: &str) -> EntityUid {
    EntityUid::from_str(&format!("App::Doc::\"{id}\"")).unwrap()
}

#[tokio::test]
async fn first_call_misses_then_caches() {
    let calls = Arc::new(AtomicUsize::new(0));
    let cached = EntityCache::new(CountingProvider {
        calls: calls.clone(),
    });
    let s = guest_session();
    let p = principal();
    let a = action();
    let r1 = doc("doc-1");

    let _ = cached.entities_for(&s, &p, &r1, &a).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let _ = cached.entities_for(&s, &p, &r1, &a).await.unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "cache hit should not invoke inner"
    );

    let r2 = doc("doc-2");
    let _ = cached.entities_for(&s, &p, &r2, &a).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn invalidate_evicts_cached_entry() {
    let calls = Arc::new(AtomicUsize::new(0));
    let cached = EntityCache::new(CountingProvider {
        calls: calls.clone(),
    });
    let s = guest_session();
    let p = principal();
    let a = action();
    let r = doc("doc-1");

    let _ = cached.entities_for(&s, &p, &r, &a).await.unwrap();
    let _ = cached.entities_for(&s, &p, &r, &a).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Guest session has no tenant_id, so invalidation key uses tenant=None.
    cached.invalidate(&p, None, &r, &a);

    let _ = cached.entities_for(&s, &p, &r, &a).await.unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "after invalidate, next call should re-invoke inner"
    );
}

/// Pin the single-flight property at the entity-cache layer:
/// concurrent cold-miss callers for the same key share one inner
/// provider call rather than fan out to N parallel DB hits. This
/// is what `ClockTtlCache::get_or_try_insert_with` enables: the
/// previous (moka-backed, no single-flight) implementation would
/// have called the inner provider N times.
#[tokio::test]
async fn concurrent_cold_misses_share_one_inner_call() {
    let calls = Arc::new(AtomicUsize::new(0));
    let cached = Arc::new(EntityCache::new(CountingProvider {
        calls: calls.clone(),
    }));
    let p = principal();
    let a = action();
    let r = doc("doc-1");

    const N: usize = 8;
    let mut handles = Vec::with_capacity(N);
    for _ in 0..N {
        let cached = cached.clone();
        let p = p.clone();
        let a = a.clone();
        let r = r.clone();
        // Each task constructs its own session; guest_session() is
        // only callable inside the test module.
        let s = guest_session();
        handles.push(tokio::spawn(async move {
            cached.entities_for(&s, &p, &r, &a).await.map(|_| ())
        }));
    }
    for h in handles {
        h.await.unwrap().unwrap();
    }

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "single-flight must collapse N concurrent cold misses into 1 inner call"
    );
}

/// Pin the DST property: with an injected MockClock, advancing time
/// past the TTL must cause the next call to re-invoke the inner
/// provider. This is the test that would have failed under the
/// previous moka-backed implementation (moka uses wall-clock time
/// internally; advancing `MockClock` had no effect on its eviction).
#[tokio::test]
async fn entries_expire_under_injected_clock() {
    let clock = Arc::new(MockClock::now());
    let calls = Arc::new(AtomicUsize::new(0));
    let cached = EntityCache::with_options(
        CountingProvider {
            calls: calls.clone(),
        },
        DEFAULT_CAPACITY,
        Duration::from_secs(60),
        clock.clone() as Arc<dyn Clock>,
    );

    let s = guest_session();
    let p = principal();
    let a = action();
    let r = doc("doc-1");

    let _ = cached.entities_for(&s, &p, &r, &a).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Inside TTL; cache hit.
    clock.advance_secs(30);
    let _ = cached.entities_for(&s, &p, &r, &a).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1, "still inside TTL");

    // Past TTL; cache miss, inner re-invoked.
    clock.advance_secs(31);
    let _ = cached.entities_for(&s, &p, &r, &a).await.unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "TTL expired under MockClock; must re-fetch from inner"
    );
}

/// Each fluent setter carries the others' settings: `.with_ttl(5s)
/// .with_capacity(100)` means both, not a capacity with the default TTL.
#[test]
fn fluent_setters_keep_each_others_settings() {
    let cached = EntityCache::new(CountingProvider {
        calls: Arc::new(AtomicUsize::new(0)),
    })
    .with_ttl(std::time::Duration::from_secs(5))
    .with_capacity(100);
    assert_eq!(cached.ttl, std::time::Duration::from_secs(5));
    assert_eq!(cached.capacity, 100);
    let clocked = cached.with_clock(Arc::new(MockClock::at(chrono::Utc::now())));
    assert_eq!(clocked.ttl, std::time::Duration::from_secs(5));
    assert_eq!(clocked.capacity, 100);
}

/// Counts calls into the metrics sink and the totals they carried.
#[derive(Default)]
struct BatchMetrics {
    calls: AtomicUsize,
    hits: std::sync::atomic::AtomicU64,
}

impl crate::metrics::AuthnMetrics for BatchMetrics {
    fn authz_cache_hits(&self, count: u64) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.hits.fetch_add(count, Ordering::SeqCst);
    }
    fn authz_cache_misses(&self, _: u64) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
    fn authz_cache_evictions(&self, _: u64) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
    fn authz_cache_invalidations(&self, _: u64) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

/// A flush reports each counter in one call whatever the window's total.
#[tokio::test]
async fn flush_metrics_reports_totals_in_one_call_per_counter() {
    let cached = EntityCache::new(CountingProvider {
        calls: Arc::new(AtomicUsize::new(0)),
    });
    let (s, p, a, r) = (guest_session(), principal(), action(), doc("d"));
    for _ in 0..501 {
        cached.entities_for(&s, &p, &r, &a).await.unwrap();
    }
    let sink = BatchMetrics::default();
    cached.flush_metrics(&sink);
    assert_eq!(sink.hits.load(Ordering::SeqCst), 500);
    assert_eq!(sink.calls.load(Ordering::SeqCst), 4);
}

/// An implementation of the per-event methods alone still sees every event.
#[test]
fn per_event_metrics_implementations_receive_batched_totals() {
    use crate::metrics::AuthnMetrics;
    #[derive(Default)]
    struct PerEvent(AtomicUsize);
    impl AuthnMetrics for PerEvent {
        fn authz_cache_hit(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let sink = PerEvent::default();
    sink.authz_cache_hits(7);
    assert_eq!(sink.0.load(Ordering::SeqCst), 7);
}

/// A provider whose entities depend on session state it names in its cache
/// discriminator, and whose build can be held open to let an invalidation
/// run while it is in flight.
struct SessionAwareProvider {
    calls: Arc<AtomicUsize>,
    mfa: Arc<std::sync::atomic::AtomicBool>,
    named: bool,
    started: Arc<tokio::sync::Notify>,
    release: Option<Arc<tokio::sync::Notify>>,
}

impl SessionAwareProvider {
    fn new(named: bool) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            mfa: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            named,
            started: Arc::new(tokio::sync::Notify::new()),
            release: None,
        }
    }
}

impl RequestEntityProvider for SessionAwareProvider {
    fn entities_for<'a>(
        &'a self,
        session: &'a AuthSession,
        principal: &'a EntityUid,
        resource: &'a EntityUid,
        action: &'a EntityUid,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Entities, AuthzError>> + Send + 'a>,
    > {
        let _ = (session, action);
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            // The state is read when the build starts, as a provider that
            // reads the session would.
            let mfa = self.mfa.load(Ordering::SeqCst);
            if let Some(release) = &self.release {
                self.started.notify_one();
                release.notified().await;
            }
            let attrs = std::collections::HashMap::from([(
                "mfa".to_string(),
                cedar_policy::RestrictedExpression::new_bool(mfa),
            )]);
            let p = cedar_policy::Entity::new(principal.clone(), attrs, HashSet::new()).unwrap();
            let r = cedar_policy::Entity::new(
                resource.clone(),
                std::collections::HashMap::new(),
                HashSet::new(),
            )
            .unwrap();
            Ok(Entities::from_entities(vec![p, r], None).unwrap())
        })
    }

    fn cache_discriminator<'a>(
        &'a self,
        session: &'a AuthSession,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<String>> + Send + 'a>> {
        let _ = session;
        let named = self.named;
        let mfa = self.mfa.load(Ordering::SeqCst);
        Box::pin(async move { named.then(|| format!("mfa={mfa}")) })
    }
}

fn principal_mfa(entities: &Entities, principal: &EntityUid) -> bool {
    matches!(
        entities.get(principal).and_then(|e| e.attr("mfa")),
        Some(Ok(cedar_policy::EvalResult::Bool(true)))
    )
}

/// Without a discriminator the key holds nothing of the session, so the
/// second session is served the first session's entities. This pins the
/// documented limit, not a goal.
#[tokio::test]
async fn session_state_in_entities_is_shared_without_a_discriminator() {
    let provider = SessionAwareProvider::new(false);
    let (calls, mfa) = (provider.calls.clone(), provider.mfa.clone());
    let cached = EntityCache::new(provider);
    let (s, p, a, r) = (guest_session(), principal(), action(), doc("d"));

    mfa.store(true, Ordering::SeqCst);
    let first = cached.entities_for(&s, &p, &r, &a).await.unwrap();
    assert!(principal_mfa(&first, &p));

    mfa.store(false, Ordering::SeqCst);
    let second = cached.entities_for(&s, &p, &r, &a).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(
        principal_mfa(&second, &p),
        "the password-only session reads the MFA session's entities"
    );
}

/// With a discriminator naming the state, the second session gets its own
/// entities.
#[tokio::test]
async fn a_cache_discriminator_separates_sessions_of_one_user() {
    let provider = SessionAwareProvider::new(true);
    let (calls, mfa) = (provider.calls.clone(), provider.mfa.clone());
    let cached = EntityCache::new(provider);
    let (s, p, a, r) = (guest_session(), principal(), action(), doc("d"));

    mfa.store(true, Ordering::SeqCst);
    let first = cached.entities_for(&s, &p, &r, &a).await.unwrap();
    assert!(principal_mfa(&first, &p));

    mfa.store(false, Ordering::SeqCst);
    let second = cached.entities_for(&s, &p, &r, &a).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(
        !principal_mfa(&second, &p),
        "the second session is denied the first one's state"
    );

    // Each state is cached under its own key.
    cached.entities_for(&s, &p, &r, &a).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

/// An invalidation that runs while a load is in flight must not be undone
/// by that load storing its stale result.
#[tokio::test]
async fn a_load_in_flight_during_an_invalidation_is_not_stored() {
    let mut provider = SessionAwareProvider::new(false);
    let release = Arc::new(tokio::sync::Notify::new());
    provider.release = Some(release.clone());
    let (calls, started) = (provider.calls.clone(), provider.started.clone());
    let cached = EntityCache::new(provider);
    let (s, p, a, r) = (guest_session(), principal(), action(), doc("d"));

    let load = cached.entities_for(&s, &p, &r, &a);
    let invalidate = async {
        started.notified().await;
        cached.invalidate_principal(&p);
        release.notify_one();
    };
    let (loaded, ()) = tokio::join!(load, invalidate);
    loaded.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // The stale result was not stored: the next lookup builds again.
    let next = cached.entities_for(&s, &p, &r, &a);
    let release_again = async {
        // A stale entry served from the cache never reaches the provider,
        // so bound the wait: a regression fails instead of hanging.
        let built =
            tokio::time::timeout(std::time::Duration::from_secs(5), started.notified()).await;
        assert!(built.is_ok(), "the stale load was served from the cache");
        release.notify_one();
    };
    let (next, ()) = tokio::join!(next, release_again);
    next.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

/// A resource-scoped invalidation drops the entries of every principal for
/// that resource and leaves other resources alone.
#[tokio::test]
async fn invalidate_resource_drops_every_principals_entry_for_it() {
    let calls = Arc::new(AtomicUsize::new(0));
    let cached = EntityCache::new(CountingProvider {
        calls: calls.clone(),
    });
    let (s, a) = (guest_session(), action());
    let alice = principal();
    let bob = EntityUid::from_str("App::User::\"bob\"").unwrap();
    let (d1, d2) = (doc("d1"), doc("d2"));
    for (who, res) in [(&alice, &d1), (&bob, &d1), (&alice, &d2)] {
        cached.entities_for(&s, who, res, &a).await.unwrap();
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);

    assert_eq!(cached.invalidate_resource(&d1), 2);

    for (who, res) in [(&alice, &d1), (&bob, &d1), (&alice, &d2)] {
        cached.entities_for(&s, who, res, &a).await.unwrap();
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        5,
        "d1 twice rebuilt, d2 still cached"
    );
}
