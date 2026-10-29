use super::*;
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

/// Construct a guest (unauthenticated) `AuthSession` for unit tests,
/// through the `pub(crate)` `SessionInner` / `SessionHandle`.
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
    let cached = MokaEntityCache::new(CountingProvider {
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

/// `invalidate_principal` must evict; without invalidation closures
/// enabled on the builder, moka answers `InvalidationClosuresDisabled`
/// and a revoked role keeps authorizing until the TTL.
#[tokio::test]
async fn invalidate_principal_evicts_that_principals_entries() {
    let calls = Arc::new(AtomicUsize::new(0));
    let cached = MokaEntityCache::new(CountingProvider {
        calls: calls.clone(),
    });
    let s = guest_session();
    let p = principal();
    let a = action();
    let r = doc("doc-1");

    let _ = cached.entities_for(&s, &p, &r, &a).await.unwrap();
    let _ = cached.entities_for(&s, &p, &r, &a).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    cached
        .invalidate_principal(&p)
        .expect("invalidation closures are enabled on the builder");
    // moka applies closure invalidation on its housekeeping pass.
    cached.cache.run_pending_tasks().await;

    let _ = cached.entities_for(&s, &p, &r, &a).await.unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "after invalidate_principal the next call must re-invoke inner"
    );
}

#[tokio::test]
async fn invalidate_evicts_cached_entry() {
    let calls = Arc::new(AtomicUsize::new(0));
    let cached = MokaEntityCache::new(CountingProvider {
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
    cached.invalidate(&p, None, &r, &a).await;

    let _ = cached.entities_for(&s, &p, &r, &a).await.unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "after invalidate, next call should re-invoke inner"
    );
}

#[tokio::test]
async fn invalidate_all_evicts_every_entry() {
    let calls = Arc::new(AtomicUsize::new(0));
    let cached = MokaEntityCache::new(CountingProvider {
        calls: calls.clone(),
    });
    let s = guest_session();
    let p = principal();
    let a = action();
    let r1 = doc("doc-1");
    let r2 = doc("doc-2");

    let _ = cached.entities_for(&s, &p, &r1, &a).await.unwrap();
    let _ = cached.entities_for(&s, &p, &r2, &a).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    let _ = cached.entities_for(&s, &p, &r1, &a).await.unwrap();
    let _ = cached.entities_for(&s, &p, &r2, &a).await.unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "warmed entries must hit cache"
    );

    cached.invalidate_all();
    // moka's `invalidate_all` is best-effort/lazy; pending invalidations
    // are flushed by `run_pending_tasks` so the assertion is deterministic.
    cached.cache.run_pending_tasks().await;

    let _ = cached.entities_for(&s, &p, &r1, &a).await.unwrap();
    let _ = cached.entities_for(&s, &p, &r2, &a).await.unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        4,
        "after invalidate_all, every entry must re-invoke inner; \
         killing the `()` no-op mutation on invalidate_all"
    );
}

/// A provider whose build can be held open, and whose entities depend on
/// session state named by an optional cache discriminator.
struct GatedProvider {
    calls: Arc<AtomicUsize>,
    discriminator: Option<Arc<std::sync::Mutex<String>>>,
    started: Arc<tokio::sync::Notify>,
    release: Option<Arc<tokio::sync::Notify>>,
}

impl RequestEntityProvider for GatedProvider {
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
            if let Some(release) = &self.release {
                self.started.notify_one();
                release.notified().await;
            }
            let p = cedar_policy::Entity::new(
                principal.clone(),
                std::collections::HashMap::new(),
                HashSet::new(),
            )
            .unwrap();
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
        let value = self
            .discriminator
            .as_ref()
            .map(|d| d.lock().unwrap().clone());
        Box::pin(async move { value })
    }
}

fn gated(discriminator: Option<Arc<std::sync::Mutex<String>>>) -> GatedProvider {
    GatedProvider {
        calls: Arc::new(AtomicUsize::new(0)),
        discriminator,
        started: Arc::new(tokio::sync::Notify::new()),
        release: None,
    }
}

#[tokio::test]
async fn a_cache_discriminator_separates_sessions_of_one_user() {
    let state = Arc::new(std::sync::Mutex::new("mfa=1".to_string()));
    let provider = gated(Some(state.clone()));
    let calls = provider.calls.clone();
    let cached = MokaEntityCache::new(provider);
    let (s, p, a, r) = (guest_session(), principal(), action(), doc("d"));

    cached.entities_for(&s, &p, &r, &a).await.unwrap();
    cached.entities_for(&s, &p, &r, &a).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    *state.lock().unwrap() = "mfa=0".to_string();
    cached.entities_for(&s, &p, &r, &a).await.unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "another state, another entry"
    );
}

#[tokio::test]
async fn a_load_in_flight_during_an_invalidation_is_not_served_afterwards() {
    let mut provider = gated(None);
    let release = Arc::new(tokio::sync::Notify::new());
    provider.release = Some(release.clone());
    let (calls, started) = (provider.calls.clone(), provider.started.clone());
    let cached = MokaEntityCache::new(provider);
    let (s, p, a, r) = (guest_session(), principal(), action(), doc("d"));

    let load = cached.entities_for(&s, &p, &r, &a);
    let invalidate = async {
        started.notified().await;
        cached.invalidate_principal(&p).unwrap();
        release.notify_one();
    };
    let (loaded, ()) = tokio::join!(load, invalidate);
    loaded.unwrap();

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
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the stale load was not reused"
    );
}

#[tokio::test]
async fn invalidate_resource_drops_the_resource_for_every_principal() {
    let provider = gated(None);
    let calls = provider.calls.clone();
    let cached = MokaEntityCache::new(provider);
    let (s, a) = (guest_session(), action());
    let alice = principal();
    let bob = EntityUid::from_str("App::User::\"bob\"").unwrap();
    let (d1, d2) = (doc("d1"), doc("d2"));
    for (who, res) in [(&alice, &d1), (&bob, &d1), (&alice, &d2)] {
        cached.entities_for(&s, who, res, &a).await.unwrap();
    }
    cached.invalidate_resource(&d1).unwrap();
    for (who, res) in [(&alice, &d1), (&bob, &d1), (&alice, &d2)] {
        cached.entities_for(&s, who, res, &a).await.unwrap();
    }
    assert_eq!(calls.load(Ordering::SeqCst), 5);
}
