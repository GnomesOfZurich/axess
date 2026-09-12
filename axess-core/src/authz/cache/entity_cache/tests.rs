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
        regenerate: false,
        pre_cycle_id: None,
        pending_fingerprint: None,
        max_custom_bytes: 64 * 1024,
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
