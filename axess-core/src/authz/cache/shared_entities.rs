//! The caching decorators hand out the cached entity set without copying
//! it, and concurrent cold misses share one inner-provider call.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use cedar_policy::{Entities, Entity, EntityUid};

use super::EntityCache;
use crate::authz::error::AuthzError;
use crate::authz::provider::RequestEntityProvider;
use crate::session::AuthSession;

/// Builds a two-entity set after a short delay, counting its calls.
struct SlowProvider {
    calls: Arc<AtomicUsize>,
}

impl RequestEntityProvider for SlowProvider {
    fn entities_for<'a>(
        &'a self,
        _session: &'a AuthSession,
        principal: &'a EntityUid,
        resource: &'a EntityUid,
        _action: &'a EntityUid,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Entities, AuthzError>> + Send + 'a>,
    > {
        let calls = self.calls.clone();
        let (principal, resource) = (principal.clone(), resource.clone());
        Box::pin(async move {
            calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(50)).await;
            let entity = |uid| Entity::new(uid, HashMap::new(), HashSet::new()).unwrap();
            Ok(Entities::from_entities([entity(principal), entity(resource)], None).unwrap())
        })
    }
}

fn session() -> AuthSession {
    use crate::session::SessionData;
    use crate::session::id::SessionId;
    use crate::session::layer::{SessionHandle, SessionInner};
    use tokio::sync::RwLock;
    AuthSession(SessionHandle(Arc::new(RwLock::new(SessionInner {
        id: SessionId::new(&axess_rng::SystemRng),
        data: SessionData::default(),
        modified: false,
        needs_persist: false,
        regenerate: false,
        pre_cycle_id: None,
        rng: std::sync::Arc::new(axess_rng::SystemRng),
        pending_fingerprint: None,
        max_custom_bytes: 64 * 1024,
    }))))
}

fn uid(s: &str) -> EntityUid {
    EntityUid::from_str(s).unwrap()
}

#[tokio::test]
async fn entity_cache_hits_return_the_same_allocation() {
    let calls = Arc::new(AtomicUsize::new(0));
    let cache = EntityCache::new(SlowProvider {
        calls: calls.clone(),
    });
    let (s, p, r, a) = (
        session(),
        uid("App::User::\"alice\""),
        uid("App::Doc::\"d\""),
        uid("App::Action::\"View\""),
    );
    let first = cache.shared_entities_for(&s, &p, &r, &a).await.unwrap();
    let second = cache.shared_entities_for(&s, &p, &r, &a).await.unwrap();
    assert!(Arc::ptr_eq(&first, &second), "a hit must not copy the set");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // The by-value method still serves the same data.
    let owned = cache.entities_for(&s, &p, &r, &a).await.unwrap();
    assert_eq!(owned.iter().count(), first.iter().count());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "moka-cache")]
#[tokio::test]
async fn moka_concurrent_misses_share_one_inner_call() {
    use super::MokaEntityCache;
    let calls = Arc::new(AtomicUsize::new(0));
    let cache = Arc::new(MokaEntityCache::new(SlowProvider {
        calls: calls.clone(),
    }));
    let (p, r, a) = (
        uid("App::User::\"alice\""),
        uid("App::Doc::\"d\""),
        uid("App::Action::\"View\""),
    );
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (cache, p, r, a) = (cache.clone(), p.clone(), r.clone(), a.clone());
        tasks.push(tokio::spawn(async move {
            let s = session();
            cache.shared_entities_for(&s, &p, &r, &a).await.unwrap()
        }));
    }
    let mut sets = Vec::new();
    for t in tasks {
        sets.push(t.await.unwrap());
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "one load for eight callers"
    );
    assert!(sets.windows(2).all(|w| Arc::ptr_eq(&w[0], &w[1])));
}
