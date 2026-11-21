//! The caching decorators hand out the cached entity set without copying
//! it, and concurrent cold misses share one inner-provider call.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use cedar_policy::{Entities, Entity, EntityUid};

use super::EntityCache;
use super::test_support::{guest_session, uid};
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
        _: &'a AuthSession,
        principal: &'a EntityUid,
        resource: &'a EntityUid,
        _: &'a EntityUid,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Entities, AuthzError>> + Send + 'a>,
    > {
        // The set depends on the principal and the resource alone.
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

#[tokio::test]
async fn entity_cache_hits_return_the_same_allocation() {
    let calls = Arc::new(AtomicUsize::new(0));
    let cache = EntityCache::new(SlowProvider {
        calls: calls.clone(),
    });
    let (s, p, r, a) = (
        guest_session(),
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
