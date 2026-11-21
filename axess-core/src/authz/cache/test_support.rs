//! Fixtures shared by the entity cache tests, the in-process tier's and the
//! Valkey tier's alike: an entity UID from its literal, a guest session, and
//! a provider that counts its builds. One copy here, so the test files of
//! both tiers stay on their assertions.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use cedar_policy::{Entities, Entity, EntityUid};

use crate::authz::error::AuthzError;
use crate::authz::provider::RequestEntityProvider;
use crate::session::AuthSession;

/// The entity UID spelled `s`, such as `App::User::"alice"`.
pub(super) fn uid(s: &str) -> EntityUid {
    EntityUid::from_str(s).expect("an entity UID literal")
}

/// A guest (unauthenticated) session. Reaches into the `pub(crate)`
/// `SessionInner` and `SessionHandle`, so it serves tests inside axess-core
/// only.
pub(super) fn guest_session() -> AuthSession {
    use crate::session::layer::{SessionHandle, SessionInner};
    use tokio::sync::RwLock;

    let inner = SessionInner::detached(Arc::new(axess_rng::SystemRng));
    AuthSession(SessionHandle(Arc::new(RwLock::new(inner))))
}

/// A provider that counts its builds in `calls` and builds the principal
/// and the resource as entities with no attributes and no parents, so a
/// test reads a cache hit or miss off the count.
#[derive(Default)]
pub(super) struct CountingProvider {
    /// The number of entity sets built so far.
    pub(super) calls: Arc<AtomicUsize>,
}

impl RequestEntityProvider for CountingProvider {
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
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let entity = |uid: &EntityUid| {
                Entity::new(uid.clone(), HashMap::new(), HashSet::new())
                    .expect("an entity with no attributes")
            };
            Ok(
                Entities::from_entities([entity(principal), entity(resource)], None)
                    .expect("two distinct entities"),
            )
        })
    }
}
