//! Per-request session handle injected into request extensions.
//!
//! `SessionHandle` wraps the mutable `SessionInner` in an `Arc<RwLock>`
//! so the inner service and the outer middleware share a single source
//! of truth. The handle is the only thing extractors take by reference;
//! `SessionInner` itself stays `pub(crate)` so external code can only
//! reach it through the typed `AuthSession` extractor surface.

use crate::session::data::SessionData;
use crate::session::id::SessionId;
use crate::session::store::{ConditionalUpdate, SessionStore};
use axess_rng::SecureRng;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// How often a consumption retries after losing a compare-and-swap to a
/// concurrent write that left the value in place.
const CONSUME_ATTEMPTS: usize = 3;

/// The two store operations a handler-time consumption needs, erased so the
/// per-request state does not carry the store's type.
pub(crate) trait ErasedSessionStore: Send + Sync {
    fn load<'a>(
        &'a self,
        id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = Result<Option<SessionData>, String>> + Send + 'a>>;

    fn update_if_revision<'a>(
        &'a self,
        id: &'a SessionId,
        expected_revision: u64,
        data: &'a SessionData,
        ttl: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<ConditionalUpdate, String>> + Send + 'a>>;
}

impl<S: SessionStore> ErasedSessionStore for S {
    fn load<'a>(
        &'a self,
        id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = Result<Option<SessionData>, String>> + Send + 'a>> {
        Box::pin(async move {
            SessionStore::load(self, id)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn update_if_revision<'a>(
        &'a self,
        id: &'a SessionId,
        expected_revision: u64,
        data: &'a SessionData,
        ttl: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<ConditionalUpdate, String>> + Send + 'a>> {
        Box::pin(async move {
            SessionStore::update_if_revision(self, id, expected_revision, data, ttl)
                .await
                .map_err(|e| e.to_string())
        })
    }
}

/// The per-request session handle injected into request extensions.
///
/// This is an internal type; handlers access the session through [`AuthSession`].
///
/// [`AuthSession`]: crate::session::extractor::AuthSession
#[derive(Clone)]
pub(crate) struct SessionHandle(pub(crate) Arc<RwLock<SessionInner>>);

/// Mutable inner state of a session for a single request.
pub(crate) struct SessionInner {
    /// The session's ID. Mutated in-place by state-transition methods that
    /// require a post-rotation id to be visible to the handler (so handler
    /// code that registers the session in `SessionRegistry` keys against
    /// the id the client will actually carry on its next request).
    pub id: SessionId,
    /// The typed session payload.
    pub data: SessionData,
    /// Set to `true` when any field of `data` is changed; triggers a save on response.
    pub(crate) modified: bool,
    /// Set to `true` when something needs this session to exist beyond the
    /// request even though its payload is unchanged: the CSRF layer minted a
    /// token bound to the id, or a handler read the id to key something on it.
    /// A request that arrived without a session cookie persists its fresh
    /// session and sets a cookie only when this or `modified` is set; any
    /// modification implies it.
    pub(crate) needs_persist: bool,
    /// Set to `true` when the session id has been cycled (or must be cycled
    /// even though the payload is unchanged, e.g. binding-mismatch reset).
    /// Triggers a `store.cycle(pre_cycle_id, id, ...)` on response.
    pub(crate) regenerate: bool,
    /// The id the session held when this request started, captured the first
    /// time a state-transition mints a new id. The layer reads this on the
    /// way out so it knows which row to invalidate when calling
    /// [`SessionStore::cycle`](crate::session::store::SessionStore::cycle).
    /// `None` means no rotation happened; the id in `id` is unchanged from
    /// request entry.
    pub(crate) pre_cycle_id: Option<SessionId>,
    /// Pre-computed binding fingerprint from the current request.
    ///
    /// Set by the layer before the handler runs. Extractor methods that
    /// transition the session to `Authenticated` apply this immediately,
    /// ensuring the fingerprint is bound before the response leaves the server.
    pub(crate) pending_fingerprint: Option<String>,
    /// Maximum custom data size (bytes). Mirrors `SessionConfig::max_custom_bytes`
    /// so `set_custom` can enforce the limit eagerly.
    pub(crate) max_custom_bytes: usize,
    /// Source of the ids minted by [`rotate_id`](Self::rotate_id); the
    /// layer shares its own RNG here so a seeded RNG drives every id.
    pub(crate) rng: Arc<dyn SecureRng>,
    /// Where the session is stored, for the compare-and-swap that makes a
    /// consumed value single-use across requests. `None` for a handle built
    /// without a layer, whose values live in memory only.
    pub(crate) consume: Option<ConsumeTarget>,
}

/// The stored row of a session, as far as a handler-time consumption needs it.
#[derive(Clone)]
pub(crate) struct ConsumeTarget {
    pub(crate) store: Arc<dyn ErasedSessionStore>,
    /// Lifetime given to a row written by a consumption.
    pub(crate) ttl: Duration,
    /// `true` when a row for this session is stored (the request arrived
    /// with a session the layer trusted). It lives under the id the session
    /// held at request entry, whatever rotation happened since.
    pub(crate) row_stored: bool,
}

impl SessionHandle {
    /// Record that this session must outlive the request: see
    /// [`SessionInner::needs_persist`].
    pub(crate) async fn mark_needs_persist(&self) {
        self.0.write().await.needs_persist = true;
    }
}

impl SessionInner {
    /// The id the stored row sits under, when there is one.
    fn row_id(&self) -> Option<SessionId> {
        self.consume
            .as_ref()
            .is_some_and(|c| c.row_stored)
            .then(|| self.pre_cycle_id.unwrap_or(self.id))
    }

    /// Remove `key` from the custom bag and return its value, so that of any
    /// number of requests holding the same session exactly one gets it.
    ///
    /// A value held in memory only (a guest session nothing has stored yet,
    /// or a handle without a layer) is simply removed. For a stored session
    /// the removal is first written to the store as a compare-and-swap on the
    /// session's revision: the request that wins gets the value, one that
    /// loses re-reads the row and gets `None` when the value is already gone
    /// (or retries when a concurrent write left it in place). A store that
    /// cannot answer, or a session ended meanwhile, gives `None`: failing
    /// closed means a one-shot ceremony has to be started again, never that
    /// it runs twice.
    pub(crate) async fn consume_custom(&mut self, key: &str) -> Option<serde_json::Value> {
        let value = self.data.custom.as_object_mut()?.remove(key)?;
        self.modified = true;
        let (Some(target), Some(row)) = (self.consume.clone(), self.row_id()) else {
            return Some(value);
        };
        let ConsumeTarget { store, ttl, .. } = target;
        for _ in 0..CONSUME_ATTEMPTS {
            let mut next = self.data.clone();
            next.revision = next.revision.wrapping_add(1);
            let swapped = store
                .update_if_revision(&row, self.data.revision, &next, ttl)
                .await;
            match swapped {
                Ok(ConditionalUpdate::Written) => {
                    self.data.revision = next.revision;
                    return Some(value);
                }
                Ok(ConditionalUpdate::Gone) => return None,
                Ok(ConditionalUpdate::Conflict) => match store.load(&row).await {
                    Ok(Some(fresh)) if fresh.custom.get(key).is_some() => {
                        self.data.revision = fresh.revision;
                    }
                    Ok(_) => return None,
                    Err(e) => {
                        tracing::warn!(error = %e, "re-reading a session after a conflict failed; the value is not handed out");
                        return None;
                    }
                },
                Err(e) => {
                    tracing::warn!(error = %e, "consuming session state failed; the value is not handed out");
                    return None;
                }
            }
        }
        None
    }

    /// Mint a new session id, swap it into `self.id`, and stash the old id
    /// in `pre_cycle_id` (idempotent: only stashes the very first time).
    /// Sets `regenerate = true` so the layer knows to call `store.cycle` on
    /// the way out instead of `store.save`.
    pub(crate) fn rotate_id(&mut self) {
        let new_id = SessionId::new(&*self.rng);
        if self.pre_cycle_id.is_none() {
            self.pre_cycle_id = Some(self.id);
        }
        self.id = new_id;
        self.regenerate = true;
    }
}
