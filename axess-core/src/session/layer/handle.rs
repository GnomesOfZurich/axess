//! Per-request session handle injected into request extensions.
//!
//! `SessionHandle` wraps the mutable `SessionInner` in an `Arc<RwLock>`
//! so the inner service and the outer middleware share a single source
//! of truth. The handle is the only thing extractors take by reference;
//! `SessionInner` itself stays `pub(crate)` so external code can only
//! reach it through the typed `AuthSession` extractor surface.

use crate::session::data::SessionData;
use crate::session::id::SessionId;
use axess_rng::SystemRng;
use std::sync::Arc;
use tokio::sync::RwLock;

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
}

impl SessionInner {
    /// Mint a new session id, swap it into `self.id`, and stash the old id
    /// in `pre_cycle_id` (idempotent: only stashes the very first time).
    /// Sets `regenerate = true` so the layer knows to call `store.cycle` on
    /// the way out instead of `store.save`.
    pub(crate) fn rotate_id(&mut self) {
        let rng = SystemRng;
        let new_id = SessionId::new(&rng);
        if self.pre_cycle_id.is_none() {
            self.pre_cycle_id = Some(self.id);
        }
        self.id = new_id;
        self.regenerate = true;
    }
}
