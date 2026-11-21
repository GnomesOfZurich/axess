//! Per-request session handle injected into request extensions.
//!
//! `SessionHandle` wraps the mutable `SessionInner` in an `Arc<RwLock>`
//! so the inner service and the outer middleware share a single source
//! of truth. The handle is the only thing extractors take by reference;
//! `SessionInner` itself stays `pub(crate)` so external code can only
//! reach it through the typed `AuthSession` extractor surface.

use super::audit::{LayerSessionEnded, SessionEndReason};
use super::lifecycle::ended_record;
use super::signing::CookieSession;
use super::swap::{Swap, SwapStore, Swapped, swap_merging};
use crate::authn::ids::{DeviceId, UserId};
use crate::session::data::{SessionData, merge_rotating};
use crate::session::id::SessionKey;
use axess_rng::SecureRng;
use std::sync::Arc;
use std::time::Duration;
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
    /// The session this request runs under. Replaced in place by
    /// state-transition methods that require a post-rotation session to be
    /// visible to the handler (so handler code that registers the session in
    /// `SessionRegistry` names the one the client will actually carry on its
    /// next request).
    pub(crate) session: CookieSession,
    /// The typed session payload.
    pub data: SessionData,
    /// The person at the browser when this request began, for whom its
    /// device was resolved. `None` when the request began with nobody
    /// signed in.
    pub(crate) device_resolved_for: Option<UserId>,
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
    /// Triggers a `store.cycle(pre_cycle, session, ...)` on response.
    pub(crate) regenerate: bool,
    /// The key of the session this request started under, captured the
    /// first time a state-transition mints a new one. The layer reads this
    /// on the way out so it knows which row to invalidate when calling
    /// [`SessionStore::cycle`](crate::session::store::SessionStore::cycle)
    /// and which registry entry to move. `None` means no rotation happened;
    /// `session` is unchanged from request entry.
    pub(crate) pre_cycle: Option<crate::session::id::SessionKey>,
    /// Pre-computed binding fingerprint from the current request.
    ///
    /// Set by the layer before the handler runs. The extractor methods that
    /// move the session out of `Guest` (identifying, the start of a login, a
    /// workflow step, authentication) apply this immediately, ensuring the
    /// fingerprint is bound before the response leaves the server.
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
    /// The entry the registry holds for this session, as far as this
    /// request knows: whose it is and under which key. Set at the load to
    /// the key the request arrived with, when the row it loaded was signed
    /// in; set again by a handler that registers or moves the entry itself.
    /// `None` when nothing is known to be registered.
    pub(crate) registered: Option<(UserId, SessionKey)>,
    /// The layer that built this handle moves the registry entry of a
    /// rotated session as it writes the response.
    pub(crate) layer_moves_registry: bool,
    /// A handler found that the registry no longer holds the stored session
    /// and asked the layer to end it: the record of that ending, for which
    /// the finish claims the row, tells the sink and removes the row.
    pub(crate) owed_ending: Option<LayerSessionEnded>,
}

/// The stored row of a session, as far as a handler-time consumption needs it.
#[derive(Clone)]
pub(crate) struct ConsumeTarget {
    pub(crate) store: Arc<dyn SwapStore>,
    /// Lifetime given to a row written by a consumption.
    pub(crate) ttl: Duration,
    /// The row as this request last saw it stored: as loaded (the request
    /// arrived with a session the layer trusted), then as each write of this
    /// request left it; `None` for a fresh guest. The row lives under the id
    /// the session held at request entry, whatever rotation happened since.
    /// A write that finds the row changed by a concurrent request merges this
    /// request's changes onto the stored row with this as the base (see
    /// [`swap_merging`]), so it must move forward with every write: a value
    /// a merge brought in from another request is not this request's change.
    pub(crate) loaded: Option<SessionData>,
}

impl SessionHandle {
    /// Record that this session must outlive the request: see
    /// [`SessionInner::needs_persist`].
    pub(crate) async fn mark_needs_persist(&self) {
        self.0.write().await.needs_persist = true;
    }
}

impl SessionInner {
    /// Remove `key` from the custom bag and return its value, so that of any
    /// number of requests holding the same session exactly one gets it.
    ///
    /// A value held in memory only (a guest session nothing has stored yet,
    /// or a handle without a layer) is simply removed. For a stored session
    /// the removal is first written to the store as a compare-and-swap on the
    /// session's revision: the request that wins gets the value. One that
    /// loses re-reads the row: when the value is already gone it gets `None`;
    /// when a concurrent write left it in place, the value handed out is the
    /// one stored now (never the copy this request loaded, which another
    /// request may have taken and replaced), and the retry writes the stored
    /// row with this request's own changes merged on top, so the concurrent
    /// write is kept. A store that cannot answer, or a session ended
    /// meanwhile, gives `None`: failing closed means a one-shot ceremony has
    /// to be started again, never that it runs twice.
    pub(crate) async fn consume_custom(&mut self, key: &str) -> Option<serde_json::Value> {
        let value = self.data.custom.as_object_mut()?.remove(key)?;
        self.modified = true;
        // Every write of this request's data holds only what holds for the
        // person at the browser now, as the response's own write does.
        self.drop_not_in_force();
        let Some(ConsumeTarget {
            store,
            ttl,
            loaded: Some(base),
        }) = self.consume.clone()
        else {
            return Some(value);
        };
        // Once the id has rotated, the row under the id the request arrived
        // with is retired and an attacker may know that id: it gets only the
        // removal, on the row as loaded, never this request's data (a login
        // would sit in it). The response stores the data under the new id.
        let rotated = self.pre_cycle.is_some();
        let removal;
        let (local, expected) = if rotated {
            let mut only_removal = base.clone();
            let present = only_removal
                .custom
                .as_object_mut()
                .is_some_and(|c| c.remove(key).is_some());
            if !present {
                // Not stored: the value was set by this request.
                return Some(value);
            }
            removal = only_removal;
            (&removal, base.revision)
        } else {
            (&self.data, self.data.revision)
        };
        let mut taken = Some(value);
        let held = self.pre_cycle.unwrap_or(*self.session.key());
        let swap = Swap {
            row: &held,
            base: Some(&base),
            local,
            expected,
            ttl,
            max_custom_bytes: self.max_custom_bytes,
        };
        // A conflict reads the row again: the value handed out is the one
        // stored now, and none at all when a concurrent request took it.
        let outcome = swap_merging(&*store, swap, |fresh| {
            taken = fresh.custom.as_object_mut().and_then(|c| c.remove(key));
            taken.is_some()
        })
        .await;
        match outcome {
            Ok(Swapped::Written(written)) => {
                if rotated {
                    // The retry merged a concurrent write into `written`.
                    // This request's data, which the response stores under
                    // the new id, learns only what a concurrent request took
                    // (or a value another request consumed would come back),
                    // never what it added: the retired id may be known to an
                    // attacker.
                    self.data = merge_rotating(&base, &self.data, &written);
                } else {
                    self.data = (*written).clone();
                }
                if let Some(target) = self.consume.as_mut() {
                    target.loaded = Some(*written);
                }
                taken
            }
            Ok(Swapped::Gone | Swapped::Conflict | Swapped::Declined) => None,
            Err(e) => {
                tracing::warn!(error = %e, "consuming session state failed; the value is not handed out");
                None
            }
        }
    }

    /// A guest's handle with no layer behind it: a freshly minted session,
    /// default data, no flags, no fingerprint, a custom-data cap of 64 KiB
    /// and no store. A test names the fields it sets and takes the rest
    /// from here, so a field added to the handle is added in one place.
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn detached(rng: Arc<dyn SecureRng>) -> Self {
        Self {
            session: CookieSession::mint(&*rng),
            data: SessionData::default(),
            device_resolved_for: None,
            modified: false,
            needs_persist: false,
            regenerate: false,
            pre_cycle: None,
            pending_fingerprint: None,
            max_custom_bytes: 64 * 1024,
            rng,
            consume: None,
            registered: None,
            layer_moves_registry: false,
            owed_ending: None,
        }
    }

    /// End the session through the layer: the handle becomes a guest's at
    /// once, as `AuthSession::clear` makes it, and the record names the
    /// session as it stood.
    ///
    /// With a loaded row behind the handle the record names the key that row
    /// lives under (the key the request arrived with, whatever was rotated
    /// since); it is owed to the finish, which ends the row through the
    /// ending protocol, and the answer is `None`. Otherwise (a fresh session,
    /// or a handle no layer built) the record names the key the registry
    /// holds the session under, as far as the handle knows, and is returned
    /// for the caller's own sink. A session that was not signed in has no
    /// record.
    pub(crate) fn end_through_layer(
        &mut self,
        reason: SessionEndReason,
    ) -> Option<LayerSessionEnded> {
        let behind = self
            .consume
            .as_ref()
            .is_some_and(|target| target.loaded.is_some());
        let named = if behind {
            self.pre_cycle.unwrap_or(*self.session.key())
        } else {
            self.registered_key()
        };
        let record = ended_record(&self.data, named, reason);
        self.data = SessionData::default();
        self.modified = true;
        self.rotate_id();
        let record = record?;
        if behind {
            self.owed_ending = Some(record);
            return None;
        }
        Some(record)
    }

    /// The key the registry holds the session under, when this request
    /// knows one for `user`.
    pub(crate) fn held_for(&self, user: &UserId) -> Option<SessionKey> {
        self.registered
            .filter(|(holder, _)| holder == user)
            .map(|(_, key)| key)
    }

    /// The key a registry check of this request asks for: the registered
    /// key while its user is the one signed in (authenticated, or in a
    /// step-up), else the session's own key.
    pub(crate) fn registered_key(&self) -> SessionKey {
        self.data
            .auth_state
            .signed_in()
            .and_then(|signed_in| self.held_for(signed_in.user_id))
            .unwrap_or(*self.session.key())
    }

    /// The device this session names while it holds for the person at its
    /// browser: the one judgement every reader of the session's device
    /// asks ([`SessionData::device_in_force`] with
    /// [`device_resolved_for`](Self::device_resolved_for)).
    pub(crate) fn device_in_force(&self) -> Option<DeviceId> {
        self.data.device_in_force(self.device_resolved_for.as_ref())
    }

    /// Drop from the data what does not hold for the person at the browser
    /// now: a key binding made for another person, and a device resolved
    /// for another person. Run before every write of this request's data.
    pub(crate) fn drop_not_in_force(&mut self) {
        self.data.drop_binding_not_in_force();
        let resolved_for = self.device_resolved_for;
        self.data.drop_device_not_in_force(resolved_for.as_ref());
    }

    /// Mint a new session, swap it into `self.session`, and stash the old
    /// one in `pre_cycle` (idempotent: only stashes the very first time).
    /// Sets `regenerate = true` so the layer knows to call `store.cycle` on
    /// the way out instead of `store.save`.
    pub(crate) fn rotate_id(&mut self) {
        let new = CookieSession::mint(&*self.rng);
        if self.pre_cycle.is_none() {
            self.pre_cycle = Some(*self.session.key());
        }
        self.session = new;
        self.regenerate = true;
    }

    /// [`AuthSession::set_custom`](crate::session::AuthSession::set_custom)
    /// for a caller that already holds the session's write lock, so the
    /// write lands in the same critical section as a state change it belongs
    /// with.
    pub(crate) fn set_custom_value(&mut self, key: String, value: serde_json::Value) -> bool {
        // The bag is an object; one that was stored as another JSON type is
        // replaced by an empty object, as `mutate_custom` does, rather than
        // indexed (which panics on an array or a scalar).
        if !self.data.custom.is_object() {
            self.data.custom = serde_json::Value::Object(serde_json::Map::new());
        }
        let limit = self.max_custom_bytes;
        if limit > 0 {
            // Speculatively apply the change, check size, and rollback if over limit.
            let prev = self.data.custom.get(&key).cloned();
            self.data.custom[key.clone()] = value;
            let size = crate::session::data::json_byte_len(&self.data.custom);
            if size > limit {
                // Rollback.
                match prev {
                    Some(v) => self.data.custom[key] = v,
                    None => {
                        if let Some(obj) = self.data.custom.as_object_mut() {
                            obj.remove(&key);
                        }
                    }
                }
                tracing::warn!(
                    size,
                    max = limit,
                    "set_custom rejected; would exceed max_custom_bytes"
                );
                return false;
            }
        } else {
            self.data.custom[key] = value;
        }
        self.modified = true;
        true
    }
}

#[cfg(test)]
mod consume_tests;
