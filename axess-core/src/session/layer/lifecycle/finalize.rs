//! The finalize stage of a request: save, cycle or fail closed for the
//! response, merging this request's changes onto a row a concurrent request
//! wrote, and capping the custom data on whatever is written.

use crate::session::config::SessionConfig;
use crate::session::data::{SessionData, cap_custom, merge_rotating};
use crate::session::id::SessionId;
use crate::session::layer::handle::SessionHandle;
use crate::session::layer::swap::{StoreError, Swap, Swapped, swap_merging};
use crate::session::store::{ConditionalUpdate, CycleOutcome, SessionStore};
use axess_clock::Clock;
use axess_rng::SecureRng;

use super::{FinalizeOutcome, Rotation};

/// Decide save vs cycle vs fail-closed for the response, enforcing the
/// custom-data size cap on whatever is written.
///
/// `existing_id` is the trusted id from [`load_session`](super::load_session)'s outcome:
/// `None` means "no trusted prior session", a fresh guest whose id was
/// already minted safely by `load_session` (never the client's cookie
/// id). Its data is *saved* under that same id; the response cookie
/// carries it unchanged. This is deliberate: a CSRF token minted during
/// the request is HMAC-bound to this id, so minting a *second*, different
/// id for the response cookie here would invalidate that token and 403
/// the next state-changing request (the login POST). Only `guard.regenerate`
/// (handler-side `rotate_id`, or binding invalidation) forces an id change.
///
/// Cycle order matters: the handler-side state-transition methods
/// already minted the new id and stashed the old one in
/// `pre_cycle_id` (see
/// [`SessionInner::rotate_id`](crate::session::layer::handle::SessionInner::rotate_id)).
/// The store's `cycle` then takes `(old, new, data)` so handler code
/// that registered with the new id keys the registry against the
/// post-rotation value. Fallback path for `regenerate` without a
/// stashed `pre_cycle_id` (binding-mismatch reset) mints fresh here.
///
/// Cycle failure: fail closed by clearing the session to Guest and
/// keeping the old id. Keeping the old id + new data would bypass
/// session fixation prevention.
pub(crate) async fn finalize_session<S>(
    store: &S,
    config: &SessionConfig,
    metrics: Option<&crate::metrics::MetricSinks>,
    clock: &dyn Clock,
    handle: &SessionHandle,
    existing_id: Option<SessionId>,
    rng: &dyn SecureRng,
) -> FinalizeOutcome
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    let mut guard = handle.0.write().await;

    // A request without a trusted session persists the fresh guest and sets a
    // cookie only when something needs it (a modification, a CSRF token bound
    // to the id, a handler that read the id); an untouched cookieless request
    // leaves the store empty and the response without `Set-Cookie`.
    let fresh_needed = existing_id.is_none() && (guard.modified || guard.needs_persist);
    // A stored session that only read, and whose row has not been re-armed
    // for half its lifetime, is refreshed so that activity keeps it alive.
    let now = clock.now();
    let touch_due = existing_id.is_some()
        && !guard.modified
        && !guard.regenerate
        && touch_is_due(guard.data.touched_at, now, config.ttl);
    let mut session_changed = guard.modified || guard.regenerate || fresh_needed || touch_due;
    let loaded_revision = guard.data.revision;
    if session_changed {
        // The custom-data cap applies to every write, the idle refresh of
        // loaded data included: data loaded from the store or migrated can be
        // oversized too.
        cap_custom(&mut guard.data.custom, config.max_custom_bytes);
        // Every write moves the revision and the refresh stamp. A write of a
        // stored session that keeps its id is a compare-and-swap on the
        // revision the request loaded (or last wrote), so it sees any
        // intervening write; a rotation replaces the row and the registry
        // entry decides.
        guard.data.revision = guard.data.revision.wrapping_add(1);
        guard.data.touched_at = Some(now);
    }
    if session_changed
        && (guard.regenerate || existing_id.is_none())
        && let Some(m) = metrics
    {
        m.session.session_created();
    }

    let mut rotation = None;
    let final_id = if session_changed {
        if guard.regenerate {
            let cycled = cycle_session(store, config, &mut guard, existing_id, rng).await;
            rotation = cycled.rotation;
            session_changed = cycled.cookie;
            cycled.id
        } else if existing_id.is_some() {
            // The request ran under a stored session: replace it only while
            // it is still stored, and only from the revision it loaded. A
            // delete that landed while the request ran (logout, administrator
            // revocation) is final, and the response does not re-issue a
            // cookie for the ended session. A write that landed meanwhile is
            // merged with this request's changes (see `write_changes`); the
            // idle refresh writes nothing in that case, since the concurrent
            // write re-armed the row.
            let written = if touch_due {
                store
                    .update_if_revision(&guard.id, loaded_revision, &guard.data, config.ttl)
                    .await
                    .map_err(StoreError::from)
            } else {
                write_changes(store, config, &mut guard, loaded_revision).await
            };
            match written {
                Ok(ConditionalUpdate::Written) => {}
                Ok(ConditionalUpdate::Conflict) if touch_due => {}
                Ok(ConditionalUpdate::Conflict) => {
                    tracing::warn!(
                        "concurrent requests kept writing the session; this request's changes are discarded"
                    );
                    session_changed = false;
                }
                Ok(ConditionalUpdate::Gone) => {
                    tracing::info!("session was ended while its request ran; changes discarded");
                    guard.data = SessionData::default();
                    session_changed = false;
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "session store update failed; session changes may be lost"
                    );
                    session_changed = false;
                }
            }
            guard.id
        } else {
            // A fresh guest: `existing_id` is `None`, so its id was minted
            // safely by `load_session` (never the client-supplied cookie id:
            // session fixation is prevented there and, on privilege change, by
            // the `regenerate` branch above). Keeping it, rather than minting
            // a second, different id for the response cookie, is what lets a
            // CSRF token minted *during* this request (bound to the same id)
            // still validate on the client's next request. Minting a fresh id
            // here would orphan both the token and any handler-time work keyed
            // to `guard.id`, and every subsequent state-changing request would
            // 403 until the cookie expired.
            if let Err(e) = store.save(&guard.id, &guard.data, config.ttl).await {
                tracing::warn!(
                    error = %e,
                    "session store save failed; session changes may be lost"
                );
                // No row names this id, so no cookie does either.
                session_changed = false;
            }
            guard.id
        }
    } else {
        guard.id
    };

    FinalizeOutcome {
        final_id,
        session_changed,
        rotation,
    }
}

/// Write a stored session a request changed, as a compare-and-swap on the
/// revision the request loaded (or last wrote), merging onto a row a
/// concurrent request wrote meanwhile ([`swap_merging`]). Without the loaded
/// row to merge from, a conflict discards this request's changes rather than
/// overwrite the other's. The guard's data, and the base of any later write,
/// end up as what was written.
async fn write_changes<S>(
    store: &S,
    config: &SessionConfig,
    guard: &mut tokio::sync::RwLockWriteGuard<'_, crate::session::layer::handle::SessionInner>,
    loaded_revision: u64,
) -> Result<ConditionalUpdate, StoreError>
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    let base = guard.consume.as_ref().and_then(|c| c.loaded.clone());
    let swap = Swap {
        row: &guard.id,
        base: base.as_ref(),
        local: &guard.data,
        expected: loaded_revision,
        ttl: config.ttl,
        max_custom_bytes: config.max_custom_bytes,
    };
    Ok(match swap_merging(store, swap, |_| true).await? {
        Swapped::Written(data) => {
            if let Some(target) = guard.consume.as_mut() {
                target.loaded = Some((*data).clone());
            }
            guard.data = *data;
            ConditionalUpdate::Written
        }
        Swapped::Gone => ConditionalUpdate::Gone,
        Swapped::Conflict | Swapped::Declined => ConditionalUpdate::Conflict,
    })
}

/// Bring a write that landed on the old row while the request ran into the
/// data a rotation carries to the new id, as the write of an unrotated
/// session does ([`swap_merging`]): a one-shot value a concurrent request
/// took stays taken, and what it wrote is kept. A store that cannot answer
/// is an error: without the row there is no telling what was taken, and the
/// rotation fails closed rather than carry a copy that may hold it.
///
/// Returns the revision of the old row the data now stands on, which the
/// rotation checks (`cycle_if_revision`), so a write landing after this read
/// is answered as a conflict and merged on the next round instead of lost.
/// `None` when there is no loaded row to merge from, and so nothing to check.
async fn merge_concurrent_writes<S>(
    store: &S,
    config: &SessionConfig,
    guard: &mut tokio::sync::RwLockWriteGuard<'_, crate::session::layer::handle::SessionInner>,
    old_id: &SessionId,
) -> Result<Option<u64>, StoreError>
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    let Some(base) = guard.consume.as_ref().and_then(|c| c.loaded.clone()) else {
        return Ok(None);
    };
    let fresh = match store.load(old_id).await.map_err(StoreError::from)? {
        Some(fresh) if fresh.revision != base.revision => fresh,
        _ => return Ok(Some(base.revision)),
    };
    let touched_at = guard.data.touched_at.max(fresh.touched_at);
    let mut merged = merge_rotating(&base, &guard.data, &fresh);
    merged.revision = fresh.revision.wrapping_add(1);
    merged.touched_at = touched_at;
    cap_custom(&mut merged.custom, config.max_custom_bytes);
    guard.data = merged;
    // A further round merges onto what was just read, so what it carries over
    // is this request's own change and not the other request's.
    let revision = fresh.revision;
    if let Some(target) = guard.consume.as_mut() {
        target.loaded = Some(fresh);
    }
    Ok(Some(revision))
}

/// How many times a rotation re-reads the old row after a concurrent write
/// beat it to the removal, before it gives up and fails closed.
const CYCLE_ATTEMPTS: usize = 4;

/// What [`cycle_session`] did.
struct Cycled {
    /// The id the response cookie carries, when it carries one.
    id: SessionId,
    /// The registry entry to move, for a session that stayed authenticated.
    rotation: Option<Rotation>,
    /// Whether the response sets a cookie: a row is stored under `id`, or the
    /// client's cookie must be replaced so a retired id is never presented
    /// again.
    cookie: bool,
}

/// Write a rotated session under its new id and retire the old row, failing
/// closed.
async fn cycle_session<S>(
    store: &S,
    config: &SessionConfig,
    guard: &mut tokio::sync::RwLockWriteGuard<'_, crate::session::layer::handle::SessionInner>,
    existing_id: Option<SessionId>,
    rng: &dyn SecureRng,
) -> Cycled
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    let mut rotation = None;
    let old_id = guard.pre_cycle_id.take().unwrap_or_else(|| {
        let prev = guard.id;
        guard.id = SessionId::new(rng);
        prev
    });
    let new_id = guard.id;
    let was_authenticated = guard
        .consume
        .as_ref()
        .and_then(|c| c.loaded.as_ref())
        .is_some_and(|loaded| loaded.auth_state.is_authenticated());
    // A request that ran under a stored session requires that row to
    // still be live: a logout that removed it while the request ran
    // must not be undone by moving the data to the new id.
    let require_old = existing_id.is_some();
    let mut cycled: Result<CycleOutcome, StoreError> = Ok(CycleOutcome::Conflict);
    for _ in 0..CYCLE_ATTEMPTS {
        let merged = if existing_id.is_some() {
            merge_concurrent_writes(store, config, guard, &old_id).await
        } else {
            Ok(None)
        };
        // The removal of the old row is conditional on the revision the
        // merge read, so a write that lands after the read is a conflict, not
        // a loss: it is merged and the rotation tried again.
        cycled = match merged {
            Ok(Some(revision)) => store
                .cycle_if_revision(
                    &old_id,
                    &new_id,
                    &guard.data,
                    config.ttl,
                    require_old,
                    revision,
                )
                .await
                .map_err(StoreError::from),
            Ok(None) => store
                .cycle(&old_id, &new_id, &guard.data, config.ttl, require_old)
                .await
                .map_err(StoreError::from),
            Err(e) => Err(e),
        };
        if !matches!(cycled, Ok(CycleOutcome::Conflict)) {
            break;
        }
    }
    match cycled {
        Ok(CycleOutcome::Rotated) => {
            if let Some(user_id) = guard.data.auth_state.authenticated_user_id()
                && old_id != new_id
            {
                rotation = Some(Rotation {
                    was_authenticated,
                    user_id: *user_id,
                    old_id,
                    new_id,
                });
            }
            Cycled {
                id: new_id,
                rotation,
                cookie: true,
            }
        }
        Ok(CycleOutcome::Conflict) => {
            // Other requests kept writing the session for every round: fail
            // closed as for a store that cannot rotate.
            tracing::error!(
                "concurrent requests kept writing the session; clearing it (fail closed)"
            );
            if let Err(e) = store.delete(&old_id).await {
                tracing::error!(
                    error = %e,
                    "session store delete after a conflicted cycle failed; \
                     the old session id may authenticate until its TTL"
                );
            }
            guard.data = SessionData::default();
            Cycled {
                id: new_id,
                rotation: None,
                cookie: true,
            }
        }
        Ok(CycleOutcome::SessionGone) => {
            // Nothing was written: the old row was already gone, so the
            // client's cookie names nothing, and no new one is set.
            tracing::info!(
                "session was ended while its request ran; \
                     not carrying it over to the rotated id"
            );
            guard.data = SessionData::default();
            Cycled {
                id: new_id,
                rotation: None,
                cookie: false,
            }
        }
        Err(e) => {
            // Fail closed in the STORE as well as in this response: the
            // row under `old_id` may still say Authenticated, so the old
            // id is deleted (best effort) and never re-issued; the cookie
            // carries the new id, which no row backs, so the next request
            // is a guest. The cookie is set although no row was written,
            // because it replaces the retired id in the client's jar.
            tracing::error!(
                error = %e,
                "session store cycle failed; clearing session (fail closed)"
            );
            if let Err(e) = store.delete(&old_id).await {
                tracing::error!(
                    error = %e,
                    "session store delete after a failed cycle also failed; \
                     the old session id may authenticate until its TTL"
                );
            }
            guard.data = SessionData::default();
            Cycled {
                id: new_id,
                rotation: None,
                cookie: true,
            }
        }
    }
}

/// Whether a stored session that only read has gone half its lifetime
/// without its row being re-armed. A session that carries no stamp (stored
/// before the stamp existed) is due at once; a stamp in the future (a clock
/// step) is not.
fn touch_is_due(
    touched_at: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
    ttl: std::time::Duration,
) -> bool {
    let Some(touched_at) = touched_at else {
        return true;
    };
    let Ok(half) = chrono::Duration::from_std(ttl / 2) else {
        return false;
    };
    now.signed_duration_since(touched_at) >= half
}
