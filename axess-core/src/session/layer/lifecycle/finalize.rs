//! The finalize stage of a request: save, cycle or fail closed for the
//! response, merging this request's changes onto a row a concurrent request
//! wrote, and capping the custom data on whatever is written.

use crate::session::config::SessionConfig;
use crate::session::data::{SessionData, cap_custom, merge_rotating};
use crate::session::id::SessionKey;
use crate::session::layer::audit::{LayerSessionEnded, SessionEndAudit, SessionEndReason};
use crate::session::layer::handle::SessionHandle;
use crate::session::layer::signing::CookieSession;
use crate::session::layer::swap::{StoreError, Swap, Swapped, swap_merging};
use crate::session::store::{ConditionalUpdate, CycleOutcome, SessionStore};
use axess_clock::Clock;
use axess_rng::SecureRng;

use super::ending::{Ended, Ending, end_stored, ended_record, entries_left};
use super::{FinalizeOutcome, Reporting, Rotation};

/// Decide save vs cycle vs fail-closed for the response, enforcing the
/// custom-data size cap on whatever is written.
///
/// `stored` is the trust [`load_session`](super::load_session)'s outcome
/// carries: `false` means "no trusted prior session", a fresh guest whose id was
/// already minted safely by `load_session` (never the client's cookie
/// id). Its data is *saved* under that same id; the response cookie
/// carries it unchanged. This is deliberate: a CSRF token minted during
/// the request is HMAC-bound to this id, so minting a *second*, different
/// id for the response cookie here would invalidate that token and 403
/// the next state-changing request (the login POST). Only `guard.regenerate`
/// (handler-side `rotate_id`, or binding invalidation) forces an id change.
///
/// Cycle order matters: the handler-side state-transition methods
/// already minted the new id and stashed the old session in
/// `pre_cycle` (see
/// [`SessionInner::rotate_id`](crate::session::layer::handle::SessionInner::rotate_id)).
/// The store's `cycle` then takes `(old, new, data)` so handler code
/// that registered with the new id keys the registry against the
/// post-rotation value. Fallback path for `regenerate` without a
/// stashed `pre_cycle` (binding-mismatch reset) mints fresh here.
///
/// Cycle failure: fail closed by clearing the session to Guest, deleting
/// the rows under both ids (best effort) and sending the cookie of the
/// new id, which no row backs, so the next request is a guest's. The old
/// id is never re-issued: keeping it with the new data would bypass
/// session fixation prevention. A session that ends this way is told to
/// the audit sink first (see `fail_rotation`).
pub(crate) async fn finalize_session<S>(
    store: &S,
    config: &SessionConfig,
    reporting: Reporting<'_>,
    clock: &dyn Clock,
    handle: &SessionHandle,
    stored: bool,
    rng: &dyn SecureRng,
) -> FinalizeOutcome
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    let mut guard = handle.0.write().await;
    if let Some(owed) = guard.owed_ending.take() {
        let at = (clock.now(), config.ttl);
        return end_owed(store, reporting.audit, &guard, owed, at).await;
    }
    // No row is written with a key binding made for, or a device resolved
    // for, another person than the one at the session's browser now.
    guard.drop_not_in_force();

    // A request without a trusted session persists the fresh guest and sets a
    // cookie only when something needs it (a modification, a CSRF token bound
    // to the id, a handler that read the id); an untouched cookieless request
    // leaves the store empty and the response without `Set-Cookie`.
    let fresh_needed = !stored && (guard.modified || guard.needs_persist);
    // A stored session that only read, and whose row has not been re-armed
    // for half its lifetime, is refreshed so that activity keeps it alive.
    let now = clock.now();
    let touch_due = stored
        && !guard.modified
        && !guard.regenerate
        && touch_is_due(guard.data.touched_at, now, config.ttl);
    let mut session_changed = guard.modified || guard.regenerate || fresh_needed || touch_due;
    let loaded_revision = guard.data.revision;
    if session_changed {
        // The custom-data cap applies to every write, the idle refresh of
        // loaded data included: data loaded from the store can be
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
        && (guard.regenerate || !stored)
        && let Some(m) = reporting.metrics
    {
        m.session.session_created();
    }

    let (mut rotation, mut released) = (None, Vec::new());
    let session = if session_changed {
        if guard.regenerate {
            let turn = Turn {
                stored,
                now,
                audit: reporting.audit,
            };
            let cycled = cycle_session(store, config, &mut guard, turn, rng).await;
            rotation = cycled.rotation;
            released = cycled.released;
            session_changed = cycled.cookie;
            cycled.session
        } else if stored {
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
                    .update_if_revision(
                        guard.session.key(),
                        loaded_revision,
                        &guard.data,
                        config.ttl,
                    )
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
            guard.session
        } else {
            // A fresh guest: `stored` is `false`, so its id was minted
            // safely by `load_session` (never the client-supplied cookie id:
            // session fixation is prevented there and, on privilege change, by
            // the `regenerate` branch above). Keeping it, rather than minting
            // a second, different id for the response cookie, is what lets a
            // CSRF token minted *during* this request (bound to the same id)
            // still validate on the client's next request. Minting a fresh id
            // here would orphan both the token and any handler-time work keyed
            // to the session, and every subsequent state-changing request would
            // 403 until the cookie expired.
            if let Err(e) = store
                .save(guard.session.key(), &guard.data, config.ttl)
                .await
            {
                tracing::warn!(
                    error = %e,
                    "session store save failed; session changes may be lost"
                );
                // No row names this id, so no cookie does either.
                session_changed = false;
            }
            guard.session
        }
    } else {
        guard.session
    };

    FinalizeOutcome {
        session,
        session_changed,
        rotation,
        released,
    }
}

/// End the stored session a handler asked the layer to end (the handle's
/// `owed_ending`): that ending is all the request writes. Ended, the response replaces the
/// client's cookie with one no row backs, and the session's registry
/// entries are handed to the finish to remove; kept (another request holds
/// its claim, or the sink failed), or moved or ended by another request
/// meanwhile, no cookie is set and nothing is recorded here.
async fn end_owed<S>(
    store: &S,
    audit: &dyn SessionEndAudit,
    guard: &tokio::sync::RwLockWriteGuard<'_, crate::session::layer::handle::SessionInner>,
    owed: LayerSessionEnded,
    (now, ttl): (axess_clock::Timestamp, std::time::Duration),
) -> FinalizeOutcome
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    let loaded = guard.consume.as_ref().and_then(|c| c.loaded.as_ref());
    let entries = loaded.map_or_else(Vec::new, |row| entries_left(row, owed.session_id));
    let ended = end_stored_session(store, audit, owed, now, ttl).await == RowEnding::Ended;
    FinalizeOutcome {
        session: guard.session,
        session_changed: ended,
        rotation: None,
        released: if ended { entries } else { Vec::new() },
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
    let session = guard.session;
    let swap = Swap {
        row: session.key(),
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
/// Returns the revision of the old row the data now stands on
/// ([`OldRow::At`]), which the rotation checks (`cycle_if_revision`), so a
/// write landing after this read is answered as a conflict and merged on
/// the next round instead of lost.
async fn merge_concurrent_writes<S>(
    store: &S,
    config: &SessionConfig,
    guard: &mut tokio::sync::RwLockWriteGuard<'_, crate::session::layer::handle::SessionInner>,
    old: &SessionKey,
) -> Result<OldRow, StoreError>
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    let Some(base) = guard.consume.as_ref().and_then(|c| c.loaded.clone()) else {
        return Ok(OldRow::Unread);
    };
    let fresh = match super::load_current(store, old).await? {
        // Whatever its revision: a take of a one-shot value by this request
        // may have written onto the claimed row and learned its revision.
        Some(fresh) if fresh.ending.is_some() => {
            tracing::warn!(
                "the session is being ended by another request: its id is not rotated, \
                 and this request's changes are discarded"
            );
            return Ok(OldRow::BeingEnded);
        }
        Some(fresh) if fresh.revision != base.revision => fresh,
        _ => return Ok(OldRow::At(base.revision)),
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
    Ok(OldRow::At(revision))
}

/// The old row of a rotation, as [`merge_concurrent_writes`] found it.
enum OldRow {
    /// The request has no loaded row to merge from: there is nothing to
    /// check, and the rotation is unconditional.
    Unread,
    /// The revision the data the rotation carries now stands on.
    At(u64),
    /// A concurrent request claimed the row to end the session (see
    /// [`SessionData::ending`]). The session is ended under the id its
    /// claim was written on: nothing is carried to the new id, where the
    /// request that ends it would not find it.
    BeingEnded,
}

/// How many times a rotation re-reads the old row after a concurrent write
/// beat it to the removal, before it gives up and fails closed.
const CYCLE_ATTEMPTS: usize = 4;

/// What [`cycle_session`] did.
struct Cycled {
    /// The session the response cookie carries, when it carries one.
    session: CookieSession,
    /// The registry entry to move, for a session that stayed authenticated.
    rotation: Option<Rotation>,
    /// The registry entries of the stored session a failed rotation ended.
    released: Vec<super::Entry>,
    /// Whether the response sets a cookie: a row is stored under `id`, or the
    /// client's cookie must be replaced so a retired id is never presented
    /// again.
    cookie: bool,
}

/// What a rotation is told of the request it finishes.
struct Turn<'a> {
    /// The request ran under a stored session the load trusted.
    stored: bool,
    /// The layer's clock at the finish.
    now: axess_clock::Timestamp,
    /// Told of a session the rotation ends.
    audit: &'a dyn SessionEndAudit,
}

/// Write a rotated session under its new id and retire the old row, failing
/// closed.
async fn cycle_session<S>(
    store: &S,
    config: &SessionConfig,
    guard: &mut tokio::sync::RwLockWriteGuard<'_, crate::session::layer::handle::SessionInner>,
    turn: Turn<'_>,
    rng: &dyn SecureRng,
) -> Cycled
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    let Turn { stored, now, audit } = turn;
    let mut rotation = None;
    let old = guard.pre_cycle.take().unwrap_or_else(|| {
        let prev = *guard.session.key();
        guard.session = CookieSession::mint(rng);
        prev
    });
    let session = guard.session;
    let new = *session.key();
    // A request that ran under a stored session requires that row to
    // still be live: a logout that removed it while the request ran
    // must not be undone by moving the data to the new id.
    let require_old = stored;
    let mut cycled: Result<CycleOutcome, StoreError> = Ok(CycleOutcome::Conflict);
    for _ in 0..CYCLE_ATTEMPTS {
        let merged = if stored {
            merge_concurrent_writes(store, config, guard, &old).await
        } else {
            Ok(OldRow::Unread)
        };
        // The removal of the old row is conditional on the revision the
        // merge read, so a write that lands after the read is a conflict, not
        // a loss: it is merged and the rotation tried again.
        cycled = match merged {
            Ok(OldRow::BeingEnded) => Ok(CycleOutcome::SessionGone),
            Ok(OldRow::At(revision)) => store
                .cycle_if_revision(&old, &new, &guard.data, config.ttl, require_old, revision)
                .await
                .map_err(StoreError::from),
            Ok(OldRow::Unread) => store
                .cycle(&old, &new, &guard.data, config.ttl, require_old)
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
            if let Some(signed_in) = guard.data.auth_state.signed_in()
                && old != new
            {
                // Signed in as the user the response names, a step-up of
                // that session included: a step-up is the signed-in session
                // it began from and holds its registry entry. The entry
                // this request knows of counts only when it is that user's:
                // a handler that changed who the session is (a login of
                // another person, the start of an impersonation) registered
                // the new key for the new user itself.
                rotation = Some(Rotation {
                    user_id: *signed_in.user_id,
                    tenant_id: *signed_in.tenant_id,
                    impersonator: signed_in.impersonator.map(|imp| imp.admin),
                    arrived: old,
                    new,
                    held: guard.held_for(signed_in.user_id),
                    anchor: signed_in
                        .impersonator
                        .map(|imp| (imp.admin, imp.registry_anchor(signed_in.user_id))),
                });
            }
            Cycled {
                session,
                rotation,
                released: Vec::new(),
                cookie: true,
            }
        }
        Ok(CycleOutcome::Conflict) => {
            // Other requests kept writing the session for every round: fail
            // closed as for a store that cannot rotate.
            tracing::error!(
                "concurrent requests kept writing the session; clearing it (fail closed)"
            );
            fail_rotation(store, audit, guard, (old, new), (now, config.ttl)).await
        }
        Ok(CycleOutcome::SessionGone) => {
            // Nothing was written: the old row was already gone, or a
            // concurrent request holds it to end the session. The client's
            // cookie names nothing that this request may carry over, and no
            // new one is set.
            tracing::info!(
                "session was ended while its request ran; \
                     not carrying it over to the rotated id"
            );
            guard.data = SessionData::default();
            Cycled {
                session,
                rotation: None,
                released: Vec::new(),
                cookie: false,
            }
        }
        Err(e) => {
            // Fail closed in the STORE as well as in this response: the
            // row under the old key may still say Authenticated, so the old
            // id is deleted (best effort) and never re-issued; the cookie
            // carries the new id, which no row backs, so the next request
            // is a guest. The cookie is set although no row was written,
            // because it replaces the retired id in the client's jar.
            tracing::error!(
                error = %e,
                "session store cycle failed; clearing session (fail closed)"
            );
            fail_rotation(store, audit, guard, (old, new), (now, config.ttl)).await
        }
    }
}

/// The sessions a failed rotation ends.
///
/// `stored` is the authenticated session the request arrived with, under
/// its old id: it ends because the layer removes its row. `unborn` is the
/// session the request leaves, under its new id, when it is another one (a
/// login, the start or the end of an impersonation): no row ever held it,
/// and the row says so for a login the audit trail already shows.
///
/// A request that leaves a guest ended its session itself (a logout): that
/// is the handler's act and its row, and the layer has none to add.
struct FailedRotation {
    stored: Option<LayerSessionEnded>,
    unborn: Option<LayerSessionEnded>,
}

impl FailedRotation {
    fn of(
        loaded: Option<&SessionData>,
        left: &SessionData,
        old: SessionKey,
        new: SessionKey,
    ) -> Self {
        let reason = SessionEndReason::RotationFailed;
        let Some(unborn) = ended_record(left, new, reason) else {
            return Self {
                stored: None,
                unborn: None,
            };
        };
        let stored = loaded.and_then(|row| ended_record(row, old, reason));
        // The same user's session under a new id is one session, the stored
        // one: it is recorded once, under the id the audit trail knows.
        let same = stored
            .as_ref()
            .is_some_and(|stored| stored.user_id == unborn.user_id);
        Self {
            stored,
            unborn: (!same).then_some(unborn),
        }
    }
}

/// Tell `audit` of an ending a failed rotation makes, and say whether the
/// row was written. A failure is logged at `error`.
async fn record_ending(audit: &dyn SessionEndAudit, ended: Option<&LayerSessionEnded>) -> bool {
    let Some(ended) = ended else {
        return true;
    };
    match audit.session_ended(ended).await {
        Ok(()) => true,
        Err(e) => {
            tracing::error!(
                error = %e,
                reason = ended.reason.as_str(),
                "session layer: the audit row of an ending could not be written"
            );
            false
        }
    }
}

/// Fail a rotation closed: the session the request leaves cannot be stored
/// under its new id, so it ends here.
///
/// The stored session, when the request ends one ([`FailedRotation`]), is
/// ended as the load ends a session: claimed, recorded, removed
/// ([`end_stored`]). So its audit row is written before it goes, a sink
/// that fails leaves it stored as it was (and no cookie is set, so the
/// client keeps the session it had without the request's changes), and a
/// store that then fails the removal leaves it claimed, which the next
/// request that presents it finishes. One thing cannot be kept that way: a
/// store that rotates in two steps has already removed the row. Its ending
/// is recorded after the fact, and an `Err` from the sink is logged.
///
/// The session the request leaves, when no row ever held it, is told to
/// the sink as well; it cannot be kept whatever the sink answers.
///
/// Then the row under the new id is deleted (best effort; a store that
/// failed may have written it all the same), and the cookie of the new id,
/// which no row backs, replaces the client's.
async fn fail_rotation<S>(
    store: &S,
    audit: &dyn SessionEndAudit,
    guard: &mut tokio::sync::RwLockWriteGuard<'_, crate::session::layer::handle::SessionInner>,
    (old, new): (SessionKey, SessionKey),
    (now, ttl): (axess_clock::Timestamp, std::time::Duration),
) -> Cycled
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    let loaded = guard.consume.as_ref().and_then(|c| c.loaded.as_ref());
    let ending = FailedRotation::of(loaded, &guard.data, old, new);
    let entries = loaded.map_or_else(Vec::new, |row| entries_left(row, old));
    guard.data = SessionData::default();
    let stored_ended = match ending.stored {
        Some(ended) => match end_stored_session(store, audit, ended.clone(), now, ttl).await {
            RowEnding::Ended => true,
            RowEnding::Kept => false,
            RowEnding::Missing => {
                // A store that rotates in two steps removed the row before
                // it failed: this request knows the row was there and that
                // its own rotation removed it. The session is gone; all
                // that is left is to say so.
                if !record_ending(audit, Some(&ended)).await {
                    tracing::error!(
                        "the rotation failed after the store had removed the session, and \
                         its ending could not be recorded: the session is gone without an \
                         audit row"
                    );
                }
                true
            }
        },
        None => {
            // No authenticated session of the layer's to end: the row of a
            // guest, or of a session the handler ended itself, is retired.
            if let Err(e) = store.delete(&old).await {
                tracing::error!(
                    error = %e,
                    "session store delete after a failed rotation also failed; \
                     the old session id may be presented until its TTL"
                );
            }
            true
        }
    };
    record_ending(audit, ending.unborn.as_ref()).await;
    if let Err(e) = store.delete(&new).await {
        tracing::error!(
            error = %e,
            "session store delete of the new id after a failed rotation also failed"
        );
    }
    Cycled {
        // The session the request leaves with, which no row backs.
        session: guard.session,
        rotation: None,
        // The stored session is gone when it was ended (or removed by a
        // two-step store before it failed); a session kept as it was
        // stored keeps its entries.
        released: if stored_ended { entries } else { Vec::new() },
        // A stored session that was not ended keeps its cookie.
        cookie: stored_ended,
    }
}

/// What became of the ending of a stored session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RowEnding {
    /// The session is ended: claimed, recorded and removed (or left
    /// claimed, when the store failed the removal).
    Ended,
    /// The session is kept as it was stored: another request holds its
    /// ending, its ending could not be recorded (the claim is taken back),
    /// or its row could not be read.
    Kept,
    /// No row is stored under the record's key. Nothing was recorded and
    /// nothing removed: what that means is the caller's to say.
    Missing,
}

/// End the stored session named by `ended`, under the key of its row,
/// through the ending protocol: read the row, claim it, tell the sink,
/// remove it ([`end_stored`]). The caller runs in a task the request only
/// waits for, as the finish does.
///
/// A row that is gone is [`RowEnding::Missing`] and records nothing here.
/// Only a failed rotation knows its own store removed the row and records
/// the ending after the fact; for an ending of the settlement or one a
/// handler asked for, a row no longer stored under the record's key was
/// moved or ended by another request while this one ran, and that request
/// recorded what it did.
pub(super) async fn end_stored_session<S>(
    store: &S,
    audit: &dyn SessionEndAudit,
    ended: LayerSessionEnded,
    now: axess_clock::Timestamp,
    ttl: std::time::Duration,
) -> RowEnding
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    // The record names the session by the key of its row.
    match super::load_current(store, &ended.session_id).await {
        // Another request is ending it already: the ending is its to make.
        Ok(Some(row)) if row.ending.is_some() => RowEnding::Kept,
        Ok(Some(row)) => {
            let what = Ending {
                row,
                ended,
                now,
                ttl,
                resumed: false,
            };
            match end_stored(store, audit, what).await {
                Ended::Done => RowEnding::Ended,
                Ended::Deferred => {
                    tracing::error!(
                        "the stored session could not be ended with its audit row: it is \
                         left as it was stored"
                    );
                    RowEnding::Kept
                }
            }
        }
        Ok(None) => RowEnding::Missing,
        Err(e) => {
            tracing::error!(
                error = %e,
                "the stored session to end could not be read: it is left to the store, \
                 unended and unrecorded"
            );
            RowEnding::Kept
        }
    }
}

/// Whether a stored session that only read has gone half its lifetime
/// without its row being re-armed. A session that carries no stamp (stored
/// before the stamp existed) is due at once; a stamp in the future (a clock
/// step) is not.
fn touch_is_due(
    touched_at: Option<axess_clock::Timestamp>,
    now: axess_clock::Timestamp,
    ttl: std::time::Duration,
) -> bool {
    let Some(touched_at) = touched_at else {
        return true;
    };
    let Ok(half) = axess_clock::SignedDuration::try_from(ttl / 2) else {
        return false;
    };
    now.since(touched_at) >= half
}
