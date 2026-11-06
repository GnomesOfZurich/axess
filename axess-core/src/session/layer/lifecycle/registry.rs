//! The session registry after an id change: move the entry of a session that
//! stayed authenticated to its new id, or end the session when the registry
//! cannot track it.

use crate::session::id::SessionId;
use crate::session::store::{
    SessionLiveness, SessionRegistryHandle, SessionStore, note_revocation,
};

use super::{FinalizeOutcome, Rotation};

/// Move the registry entry of a rotated, still-authenticated session from
/// its old id to its new one, and say whether the session may get a cookie.
///
/// The registry's three calls (liveness of the old id, registration of the
/// new one, invalidation of the old one) are not one transaction, so a
/// revocation can land between them. It is honoured by reading the old id
/// again after the new one is registered: when the registry no longer holds
/// the old id, the new one is invalidated too. A registry that cannot answer
/// is not a revocation: `unknown` decides what a session the registry cannot
/// confirm or register may do, whichever check found it out.
///
/// A login rotates a guest id the registry never held, and the handler
/// registers the new id itself; the registry then holds the new id and the
/// cookie is issued. When it holds neither id, or the session was already
/// authenticated and the old id is gone, the session was revoked while its
/// request ran.
///
/// Returns `false` when the session was ended instead of moved: its row
/// under the new id has been deleted, and the response sets no cookie.
pub(super) async fn move_registry_entry<S>(
    store: &S,
    registry: &dyn SessionRegistryHandle,
    rotation: &Rotation,
    unknown: crate::session::layer::UnknownLiveness,
) -> bool
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    let Rotation {
        was_authenticated,
        user_id,
        old_id,
        new_id,
    } = rotation;
    match registry.liveness(user_id, old_id).await {
        SessionLiveness::Valid => {
            if !registry.register(user_id, new_id).await {
                return on_untracked(
                    unknown,
                    store,
                    new_id,
                    "registering the rotated session failed; ending it rather than leaving it untracked",
                )
                .await;
            }
            if let Some(end) = reread_old_id(registry, store, rotation, unknown).await {
                return end;
            }
            note_revocation(
                registry.invalidate_session(user_id, old_id).await,
                "moving a rotated session's registry entry",
            );
            true
        }
        SessionLiveness::Gone => match registry.liveness(user_id, new_id).await {
            // A login rotates a guest id the registry never held, and the
            // handler registered the new id: that is a session. A session
            // that was authenticated held its old id, so an old id that is
            // gone was revoked, whatever the new id says.
            SessionLiveness::Valid if *was_authenticated => {
                end_revoked_rotation(registry, store, rotation).await
            }
            SessionLiveness::Valid => true,
            SessionLiveness::Gone => {
                end_untracked(
                    store,
                    new_id,
                    "the registry holds the session under neither id: it was revoked while its request ran",
                )
                .await
            }
            SessionLiveness::Unknown => {
                on_untracked(
                    unknown,
                    store,
                    new_id,
                    "the registry could not confirm the rotated session; ending it",
                )
                .await
            }
        },
        SessionLiveness::Unknown => {
            if registry.register(user_id, new_id).await {
                if let Some(end) = reread_old_id(registry, store, rotation, unknown).await {
                    return end;
                }
                note_revocation(
                    registry.invalidate_session(user_id, old_id).await,
                    "moving a rotated session's registry entry",
                );
                return true;
            }
            on_untracked(
                unknown,
                store,
                new_id,
                "the registry could not track the rotated session; ending it",
            )
            .await
        }
    }
}

/// Read the old id again after the new one was registered. `Some(false)`
/// ends the rotation (no cookie), `None` lets it go ahead.
///
/// `Gone` means a revocation landed during the rotation: the session ends.
/// `Unknown` means the registry could not answer this time, which is not a
/// revocation but is not a confirmation either: `unknown` decides, as for
/// every other registry call of the rotation. `Reject` ends the session and
/// invalidates the new id again; `Accept` lets it go ahead.
///
/// A window remains by construction: the registry's calls are not one
/// transaction, so a revocation that lands after this read, and before the
/// old id is invalidated, is not seen here. It is caught by the next request's
/// registry check, which finds the new id revoked with the rest.
async fn reread_old_id<S>(
    registry: &dyn SessionRegistryHandle,
    store: &S,
    rotation: &Rotation,
    unknown: crate::session::layer::UnknownLiveness,
) -> Option<bool>
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    match registry.liveness(&rotation.user_id, &rotation.old_id).await {
        SessionLiveness::Valid => None,
        SessionLiveness::Gone => Some(end_revoked_rotation(registry, store, rotation).await),
        SessionLiveness::Unknown => match unknown {
            crate::session::layer::UnknownLiveness::Accept => None,
            crate::session::layer::UnknownLiveness::Reject => {
                tracing::error!(
                    "the registry could not confirm the old id after the rotation registered the new one; ending it"
                );
                Some(end_revoked_rotation(registry, store, rotation).await)
            }
        },
    }
}

/// End a session revoked while its id rotated: invalidate the new id too and
/// delete its row. Returns `false` (no cookie).
async fn end_revoked_rotation<S>(
    registry: &dyn SessionRegistryHandle,
    store: &S,
    rotation: &Rotation,
) -> bool
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    note_revocation(
        registry
            .invalidate_session(&rotation.user_id, &rotation.new_id)
            .await,
        "ending a session revoked while its id rotated",
    );
    end_untracked(
        store,
        &rotation.new_id,
        "the session was revoked while its id rotated; ending it",
    )
    .await
}

/// A rotated session the registry could not answer for, or could not
/// register: [`UnknownLiveness`](crate::session::layer::UnknownLiveness)
/// decides. `Accept` keeps it (the cookie is set); `Reject` ends it as
/// [`end_untracked`] does. A failed registration is a registry that could not
/// answer, whatever the liveness check before it said, so every such case
/// comes here.
async fn on_untracked<S>(
    unknown: crate::session::layer::UnknownLiveness,
    store: &S,
    id: &SessionId,
    reason: &'static str,
) -> bool
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    match unknown {
        crate::session::layer::UnknownLiveness::Accept => true,
        crate::session::layer::UnknownLiveness::Reject => end_untracked(store, id, reason).await,
    }
}

/// Delete the row of a rotated session the registry does not track, so that
/// no untracked authenticated session remains, and report that no cookie is
/// set. The reason is logged at error level.
async fn end_untracked<S>(store: &S, id: &SessionId, reason: &'static str) -> bool
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    tracing::error!(reason);
    if let Err(e) = store.delete(id).await {
        tracing::error!(error = %e, "deleting the untracked session failed");
    }
    false
}

/// Move the registry entry of a session that stayed authenticated across an
/// id change, which is still registered under its old id. Returns whether
/// the session may get a cookie: `false` when the registry could not track
/// the new id and the session was ended instead.
pub(crate) async fn settle_registry<S>(
    store: &S,
    registry: Option<&dyn SessionRegistryHandle>,
    unknown: crate::session::layer::UnknownLiveness,
    outcome: &FinalizeOutcome,
) -> bool
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    match (registry, &outcome.rotation) {
        (Some(registry), Some(rotation)) => {
            move_registry_entry(store, registry, rotation, unknown).await
        }
        _ => true,
    }
}
