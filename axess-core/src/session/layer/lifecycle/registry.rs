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
/// cookie is issued. When it holds neither id the session was revoked while
/// its request ran.
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
            if registry.liveness(user_id, old_id).await == SessionLiveness::Gone {
                note_revocation(
                    registry.invalidate_session(user_id, new_id).await,
                    "ending a session revoked while its id rotated",
                );
                return end_untracked(
                    store,
                    new_id,
                    "the session was revoked while its id rotated; ending it",
                )
                .await;
            }
            note_revocation(
                registry.invalidate_session(user_id, old_id).await,
                "moving a rotated session's registry entry",
            );
            true
        }
        SessionLiveness::Gone => match registry.liveness(user_id, new_id).await {
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
