//! The session registry after a key change: move the entry of a session
//! that stayed signed in to its new key in one step, or end the session
//! when the registry no longer holds it or cannot track it.
//!
//! The store is rotated first and the registry second. That order is what
//! makes the layer the one place an entry moves: between the two, a request
//! that presents the old cookie finds no row and is a guest. Had the
//! registry moved first, that request would find its row, find the old key
//! gone from the registry, and end the session.
//!
//! A session ended here goes through the ending protocol of the load:
//! claimed on its row under the new key, recorded, then removed. A session
//! whose ending could not be recorded keeps its row and its cookie, and the
//! next request that presents it meets the registry at the load, which ends
//! a session the registry does not hold.

use crate::session::layer::UnknownLiveness;
use crate::session::layer::audit::{LayerSessionEnded, SessionEndAudit, SessionEndReason};
use crate::session::store::{
    MoveOutcome, SessionLiveness, SessionRegistryHandle, SessionStore, note_revocation,
};

use super::ending::release_entries;
use super::finalize::{RowEnding, end_stored_session};
use super::{FinalizeOutcome, Rotation};

impl Rotation {
    /// The rotated session as the audit sink is told of its ending, by the
    /// key its row now lives under.
    fn ended(&self, reason: SessionEndReason) -> LayerSessionEnded {
        LayerSessionEnded {
            user_id: self.user_id,
            tenant_id: self.tenant_id,
            session_id: self.new,
            impersonator: self.impersonator,
            reason,
        }
    }
}

/// What a registry settlement needs beside the registry and the rotation:
/// the store that holds the rotated row, what to do when the registry
/// cannot answer for a key it should hold, the sink told of a session that
/// is ended, and the layer's clock reading and row lifetime, which stamp
/// the claim of an ending.
pub(super) struct Settling<'a, S> {
    pub(super) store: &'a S,
    pub(super) unknown: UnknownLiveness,
    pub(super) audit: &'a dyn SessionEndAudit,
    pub(super) now: axess_clock::Timestamp,
    pub(super) ttl: std::time::Duration,
}

// Written out, not derived: a derive would ask the store itself to be
// `Copy`, and only references are held.
impl<S> Clone for Settling<'_, S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S> Copy for Settling<'_, S> {}

/// Settle the registry entry of a rotated, still signed-in session, and say
/// whether the response may set the cookie of its new key.
///
/// What the request knows the registry holds (`Rotation::held`) decides:
///
/// - Another key than the new one (a rotation, a step-up, a rotation after
///   a login in the same request): the entry is moved in one step. A key
///   the registry no longer holds was revoked while the request ran. A
///   registry that cannot move it (full, or erring) ends the session as
///   not tracked under either [`UnknownLiveness`]: the registry still holds
///   the old key and not the new one, so the cookie of the new key would
///   be ended as not registered by the first later request the registry
///   answers for. Keeping it would only postpone its end by a request and
///   record a reason that hides the cause.
/// - The new key (a handler registered the final key itself: a login, a
///   sign-up, the start of an impersonation): the registry is asked whether
///   it still holds it.
/// - Nothing known for this user: the new key is asked for first (a handler
///   of the adopter's own registered it), and when it is not held, the key
///   the request arrived with is moved (a handler of the adopter's own
///   registered that one, and the session rotated since).
///
/// Returns `false` when the session was ended, or found ended by another
/// request, instead of moved: the response sets no cookie. A session whose
/// ending could not be recorded is not ended, and the answer is `true`: it
/// keeps its row and its cookie, and the next request ends it at the load.
pub(super) async fn move_registry_entry<S>(
    settling: Settling<'_, S>,
    registry: &dyn SessionRegistryHandle,
    rotation: &Rotation,
) -> bool
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    let Rotation {
        user_id,
        arrived,
        new,
        held,
        ..
    } = rotation;
    match held {
        Some(held) if held != new => {
            let moved = registry.move_session(user_id, held, new).await;
            settle_move(settling, registry, rotation, held, moved).await
        }
        Some(_) => match registry.liveness(user_id, new).await {
            SessionLiveness::Valid => true,
            SessionLiveness::Gone => {
                end_rotated(
                    settling,
                    registry,
                    rotation,
                    SessionEndReason::RevokedDuringRotation,
                    "the registry no longer holds the key this request registered: the \
                     session was revoked while its request ran; ending it",
                )
                .await
            }
            SessionLiveness::Unknown => on_unknown(settling, registry, rotation).await,
        },
        None => match registry.liveness(user_id, new).await {
            SessionLiveness::Valid => true,
            SessionLiveness::Unknown => on_unknown(settling, registry, rotation).await,
            SessionLiveness::Gone => {
                let moved = registry.move_session(user_id, arrived, new).await;
                settle_move(settling, registry, rotation, arrived, moved).await
            }
        },
    }
}

/// What the registry's move from `from` to the rotation's new key means for
/// the session.
async fn settle_move<S>(
    settling: Settling<'_, S>,
    registry: &dyn SessionRegistryHandle,
    rotation: &Rotation,
    from: &crate::session::id::SessionKey,
    moved: Result<MoveOutcome, crate::session::store::RevocationError>,
) -> bool
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    match moved {
        Ok(MoveOutcome::Moved) => true,
        Ok(MoveOutcome::OldGone) => {
            end_rotated(
                settling,
                registry,
                rotation,
                SessionEndReason::RevokedDuringRotation,
                "the registry no longer holds the key the session rotated from: it was \
                 revoked while its request ran; ending it",
            )
            .await
        }
        Ok(MoveOutcome::Full) => {
            // The old key is still held and would stay listed and counted
            // for a session that ends here.
            note_revocation(
                registry.invalidate_session(&rotation.user_id, from).await,
                "ending a session whose registry entry could not move",
            );
            end_rotated(
                settling,
                registry,
                rotation,
                SessionEndReason::NotTracked,
                "the registry holds too many former keys of the user to move the rotated \
                 session; ending it",
            )
            .await
        }
        // Under either `UnknownLiveness`: the registry still holds the old
        // key and not the new one, so the cookie of the new key would end
        // as not registered on the first later request the registry answers.
        // The old key is let go as for a full registry, as far as the
        // registry answers.
        Err(e) => {
            tracing::error!(
                user_id = %rotation.user_id,
                error = %e,
                "the registry could not move the rotated session"
            );
            note_revocation(
                registry.invalidate_session(&rotation.user_id, from).await,
                "ending a session whose registry entry could not move",
            );
            end_rotated(
                settling,
                registry,
                rotation,
                SessionEndReason::NotTracked,
                "the registry could not move the rotated session; ending it",
            )
            .await
        }
    }
}

/// The registry could not say whether it holds the key the session is to
/// carry: [`UnknownLiveness`] decides. `Accept` keeps it (the cookie is
/// set); `Reject` ends it as not tracked.
async fn on_unknown<S>(
    settling: Settling<'_, S>,
    registry: &dyn SessionRegistryHandle,
    rotation: &Rotation,
) -> bool
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    match settling.unknown {
        UnknownLiveness::Accept => true,
        UnknownLiveness::Reject => {
            end_rotated(
                settling,
                registry,
                rotation,
                SessionEndReason::NotTracked,
                "the registry could not confirm the rotated session; ending it",
            )
            .await
        }
    }
}

/// End a rotated session: remove any entry under its new key (one a handler
/// registered; harmless otherwise), then end its row under the new key
/// through the ending protocol. `why` is logged at error level.
///
/// Returns whether the response sets the cookie: `false` for a session that
/// was ended, or whose row another request had moved or ended meanwhile
/// (that request recorded what it did); `true` for one that is kept because
/// its ending could not be recorded or its row could not be read.
async fn end_rotated<S>(
    settling: Settling<'_, S>,
    registry: &dyn SessionRegistryHandle,
    rotation: &Rotation,
    reason: SessionEndReason,
    why: &'static str,
) -> bool
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    tracing::error!(why);
    note_revocation(
        registry
            .invalidate_session(&rotation.user_id, &rotation.new)
            .await,
        "ending a session whose key rotated",
    );
    let ended = rotation.ended(reason);
    match end_stored_session(
        settling.store,
        settling.audit,
        ended,
        settling.now,
        settling.ttl,
    )
    .await
    {
        RowEnding::Ended => {
            // The impersonation the session carried ended with it.
            release_entries(Some(registry), rotation.anchor.as_slice()).await;
            false
        }
        RowEnding::Missing => false,
        RowEnding::Kept => true,
    }
}

/// Settle the registry for the response of a request: move the entry of a
/// session that stayed signed in across a key change. Returns whether the
/// session gets a cookie: `false` when it was ended instead, with its
/// ending recorded.
pub(crate) async fn settle_registry<S>(
    store: &S,
    registry: Option<&dyn SessionRegistryHandle>,
    (unknown, audit): (UnknownLiveness, &dyn SessionEndAudit),
    (now, ttl): (axess_clock::Timestamp, std::time::Duration),
    outcome: &FinalizeOutcome,
) -> bool
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    match (registry, &outcome.rotation) {
        (Some(registry), Some(rotation)) => {
            let settling = Settling {
                store,
                unknown,
                audit,
                now,
                ttl,
            };
            move_registry_entry(settling, registry, rotation).await
        }
        _ => true,
    }
}
