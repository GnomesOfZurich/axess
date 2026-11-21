//! Rotating a signed-in session to a new key with its registry entry in
//! step.

use super::{AuthnService, RequestAuthnService};
use crate::authn::{
    error::AuthnError,
    ids::UserId,
    store::{FactorStore, IdentityStore},
};
use crate::session::extractor::AuthSession;
use crate::session::id::SessionKey;
use crate::session::layer::SessionEndReason;
use crate::session::store::{MoveOutcome, SessionRegistryHandle, note_revocation};

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Rotate the key of an authenticated session, with its registry entry
    /// in step. Use it at the privilege boundaries
    /// [`AuthSession::regenerate`] documents (factor added, password
    /// changed, tenant switched).
    ///
    /// - A session that is not authenticated, or a service without a
    ///   registry: the key rotates and nothing else happens.
    /// - Behind a session layer built with a registry: the key rotates and
    ///   this method writes nothing to the registry. The layer moves the
    ///   entry, in one step, after the session's row has moved, and ends a
    ///   session the registry no longer holds, with its audit record.
    /// - Otherwise (a layer built without a registry, or a session no layer
    ///   stands behind): the key rotates and the registry moves the entry
    ///   from [`AuthSession::registered_key`] to the new key in one call. A
    ///   session the registry no longer holds was revoked while the request
    ///   ran, and a registry that cannot move it (full, or erring) cannot
    ///   track it: either way the session is ended through the session
    ///   layer's ending protocol, with its audit record (the service's own
    ///   sink records it for a session no layer stands behind), and the
    ///   call returns [`AuthnError::NoFlow`].
    ///
    /// The registry holds the key it held before until the response is
    /// written: a registry call later in the same handler names the session
    /// by [`AuthSession::registered_key`].
    #[tracing::instrument(skip(self, session))]
    pub async fn rotate_session(&self, session: &AuthSession) -> Result<(), AuthnError<I::Error>> {
        let user = if session.is_authenticated().await {
            session.user_id().await
        } else {
            None
        };
        let (Some(user_id), Some(reg)) = (user, &self.inner.registry) else {
            session.regenerate().await;
            return Ok(());
        };
        if session.layer_moves_registry().await {
            session.regenerate().await;
            return Ok(());
        }
        let old = session.registered_key().await;
        session.regenerate().await;
        self.move_entry_now(reg.as_ref(), &user_id, &old, session)
            .await
    }
}

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Move the registry entry of `session` from `from` to the key the
    /// session carries now, in one call, for a session no layer moves.
    ///
    /// A session the registry no longer holds under `from` was revoked
    /// while the request ran; a registry that cannot move it (full, or
    /// erring) cannot track it. Either way the session ends and the answer
    /// is [`AuthnError::NoFlow`]; a registry that could not move it first
    /// loses `from`, as far as it answers, which would otherwise stay listed
    /// and counted for a session that ended.
    pub(super) async fn move_entry_now(
        &self,
        reg: &dyn SessionRegistryHandle,
        user_id: &UserId,
        from: &SessionKey,
        session: &AuthSession,
    ) -> Result<(), AuthnError<I::Error>> {
        let new = session.session_key().await;
        let (reason, why) = match reg.move_session(user_id, from, &new).await {
            Ok(MoveOutcome::Moved) => {
                session.note_registered(user_id, new).await;
                return Ok(());
            }
            Ok(MoveOutcome::OldGone) => (
                SessionEndReason::RevokedDuringRotation,
                "the registry no longer holds the session: it was revoked while its request \
                 ran; ending it",
            ),
            Ok(MoveOutcome::Full) => {
                note_revocation(
                    reg.invalidate_session(user_id, from).await,
                    "ending a session whose registry entry could not move",
                );
                (
                    SessionEndReason::NotTracked,
                    "the registry holds too many former keys of the user to move the session; \
                     ending it",
                )
            }
            Err(e) => {
                tracing::error!(user_id = %user_id, error = %e, "moving a session's registry entry failed");
                note_revocation(
                    reg.invalidate_session(user_id, from).await,
                    "ending a session whose registry entry could not move",
                );
                (
                    SessionEndReason::NotTracked,
                    "the registry could not move the session; ending it",
                )
            }
        };
        tracing::warn!(user_id = %user_id, why);
        self.end_through_layer(session, reason, from).await;
        Err(AuthnError::NoFlow)
    }

    /// End `session` through the session layer's ending protocol, with
    /// `reason`: under a layer the finish claims the stored row, records the
    /// ending and removes the row; with no stored row and no layer behind
    /// the handle, this service's own sink
    /// ([`session_end_audit`](AuthnService::session_end_audit)) is told
    /// here, of the session under `held`, the key the registry held it
    /// under. The handle is a guest's at once either way. A sink that fails
    /// is logged at `error`.
    async fn end_through_layer(
        &self,
        session: &AuthSession,
        reason: SessionEndReason,
        held: &SessionKey,
    ) {
        let Some(mut record) = session.end_through_layer(reason).await else {
            return;
        };
        record.session_id = *held;
        if let Err(e) = self.session_end_audit().session_ended(&record).await {
            tracing::error!(
                user_id = %record.user_id,
                error = %e,
                ending = record.reason.as_str(),
                "the record of a session the service ended could not be written"
            );
        }
    }

    /// Note that `session` is registered for `user_id` under `key`, at
    /// every place the service registers a session. When the entry the
    /// session held before was another user's (a person signed in, in one
    /// request, on a session another person was signed in on), that entry
    /// is ended: the session is no longer that user's, and without this the
    /// entry would stay listed and counted until it lapsed.
    pub(super) async fn note_registration(
        &self,
        reg: &dyn SessionRegistryHandle,
        session: &AuthSession,
        user_id: &UserId,
        key: SessionKey,
    ) {
        if let Some((other, other_key)) = session.note_registered(user_id, key).await {
            note_revocation(
                reg.invalidate_session(&other, &other_key).await,
                "ending the entry of a session another person signed in on",
            );
        }
    }
}
