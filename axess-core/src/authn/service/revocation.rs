//! Ending sessions on purpose: an administrator's kick, a suspension, a
//! password reset. Every public entry point names who acted.

use super::{AuthnService, RequestAuthnService};
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventStatus, AuthEventType},
    ids::UserId,
    store::{FactorStore, IdentityStore},
};
use crate::session::{id::SessionId, store::RevocationError};

/// Who performs an administrative action, as its audit row records it.
///
/// Every session kick, suspension and activation names one: there is no form
/// of these calls that leaves the actor out.
#[derive(Debug, Clone, Copy)]
pub enum Actor<'a> {
    /// An administrator; the row names them.
    Admin(&'a UserId),
    /// The system itself (a back-channel logout, a scheduled sweep, an
    /// automated lock): the row carries no actor.
    System,
}

impl Actor<'_> {
    pub(crate) fn id(&self) -> Option<&UserId> {
        match self {
            Self::Admin(id) => Some(id),
            Self::System => None,
        }
    }
}

/// Why sessions could not be ended.
pub(crate) enum RevokeFailure {
    /// No registry is wired, so nothing can be revoked.
    NoRegistry,
    /// The registry backend failed; the sessions may still be valid.
    Registry(RevocationError),
}

impl RevokeFailure {
    pub(crate) fn into_authn<E>(self) -> AuthnError<E>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        match self {
            Self::NoRegistry => AuthnError::Internal(
                "no session registry is configured, so sessions cannot be revoked".to_owned(),
            ),
            Self::Registry(e) => AuthnError::ExternalService(e.to_string()),
        }
    }
}

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// End every session of `user_id`: the registry entries first, then the
    /// stored rows when the service was given the session store. The rows are
    /// deleted even when the registry failed, so a store that is up still
    /// closes the sessions; the registry's failure is returned either way.
    pub(crate) async fn revoke_user_sessions(&self, user_id: &UserId) -> Result<(), RevokeFailure> {
        let Some(reg) = &self.inner.registry else {
            return Err(RevokeFailure::NoRegistry);
        };
        let live = reg.active_sessions(user_id).await;
        let revoked = reg.invalidate_user(user_id).await;
        self.delete_session_rows(&live).await;
        revoked.map_err(RevokeFailure::Registry)
    }

    /// End every session of `user_id` when a registry is wired, and do
    /// nothing when none is. For the paths that change an account (a
    /// suspension, a password reset) and report a failed revocation to their
    /// caller after the change and its audit row are done.
    pub(crate) async fn end_user_sessions(
        &self,
        user_id: &UserId,
    ) -> Result<(), AuthnError<I::Error>> {
        match self.revoke_user_sessions(user_id).await {
            Ok(()) | Err(RevokeFailure::NoRegistry) => Ok(()),
            Err(failure) => Err(failure.into_authn()),
        }
    }

    /// End one session of `user_id`; see
    /// [`revoke_user_sessions`](Self::revoke_user_sessions).
    pub(crate) async fn revoke_session(
        &self,
        user_id: &UserId,
        session_id: &SessionId,
    ) -> Result<(), RevokeFailure> {
        let Some(reg) = &self.inner.registry else {
            return Err(RevokeFailure::NoRegistry);
        };
        let revoked = reg.invalidate_session(user_id, session_id).await;
        self.delete_session_rows(std::slice::from_ref(session_id))
            .await;
        revoked.map_err(RevokeFailure::Registry)
    }

    /// Delete the stored rows of sessions the registry no longer holds, when a
    /// session store was wired. Best effort: a row that stays is refused on
    /// its next request by a layer that consults the registry, and expires
    /// with its TTL otherwise.
    async fn delete_session_rows(&self, ids: &[SessionId]) {
        let Some(rows) = &self.inner.session_rows else {
            return;
        };
        for id in ids {
            if let Err(e) = rows.delete_row(id).await {
                tracing::warn!(error = %e, "deleting a revoked session's row failed");
            }
        }
    }
}

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// End every session of a user and record who did it.
    ///
    /// The registry entries are removed (and, when the service was built
    /// with [`with_session_store`](crate::authn::service::AuthnServiceBuilder::with_session_store),
    /// the stored rows deleted), then a `SessionInvalidated` audit row is
    /// written for the user with `actor` as the administrator who acted.
    ///
    /// # Errors
    ///
    /// [`AuthnError::Internal`] when no registry is wired,
    /// [`AuthnError::ExternalService`] when the registry backend failed (the
    /// sessions may still be valid, and no audit row claims otherwise), and
    /// `Store` when the audit write fails after the sessions were ended.
    pub async fn invalidate_user_sessions(
        &self,
        user_id: &UserId,
        actor: Actor<'_>,
    ) -> Result<(), AuthnError<I::Error>> {
        self.revoke_user_sessions(user_id)
            .await
            .map_err(RevokeFailure::into_authn)?;
        self.audit_invalidation(user_id, None, actor).await
    }

    /// End one session and record who did it. The single-session form of
    /// [`invalidate_user_sessions`](Self::invalidate_user_sessions), with the
    /// same error contract.
    ///
    /// # Errors
    ///
    /// As [`invalidate_user_sessions`](Self::invalidate_user_sessions).
    pub async fn invalidate_session(
        &self,
        user_id: &UserId,
        session_id: &SessionId,
        actor: Actor<'_>,
    ) -> Result<(), AuthnError<I::Error>> {
        self.revoke_session(user_id, session_id)
            .await
            .map_err(RevokeFailure::into_authn)?;
        self.audit_invalidation(user_id, Some(session_id), actor)
            .await
    }

    /// Write the `SessionInvalidated` row for a kick.
    pub(super) async fn audit_invalidation(
        &self,
        user_id: &UserId,
        session_id: Option<&SessionId>,
        actor: Actor<'_>,
    ) -> Result<(), AuthnError<I::Error>> {
        let tenant = self
            .inner
            .identity
            .get_user_tenant(user_id)
            .await
            .map_err(AuthnError::Store)?;
        let mut builder = AuthEventBuilder::new(
            Some(*user_id),
            tenant,
            AuthEventType::SessionInvalidated,
            AuthEventStatus::Success,
        );
        if let Some(actor) = actor.id() {
            builder = builder.with_actor(*actor);
        }
        if let Some(session_id) = session_id {
            builder = builder.with_session(*session_id);
        }
        self.emit_audit(builder).await
    }
}
