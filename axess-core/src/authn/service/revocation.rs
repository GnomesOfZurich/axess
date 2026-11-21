//! Ending sessions on purpose: an administrator's kick, a suspension, a
//! password reset. Every public entry point names who acted.

use super::{AuthnService, RequestAuthnService};
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventStatus, AuthEventType, AuthFailureReason},
    ids::UserId,
    store::{FactorStore, IdentityStore},
};
use crate::session::{
    id::SessionKey,
    store::{CutOff, RevocationError},
};

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

/// The `error` of the failed `SessionInvalidated` row
/// [`invalidate_other_sessions`](RequestAuthnService::invalidate_other_sessions)
/// writes when the registry did not end the user's other sessions.
pub const OTHER_SESSIONS_NOT_ENDED_REASON: &str = "other_sessions_not_ended";

/// The `error` of the failed `SessionInvalidated` row
/// [`invalidate_other_sessions`](RequestAuthnService::invalidate_other_sessions)
/// writes when the other sessions were ended and the user's refresh tokens
/// could not be revoked.
pub const REFRESH_TOKENS_NOT_REVOKED_REASON: &str = "refresh_tokens_not_revoked";

/// Why [`invalidate_other_sessions`](RequestAuthnService::invalidate_other_sessions)
/// did not leave the session to keep as the user's only credential in use,
/// and a record that says so.
///
/// Each variant says what was done. An audit write that failed is carried
/// beside the failure it was recording and never takes its place.
#[derive(Debug, thiserror::Error)]
pub enum OtherSessionsError<E: std::error::Error + Send + Sync + 'static> {
    /// Nothing was ended, no refresh token was revoked and no audit row was
    /// written: no registry is wired ([`AuthnError::Internal`]), or the
    /// registry does not hold the session to keep for the user
    /// ([`AuthnError::NoFlow`]).
    #[error(transparent)]
    Refused(AuthnError<E>),
    /// The registry did not confirm that it ended the other sessions
    /// (`cause`), so they may still be live. The refresh tokens were
    /// attempted all the same: `refresh_tokens` holds why they were not
    /// revoked, when they were not. A failed row naming
    /// [`OTHER_SESSIONS_NOT_ENDED_REASON`] was written, unless `audit` holds
    /// why it was not. Calling again ends what is left.
    #[error("the other sessions were not ended: {cause}")]
    SessionsNotEnded {
        /// Why the registry did not end the other sessions.
        cause: AuthnError<E>,
        /// Why the refresh tokens were not revoked, when they were not.
        refresh_tokens: Option<Box<AuthnError<E>>>,
        /// Why the failed row could not be written, when it could not.
        audit: Option<Box<AuthnError<E>>>,
    },
    /// Every other session was ended, and the user's refresh tokens were not
    /// revoked (`cause`): a token issued before the call can still mint a
    /// session. A failed row naming [`REFRESH_TOKENS_NOT_REVOKED_REASON`]
    /// was written, unless `audit` holds why it was not.
    #[error("the other sessions were ended, and the refresh tokens were not revoked: {cause}")]
    RefreshTokensNotRevoked {
        /// Why the refresh tokens were not revoked.
        cause: AuthnError<E>,
        /// Why the failed row could not be written, when it could not.
        audit: Option<Box<AuthnError<E>>>,
    },
    /// Every other session was ended and the refresh tokens were revoked,
    /// but the success row could not be written ([`AuthnError::Store`]).
    #[error("the other sessions were ended, and the audit row was not written: {0}")]
    Unrecorded(AuthnError<E>),
    /// Every session of the user was ended, the caller's own included, and
    /// the refresh tokens were revoked: another request that carried the
    /// caller's cookie had rotated the session before the cut-off ran, so the
    /// session to keep could not be told from a copy of it. The success row
    /// was written. The person signs in again.
    #[error(
        "every session of the user was ended, the caller's included: its key was rotated by another request"
    )]
    CallerEnded,
}

/// The error a handler that answers with [`AuthnError`] gives: the refusal,
/// the registry's or the refresh store's failure, or the audit failure, and
/// [`AuthnError::NoFlow`] for [`OtherSessionsError::CallerEnded`], what such
/// a handler saw for that race before. What was done and what was recorded
/// are lost on the way; match on [`OtherSessionsError`] to keep them.
impl<E> From<OtherSessionsError<E>> for AuthnError<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn from(error: OtherSessionsError<E>) -> Self {
        match error {
            OtherSessionsError::Refused(error) | OtherSessionsError::Unrecorded(error) => error,
            OtherSessionsError::SessionsNotEnded { cause, .. }
            | OtherSessionsError::RefreshTokensNotRevoked { cause, .. } => cause,
            OtherSessionsError::CallerEnded => AuthnError::NoFlow,
        }
    }
}

/// Whether ending a user's other sessions also revokes the user's refresh
/// tokens.
#[derive(Debug, Clone, Copy)]
enum RefreshTokens {
    Revoke,
    Keep,
}

/// Why sessions could not be ended.
pub(crate) enum RevokeFailure {
    /// No registry is wired, so nothing can be revoked.
    NoRegistry,
    /// The registry backend failed; the sessions may still be valid.
    Registry(RevocationError),
    /// The registry does not hold the named session for the named user: it
    /// is somebody else's, or already gone. Nothing was touched.
    NotHeld,
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
            Self::NotHeld => AuthnError::NoFlow,
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
        // Best effort: the rows of sessions the registry could not name are
        // left to expire, while `invalidate_user` below still runs and its
        // failure is what the caller hears.
        let live = reg.held_sessions(user_id).await.unwrap_or_else(|e| {
            tracing::warn!(
                user_id = %user_id,
                error = %e,
                "session registry could not list the user's sessions; \
                 their stored rows are not deleted here"
            );
            Vec::new()
        });
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
    /// [`revoke_user_sessions`](Self::revoke_user_sessions). Returns the key
    /// the session was under when it ended.
    ///
    /// `session` may be a key the session held before a rotation (a list
    /// read a moment ago): the registry answers the key the session is under
    /// now ([`SessionRevoker::current_key`](crate::session::store::SessionRevoker::current_key)),
    /// and that key is ended and its row deleted.
    ///
    /// The session must be one the registry holds for `user_id`, under
    /// `session` or a key a move took it to: the stored row is keyed by the
    /// session's key alone and the audit row names the caller's user, so a
    /// pair that does not match would end another user's session and record
    /// it against the wrong one. For such a pair nothing is touched: the row
    /// stays, no revocation is published, and the caller gets
    /// [`RevokeFailure::NotHeld`]. A registry that cannot be asked refuses
    /// too, rather than reading an outage as "not theirs".
    pub(crate) async fn revoke_session(
        &self,
        user_id: &UserId,
        session: &SessionKey,
    ) -> Result<SessionKey, RevokeFailure> {
        let Some(reg) = &self.inner.registry else {
            return Err(RevokeFailure::NoRegistry);
        };
        let held = reg
            .current_key(user_id, session)
            .await
            .map_err(RevokeFailure::Registry)?;
        let Some(current) = held else {
            tracing::warn!(
                user_id = %user_id,
                session_id = %session.prefix(),
                "session kick refused: the registry does not hold this session for this user"
            );
            return Err(RevokeFailure::NotHeld);
        };
        let revoked = reg.invalidate_session(user_id, &current).await;
        self.delete_session_rows(std::slice::from_ref(&current))
            .await;
        revoked.map_err(RevokeFailure::Registry)?;
        Ok(current)
    }

    /// Delete the stored rows of sessions the registry no longer holds, when a
    /// session store was wired. Best effort: a row that stays is refused on
    /// its next request by a layer that consults the registry, and expires
    /// with its TTL otherwise.
    async fn delete_session_rows(&self, keys: &[SessionKey]) {
        let Some(rows) = &self.inner.session_rows else {
            return;
        };
        for key in keys {
            if let Err(e) = rows.delete_row(key).await {
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
    /// same error contract plus one refusal: the session must be one the
    /// registry holds for `user_id`.
    ///
    /// `session` may be a key the session held before a rotation, such as
    /// one from a list of
    /// [`active_sessions`](crate::authn::service::AuthnService::active_sessions)
    /// read before a step-up: the session it led to is ended, and the audit
    /// row names the key the session was under when it ended.
    ///
    /// # Errors
    ///
    /// As [`invalidate_user_sessions`](Self::invalidate_user_sessions), and
    /// [`AuthnError::NoFlow`] when the registry holds no session of
    /// `user_id` under `session` or a key a move took it to (somebody else's
    /// session, or already gone): nothing is deleted, nothing is published
    /// and no audit row is written. A registry that cannot be asked is
    /// `ExternalService`, not a refusal that pretends to know.
    pub async fn invalidate_session(
        &self,
        user_id: &UserId,
        session: &SessionKey,
        actor: Actor<'_>,
    ) -> Result<(), AuthnError<I::Error>> {
        let ended = self
            .revoke_session(user_id, session)
            .await
            .map_err(RevokeFailure::into_authn)?;
        self.audit_invalidation(user_id, Some(&ended), actor).await
    }

    /// End every session of a user but one, revoke the user's refresh
    /// tokens, and record who did it: the call for a password or other
    /// credential change, after which the person who made the change stays
    /// signed in on the device they made it from and nothing issued before
    /// the change works anywhere else.
    ///
    /// Change the credential first, then call this. What is ended:
    ///
    /// - **Every session the registry holds for the user but `keep`**, in
    ///   one step of the registry
    ///   ([`SessionRegistry::invalidate_other_sessions`](crate::session::store::SessionRegistry::invalidate_other_sessions)):
    ///   a session that registers or moves to a new key while this runs is
    ///   ended with the rest or came after the step. A sign-in that began
    ///   before the credential changed and registers after the step is
    ///   refused by its own check of the credentials it began against. The
    ///   stored rows of the ended sessions are deleted when the service was
    ///   built with
    ///   [`with_session_store`](crate::authn::service::AuthnServiceBuilder::with_session_store).
    /// - **Every refresh token of the user**, in every family and on every
    ///   device, the caller's own device included, when the service was
    ///   built with
    ///   [`with_refresh_store`](crate::authn::service::AuthnServiceBuilder::with_refresh_store):
    ///   a refresh token mints a session and would outlive the cut-off. A
    ///   caller that holds one is issued a new one after this call. Without
    ///   that store the service cannot reach refresh tokens and they stay
    ///   as they were.
    ///   [`invalidate_other_sessions_keeping_refresh_tokens`](Self::invalidate_other_sessions_keeping_refresh_tokens)
    ///   ends the sessions only.
    ///
    /// What is not touched: `keep`, the user's device records (the refresh
    /// families their bindings name are revoked with the tokens), and
    /// credentials the service does not hold, such as tokens issued by an
    /// identity provider.
    ///
    /// `keep` is the key the registry holds for the caller's session:
    /// [`AuthSession::registered_key`](crate::session::AuthSession::registered_key),
    /// before or after an
    /// [`AuthSession::regenerate`](crate::session::AuthSession::regenerate)
    /// or a [`rotate_session`](Self::rotate_session) in the same handler (the
    /// session layer moves the registry entry to a rotated key only as the
    /// response is written). The caller is kept when its own request holds the key the registry
    /// holds the session under. When another request of the same session
    /// had rotated it to a new key before the step ran, the session to keep
    /// cannot be told from a copy of its cookie: every session of the user
    /// is ended, the caller's included, the refresh tokens are revoked and
    /// the success row is written, and the call answers
    /// [`OtherSessionsError::CallerEnded`]. The person signs in again.
    ///
    /// One `SessionInvalidated` audit row is written for the user. It names
    /// no session, because it stands for all that ended, and `actor` as who
    /// acted: [`Actor::System`] when the user acts for themselves, which
    /// leaves the row without an actor as a self-service row is.
    ///
    /// # Errors
    ///
    /// An [`OtherSessionsError`] says which of these happened: refused with
    /// nothing done, the sessions not confirmed ended, the sessions ended
    /// and the refresh tokens not revoked, everything done and the audit
    /// row not written, or everything done with the caller's own session
    /// ended too. A failed audit write never hides what happened to the
    /// sessions and the tokens: it is carried beside it.
    pub async fn invalidate_other_sessions(
        &self,
        user_id: &UserId,
        keep: &SessionKey,
        actor: Actor<'_>,
    ) -> Result<(), OtherSessionsError<I::Error>> {
        self.end_other_sessions(user_id, keep, actor, RefreshTokens::Revoke)
            .await
    }

    /// End every session of a user but one and leave the user's refresh
    /// tokens as they are:
    /// [`invalidate_other_sessions`](Self::invalidate_other_sessions) without
    /// the revocation of refresh tokens, for a deployment that revokes them
    /// by a rule of its own (per device, or after a grace period).
    ///
    /// A refresh token issued before the call still mints a session after
    /// it. Do not call this for a changed password unless every such token
    /// is ended some other way.
    ///
    /// # Errors
    ///
    /// As [`invalidate_other_sessions`](Self::invalidate_other_sessions),
    /// without the refresh token cases.
    pub async fn invalidate_other_sessions_keeping_refresh_tokens(
        &self,
        user_id: &UserId,
        keep: &SessionKey,
        actor: Actor<'_>,
    ) -> Result<(), OtherSessionsError<I::Error>> {
        self.end_other_sessions(user_id, keep, actor, RefreshTokens::Keep)
            .await
    }

    async fn end_other_sessions(
        &self,
        user_id: &UserId,
        keep: &SessionKey,
        actor: Actor<'_>,
        refresh_tokens: RefreshTokens,
    ) -> Result<(), OtherSessionsError<I::Error>> {
        let Some(reg) = &self.inner.registry else {
            return Err(OtherSessionsError::Refused(
                RevokeFailure::NoRegistry.into_authn(),
            ));
        };
        // Whether the caller's own session was ended with the rest: another
        // request had moved it, and the step ended it (see `CutOff`).
        let mut caller_ended = false;
        let sessions = match reg.invalidate_other_sessions(user_id, keep).await {
            Ok(CutOff::KeptOne(ended)) => {
                self.delete_session_rows(&ended).await;
                Ok(())
            }
            Ok(CutOff::KeptNone(ended)) => {
                caller_ended = true;
                self.delete_session_rows(&ended).await;
                Ok(())
            }
            Ok(CutOff::NotHeld) => {
                tracing::warn!(
                    user_id = %user_id,
                    session_id = %keep.prefix(),
                    "ending the other sessions refused: the registry does not hold \
                     the session to keep for this user"
                );
                return Err(OtherSessionsError::Refused(AuthnError::NoFlow));
            }
            Err(e) => Err(RevokeFailure::Registry(e).into_authn()),
        };
        // The tokens are revoked whether or not the registry answered: a
        // registry outage is no reason to leave them live as well.
        let tokens = match refresh_tokens {
            RefreshTokens::Revoke => self.revoke_refresh_tokens(user_id).await,
            RefreshTokens::Keep => Ok(()),
        };

        match (sessions, tokens) {
            (Ok(()), Ok(())) => {
                self.audit_invalidation(user_id, None, actor)
                    .await
                    .map_err(OtherSessionsError::Unrecorded)?;
                if caller_ended {
                    Err(OtherSessionsError::CallerEnded)
                } else {
                    Ok(())
                }
            }
            (Err(cause), tokens) => Err(OtherSessionsError::SessionsNotEnded {
                cause,
                refresh_tokens: tokens.err().map(Box::new),
                audit: self
                    .failed_invalidation_row(user_id, actor, OTHER_SESSIONS_NOT_ENDED_REASON)
                    .await,
            }),
            (Ok(()), Err(cause)) => Err(OtherSessionsError::RefreshTokensNotRevoked {
                cause,
                audit: self
                    .failed_invalidation_row(user_id, actor, REFRESH_TOKENS_NOT_REVOKED_REASON)
                    .await,
            }),
        }
    }

    /// Write the failed `SessionInvalidated` row naming `reason`, and return
    /// why it could not be written, when it could not.
    async fn failed_invalidation_row(
        &self,
        user_id: &UserId,
        actor: Actor<'_>,
        reason: &'static str,
    ) -> Option<Box<AuthnError<I::Error>>> {
        self.audit_invalidation_outcome(user_id, None, actor, Some(AuthFailureReason::from(reason)))
            .await
            .err()
            .map(Box::new)
    }

    /// Write the `SessionInvalidated` row for a kick.
    pub(super) async fn audit_invalidation(
        &self,
        user_id: &UserId,
        session: Option<&SessionKey>,
        actor: Actor<'_>,
    ) -> Result<(), AuthnError<I::Error>> {
        self.audit_invalidation_outcome(user_id, session, actor, None)
            .await
    }

    /// Write a `SessionInvalidated` row: a success, or a failure for
    /// `not_ended`.
    async fn audit_invalidation_outcome(
        &self,
        user_id: &UserId,
        session: Option<&SessionKey>,
        actor: Actor<'_>,
        not_ended: Option<AuthFailureReason>,
    ) -> Result<(), AuthnError<I::Error>> {
        let tenant = self
            .inner
            .identity
            .get_user_tenant(user_id)
            .await
            .map_err(AuthnError::Store)?;
        let status = match not_ended {
            Some(_) => AuthEventStatus::Failure,
            None => AuthEventStatus::Success,
        };
        let mut builder = AuthEventBuilder::new(
            Some(*user_id),
            tenant,
            AuthEventType::SessionInvalidated,
            status,
        );
        if let Some(reason) = not_ended {
            builder = builder.with_error(reason);
        }
        if let Some(actor) = actor.id() {
            builder = builder.with_actor(*actor);
        }
        if let Some(session) = session {
            builder = builder.with_session(*session);
        }
        self.emit_audit(builder).await
    }
}
