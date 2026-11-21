//! Dyn-safe handles over a session registry: revocation, liveness and
//! registration, plus the adapter that erases a concrete registry.

use crate::session::{
    id::SessionKey,
    store::{CutOff, MoveOutcome, SessionRegistry},
};
use std::future::Future;
use std::pin::Pin;

// Dyn-safe adapters over `SessionRegistry`. The trait uses RPITIT + an
// associated `Error` so it is not dyn-safe; `SessionRevoker` narrows to
// the logout surface (`invalidate_*`) and `SessionRegistryHandle` adds
// the full registry surface used by `AuthnService`. Error handling is
// baked in: `is_valid` fails closed, `invalidate_*` report a failed
// revocation as a [`RevocationError`], `register` returns `bool`,
// `held_sessions` returns the registry's error, and so does
// `active_sessions`, which is built on it. With a concurrent-session cap
// set, a login whose listing fails is refused.

/// What [`SessionRegistryHandle::invalidate_other_sessions`] answers: the
/// registry's [`CutOff`], which names the sessions that were ended and
/// whether the session to keep was among them.
pub type OtherSessionsEnded = Result<CutOff, RevocationError>;

/// A revocation the registry could not carry out.
///
/// The registry backend failed (an outage, a lost connection), so the
/// sessions named by the call may still be valid. A caller that ends a
/// session in its own state as well (logout) may log this and go on; an
/// administrator action that promises the sessions are gone must surface it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("session registry revocation failed: {0}")]
pub struct RevocationError(pub String);

/// Record a revocation that failed on a path that has already ended the
/// session in its own state and cannot do more about the registry: the login
/// steps that refuse a session, the logout that clears it. Paths that promise
/// the sessions are gone (an administrator's kick, a suspension, a password
/// reset) return the error instead.
pub(crate) fn note_revocation(result: Result<(), RevocationError>, during: &str) {
    if let Err(e) = result {
        tracing::warn!(error = %e, during, "the registry did not confirm the revocation");
    }
}

/// Dyn-safe narrow handle for session revocation. Implemented by
/// [`SessionRegistryAdapter`]; consumers (logout handlers) take
/// `Arc<dyn SessionRevoker>` so they can't accidentally call broader
/// registry operations.
pub trait SessionRevoker: Send + Sync + 'static {
    /// Invalidate every session belonging to the user.
    ///
    /// # Errors
    ///
    /// [`RevocationError`] when the registry backend failed, so the user's
    /// sessions may still be valid.
    fn invalidate_user<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
    ) -> Pin<Box<dyn Future<Output = Result<(), RevocationError>> + Send + 'a>>;

    /// Invalidate a single session for the user.
    ///
    /// # Errors
    ///
    /// [`RevocationError`] when the registry backend failed, so the session
    /// may still be valid.
    fn invalidate_session<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
        session: &'a SessionKey,
    ) -> Pin<Box<dyn Future<Output = Result<(), RevocationError>> + Send + 'a>>;

    /// The key the session once under `session` is under now:
    /// [`SessionRegistry::current_key`]. `Ok(None)` when the registry holds
    /// no live session under it and no record of a move from it.
    ///
    /// Required: a logout that holds a key from before a rotation finds the
    /// session by it, and a handle that answered `None` for every key would
    /// let that session stay signed in.
    ///
    /// # Errors
    ///
    /// [`RevocationError`] when the registry backend failed, so nothing is
    /// known.
    fn current_key<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
        session: &'a SessionKey,
    ) -> Pin<Box<dyn Future<Output = Result<Option<SessionKey>, RevocationError>> + Send + 'a>>;
}

/// What the registry can say about one session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionLiveness {
    /// The registry holds the session as valid.
    Valid,
    /// The registry answered and does not hold the session as valid.
    Gone,
    /// The registry could not answer (an error), so nothing is known.
    Unknown,
}

/// Dyn-safe full handle for the session registry. Adds session
/// registration + validity-check + active-session listing on top of
/// [`SessionRevoker`].
pub trait SessionRegistryHandle: SessionRevoker {
    /// Return `true` if the named session is still valid for the user.
    /// Fails closed on registry error.
    fn is_valid<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
        session: &'a SessionKey,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;

    /// Three-way liveness of a session: [`SessionLiveness::Gone`] only when
    /// the registry answered that the session is not valid, and
    /// [`SessionLiveness::Unknown`] when it could not answer. Bookkeeping
    /// that drops state for ended sessions acts on `Gone` alone.
    ///
    /// Required: [`is_valid`](Self::is_valid) fails closed with `false`, so
    /// it cannot tell an error from a negative answer, and a handle that
    /// derived `liveness` from it could only ever say `Unknown` for a revoked
    /// session. [`SessionRegistryAdapter`] reports the exact answer.
    fn liveness<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
        session: &'a SessionKey,
    ) -> Pin<Box<dyn Future<Output = SessionLiveness> + Send + 'a>>;

    /// Register a session under the user. Returns `true` on success,
    /// `false` on registry error. Callers that *require* the registry
    /// to track the session (signup, factor completion) should react to
    /// `false` by clearing the session and refusing authentication.
    fn register<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
        session: &'a SessionKey,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;

    /// Move the session under `old` to `new` in one step of the registry:
    /// [`SessionRegistry::move_session`].
    ///
    /// Required: a handle has no one-step form to fall back on, and a
    /// registration followed by a removal would hold both keys between the
    /// two.
    ///
    /// # Errors
    ///
    /// [`RevocationError`] when the registry backend failed, so the session
    /// may still be under `old`, or already under `new`.
    fn move_session<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
        old: &'a SessionKey,
        new: &'a SessionKey,
    ) -> Pin<Box<dyn Future<Output = Result<MoveOutcome, RevocationError>> + Send + 'a>>;

    /// The sessions the registry holds for the user, oldest first, or the
    /// error when it could not answer. The paths that must know whose a
    /// session is before acting on it (an administrator's kick of one
    /// session) read this, so an outage refuses rather than passes as
    /// "none".
    ///
    /// Required: a registry that cannot list sessions returns the error,
    /// and the callers that may go on without the list say so themselves
    /// (see [`active_sessions`](Self::active_sessions)).
    fn held_sessions<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SessionKey>, RevocationError>> + Send + 'a>>;

    /// End every session of the user but `keep` in one step of the store:
    /// [`SessionRegistry::invalidate_other_sessions`].
    /// `Ok(CutOff::NotHeld)` when the registry holds no session under
    /// `keep` for the user and no record of a move from it, with nothing
    /// ended; `Ok(CutOff::KeptNone(..))` when another request had moved
    /// that session, which is then ended with the rest.
    ///
    /// The provided body refuses: a handle that is not built over a
    /// [`SessionRegistry`] has no one-step form to call, and ending the
    /// sessions one by one would report a cut-off that was not made.
    /// [`SessionRegistryAdapter`] forwards to the registry.
    ///
    /// # Errors
    ///
    /// [`RevocationError`] when the registry backend failed, so the other
    /// sessions may still be valid.
    fn invalidate_other_sessions<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
        keep: &'a SessionKey,
    ) -> Pin<Box<dyn Future<Output = OtherSessionsEnded> + Send + 'a>> {
        Box::pin(async move {
            tracing::error!(
                user_id = %user_id,
                session_id = %keep.prefix(),
                "this registry handle cannot end a user's other sessions in one step"
            );
            Err(RevocationError(
                "the registry handle has no one-step form of ending the other sessions".to_owned(),
            ))
        })
    }

    /// The same list as [`held_sessions`](Self::held_sessions), under the name
    /// admin session lists use. A registry that cannot answer returns the
    /// error, never an empty list: "no sessions" and "could not ask" must not
    /// look alike to a caller that enforces a limit or revokes on the result.
    fn active_sessions<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SessionKey>, RevocationError>> + Send + 'a>> {
        self.held_sessions(user_id)
    }
}

/// Type-erasing adapter that turns any concrete [`SessionRegistry`] into
/// `dyn SessionRevoker` *and* `dyn SessionRegistryHandle`. One wrapper
/// for both shapes; pick the trait that matches the call site's needs.
pub struct SessionRegistryAdapter<T: SessionRegistry>(pub T);

impl<T: SessionRegistry + 'static> SessionRevoker for SessionRegistryAdapter<T> {
    fn invalidate_user<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
    ) -> Pin<Box<dyn Future<Output = Result<(), RevocationError>> + Send + 'a>> {
        Box::pin(async move {
            self.0.invalidate_user(user_id).await.map_err(|e| {
                tracing::warn!(
                    user_id = %user_id,
                    error = %e,
                    "session registry invalidate_user failed; user sessions may remain active"
                );
                RevocationError(e.to_string())
            })
        })
    }

    fn invalidate_session<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
        session: &'a SessionKey,
    ) -> Pin<Box<dyn Future<Output = Result<(), RevocationError>> + Send + 'a>> {
        Box::pin(async move {
            self.0
                .invalidate_session(user_id, session)
                .await
                .map_err(|e| {
                    tracing::warn!(
                        user_id = %user_id,
                        error = %e,
                        "session registry invalidate_session failed; the session may remain active"
                    );
                    RevocationError(e.to_string())
                })
        })
    }

    fn current_key<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
        session: &'a SessionKey,
    ) -> Pin<Box<dyn Future<Output = Result<Option<SessionKey>, RevocationError>> + Send + 'a>>
    {
        Box::pin(async move {
            self.0.current_key(user_id, session).await.map_err(|e| {
                tracing::warn!(
                    user_id = %user_id,
                    error = %e,
                    "session registry current_key failed; the session's current key is unknown"
                );
                RevocationError(e.to_string())
            })
        })
    }
}

impl<T: SessionRegistry + 'static> SessionRegistryHandle for SessionRegistryAdapter<T> {
    fn liveness<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
        session: &'a SessionKey,
    ) -> Pin<Box<dyn Future<Output = SessionLiveness> + Send + 'a>> {
        Box::pin(async move {
            match self.0.is_valid(user_id, session).await {
                Ok(true) => SessionLiveness::Valid,
                Ok(false) => SessionLiveness::Gone,
                Err(e) => {
                    tracing::warn!(
                        user_id = %user_id,
                        error = %e,
                        "session registry liveness check failed; treating as unknown"
                    );
                    SessionLiveness::Unknown
                }
            }
        })
    }

    fn is_valid<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
        session: &'a SessionKey,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            match self.0.is_valid(user_id, session).await {
                Ok(valid) => valid,
                Err(e) => {
                    tracing::warn!(
                        user_id = %user_id,
                        error = %e,
                        "session registry is_valid check failed; failing closed"
                    );
                    false
                }
            }
        })
    }

    fn register<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
        session: &'a SessionKey,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            match self.0.register(user_id, session).await {
                Ok(()) => true,
                Err(e) => {
                    tracing::warn!(
                        user_id = %user_id,
                        error = %e,
                        "session registry register failed; caller must clear the session \
                         to avoid an Authenticated-but-untracked outcome"
                    );
                    false
                }
            }
        })
    }

    fn move_session<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
        old: &'a SessionKey,
        new: &'a SessionKey,
    ) -> Pin<Box<dyn Future<Output = Result<MoveOutcome, RevocationError>> + Send + 'a>> {
        Box::pin(async move {
            self.0.move_session(user_id, old, new).await.map_err(|e| {
                tracing::warn!(
                    user_id = %user_id,
                    error = %e,
                    "session registry move_session failed; the session may be under \
                     either key"
                );
                RevocationError(e.to_string())
            })
        })
    }

    fn held_sessions<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SessionKey>, RevocationError>> + Send + 'a>> {
        Box::pin(async move {
            self.0
                .active_sessions(user_id)
                .await
                .map_err(|e| RevocationError(e.to_string()))
        })
    }

    fn invalidate_other_sessions<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
        keep: &'a SessionKey,
    ) -> Pin<Box<dyn Future<Output = OtherSessionsEnded> + Send + 'a>> {
        Box::pin(async move {
            self.0
                .invalidate_other_sessions(user_id, keep)
                .await
                .map_err(|e| {
                    tracing::warn!(
                        user_id = %user_id,
                        error = %e,
                        "session registry invalidate_other_sessions failed; the user's \
                         other sessions may remain active"
                    );
                    RevocationError(e.to_string())
                })
        })
    }
}

#[cfg(test)]
mod tests;
