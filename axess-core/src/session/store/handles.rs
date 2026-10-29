//! Dyn-safe handles over a session registry: revocation, liveness and
//! registration, plus the adapter that erases a concrete registry.

use crate::session::{id::SessionId, store::SessionRegistry};
use std::future::Future;
use std::pin::Pin;

// Dyn-safe adapters over `SessionRegistry`. The trait uses RPITIT + an
// associated `Error` so it is not dyn-safe; `SessionRevoker` narrows to
// the logout surface (`invalidate_*`) and `SessionRegistryHandle` adds
// the full registry surface used by `AuthnService`. Error handling is
// baked in: `is_valid` fails closed, `invalidate_*` report a failed
// revocation as a [`RevocationError`], `register` returns `bool`,
// `active_sessions` fails open with `vec![]` so registry outages don't
// lock users out.

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
        session_id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = Result<(), RevocationError>> + Send + 'a>>;
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
        session_id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;

    /// Three-way liveness of a session: [`SessionLiveness::Gone`] only when
    /// the registry answered that the session is not valid, and
    /// [`SessionLiveness::Unknown`] when it could not answer. Bookkeeping
    /// that drops state for ended sessions acts on `Gone` alone.
    ///
    /// The default cannot tell an error from a negative answer, because
    /// [`is_valid`](Self::is_valid) fails closed with `false`; it reports
    /// `Unknown` for `false`. [`SessionRegistryAdapter`] overrides it with the
    /// exact answer.
    fn liveness<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
        session_id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = SessionLiveness> + Send + 'a>> {
        Box::pin(async move {
            if self.is_valid(user_id, session_id).await {
                SessionLiveness::Valid
            } else {
                SessionLiveness::Unknown
            }
        })
    }

    /// Register a session under the user. Returns `true` on success,
    /// `false` on registry error. Callers that *require* the registry
    /// to track the session (signup, factor completion) should react to
    /// `false` by clearing the session and refusing authentication.
    fn register<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
        session_id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;

    /// Return all active session IDs for the user, oldest first.
    /// Fails open with an empty vec on registry error so the
    /// concurrent-session limit doesn't lock users out during outage.
    fn active_sessions<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
    ) -> Pin<Box<dyn Future<Output = Vec<SessionId>> + Send + 'a>>;
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
        session_id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = Result<(), RevocationError>> + Send + 'a>> {
        Box::pin(async move {
            self.0
                .invalidate_session(user_id, session_id)
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
}

impl<T: SessionRegistry + 'static> SessionRegistryHandle for SessionRegistryAdapter<T> {
    fn liveness<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
        session_id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = SessionLiveness> + Send + 'a>> {
        Box::pin(async move {
            match self.0.is_valid(user_id, session_id).await {
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
        session_id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            match self.0.is_valid(user_id, session_id).await {
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
        session_id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            match self.0.register(user_id, session_id).await {
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

    fn active_sessions<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
    ) -> Pin<Box<dyn Future<Output = Vec<SessionId>> + Send + 'a>> {
        Box::pin(async move {
            match self.0.active_sessions(user_id).await {
                Ok(sessions) => sessions,
                Err(e) => {
                    tracing::error!(
                        user_id = %user_id,
                        error = %e,
                        "session registry active_sessions failed; concurrent session limit disabled for this request"
                    );
                    Vec::new()
                }
            }
        })
    }
}
