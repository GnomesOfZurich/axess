//! A session registry for tests that records every call and takes a hook
//! before and after each.
//!
//! [`RegistryDouble`] wraps a [`MemorySessionRegistry`]. Each call of the
//! [`SessionRegistry`] surface is first recorded, then put to the `before`
//! hook, which answers a [`Step`]: pass the call on to the registry inside,
//! answer it with an error, or never answer it. A call that was passed on
//! and answered is then put to the `after` hook. Both hooks are given the
//! call and the registry inside, so a hook can wait, read a flag, count, or
//! change what the registry holds before or after the call lands.
//!
//! ```rust
//! use axess_core::SessionRegistry;
//! use axess_core::authn::ids::UserId;
//! use axess_core::session::id::SessionKey;
//! use axess_core::testing::registry_double::{RegistryCall, RegistryDouble, RegistryOp, Step};
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! // A registry that refuses every registration and answers the rest.
//! let registry = RegistryDouble::new().before(|call, _| async move {
//!     match call {
//!         RegistryCall::Register { .. } => Step::Fail("registration refused"),
//!         _ => Step::Forward,
//!     }
//! });
//! let user = UserId::system();
//! let session = SessionKey::from_bytes([1; 32]);
//! assert!(registry.register(&user, &session).await.is_err());
//! assert!(!registry.is_valid(&user, &session).await.unwrap());
//! assert_eq!(registry.count(RegistryOp::Register), 1);
//! assert_eq!(registry.calls().len(), 2);
//! # });
//! ```
//!
//! The double reads no clock of its own. A test that needs time builds the
//! registry inside with [`MemorySessionRegistry::with_clock`] and hands it to
//! [`RegistryDouble::over`].
//!
//! [`watch_revocation`](SessionRegistry::watch_revocation) is passed to the
//! registry inside as it is, neither recorded nor put to a hook.

use crate::authn::ids::UserId;
use crate::locked::lock;
use crate::session::id::SessionKey;
use crate::session::store::{
    CutOff, MemoryRegistryError, MemorySessionRegistry, MoveOutcome, SessionRegistry,
    SessionRegistryAdapter, SessionRegistryHandle,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

/// One call on a registry, as the double saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryCall {
    /// [`SessionRegistry::register`].
    Register {
        /// The user the session is registered under.
        user: UserId,
        /// The session registered.
        session: SessionKey,
    },
    /// [`SessionRegistry::is_valid`].
    IsValid {
        /// The user asked about.
        user: UserId,
        /// The session asked about.
        session: SessionKey,
    },
    /// [`SessionRegistry::invalidate_user`].
    InvalidateUser {
        /// The user whose sessions are ended.
        user: UserId,
    },
    /// [`SessionRegistry::invalidate_session`].
    InvalidateSession {
        /// The user the session belongs to.
        user: UserId,
        /// The session ended.
        session: SessionKey,
    },
    /// [`SessionRegistry::invalidate_other_sessions`].
    InvalidateOtherSessions {
        /// The user whose other sessions are ended.
        user: UserId,
        /// The session kept.
        keep: SessionKey,
    },
    /// [`SessionRegistry::active_sessions`].
    ActiveSessions {
        /// The user whose sessions are listed.
        user: UserId,
    },
    /// [`SessionRegistry::move_session`].
    MoveSession {
        /// The user the session belongs to.
        user: UserId,
        /// The key the session is moved from.
        old: SessionKey,
        /// The key the session is moved to.
        new: SessionKey,
    },
    /// [`SessionRegistry::current_key`].
    CurrentKey {
        /// The user asked about.
        user: UserId,
        /// The key asked about.
        session: SessionKey,
    },
}

impl RegistryCall {
    /// Which method this call is.
    pub fn op(&self) -> RegistryOp {
        match self {
            Self::Register { .. } => RegistryOp::Register,
            Self::IsValid { .. } => RegistryOp::IsValid,
            Self::InvalidateUser { .. } => RegistryOp::InvalidateUser,
            Self::InvalidateSession { .. } => RegistryOp::InvalidateSession,
            Self::InvalidateOtherSessions { .. } => RegistryOp::InvalidateOtherSessions,
            Self::ActiveSessions { .. } => RegistryOp::ActiveSessions,
            Self::MoveSession { .. } => RegistryOp::MoveSession,
            Self::CurrentKey { .. } => RegistryOp::CurrentKey,
        }
    }

    /// The user the call names.
    pub fn user(&self) -> &UserId {
        match self {
            Self::Register { user, .. }
            | Self::IsValid { user, .. }
            | Self::InvalidateUser { user }
            | Self::InvalidateSession { user, .. }
            | Self::InvalidateOtherSessions { user, .. }
            | Self::ActiveSessions { user }
            | Self::MoveSession { user, .. }
            | Self::CurrentKey { user, .. } => user,
        }
    }

    /// The session the call names, the one kept for
    /// [`InvalidateOtherSessions`](Self::InvalidateOtherSessions) and the
    /// one moved from for [`MoveSession`](Self::MoveSession); `None` for a
    /// call that names only a user.
    pub fn session(&self) -> Option<&SessionKey> {
        match self {
            Self::Register { session, .. }
            | Self::IsValid { session, .. }
            | Self::InvalidateSession { session, .. }
            | Self::CurrentKey { session, .. } => Some(session),
            Self::MoveSession { old, .. } => Some(old),
            Self::InvalidateOtherSessions { keep, .. } => Some(keep),
            Self::InvalidateUser { .. } | Self::ActiveSessions { .. } => None,
        }
    }
}

/// Which method a call is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegistryOp {
    /// [`SessionRegistry::register`].
    Register,
    /// [`SessionRegistry::is_valid`].
    IsValid,
    /// [`SessionRegistry::invalidate_user`].
    InvalidateUser,
    /// [`SessionRegistry::invalidate_session`].
    InvalidateSession,
    /// [`SessionRegistry::invalidate_other_sessions`].
    InvalidateOtherSessions,
    /// [`SessionRegistry::active_sessions`].
    ActiveSessions,
    /// [`SessionRegistry::move_session`].
    MoveSession,
    /// [`SessionRegistry::current_key`].
    CurrentKey,
}

/// What the double does with a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Pass it to the registry inside.
    Forward,
    /// Answer with an error carrying this text.
    Fail(&'static str),
    /// Never answer.
    Hang,
}

/// The error a [`RegistryDouble`] answers a call its `before` hook failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("registry double: {0}")]
pub struct RegistryDoubleError(pub String);

type BeforeHook = Arc<
    dyn Fn(RegistryCall, MemorySessionRegistry) -> Pin<Box<dyn Future<Output = Step> + Send>>
        + Send
        + Sync,
>;
type AfterHook = Arc<
    dyn Fn(RegistryCall, MemorySessionRegistry) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

#[derive(Default)]
struct Hooks {
    before: Option<BeforeHook>,
    after: Option<AfterHook>,
}

/// A [`MemorySessionRegistry`] behind two hooks. It records every call.
///
/// A clone shares the registry inside, the record of calls and the hooks:
/// a hook set on one clone holds for every clone.
#[derive(Clone)]
pub struct RegistryDouble {
    inner: MemorySessionRegistry,
    calls: Arc<Mutex<Vec<RegistryCall>>>,
    hooks: Arc<Mutex<Hooks>>,
}

impl Default for RegistryDouble {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for RegistryDouble {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hooks = lock(&self.hooks);
        f.debug_struct("RegistryDouble")
            .field("calls", &lock(&self.calls).len())
            .field("before", &hooks.before.is_some())
            .field("after", &hooks.after.is_some())
            .finish_non_exhaustive()
    }
}

impl RegistryDouble {
    /// A double over a new [`MemorySessionRegistry`] that passes every call
    /// on.
    pub fn new() -> Self {
        Self::over(MemorySessionRegistry::new())
    }

    /// A double over `inner` that passes every call on.
    pub fn over(inner: MemorySessionRegistry) -> Self {
        Self {
            inner,
            calls: Arc::default(),
            hooks: Arc::default(),
        }
    }

    /// Runs before a call and decides what becomes of it. It may wait.
    ///
    /// The call is recorded before the hook runs, so a call the hook fails
    /// or holds is in [`calls`](Self::calls) as well. A second `before`
    /// replaces the hook given earlier.
    pub fn before<F, Fut>(self, hook: F) -> Self
    where
        F: Fn(RegistryCall, MemorySessionRegistry) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Step> + Send + 'static,
    {
        lock(&self.hooks).before = Some(Arc::new(move |call, inner| Box::pin(hook(call, inner))));
        self
    }

    /// Runs after a call that was forwarded and answered.
    ///
    /// The caller has its answer once the hook is done, so what the hook
    /// changes lands between the registry's answer and the caller reading
    /// it. A second `after` replaces the hook given earlier.
    pub fn after<F, Fut>(self, hook: F) -> Self
    where
        F: Fn(RegistryCall, MemorySessionRegistry) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        lock(&self.hooks).after = Some(Arc::new(move |call, inner| Box::pin(hook(call, inner))));
        self
    }

    /// The registry inside.
    pub fn inner(&self) -> &MemorySessionRegistry {
        &self.inner
    }

    /// Every call so far, in the order the calls reached the double.
    pub fn calls(&self) -> Vec<RegistryCall> {
        lock(&self.calls).clone()
    }

    /// How many of the calls so far were `op`.
    pub fn count(&self, op: RegistryOp) -> usize {
        lock(&self.calls)
            .iter()
            .filter(|call| call.op() == op)
            .count()
    }

    /// This double as the handle the session layer and the authentication
    /// service take, through [`SessionRegistryAdapter`].
    pub fn handle(self) -> Arc<dyn SessionRegistryHandle> {
        Arc::new(SessionRegistryAdapter(self))
    }

    /// Record `call`, ask the `before` hook, and only on
    /// [`Step::Forward`] hand the registry inside to `forward`; then the
    /// `after` hook. The hooks are read once, when the call arrives.
    async fn run<T, Fut>(
        &self,
        call: RegistryCall,
        forward: impl FnOnce(MemorySessionRegistry) -> Fut,
    ) -> Result<T, RegistryDoubleError>
    where
        Fut: Future<Output = Result<T, MemoryRegistryError>>,
    {
        lock(&self.calls).push(call.clone());
        let (before, after) = {
            let hooks = lock(&self.hooks);
            (hooks.before.clone(), hooks.after.clone())
        };
        let step = match before {
            Some(hook) => hook(call.clone(), self.inner.clone()).await,
            None => Step::Forward,
        };
        match step {
            Step::Forward => {}
            Step::Fail(reason) => return Err(RegistryDoubleError(reason.to_owned())),
            Step::Hang => std::future::pending::<()>().await,
        }
        let answer = match forward(self.inner.clone()).await {
            Ok(answer) => answer,
            Err(never) => match never {},
        };
        if let Some(hook) = after {
            hook(call, self.inner.clone()).await;
        }
        Ok(answer)
    }
}

impl SessionRegistry for RegistryDouble {
    type Error = RegistryDoubleError;

    async fn register(&self, user: &UserId, session: &SessionKey) -> Result<(), Self::Error> {
        let call = RegistryCall::Register {
            user: *user,
            session: *session,
        };
        self.run(
            call,
            |inner| async move { inner.register(user, session).await },
        )
        .await
    }

    async fn is_valid(&self, user: &UserId, session: &SessionKey) -> Result<bool, Self::Error> {
        let call = RegistryCall::IsValid {
            user: *user,
            session: *session,
        };
        self.run(
            call,
            |inner| async move { inner.is_valid(user, session).await },
        )
        .await
    }

    async fn invalidate_user(&self, user: &UserId) -> Result<(), Self::Error> {
        let call = RegistryCall::InvalidateUser { user: *user };
        self.run(
            call,
            |inner| async move { inner.invalidate_user(user).await },
        )
        .await
    }

    async fn invalidate_session(
        &self,
        user: &UserId,
        session: &SessionKey,
    ) -> Result<(), Self::Error> {
        let call = RegistryCall::InvalidateSession {
            user: *user,
            session: *session,
        };
        self.run(call, |inner| async move {
            inner.invalidate_session(user, session).await
        })
        .await
    }

    async fn invalidate_other_sessions(
        &self,
        user: &UserId,
        keep: &SessionKey,
    ) -> Result<CutOff, Self::Error> {
        let call = RegistryCall::InvalidateOtherSessions {
            user: *user,
            keep: *keep,
        };
        self.run(call, |inner| async move {
            inner.invalidate_other_sessions(user, keep).await
        })
        .await
    }

    async fn move_session(
        &self,
        user: &UserId,
        old: &SessionKey,
        new: &SessionKey,
    ) -> Result<MoveOutcome, Self::Error> {
        let call = RegistryCall::MoveSession {
            user: *user,
            old: *old,
            new: *new,
        };
        self.run(call, |inner| async move {
            inner.move_session(user, old, new).await
        })
        .await
    }

    async fn current_key(
        &self,
        user: &UserId,
        session: &SessionKey,
    ) -> Result<Option<SessionKey>, Self::Error> {
        let call = RegistryCall::CurrentKey {
            user: *user,
            session: *session,
        };
        self.run(call, |inner| async move {
            inner.current_key(user, session).await
        })
        .await
    }

    async fn active_sessions(&self, user: &UserId) -> Result<Vec<SessionKey>, Self::Error> {
        let call = RegistryCall::ActiveSessions { user: *user };
        self.run(
            call,
            |inner| async move { inner.active_sessions(user).await },
        )
        .await
    }

    async fn watch_revocation(&self, user: &UserId, session: &SessionKey) {
        self.inner.watch_revocation(user, session).await;
    }
}

#[cfg(test)]
mod tests;
