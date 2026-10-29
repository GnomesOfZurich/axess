//! WebSocket helpers: revocation-aware connection wrapper.
//!
//! `axess` itself is transport-agnostic. This module is a thin convenience
//! layer for the common case of long-lived WebSocket connections that should
//! close cleanly when the underlying session is revoked.
//!
//! # Why this exists
//!
//! HTTP requests check session validity on every request via
//! `SessionRegistry::is_valid`, so request-time revocation is already
//! handled by `SessionLayer`. WebSocket
//! upgrades pass through the same middleware once, but subsequent messages
//! on the open connection do not; the session can be revoked while the
//! socket is open and no enforcement fires until the next message attempt
//! happens to fail.
//!
//! [`RevocationAwareSocket`](crate::middleware::ws::RevocationAwareSocket) wraps an [`axum::extract::ws::WebSocket`] so
//! the registry's [`watch_revocation`](crate::SessionRegistry::watch_revocation)
//! event channel transparently closes the connection. Handler code looks
//! identical to a normal WebSocket loop; `recv()` returns `None` when
//! the session is revoked, just as if the client disconnected.
//!
//! # Backend support
//!
//! Immediate revocation requires a `SessionRegistry` backend that implements
//! `watch_revocation` with a real push channel. Today that is
//! `ValkeySessionRegistry` via Redis pub/sub. Other backends fall through
//! to the trait default (`pending().await`). The wrapper therefore also asks
//! the registry whether the session is still valid on a timer
//! ([`WatchOptions::poll_interval`](crate::middleware::ws::WatchOptions::poll_interval)), so a revocation is noticed within one
//! interval on every backend, and after a subscriber outage on Valkey. The
//! poll can fail closed ([`WatchOptions::fail_closed`](crate::middleware::ws::WatchOptions::fail_closed)) and a connection can
//! be given a maximum lifetime ([`WatchOptions::max_lifetime`](crate::middleware::ws::WatchOptions::max_lifetime)).
//!
//! # Example
//!
//! ```ignore
//! use axum::extract::ws::WebSocketUpgrade;
//! use axess_core::ws::RevocationAwareSocket;
//!
//! async fn ws_handler(
//!     ws: WebSocketUpgrade,
//!     auth: axess_core::AuthSession,
//!     Extension(registry): Extension<MyRegistry>,
//! ) -> impl IntoResponse {
//!     // `snapshot` is `None` unless the session is fully authenticated.
//!     let Some(who) = auth.snapshot().await else {
//!         return StatusCode::UNAUTHORIZED.into_response();
//!     };
//!     let (user_id, session_id) = (who.user_id, who.session_id);
//!     ws.on_upgrade(move |socket| async move {
//!         let mut socket = RevocationAwareSocket::new(
//!             socket, registry, user_id, session_id);
//!         while let Some(Ok(msg)) = socket.recv().await {
//!             // handle msg as usual
//!         }
//!         // recv() returned None: client closed OR session revoked.
//!         // Either way, the connection is over.
//!     })
//! }
//! ```

use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket};
use tokio::sync::mpsc;

use crate::authn::ids::UserId;
use crate::session::SessionId;
use crate::session::store::SessionRegistry;

/// WebSocket close code for session-revocation. Application-defined range
/// (4000-4999) per RFC 6455 §7.4.2. Clients that need to distinguish
/// "session revoked" from other close conditions can match on this code.
pub const SESSION_REVOKED_CLOSE_CODE: u16 = 4001;

/// Standard reason string accompanying a session-revocation close frame.
pub const SESSION_REVOKED_CLOSE_REASON: &str = "session_revoked";

/// How a [`RevocationAwareSocket`] supervises its session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchOptions {
    /// How often the registry is asked whether the session is still valid,
    /// in addition to the push channel. Zero is treated as one second.
    pub poll_interval: Duration,
    /// Close the socket when the registry cannot be asked (a store error),
    /// instead of keeping it open until the next successful answer.
    pub fail_closed: bool,
    /// Close the socket after this long even if the session stays valid.
    pub max_lifetime: Option<Duration>,
}

impl Default for WatchOptions {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(30),
            fail_closed: false,
            max_lifetime: None,
        }
    }
}

/// Resolve when the session must be closed: the push channel fired, the
/// poll found it invalid (or, when failing closed, could not tell), or the
/// lifetime ran out.
async fn supervise<R: SessionRegistry>(
    registry: &R,
    user_id: &UserId,
    session_id: &SessionId,
    options: WatchOptions,
) {
    let poll = async {
        let every = options.poll_interval.max(Duration::from_secs(1));
        loop {
            tokio::time::sleep(every).await;
            match registry.is_valid(user_id, session_id).await {
                Ok(true) => {}
                Ok(false) => return,
                Err(err) => {
                    tracing::warn!(
                        target: "axess::ws",
                        %err,
                        fail_closed = options.fail_closed,
                        "ws revocation poll: registry unavailable",
                    );
                    if options.fail_closed {
                        return;
                    }
                }
            }
        }
    };
    let lifetime = async {
        match options.max_lifetime {
            Some(limit) => tokio::time::sleep(limit).await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        () = registry.watch_revocation(user_id, session_id) => {}
        () = poll => {}
        () = lifetime => {}
    }
}

/// A [`WebSocket`] wrapper that closes itself when the session is revoked.
///
/// Spawns one tokio task at construction time that awaits
/// [`SessionRegistry::watch_revocation`]; on revocation, signals the
/// wrapper to send a close frame and end the stream.
///
/// The wrapper presents `recv()` and `send()` mirroring `WebSocket`'s
/// own API. On revocation, `recv()` returns `None` so calling code that
/// uses `while let Some(msg) = socket.recv().await` exits naturally.
///
/// The watch task is held in [`watch_task`](Self::watch_task) so its
/// drop semantics, aborting the spawned task, propagate correctly when
/// the wrapper itself is dropped. Without this hold, dropping the
/// wrapper mid-connection would leak the spawned future.
pub struct RevocationAwareSocket {
    socket: WebSocket,
    revoke_rx: mpsc::Receiver<()>,
    closed: bool,
    /// Held to keep the watch task alive for the wrapper's lifetime.
    /// Dropping this aborts the task (via `JoinHandle`'s Drop), preventing
    /// a leaked future when the wrapper is dropped before revocation fires.
    /// Field is intentionally not consumed elsewhere; its purpose is the
    /// Drop side effect.
    watch_task: AbortOnDrop,
}

/// The error `send` returns after the session was revoked.
#[derive(Debug)]
struct RevokedError;

impl std::fmt::Display for RevokedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("websocket closed: session revoked")
    }
}

impl std::error::Error for RevokedError {}

/// A task handle that ABORTS its task when dropped. Dropping a bare
/// `JoinHandle` only detaches the task, so every closed socket left a
/// watcher and its subscription running until the registry fired.
pub(crate) struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl AbortOnDrop {
    /// The handle itself, for a test that awaits the task's end.
    pub(crate) fn handle(&self) -> &tokio::task::JoinHandle<()> {
        &self.0
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl RevocationAwareSocket {
    /// Wrap a `WebSocket` with revocation supervision.
    ///
    /// The provided `registry`, `user_id`, and `session_id` are moved into
    /// a background task that awaits `registry.watch_revocation`. The
    /// task is cancelled when the wrapper is dropped.
    ///
    /// # Panics
    ///
    /// Panics when called outside a Tokio runtime, because the watcher is
    /// started with `tokio::spawn`. A WebSocket upgrade handler always runs
    /// inside one.
    pub fn new<R>(socket: WebSocket, registry: R, user_id: UserId, session_id: SessionId) -> Self
    where
        R: SessionRegistry,
    {
        Self::with_options(
            socket,
            registry,
            user_id,
            session_id,
            WatchOptions::default(),
        )
    }

    /// Like [`new`](Self::new), with explicit [`WatchOptions`].
    ///
    /// # Panics
    ///
    /// Panics when called outside a Tokio runtime.
    pub fn with_options<R>(
        socket: WebSocket,
        registry: R,
        user_id: UserId,
        session_id: SessionId,
        options: WatchOptions,
    ) -> Self
    where
        R: SessionRegistry,
    {
        let (tx, rx) = mpsc::channel(1);
        let watch_task = tokio::spawn(async move {
            supervise(&registry, &user_id, &session_id, options).await;
            if let Err(err) = tx.send(()).await {
                tracing::trace!(
                    target: "axess::ws",
                    ?err,
                    "ws revocation channel: send failed (receiver dropped)",
                );
            }
        });
        Self {
            socket,
            revoke_rx: rx,
            closed: false,
            watch_task: AbortOnDrop(watch_task),
        }
    }

    /// Receive the next message from the socket.
    ///
    /// Races the underlying `socket.recv()` against the revocation channel.
    /// On revocation, sends a `Close { code: 4001, reason: "session_revoked" }`
    /// frame and returns `None` so callers using
    /// `while let Some(msg) = socket.recv().await` exit cleanly.
    ///
    /// After a revocation-induced close, subsequent calls return `None`
    /// immediately without doing further work.
    pub async fn recv(&mut self) -> Option<Result<Message, axum::Error>> {
        if self.closed {
            return None;
        }
        tokio::select! {
            msg = self.socket.recv() => msg,
            _ = self.revoke_rx.recv() => {
                self.close_revoked().await;
                None
            }
        }
    }

    /// Send a message on the socket.
    ///
    /// If the session has been revoked since the last call, the close frame
    /// (code 4001) is sent instead and an error is returned, so a handler
    /// that only ever sends (a push stream) stops delivering to a revoked
    /// session. After a revocation-induced close, every call returns an
    /// error.
    ///
    /// # Errors
    ///
    /// Returns the underlying socket's error, or a closed-connection error
    /// when the session was revoked.
    pub async fn send(&mut self, msg: Message) -> Result<(), axum::Error> {
        if !self.closed && self.revoke_rx.try_recv().is_ok() {
            self.close_revoked().await;
        }
        if self.closed {
            return Err(axum::Error::new(RevokedError));
        }
        self.socket.send(msg).await
    }

    /// Whether the session has been revoked and the socket closed.
    pub fn is_revoked(&self) -> bool {
        self.closed
    }

    /// Send the revocation close frame and mark the socket closed.
    async fn close_revoked(&mut self) {
        self.closed = true;
        let close = Message::Close(Some(CloseFrame {
            code: SESSION_REVOKED_CLOSE_CODE,
            reason: Utf8Bytes::from_static(SESSION_REVOKED_CLOSE_REASON),
        }));
        if let Err(err) = self.socket.send(close).await {
            tracing::warn!(
                target: "axess::ws",
                %err,
                "ws revocation: failed to send Close frame to client",
            );
        }
    }

    /// Consume the wrapper and return the underlying `WebSocket`.
    ///
    /// Useful for handlers that need direct access for `split()` or
    /// other axum-specific operations. The revocation watch task is
    /// aborted (revocation will no longer auto-close).
    pub fn into_inner(self) -> WebSocket {
        self.socket
    }

    /// Returns a reference to the watch task's `JoinHandle`. Exposed so
    /// callers can `await` task completion in tests; production code
    /// rarely needs this.
    pub fn watch_task(&self) -> &tokio::task::JoinHandle<()> {
        self.watch_task.handle()
    }
}

#[cfg(test)]
mod abort_on_drop_tests {
    use super::AbortOnDrop;

    /// Dropping the wrapper aborts the task; a bare `JoinHandle` only detaches
    /// it, which is how every closed socket left a watcher running.
    #[tokio::test]
    async fn dropping_the_handle_aborts_the_task() {
        let task = tokio::spawn(std::future::pending::<()>());
        let abort = task.abort_handle();
        drop(AbortOnDrop(task));
        tokio::task::yield_now().await;
        assert!(
            abort.is_finished(),
            "the task must be aborted when its handle is dropped"
        );
    }
}

#[cfg(all(test, feature = "memory"))]
mod supervise_tests {
    use super::*;
    use crate::session::store::MemorySessionRegistry;

    fn ids() -> (UserId, SessionId) {
        (
            axess_identity::testing::user("ws-user"),
            SessionId::new(&crate::testing::mock_random::MockRng::new(7)),
        )
    }

    /// The memory registry has no push channel, so only the poll can notice
    /// a revocation; it must, within one interval.
    #[tokio::test(start_paused = true)]
    async fn the_poll_closes_a_revoked_session_on_a_registry_without_push() {
        let registry = MemorySessionRegistry::new();
        let (user, session) = ids();
        registry.register(&user, &session).await.expect("register");
        let options = WatchOptions {
            poll_interval: Duration::from_secs(5),
            ..WatchOptions::default()
        };
        let watcher = {
            let registry = registry.clone();
            let (user, session) = (user, session);
            tokio::spawn(async move { supervise(&registry, &user, &session, options).await })
        };
        tokio::time::sleep(Duration::from_secs(6)).await;
        assert!(!watcher.is_finished(), "a valid session stays open");
        registry.invalidate_user(&user).await.expect("revoke");
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(watcher.is_finished(), "the poll must notice the revocation");
    }

    /// A connection with a maximum lifetime ends when it runs out.
    #[tokio::test(start_paused = true)]
    async fn the_lifetime_ends_a_valid_session() {
        let registry = MemorySessionRegistry::new();
        let (user, session) = ids();
        registry.register(&user, &session).await.expect("register");
        let options = WatchOptions {
            max_lifetime: Some(Duration::from_secs(60)),
            ..WatchOptions::default()
        };
        let watcher = tokio::spawn(async move {
            supervise(&registry, &user, &session, options).await;
        });
        tokio::time::sleep(Duration::from_secs(59)).await;
        assert!(!watcher.is_finished());
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(watcher.is_finished());
    }
}
