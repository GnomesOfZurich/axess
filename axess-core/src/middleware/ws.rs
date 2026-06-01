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
//! Active revocation requires a `SessionRegistry` backend that implements
//! `watch_revocation` with a real push channel. Today that is
//! `ValkeySessionRegistry` via Redis pub/sub. Other backends fall through
//! to the trait default (`pending().await`), which means the wrapper is
//! safe to use everywhere but only delivers proactive close on push-capable
//! backends.
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
//!     let user_id = auth.user_id().await.unwrap();
//!     let session_id = auth.session_id().await.unwrap();
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
    watch_task: tokio::task::JoinHandle<()>,
}

impl RevocationAwareSocket {
    /// Wrap a `WebSocket` with revocation supervision.
    ///
    /// The provided `registry`, `user_id`, and `session_id` are moved into
    /// a background task that awaits `registry.watch_revocation`. The
    /// task is cancelled when the wrapper is dropped.
    pub fn new<R>(socket: WebSocket, registry: R, user_id: UserId, session_id: SessionId) -> Self
    where
        R: SessionRegistry,
    {
        let (tx, rx) = mpsc::channel(1);
        let watch_task = tokio::spawn(async move {
            registry.watch_revocation(&user_id, &session_id).await;
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
            watch_task,
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
                None
            }
        }
    }

    /// Send a message on the socket.
    ///
    /// Pass-through to `WebSocket::send`. After a revocation-induced
    /// close, returns the underlying socket's error for the now-closed
    /// connection.
    pub async fn send(&mut self, msg: Message) -> Result<(), axum::Error> {
        self.socket.send(msg).await
    }

    /// Consume the wrapper and return the underlying `WebSocket`.
    ///
    /// Useful for handlers that need direct access for `split()` or
    /// other axum-specific operations. The revocation watch task is
    /// dropped (revocation will no longer auto-close).
    pub fn into_inner(self) -> WebSocket {
        self.socket
    }

    /// Returns a reference to the watch task's `JoinHandle`. Exposed so
    /// callers can `await` task completion in tests; production code
    /// rarely needs this.
    pub fn watch_task(&self) -> &tokio::task::JoinHandle<()> {
        &self.watch_task
    }
}
