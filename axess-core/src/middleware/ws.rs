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
//! [`RevocationAwareSocket`] wraps an [`axum::extract::ws::WebSocket`] so
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
//! poll fails closed by default ([`WatchOptions::fail_closed`](crate::middleware::ws::WatchOptions::fail_closed)):
//! a registry that cannot answer closes the socket at the next poll, as the
//! HTTP path refuses a request it cannot check. A connection has a maximum
//! lifetime of one day by default ([`WatchOptions::max_lifetime`](crate::middleware::ws::WatchOptions::max_lifetime),
//! [`DEFAULT_MAX_LIFETIME`]); the client reconnects and the upgrade runs
//! through the session layer's checks again. Both can be turned off, and a
//! deployment that does so has decided that a socket may outlive the
//! library's ability to check its session.
//!
//! # Rotations
//!
//! A rotation of the session by another request (a step-up in another tab,
//! [`RequestAuthnService::rotate_session`](crate::authn::service::RequestAuthnService::rotate_session),
//! a `regenerate` behind the session layer) moves its registry entry to a new
//! key, and the key the socket was opened under is no longer valid. That is
//! not an ending, so it does not close the socket: the poll asks the registry
//! where the session is now ([`SessionRegistry::current_key`])
//! and the wrapper watches that key from then on, on the poll and on the push
//! channel. The socket closes when the rotated session ends, by the push on
//! its new key, or at the next poll when it ended before the poll found it.
//!
//! # Cross-site upgrades
//!
//! A page on any site can open a WebSocket to this server, and the browser
//! sends the session cookie with the upgrade: the CSRF token never travels
//! on it. The gate is the `Origin` header, which the
//! [`SessionLayer`](crate::session::SessionLayer) checks on every upgrade it
//! sees, before it reads the session: against the allow-list
//! ([`SessionLayer::with_websocket_origins`](crate::session::SessionLayer::with_websocket_origins))
//! when one is configured, and otherwise against the request's own `Host`
//! and scheme. A socket route is covered wherever it is mounted, with or
//! without the [`CsrfLayer`](crate::middleware::csrf::CsrfLayer), which
//! applies the same rule to the upgrades it sees (its own allow-list, from
//! [`CsrfConfig::require_origin`](crate::middleware::csrf::CsrfConfig::require_origin)).
//! When the page that opens the socket is on another host than the socket,
//! name its origin on the session layer.
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
//!     let (user_id, session) = (who.user_id, who.session_key);
//!     ws.on_upgrade(move |socket| async move {
//!         let mut socket = RevocationAwareSocket::new(
//!             socket, registry, user_id, session);
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
use crate::session::SessionKey;
use crate::session::store::SessionRegistry;

/// WebSocket close code for session-revocation. Application-defined range
/// (4000-4999) per RFC 6455 §7.4.2. Clients that need to distinguish
/// "session revoked" from other close conditions can match on this code.
pub const SESSION_REVOKED_CLOSE_CODE: u16 = 4001;

/// Standard reason string accompanying a session-revocation close frame.
pub const SESSION_REVOKED_CLOSE_REASON: &str = "session_revoked";

/// WebSocket close code for a socket that reached its
/// [`max_lifetime`](WatchOptions::max_lifetime) while its session stayed
/// valid. The client may reconnect at once; the session is not revoked.
pub const LIFETIME_REACHED_CLOSE_CODE: u16 = 4002;

/// Reason string accompanying a [`LIFETIME_REACHED_CLOSE_CODE`] close frame.
pub const LIFETIME_REACHED_CLOSE_REASON: &str = "lifetime_reached";

/// WebSocket close code for a socket closed because the registry could not
/// be asked whether the session is valid ([`fail_closed`](WatchOptions::fail_closed)).
/// The session may still be valid; the client may reconnect and the upgrade
/// is checked again.
pub const SESSION_UNVERIFIED_CLOSE_CODE: u16 = 4003;

/// Reason string accompanying a [`SESSION_UNVERIFIED_CLOSE_CODE`] close frame.
pub const SESSION_UNVERIFIED_CLOSE_REASON: &str = "session_unverified";

/// The lifetime a [`RevocationAwareSocket`] has by default: one day, after
/// which the client reconnects and the upgrade runs through the session
/// layer's checks again.
pub const DEFAULT_MAX_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// How a [`RevocationAwareSocket`] supervises its session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchOptions {
    /// How often the registry is asked whether the session is still valid,
    /// in addition to the push channel. Zero is treated as one second.
    pub poll_interval: Duration,
    /// Close the socket when the registry cannot be asked (a store error),
    /// instead of keeping it open until the next successful answer. On by
    /// default: the HTTP path refuses a request whose session it cannot
    /// check, and a socket kept open through an outage would be the one
    /// place a revoked session stays usable. `false` keeps the socket open
    /// until the next answer.
    pub fail_closed: bool,
    /// Close the socket after this long even if the session stays valid.
    /// [`DEFAULT_MAX_LIFETIME`] (one day) by default; `None` lets a socket
    /// live as long as the session.
    pub max_lifetime: Option<Duration>,
}

impl Default for WatchOptions {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(30),
            fail_closed: true,
            max_lifetime: Some(DEFAULT_MAX_LIFETIME),
        }
    }
}

/// Why a supervised socket is closed. Each has its own close frame, so a
/// client tells a revoked session from one it may reconnect with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    /// The push channel fired, or the poll found the session invalid.
    Revoked,
    /// The registry could not be asked and the options fail closed.
    Unverified,
    /// The maximum lifetime ran out.
    LifetimeReached,
}

impl Ending {
    fn close_frame(self) -> CloseFrame {
        let (code, reason) = match self {
            Self::Revoked => (SESSION_REVOKED_CLOSE_CODE, SESSION_REVOKED_CLOSE_REASON),
            Self::Unverified => (
                SESSION_UNVERIFIED_CLOSE_CODE,
                SESSION_UNVERIFIED_CLOSE_REASON,
            ),
            Self::LifetimeReached => (LIFETIME_REACHED_CLOSE_CODE, LIFETIME_REACHED_CLOSE_REASON),
        };
        CloseFrame {
            code,
            reason: Utf8Bytes::from_static(reason),
        }
    }
}

/// What a check of the watched key found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Check {
    /// The socket closes, for this reason.
    Ends(Ending),
    /// The session is live under this key, which the socket watches from now
    /// on: the key it watched, or the key another request rotated it to.
    LiveUnder(SessionKey),
}

/// The registry could not be asked: the socket closes as unverified when the
/// options fail closed, and otherwise keeps watching the key it watched.
fn unanswered(err: &dyn std::error::Error, watched: &SessionKey, options: WatchOptions) -> Check {
    tracing::warn!(
        target: "axess::ws",
        %err,
        fail_closed = options.fail_closed,
        "ws revocation poll: registry unavailable",
    );
    if options.fail_closed {
        Check::Ends(Ending::Unverified)
    } else {
        Check::LiveUnder(*watched)
    }
}

/// The poll of the watched key. A key the registry still holds is the
/// common case and costs one call, which also renews the entry as a request
/// would. A key it does not hold is no proof that the session ended: another
/// request (a step-up in another tab, `rotate_session`) may have moved the
/// session to a new key, so the registry is asked where the session is now,
/// and only "nowhere" closes the socket as revoked. Asking in this order
/// leaves no window: a move that lands between the two calls is followed by
/// the second, which resolves every earlier key of the session in one hop.
async fn poll<R: SessionRegistry>(
    registry: &R,
    user_id: &UserId,
    watched: &SessionKey,
    options: WatchOptions,
) -> Check {
    match registry.is_valid(user_id, watched).await {
        Ok(true) => return Check::LiveUnder(*watched),
        Ok(false) => {}
        Err(err) => return unanswered(&err, watched, options),
    }
    match registry.current_key(user_id, watched).await {
        Ok(Some(now)) => Check::LiveUnder(now),
        Ok(None) => Check::Ends(Ending::Revoked),
        Err(err) => unanswered(&err, watched, options),
    }
}

/// The push channel fired for the watched key. It fires when that key was
/// ended, and also when a watcher found the key no longer live (a Valkey
/// watcher after a dropped message, or while it polls without a connection),
/// which a move away from it is. So the registry is asked where the session
/// is now: a key other than the watched one is followed, and every other
/// answer closes the socket as revoked. The push is the registry's word that
/// the watched key ended, and only an answer naming the key the session moved
/// to outweighs it; an error is no such answer, whatever `fail_closed` says.
async fn after_push<R: SessionRegistry>(
    registry: &R,
    user_id: &UserId,
    watched: &SessionKey,
) -> Check {
    match registry.current_key(user_id, watched).await {
        Ok(Some(now)) if now != *watched => Check::LiveUnder(now),
        Ok(_) => Check::Ends(Ending::Revoked),
        Err(err) => {
            tracing::warn!(
                target: "axess::ws",
                %err,
                "ws revocation push: registry unavailable, closing the socket",
            );
            Check::Ends(Ending::Revoked)
        }
    }
}

/// The push channel of the registry for one key. The future owns its key, so
/// a watch can be replaced by one for another key while the supervisor runs.
async fn watch_key<R: SessionRegistry>(registry: &R, user_id: &UserId, key: SessionKey) {
    registry.watch_revocation(user_id, &key).await;
}

/// Resolve when the session must be closed, with the reason: the push
/// channel fired or the poll found it ended, the poll could not tell and the
/// options fail closed, or the lifetime ran out.
///
/// The session is followed across a rotation another request makes: the
/// supervisor watches the key the registry holds the session under now
/// ([`SessionRegistry::current_key`]), which starts as the key the socket
/// was opened under. A rotation is not an ending, so it does not close the
/// socket; an ending of the rotated session does. A move publishes nothing,
/// so the poll is what finds a rotation; from then on the push channel
/// listens on the new key. An ending of the rotated session before the poll
/// found it is caught by that poll, which then finds the session nowhere.
async fn supervise<R: SessionRegistry>(
    registry: &R,
    user_id: &UserId,
    session: &SessionKey,
    options: WatchOptions,
) -> Ending {
    let every = options.poll_interval.max(Duration::from_secs(1));
    let mut watched = *session;
    let mut watch = std::pin::pin!(watch_key(registry, user_id, watched));
    let mut lifetime = std::pin::pin!(async {
        match options.max_lifetime {
            Some(limit) => tokio::time::sleep(limit).await,
            None => std::future::pending().await,
        }
    });
    loop {
        // A push is acted on at once; `after_push` never answers the watched
        // key, so a completed watch is always replaced before it is polled
        // again.
        let check = tokio::select! {
            () = watch.as_mut() => after_push(registry, user_id, &watched).await,
            () = tokio::time::sleep(every) => poll(registry, user_id, &watched, options).await,
            () = lifetime.as_mut() => return Ending::LifetimeReached,
        };
        match check {
            Check::Ends(ending) => return ending,
            Check::LiveUnder(now) if now == watched => {}
            Check::LiveUnder(now) => {
                watched = now;
                watch.set(watch_key(registry, user_id, watched));
            }
        }
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
    revoke_rx: mpsc::Receiver<Ending>,
    closed: bool,
    /// Held to keep the watch task alive for the wrapper's lifetime.
    /// Dropping this aborts the task (via `JoinHandle`'s Drop), preventing
    /// a leaked future when the wrapper is dropped before revocation fires.
    /// Field is intentionally not consumed elsewhere; its purpose is the
    /// Drop side effect.
    watch_task: AbortOnDrop,
}

/// The error `send` returns after the supervisor closed the socket.
#[derive(Debug)]
struct RevokedError;

impl std::fmt::Display for RevokedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("websocket closed by its session supervisor")
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

/// What the watcher has reported, or `Unverified` if it died. Only an empty
/// channel means "still live"; a closed channel (the watcher panicked or was
/// aborted) leaves the session unsupervised, so a dead watcher fails closed.
fn watcher_signalled(rx: &mut mpsc::Receiver<Ending>) -> Option<Ending> {
    match rx.try_recv() {
        Ok(ending) => Some(ending),
        Err(mpsc::error::TryRecvError::Empty) => None,
        Err(mpsc::error::TryRecvError::Disconnected) => Some(Ending::Unverified),
    }
}

impl RevocationAwareSocket {
    /// Wrap a `WebSocket` with revocation supervision.
    ///
    /// The provided `registry`, `user_id`, and `session` (the session's key,
    /// [`AuthSession::session_key`](crate::session::AuthSession::session_key))
    /// are moved into
    /// a background task that awaits `registry.watch_revocation`. The
    /// task is cancelled when the wrapper is dropped.
    ///
    /// # Panics
    ///
    /// Panics when called outside a Tokio runtime, because the watcher is
    /// started with `tokio::spawn`. A WebSocket upgrade handler always runs
    /// inside one.
    pub fn new<R>(socket: WebSocket, registry: R, user_id: UserId, session: SessionKey) -> Self
    where
        R: SessionRegistry,
    {
        Self::with_options(socket, registry, user_id, session, WatchOptions::default())
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
        session: SessionKey,
        options: WatchOptions,
    ) -> Self
    where
        R: SessionRegistry,
    {
        let (tx, rx) = mpsc::channel(1);
        let watch_task = tokio::spawn(async move {
            let ending = supervise(&registry, &user_id, &session, options).await;
            if let Err(err) = tx.send(ending).await {
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
    /// Races the underlying `socket.recv()` against the supervisor. When it
    /// ends the session, sends the close frame for the reason
    /// (`4001 session_revoked`, `4002 lifetime_reached` or
    /// `4003 session_unverified`) and returns `None` so callers using
    /// `while let Some(msg) = socket.recv().await` exit cleanly.
    ///
    /// After that close, subsequent calls return `None` immediately without
    /// doing further work.
    pub async fn recv(&mut self) -> Option<Result<Message, axum::Error>> {
        if self.closed {
            return None;
        }
        // Biased: a revocation that is already signalled ends the session
        // before a message the client has already sent is handed over.
        tokio::select! {
            biased;
            ending = self.revoke_rx.recv() => {
                // `None`: the watcher ended without a word, so the session
                // is no longer supervised; fail closed.
                self.close_supervised(ending.unwrap_or(Ending::Unverified)).await;
                None
            }
            msg = self.socket.recv() => msg,
        }
    }

    /// Send a message on the socket.
    ///
    /// If the supervisor has ended the session since the last call, its
    /// close frame is sent instead (as in [`recv`](Self::recv)) and an error
    /// is returned, so a handler that only ever sends (a push stream) stops
    /// delivering to a revoked session. After that close, every call returns
    /// an error.
    ///
    /// # Errors
    ///
    /// Returns the underlying socket's error, or a closed-connection error
    /// when the session was revoked.
    pub async fn send(&mut self, msg: Message) -> Result<(), axum::Error> {
        if !self.closed
            && let Some(ending) = watcher_signalled(&mut self.revoke_rx)
        {
            self.close_supervised(ending).await;
        }
        if self.closed {
            return Err(axum::Error::new(RevokedError));
        }
        self.socket.send(msg).await
    }

    /// Whether the supervisor closed the socket: the session was revoked,
    /// could not be verified while failing closed, or the socket reached its
    /// maximum lifetime. The close frame sent to the client says which.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Send the close frame for `ending` and mark the socket closed.
    async fn close_supervised(&mut self, ending: Ending) {
        self.closed = true;
        let close = Message::Close(Some(ending.close_frame()));
        if let Err(err) = self.socket.send(close).await {
            tracing::warn!(
                target: "axess::ws",
                %err,
                ?ending,
                "ws supervisor: failed to send Close frame to client",
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
    use super::{AbortOnDrop, Ending, watcher_signalled};
    use tokio::sync::mpsc;

    /// A watcher that died without reporting must close the socket.
    #[tokio::test]
    async fn a_dead_watcher_fails_closed() {
        let (tx, mut rx) = mpsc::channel::<Ending>(1);
        assert_eq!(
            watcher_signalled(&mut rx),
            None,
            "a live watcher is not a signal"
        );
        drop(tx);
        assert_eq!(
            watcher_signalled(&mut rx),
            Some(Ending::Unverified),
            "a dead watcher must fail closed"
        );
    }

    #[tokio::test]
    async fn a_reported_ending_is_passed_on() {
        let (tx, mut rx) = mpsc::channel::<Ending>(1);
        tx.send(Ending::Revoked).await.expect("send");
        assert_eq!(watcher_signalled(&mut rx), Some(Ending::Revoked));
    }

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
mod recv_tests;

#[cfg(all(test, feature = "memory"))]
mod follow_tests;

#[cfg(all(test, feature = "memory"))]
mod supervise_tests {
    use super::*;
    use crate::session::store::MemorySessionRegistry;
    use crate::testing::registry_double::{RegistryDouble, Step};

    fn ids() -> (UserId, SessionKey) {
        (
            axess_identity::testing::user("ws-user"),
            SessionKey::from_bytes([7; 32]),
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
        assert_eq!(watcher.await.expect("watcher"), Ending::Revoked);
    }

    /// A registry that cannot be asked.
    fn unreachable() -> RegistryDouble {
        RegistryDouble::new().before(|_, _| async { Step::Fail("registry unreachable") })
    }

    /// The defaults of a security library fail closed and bound the
    /// connection: a registry that cannot answer closes the socket at the
    /// next poll, as the HTTP path refuses a request it cannot check, and a
    /// socket does not outlive a day without a new handshake.
    #[test]
    fn the_defaults_fail_closed_with_a_bounded_lifetime() {
        let defaults = WatchOptions::default();
        assert!(defaults.fail_closed, "a registry outage closes the socket");
        assert_eq!(
            defaults.max_lifetime,
            Some(DEFAULT_MAX_LIFETIME),
            "a socket is re-handshaken within a day"
        );
        assert_eq!(defaults.poll_interval, Duration::from_secs(30));
    }

    /// Under the defaults an unreachable registry closes the socket within
    /// one poll interval.
    #[tokio::test(start_paused = true)]
    async fn an_unreachable_registry_closes_the_socket_under_the_defaults() {
        let (user, session) = ids();
        let watcher = tokio::spawn(async move {
            supervise(&unreachable(), &user, &session, WatchOptions::default()).await
        });
        tokio::time::sleep(Duration::from_secs(29)).await;
        assert!(
            !watcher.is_finished(),
            "nothing is known before the first poll"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(
            watcher.is_finished(),
            "the first poll that cannot be answered closes the socket"
        );
        assert_eq!(watcher.await.expect("watcher"), Ending::Unverified);
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
        let watcher =
            tokio::spawn(async move { supervise(&registry, &user, &session, options).await });
        tokio::time::sleep(Duration::from_secs(59)).await;
        assert!(!watcher.is_finished());
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(watcher.is_finished());
        assert_eq!(watcher.await.expect("watcher"), Ending::LifetimeReached);
    }

    /// Only a revoked session is closed as revoked. A socket that reached its
    /// lifetime, or whose session could not be checked, closes with a code a
    /// client reads as "reconnect", not "signed out".
    #[test]
    fn each_ending_has_its_own_close_frame() {
        let frame = |ending: Ending| {
            let frame = ending.close_frame();
            (frame.code, frame.reason.as_str().to_owned())
        };
        assert_eq!(frame(Ending::Revoked), (4001, "session_revoked".to_owned()));
        assert_eq!(
            frame(Ending::LifetimeReached),
            (4002, "lifetime_reached".to_owned())
        );
        assert_eq!(
            frame(Ending::Unverified),
            (4003, "session_unverified".to_owned())
        );
    }
}
