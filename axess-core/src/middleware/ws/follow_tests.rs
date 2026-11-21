//! A socket's session rotated by another request (a step-up in another tab,
//! `rotate_session`, a `regenerate` behind the layer: each is one
//! `move_session` of the registry) stays open, and closes when the rotated
//! session ends. The poll and the push channel each follow the session to
//! the key it is under now.

use super::*;
use crate::session::store::{CutOff, MemorySessionRegistry, MoveOutcome};
use crate::testing::registry_double::{RegistryCall, RegistryDouble, Step};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

/// The poll interval of every test here.
const EVERY: Duration = Duration::from_secs(5);

/// Long enough for a push to be acted on, far short of a poll interval.
const SETTLE: Duration = Duration::from_millis(10);

fn ids() -> (UserId, SessionKey, SessionKey) {
    (
        axess_identity::testing::user("ws-follow"),
        SessionKey::from_bytes([1; 32]),
        SessionKey::from_bytes([2; 32]),
    )
}

fn options(fail_closed: bool) -> WatchOptions {
    WatchOptions {
        poll_interval: EVERY,
        fail_closed,
        ..WatchOptions::default()
    }
}

/// A socket opened under `key`, supervised as `RevocationAwareSocket` does.
fn open<R: SessionRegistry>(
    registry: &R,
    user: UserId,
    key: SessionKey,
    options: WatchOptions,
) -> JoinHandle<Ending> {
    let registry = registry.clone();
    tokio::spawn(async move { supervise(&registry, &user, &key, options).await })
}

/// Another request rotates the session: the registry's one move.
async fn rotate<R: SessionRegistry>(
    registry: &R,
    user: &UserId,
    old: &SessionKey,
    new: &SessionKey,
) {
    let moved = registry.move_session(user, old, new).await;
    assert!(
        matches!(moved, Ok(MoveOutcome::Moved)),
        "the rotation moves the entry"
    );
}

/// What the pushing registry tells its watchers.
#[derive(Debug, Clone, Copy)]
enum Told {
    /// The session under this key ended.
    Ended(SessionKey),
    /// Every session of this user ended.
    User(UserId),
    /// Every watcher asks the registry whether its key is still live.
    Recheck,
}

/// The registry cannot be asked.
#[derive(Debug, thiserror::Error)]
#[error("registry unreachable")]
struct Unreachable;

/// A memory registry with a push channel shaped like the Valkey registry's:
/// a watcher listens by the key it was given; an ending by key tells the key
/// it names and the key the session was under; the end of a user's sessions
/// tells every watcher of the user; a move tells nothing; a recheck (a
/// dropped message, a degraded poll) ends every watch whose key is no longer
/// live. `asking_fails` makes `current_key` answer an error.
#[derive(Clone)]
struct Pushing {
    inner: MemorySessionRegistry,
    told: broadcast::Sender<Told>,
    asking_fails: Arc<AtomicBool>,
}

impl Pushing {
    fn new() -> Self {
        Self {
            inner: MemorySessionRegistry::new(),
            told: broadcast::channel(16).0,
            asking_fails: Arc::new(AtomicBool::new(false)),
        }
    }

    fn tell(&self, told: Told) {
        // No watcher yet is no one to tell.
        let _ = self.told.send(told);
    }

    async fn live(&self, user: &UserId, key: &SessionKey) -> bool {
        matches!(self.inner.current_key(user, key).await, Ok(Some(now)) if now == *key)
    }
}

impl SessionRegistry for Pushing {
    type Error = Unreachable;

    async fn register(&self, user: &UserId, key: &SessionKey) -> Result<(), Unreachable> {
        self.inner
            .register(user, key)
            .await
            .map_err(|_| Unreachable)
    }

    async fn is_valid(&self, user: &UserId, key: &SessionKey) -> Result<bool, Unreachable> {
        self.inner
            .is_valid(user, key)
            .await
            .map_err(|_| Unreachable)
    }

    async fn invalidate_user(&self, user: &UserId) -> Result<(), Unreachable> {
        self.inner
            .invalidate_user(user)
            .await
            .map_err(|_| Unreachable)?;
        self.tell(Told::User(*user));
        Ok(())
    }

    async fn invalidate_session(&self, user: &UserId, key: &SessionKey) -> Result<(), Unreachable> {
        let target = self
            .inner
            .current_key(user, key)
            .await
            .map_err(|_| Unreachable)?;
        self.inner
            .invalidate_session(user, key)
            .await
            .map_err(|_| Unreachable)?;
        self.tell(Told::Ended(*key));
        if let Some(target) = target {
            self.tell(Told::Ended(target));
        }
        Ok(())
    }

    async fn invalidate_other_sessions(
        &self,
        user: &UserId,
        keep: &SessionKey,
    ) -> Result<CutOff, Unreachable> {
        let cut = self
            .inner
            .invalidate_other_sessions(user, keep)
            .await
            .map_err(|_| Unreachable)?;
        if let CutOff::KeptOne(ended) | CutOff::KeptNone(ended) = &cut {
            for key in ended {
                self.tell(Told::Ended(*key));
            }
        }
        Ok(cut)
    }

    async fn move_session(
        &self,
        user: &UserId,
        old: &SessionKey,
        new: &SessionKey,
    ) -> Result<MoveOutcome, Unreachable> {
        self.inner
            .move_session(user, old, new)
            .await
            .map_err(|_| Unreachable)
    }

    async fn current_key(
        &self,
        user: &UserId,
        key: &SessionKey,
    ) -> Result<Option<SessionKey>, Unreachable> {
        if self.asking_fails.load(Ordering::SeqCst) {
            return Err(Unreachable);
        }
        self.inner
            .current_key(user, key)
            .await
            .map_err(|_| Unreachable)
    }

    async fn active_sessions(&self, user: &UserId) -> Result<Vec<SessionKey>, Unreachable> {
        self.inner
            .active_sessions(user)
            .await
            .map_err(|_| Unreachable)
    }

    async fn watch_revocation(&self, user: &UserId, key: &SessionKey) {
        let mut told = self.told.subscribe();
        // As the Valkey watcher: listening first, then one check, so an
        // ending between the two is not missed.
        if !self.live(user, key).await {
            return;
        }
        loop {
            match told.recv().await {
                Ok(Told::Ended(ended)) if ended == *key => return,
                Ok(Told::User(who)) if who == *user => return,
                Ok(Told::Recheck) | Err(broadcast::error::RecvError::Lagged(_)) => {
                    if !self.live(user, key).await {
                        return;
                    }
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Closed) => std::future::pending().await,
            }
        }
    }
}

/// The poll follows a rotation: a registry without a push channel, a
/// session rotated by another request. The socket stays open through polls
/// that find the opening key gone, and the poll after the rotated session
/// ends closes it as revoked.
#[tokio::test(start_paused = true)]
async fn the_poll_follows_a_rotation_and_closes_when_the_rotated_session_ends() {
    let registry = MemorySessionRegistry::new();
    let (user, opened, rotated) = ids();
    registry.register(&user, &opened).await.expect("register");
    let socket = open(&registry, user, opened, options(true));

    tokio::time::sleep(Duration::from_secs(1)).await;
    rotate(&registry, &user, &opened, &rotated).await;
    tokio::time::sleep(EVERY * 3).await;
    assert!(
        !socket.is_finished(),
        "a socket stays open across a rotation another request made"
    );

    registry
        .invalidate_session(&user, &rotated)
        .await
        .expect("end");
    tokio::time::sleep(EVERY).await;
    assert!(
        socket.is_finished(),
        "the poll closes the socket once the rotated session ended"
    );
    assert_eq!(socket.await.expect("socket"), Ending::Revoked);
}

/// The push channel follows a rotation: once the poll found the session
/// under its new key, an ending of it by that key closes the socket at once,
/// not at the next poll.
#[tokio::test(start_paused = true)]
async fn the_push_follows_a_rotation_and_closes_the_socket_when_the_rotated_session_ends() {
    let registry = Pushing::new();
    let (user, opened, rotated) = ids();
    registry.register(&user, &opened).await.expect("register");
    let socket = open(&registry, user, opened, options(true));

    tokio::time::sleep(Duration::from_secs(1)).await;
    rotate(&registry, &user, &opened, &rotated).await;
    // The poll at EVERY finds the session under its new key.
    tokio::time::sleep(EVERY).await;
    assert!(
        !socket.is_finished(),
        "a socket stays open across a rotation another request made"
    );

    registry
        .invalidate_session(&user, &rotated)
        .await
        .expect("end");
    tokio::time::sleep(SETTLE).await;
    assert!(
        socket.is_finished(),
        "the push on the rotated key closes the socket before the next poll"
    );
    assert_eq!(socket.await.expect("socket"), Ending::Revoked);
}

/// A push for the key a session moved away from (the Valkey watcher's
/// recheck after a dropped message, or its degraded poll, finds that key no
/// longer live) follows the session instead of closing the socket; the push
/// then listens on the new key.
#[tokio::test(start_paused = true)]
async fn a_push_for_the_key_a_session_moved_away_from_follows_the_session() {
    let registry = Pushing::new();
    let (user, opened, rotated) = ids();
    registry.register(&user, &opened).await.expect("register");
    let socket = open(&registry, user, opened, options(true));

    tokio::time::sleep(Duration::from_secs(1)).await;
    rotate(&registry, &user, &opened, &rotated).await;
    registry.tell(Told::Recheck);
    tokio::time::sleep(SETTLE).await;
    assert!(
        !socket.is_finished(),
        "a push for the opening key of a rotated session leaves the socket open"
    );

    registry
        .invalidate_session(&user, &rotated)
        .await
        .expect("end");
    tokio::time::sleep(SETTLE).await;
    assert!(
        socket.is_finished(),
        "the push on the rotated key closes the socket before any poll"
    );
    assert_eq!(socket.await.expect("socket"), Ending::Revoked);
}

/// A rotated session that ends before any poll found its new key: the push
/// of that ending goes to the new key, which no watch listens on yet, and
/// the next poll finds nothing under either key and closes the socket.
#[tokio::test(start_paused = true)]
async fn an_ending_of_a_rotated_session_before_the_next_poll_closes_the_socket_at_that_poll() {
    let registry = Pushing::new();
    let (user, opened, rotated) = ids();
    registry.register(&user, &opened).await.expect("register");
    let socket = open(&registry, user, opened, options(true));

    tokio::time::sleep(Duration::from_secs(1)).await;
    rotate(&registry, &user, &opened, &rotated).await;
    registry
        .invalidate_session(&user, &rotated)
        .await
        .expect("end");
    tokio::time::sleep(EVERY).await;
    assert!(socket.is_finished(), "the poll closes the socket");
    assert_eq!(socket.await.expect("socket"), Ending::Revoked);
}

/// A session that ends without a move closes its socket at once through the
/// push channel, by its key or with every session of its user.
#[tokio::test(start_paused = true)]
async fn the_push_closes_a_socket_whose_session_ends_without_a_move() {
    for by_user in [false, true] {
        let registry = Pushing::new();
        let (user, opened, _) = ids();
        registry.register(&user, &opened).await.expect("register");
        let socket = open(&registry, user, opened, options(true));

        tokio::time::sleep(Duration::from_secs(1)).await;
        if by_user {
            registry.invalidate_user(&user).await.expect("end");
        } else {
            registry
                .invalidate_session(&user, &opened)
                .await
                .expect("end");
        }
        tokio::time::sleep(SETTLE).await;
        assert!(
            socket.is_finished(),
            "by user {by_user}: the push closes it"
        );
        assert_eq!(socket.await.expect("socket"), Ending::Revoked);
    }
}

/// A push for a key the registry still holds the session under is taken at
/// its word: the channel says that key ended, and nothing says the session
/// went elsewhere.
#[tokio::test(start_paused = true)]
async fn a_push_for_a_key_the_registry_still_holds_closes_the_socket() {
    let registry = Pushing::new();
    let (user, opened, _) = ids();
    registry.register(&user, &opened).await.expect("register");
    let socket = open(&registry, user, opened, options(true));

    tokio::time::sleep(Duration::from_secs(1)).await;
    registry.tell(Told::Ended(opened));
    tokio::time::sleep(SETTLE).await;
    assert!(socket.is_finished(), "the push closes the socket");
    assert_eq!(socket.await.expect("socket"), Ending::Revoked);
}

/// A push after which the registry cannot say where the session went closes
/// the socket as revoked whatever `fail_closed` says: the push is the
/// registry's own word that the watched key ended, and only an answer naming
/// the key the session moved to outweighs it.
#[tokio::test(start_paused = true)]
async fn a_push_the_registry_cannot_then_place_closes_the_socket() {
    for fail_closed in [true, false] {
        let registry = Pushing::new();
        let (user, opened, rotated) = ids();
        registry.register(&user, &opened).await.expect("register");
        let socket = open(&registry, user, opened, options(fail_closed));

        tokio::time::sleep(Duration::from_secs(1)).await;
        rotate(&registry, &user, &opened, &rotated).await;
        registry.asking_fails.store(true, Ordering::SeqCst);
        registry.tell(Told::Recheck);
        tokio::time::sleep(SETTLE).await;
        assert!(
            socket.is_finished(),
            "fail closed {fail_closed}: the push closes it"
        );
        assert_eq!(socket.await.expect("socket"), Ending::Revoked);
    }
}

/// A registry that fails every call: the poll's error path, as before. Under
/// `fail_closed` the first poll closes the socket as unverified; without it
/// the socket stays open while the registry cannot answer.
#[tokio::test(start_paused = true)]
async fn an_unreachable_registry_closes_the_socket_only_when_the_options_fail_closed() {
    for fail_closed in [true, false] {
        let registry =
            RegistryDouble::new().before(|_, _| async { Step::Fail("registry unreachable") });
        let (user, opened, _) = ids();
        let socket = open(&registry, user, opened, options(fail_closed));
        tokio::time::sleep(EVERY * 3 + Duration::from_secs(1)).await;
        if fail_closed {
            assert!(socket.is_finished(), "the first poll closes the socket");
            assert_eq!(socket.await.expect("socket"), Ending::Unverified);
        } else {
            assert!(
                !socket.is_finished(),
                "a socket that does not fail closed stays open"
            );
            socket.abort();
        }
    }
}

/// A rotation the registry cannot then place (its question for the key the
/// session is under now fails) follows `fail_closed` as any failed poll
/// does: closed as unverified, or kept open until the registry answers, at
/// which point the socket follows the session.
#[tokio::test(start_paused = true)]
async fn a_rotation_the_registry_cannot_place_follows_the_fail_closed_option() {
    for fail_closed in [true, false] {
        let asking_fails = Arc::new(AtomicBool::new(true));
        let fails = Arc::clone(&asking_fails);
        let registry = RegistryDouble::new().before(move |call, _| {
            let refuse =
                fails.load(Ordering::SeqCst) && matches!(call, RegistryCall::CurrentKey { .. });
            async move {
                if refuse {
                    Step::Fail("registry unreachable")
                } else {
                    Step::Forward
                }
            }
        });
        let (user, opened, rotated) = ids();
        registry.register(&user, &opened).await.expect("register");
        let socket = open(&registry, user, opened, options(fail_closed));

        tokio::time::sleep(Duration::from_secs(1)).await;
        rotate(&registry, &user, &opened, &rotated).await;
        tokio::time::sleep(EVERY).await;
        if fail_closed {
            assert!(socket.is_finished(), "the poll closes the socket");
            assert_eq!(socket.await.expect("socket"), Ending::Unverified);
            continue;
        }
        assert!(!socket.is_finished(), "kept open while it cannot be asked");
        asking_fails.store(false, Ordering::SeqCst);
        tokio::time::sleep(EVERY * 2).await;
        assert!(
            !socket.is_finished(),
            "the registry answers again and the socket follows the session"
        );
        registry
            .invalidate_session(&user, &rotated)
            .await
            .expect("end");
        tokio::time::sleep(EVERY).await;
        assert!(socket.is_finished(), "the rotated session's end closes it");
        assert_eq!(socket.await.expect("socket"), Ending::Revoked);
    }
}
