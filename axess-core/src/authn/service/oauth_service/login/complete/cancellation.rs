//! The sessions a login owes an end to are not lost when the login is
//! cancelled, refused or settled: see [`PendingEnds`](super::pending_ends).

use super::pending_ends::PendingEnds;
use crate::authn::ids::UserId;
use crate::federation::sid_map::SidMap;
use crate::session::id::SessionId;
use crate::session::store::{
    MemorySessionRegistry, SessionRegistry, SessionRegistryAdapter, SessionRegistryHandle,
};
use axess_rng::testing::MockRng;
use std::sync::Arc;
use std::time::Duration;

const ISS: &str = "https://idp.example.com";

/// A registry whose invalidation takes `delay`, over a memory registry.
#[derive(Clone)]
struct Slow {
    inner: MemorySessionRegistry,
    delay: Duration,
}

impl SessionRegistry for Slow {
    type Error = std::io::Error;
    async fn register(&self, u: &UserId, s: &SessionId) -> Result<(), Self::Error> {
        self.inner
            .register(u, s)
            .await
            .map_err(std::io::Error::other)
    }
    async fn is_valid(&self, u: &UserId, s: &SessionId) -> Result<bool, Self::Error> {
        self.inner
            .is_valid(u, s)
            .await
            .map_err(std::io::Error::other)
    }
    async fn invalidate_user(&self, u: &UserId) -> Result<(), Self::Error> {
        self.inner
            .invalidate_user(u)
            .await
            .map_err(std::io::Error::other)
    }
    async fn invalidate_session(&self, u: &UserId, s: &SessionId) -> Result<(), Self::Error> {
        tokio::time::sleep(self.delay).await;
        self.inner
            .invalidate_session(u, s)
            .await
            .map_err(std::io::Error::other)
    }
    async fn active_sessions(&self, u: &UserId) -> Result<Vec<SessionId>, Self::Error> {
        self.inner
            .active_sessions(u)
            .await
            .map_err(std::io::Error::other)
    }
}

struct Fixture {
    registry: Slow,
    sid_map: SidMap,
    user: UserId,
    aged: SessionId,
    displaced: SessionId,
}

/// One session aged out of the map and one displaced from `sid-1`, both live
/// in the registry.
async fn fixture(delay: Duration) -> Fixture {
    let registry = Slow {
        inner: MemorySessionRegistry::new(),
        delay,
    };
    let sid_map = SidMap::new();
    let rng = MockRng::new(31);
    let user = axess_identity::testing::user("u1");
    let (aged, displaced, newcomer) = (
        SessionId::new(&rng),
        SessionId::new(&rng),
        SessionId::new(&rng),
    );
    for s in [&aged, &displaced, &newcomer] {
        registry.inner.register(&user, s).await.unwrap();
        sid_map.register_subject_session(ISS, &user.to_string(), user, *s);
    }
    let now = chrono::Utc::now();
    sid_map.insert(
        (ISS.into(), "sid-1".into()),
        &user.to_string(),
        user,
        displaced,
        now,
    );
    // The login under test takes the key over.
    Fixture {
        registry,
        sid_map,
        user,
        aged,
        displaced,
    }
}

fn pending_for(f: &Fixture, newcomer_user: UserId) -> PendingEnds {
    let handle: Arc<dyn SessionRegistryHandle> =
        Arc::new(SessionRegistryAdapter(f.registry.clone()));
    let mut pending = PendingEnds::new(Some(handle), f.sid_map.clone());
    pending.age_out((ISS.to_string(), f.user, f.aged));
    let key = (ISS.to_string(), "sid-1".to_string());
    let rng = MockRng::new(99);
    let displaced = f
        .sid_map
        .insert_displacing(
            key.clone(),
            &newcomer_user.to_string(),
            newcomer_user,
            SessionId::new(&rng),
            chrono::Utc::now(),
        )
        .expect("the fixture mapped sid-1");
    pending.displace(key, displaced);
    pending
}

async fn valid(f: &Fixture, s: &SessionId) -> bool {
    f.registry.inner.is_valid(&f.user, s).await.unwrap()
}

/// Dropping the holder unsettled (the login future was cancelled between the
/// map upkeep and the end of the login) still ends every owed session, on a
/// task that outlives the dropped caller. Before the holder existed those
/// sessions were out of the map and never ended.
#[tokio::test]
async fn a_cancelled_login_still_ends_the_sessions_it_took_out_of_the_map() {
    let f = fixture(Duration::ZERO).await;
    let pending = pending_for(&f, axess_identity::testing::user("newcomer"));
    assert!(valid(&f, &f.aged).await && valid(&f, &f.displaced).await);

    drop(pending);
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(!valid(&f, &f.aged).await, "the aged-out session ended");
    assert!(
        !valid(&f, &f.displaced).await,
        "the displaced session ended"
    );
}

/// The ending runs on its own task: aborting the caller that awaits `commit`
/// while the invalidations are in flight does not abort them.
#[tokio::test]
async fn aborting_the_caller_during_commit_does_not_abort_the_invalidations() {
    let f = fixture(Duration::from_millis(60)).await;
    let pending = pending_for(&f, axess_identity::testing::user("newcomer"));

    let caller = tokio::spawn(async move { pending.commit().await });
    tokio::time::sleep(Duration::from_millis(10)).await;
    caller.abort();
    let _ = caller.await;
    tokio::time::sleep(Duration::from_millis(250)).await;

    assert!(!valid(&f, &f.aged).await);
    assert!(!valid(&f, &f.displaced).await);
}

/// A refused login puts the displaced mapping back, with its time, and ends
/// only the session that aged out.
#[tokio::test]
async fn a_refused_login_restores_the_displaced_mapping_and_ends_only_the_aged_session() {
    let f = fixture(Duration::ZERO).await;
    let newcomer_user = axess_identity::testing::user("newcomer");
    let pending = pending_for(&f, newcomer_user);
    // The refused login's own mapping is unwound first, as the caller does.
    let key = (ISS.to_string(), "sid-1".to_string());
    let taken = f.sid_map.get(&key).expect("the newcomer's mapping");
    f.sid_map.remove_session(&taken.1);

    pending.refuse().await;

    let restored = f.sid_map.get(&key).expect("the displaced mapping is back");
    assert_eq!((restored.0, restored.1), (f.user, f.displaced));
    assert!(valid(&f, &f.displaced).await, "its session was not ended");
    assert!(!valid(&f, &f.aged).await, "the aged-out session ended");
}
