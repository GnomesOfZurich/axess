//! The sessions a login owes an end to are not lost when the login is
//! cancelled, refused or settled: see [`PendingEnds`](super::pending_ends).

use super::pending_ends::PendingEnds;
use crate::authn::ids::TenantId;
use crate::authn::ids::UserId;
use crate::federation::sid_map::{DisplacedSid, SidEntry, SidKey, SidMap};
use crate::federation::sid_store::{SidFuture, SidStore};
use crate::session::id::{SessionId, SessionKey};
use crate::session::store::{SessionRegistry, SessionRegistryAdapter, SessionRegistryHandle};
use crate::testing::registry_double::{RegistryDouble, RegistryOp, Step};
use axess_clock::Timestamp;
use axess_rng::testing::MockRng;
use axess_testing::mock_tracing::TracingCapture;
use axess_testing::stall::{Gate, abort_inside, eventually};
use std::sync::Arc;
use std::time::Duration;

const ISS: &str = "https://idp.example.com";

/// A registry whose invalidation takes `delay`, over a memory registry.
fn slow(delay: Duration) -> RegistryDouble {
    RegistryDouble::new().before(move |call, _| async move {
        if call.op() == RegistryOp::InvalidateSession {
            tokio::time::sleep(delay).await;
        }
        Step::Forward
    })
}

/// The instant the fixtures stamp their mappings with: a fixed one, so the
/// tests read the same clock on every run and nothing here reads the wall.
fn at() -> Timestamp {
    Timestamp::parse_rfc3339("2026-01-01T00:00:00Z").expect("a valid instant")
}

struct Fixture {
    registry: RegistryDouble,
    sid_map: SidMap,
    user: UserId,
    aged: SessionKey,
    displaced: SessionKey,
}

/// One session aged out of the map and one displaced from `sid-1`, both live
/// in the registry.
async fn fixture(delay: Duration) -> Fixture {
    let registry = slow(delay);
    let sid_map = SidMap::new();
    let rng = MockRng::new(31);
    let user = axess_identity::testing::user("u1");
    let (aged, displaced, newcomer) = (
        SessionKey::of(&SessionId::new(&rng)),
        SessionKey::of(&SessionId::new(&rng)),
        SessionKey::of(&SessionId::new(&rng)),
    );
    for s in [&aged, &displaced, &newcomer] {
        registry.inner().register(&user, s).await.unwrap();
        sid_map.register_subject_session(ISS, &user.to_string(), None, user, *s);
    }
    let now = at();
    sid_map.insert(
        (ISS.into(), "sid-1".into()),
        &user.to_string(),
        None,
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
    let mut pending = PendingEnds::new(Some(handle), std::sync::Arc::new(f.sid_map.clone()));
    pending.age_out((ISS.to_string(), f.user, f.aged));
    let key = (ISS.to_string(), "sid-1".to_string());
    let rng = MockRng::new(99);
    let displaced = f
        .sid_map
        .insert_displacing(
            key.clone(),
            &newcomer_user.to_string(),
            None,
            newcomer_user,
            SessionKey::of(&SessionId::new(&rng)),
            at(),
        )
        .expect("the fixture mapped sid-1");
    pending.displace(key, displaced);
    pending
}

async fn valid(f: &Fixture, s: &SessionKey) -> bool {
    f.registry.inner().is_valid(&f.user, s).await.unwrap()
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

/// The in-memory `sid` store, except that `restore_if_vacant` parks on a
/// gate: where a networked store does its I/O.
struct StallingSid {
    inner: Arc<dyn SidStore>,
    gate: Gate,
}

impl SidStore for StallingSid {
    fn insert_displacing<'a>(
        &'a self,
        key: SidKey,
        subject: &'a str,
        tenant: Option<TenantId>,
        user: UserId,
        session: SessionKey,
        inserted_at: Timestamp,
    ) -> SidFuture<'a, Option<DisplacedSid>> {
        self.inner
            .insert_displacing(key, subject, tenant, user, session, inserted_at)
    }

    fn restore_if_vacant(&self, key: SidKey, displaced: DisplacedSid) -> SidFuture<'_, bool> {
        Box::pin(async move {
            self.gate.wait().await;
            self.inner.restore_if_vacant(key, displaced).await
        })
    }

    fn get<'a>(
        &'a self,
        key: &'a SidKey,
        scope: Option<&'a TenantId>,
    ) -> SidFuture<'a, Option<SidEntry>> {
        self.inner.get(key, scope)
    }

    fn remove_if_session<'a>(
        &'a self,
        key: &'a SidKey,
        session: &'a SessionKey,
    ) -> SidFuture<'a, Option<SidEntry>> {
        self.inner.remove_if_session(key, session)
    }

    fn register_subject_session<'a>(
        &'a self,
        issuer: &'a str,
        subject: &'a str,
        tenant: Option<TenantId>,
        user: UserId,
        session: SessionKey,
    ) -> SidFuture<'a, ()> {
        self.inner
            .register_subject_session(issuer, subject, tenant, user, session)
    }

    fn forget_subject_session<'a>(
        &'a self,
        issuer: &'a str,
        user: &'a UserId,
        session: &'a SessionKey,
    ) -> SidFuture<'a, bool> {
        self.inner.forget_subject_session(issuer, user, session)
    }

    fn subject_sessions<'a>(
        &'a self,
        issuer: &'a str,
        subject: &'a str,
        scope: Option<&'a TenantId>,
    ) -> SidFuture<'a, Vec<(UserId, SessionKey)>> {
        self.inner.subject_sessions(issuer, subject, scope)
    }

    fn sweep_subject_candidates(
        &self,
        max: usize,
    ) -> SidFuture<'_, Vec<(String, UserId, SessionKey)>> {
        self.inner.sweep_subject_candidates(max)
    }

    fn remove_session<'a>(&'a self, session: &'a SessionKey) -> SidFuture<'a, usize> {
        self.inner.remove_session(session)
    }

    fn evict_inserted_before(
        &self,
        cutoff: Timestamp,
        max: usize,
    ) -> SidFuture<'_, Vec<(SidKey, SidEntry)>> {
        self.inner.evict_inserted_before(cutoff, max)
    }

    fn evict_oldest(&self, max: usize) -> SidFuture<'_, Vec<(SidKey, SidEntry)>> {
        self.inner.evict_oldest(max)
    }

    fn mapping_count(&self) -> SidFuture<'_, usize> {
        self.inner.mapping_count()
    }
}

/// A refused login cancelled while it puts the displaced mapping back (a
/// networked store's round trip) still ends the session that aged out, and
/// leaves the displaced session either mapped again or ended: never unmapped
/// and live, out of reach of every `sid` logout.
#[tokio::test]
async fn aborting_the_caller_during_refuse_still_ends_the_aged_session() {
    let f = fixture(Duration::ZERO).await;
    let gate = Gate::new();
    let stalling: Arc<dyn SidStore> = Arc::new(StallingSid {
        inner: Arc::new(f.sid_map.clone()),
        gate: gate.clone(),
    });
    let registry: Arc<dyn SessionRegistryHandle> =
        Arc::new(SessionRegistryAdapter(f.registry.clone()));
    let mut pending =
        PendingEnds::new(Some(registry), stalling).restore_timeout(Duration::from_millis(100));
    pending.age_out((ISS.to_string(), f.user, f.aged));
    let key = (ISS.to_string(), "sid-1".to_string());
    let newcomer = axess_identity::testing::user("newcomer");
    let displaced = f
        .sid_map
        .insert_displacing(
            key.clone(),
            &newcomer.to_string(),
            None,
            newcomer,
            SessionKey::of(&SessionId::new(&MockRng::new(99))),
            at(),
        )
        .expect("the fixture mapped sid-1");
    pending.displace(key.clone(), displaced);
    // The refused login's own mapping is unwound first, as the caller does.
    let taken = f.sid_map.get(&key).expect("the newcomer's mapping");
    f.sid_map.remove_session(&taken.1);

    let caller = tokio::spawn(async move { pending.refuse().await });
    abort_inside(&gate, caller).await;

    assert!(
        !valid(&f, &f.aged).await,
        "the aged-out session is still live after a cancelled refusal"
    );
    // The restore never finishes, so after its wait the displaced session
    // ends rather than stay live with no mapping to reach it.
    let settled =
        eventually(|| async { f.sid_map.get(&key).is_some() || !valid(&f, &f.displaced).await })
            .await;
    assert!(
        settled,
        "the displaced session is unmapped and live: no sid logout reaches it"
    );
}

/// What a refused login logs about the session it displaced names that
/// session by the first eight characters of its key, never by the whole
/// key: when the mapping is not put back because the key is taken, and when
/// the store does not answer and the session is ended instead.
#[tokio::test]
async fn a_refused_login_logs_the_displaced_session_by_a_prefix_only() {
    let capture = TracingCapture::install();
    let newcomer = axess_identity::testing::user("newcomer");

    // The key is still taken by the newcomer's mapping: nothing is put back.
    let f = fixture(Duration::ZERO).await;
    pending_for(&f, newcomer).refuse().await;

    // The store never answers the restore: after the wait the displaced
    // session is ended instead.
    let g = fixture(Duration::ZERO).await;
    let stalling: Arc<dyn SidStore> = Arc::new(StallingSid {
        inner: Arc::new(g.sid_map.clone()),
        gate: Gate::new(),
    });
    let registry: Arc<dyn SessionRegistryHandle> =
        Arc::new(SessionRegistryAdapter(g.registry.clone()));
    let mut pending =
        PendingEnds::new(Some(registry), stalling).restore_timeout(Duration::from_millis(100));
    let key = (ISS.to_string(), "sid-1".to_string());
    let displaced = g
        .sid_map
        .insert_displacing(
            key.clone(),
            &newcomer.to_string(),
            None,
            newcomer,
            SessionKey::of(&SessionId::new(&MockRng::new(99))),
            at(),
        )
        .expect("the fixture mapped sid-1");
    pending.displace(key.clone(), displaced);
    let taken = g.sid_map.get(&key).expect("the newcomer's mapping");
    g.sid_map.remove_session(&taken.1);
    pending.refuse().await;
    assert!(
        !valid(&g, &g.displaced).await,
        "the displaced session ended"
    );

    assert_eq!(f.displaced, g.displaced, "both fixtures draw the same ids");
    let full = f.displaced.to_string();
    let prefix = f.displaced.prefix().to_string();
    assert_eq!(prefix, format!("{}...", &full[..8]));
    let events = capture.events();
    for line in ["was not put back", "could not be put back"] {
        let logged: Vec<_> = events
            .iter()
            .filter(|event| event.message.contains(line))
            .collect();
        assert_eq!(logged.len(), 1, "{line}: {events:?}");
        assert!(logged[0].message.contains(&prefix), "{}", logged[0]);
    }
    assert!(
        events.iter().all(|event| !event.message.contains(&full)),
        "the whole session key is logged: {events:?}"
    );
}
