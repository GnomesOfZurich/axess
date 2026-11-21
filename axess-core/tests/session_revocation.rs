//! A session layer built with a registry enforces revocation on every
//! request, whatever guards the route, and moves the registry entry when a
//! handler rotates the session id.

#![cfg(all(feature = "memory", feature = "testing"))]

use axess_core::session::SessionKey;
use axess_core::testing::fixtures as common;

use axess_clock::testing::MockClock;
use axess_core::authn::event::{AuthEvent, AuthEventStatus, AuthEventType};
use axess_core::authn::ids::testing;
use axess_core::authn::service::AuthnService;
use axess_core::session::{SessionEndAudit, SessionEndReason, UnrecordedSessionEnds};
use axess_core::session::{
    extractor::AuthSession,
    layer::SessionLayer,
    store::{
        MemorySessionRegistry, MemorySessionStore, SessionRegistryAdapter, SessionRegistryHandle,
        SessionStore,
    },
};
use axess_core::testing::AuthSessionTestExt;
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axum::{
    Router,
    body::Body,
    http::{Request, header},
    routing::get,
};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

#[derive(Clone)]
struct World {
    store: MemorySessionStore,
    registry: Arc<dyn SessionRegistryHandle>,
    clock: MockClock,
    app: Router,
}

fn world(max_age: Option<Duration>) -> World {
    world_with(|layer| match max_age {
        Some(max_age) => layer.with_max_session_age(Some(max_age)),
        None => layer.with_max_session_age(None),
    })
}

fn world_with(
    configure: impl FnOnce(SessionLayer<MemorySessionStore>) -> SessionLayer<MemorySessionStore>,
) -> World {
    world_on(
        common::test_clock(),
        Arc::new(UnrecordedSessionEnds),
        configure,
    )
}

/// The world on a clock the caller made and with the audit sink the caller
/// built on that clock before the layer exists.
fn world_on(
    clock: MockClock,
    audit: Arc<dyn SessionEndAudit>,
    configure: impl FnOnce(SessionLayer<MemorySessionStore>) -> SessionLayer<MemorySessionStore>,
) -> World {
    let store = MemorySessionStore::new().with_clock(Arc::new(clock.clone()));
    let registry: Arc<dyn SessionRegistryHandle> = Arc::new(SessionRegistryAdapter(
        MemorySessionRegistry::new().with_clock(Arc::new(clock.clone())),
    ));
    let reg = registry.clone();
    let layer = configure(
        SessionLayer::new(
            store.clone(),
            axess_core::testing::test_key(9),
            registry.clone(),
            audit,
        )
        .with_secure(false)
        .with_clock(clock.clone()),
    );
    let clock_login = clock.clone();
    let (reg_impersonated, clock_impersonated) = (registry.clone(), clock.clone());
    let reg_kicked = registry.clone();
    let app = Router::new()
        .route(
            "/login",
            get(move |s: AuthSession| {
                let reg = reg.clone();
                let clock = clock_login.clone();
                async move {
                    let (u, t) = (testing::user("u1"), testing::tenant("t1"));
                    s.set_authenticated(u, t, axess_clock::Clock::now(&clock))
                        .await;
                    let key = s.session_key().await;
                    assert!(reg.register(&u, &key).await);
                    "in"
                }
            }),
        )
        .route(
            "/whoami",
            get(|s: AuthSession| async move {
                if s.is_authenticated().await {
                    s.session_key().await.to_string()
                } else {
                    "guest".to_owned()
                }
            }),
        )
        .route(
            "/regen",
            get(|s: AuthSession| async move {
                s.regenerate().await;
                "regen"
            }),
        )
        // Signs in as `u1` under an impersonation by `a1` whose registry
        // entry under the administrator is not made: the next request finds
        // the impersonation no longer held.
        .route(
            "/impersonated",
            get(move |s: AuthSession| {
                let (reg, clock) = (reg_impersonated.clone(), clock_impersonated.clone());
                async move {
                    let (u, t) = (testing::user("u1"), testing::tenant("t1"));
                    let now = axess_clock::Clock::now(&clock);
                    s.set_authenticated(u, t, now).await;
                    assert!(s.set_impersonator(testing::user("a1"), now).await);
                    assert!(reg.register(&u, &s.session_key().await).await);
                    "in"
                }
            }),
        )
        // Rotates the session id while every session of `u1` is revoked.
        .route(
            "/regen-while-revoked",
            get(move |s: AuthSession| {
                let reg = reg_kicked.clone();
                async move {
                    s.regenerate().await;
                    reg.invalidate_user(&testing::user("u1"))
                        .await
                        .expect("revoke");
                    "regen"
                }
            }),
        )
        .layer(layer);
    World {
        store,
        registry,
        clock,
        app,
    }
}

/// Send a GET with the cookie jar and fold the response's cookies back in.
async fn get_as(app: &Router, jar: &mut Option<String>, path: &str) -> String {
    let mut req = Request::get(path);
    if let Some(c) = jar.as_deref() {
        req = req.header(header::COOKIE, c);
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    if let Some(v) = resp.headers().get(header::SET_COOKIE) {
        *jar = Some(v.to_str().unwrap().split(';').next().unwrap().to_owned());
    }
    let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn a_session_the_registry_dropped_is_ended_and_its_row_deleted() {
    let w = world(None);
    let mut jar = None;
    assert_eq!(get_as(&w.app, &mut jar, "/login").await, "in");
    let sid = get_as(&w.app, &mut jar, "/whoami").await;
    assert_ne!(sid, "guest", "the session works before revocation");
    let sid: SessionKey = sid.parse().unwrap();
    assert!(w.store.load(&sid).await.unwrap().is_some());

    w.registry
        .invalidate_user(&testing::user("u1"))
        .await
        .expect("revoke");

    let stale_cookie = jar.clone();
    assert_eq!(get_as(&w.app, &mut jar, "/whoami").await, "guest");
    assert!(
        w.store.load(&sid).await.unwrap().is_none(),
        "the store must not keep an Authenticated row for a revoked session"
    );
    // The old cookie keeps being a guest.
    let mut old = stale_cookie;
    assert_eq!(get_as(&w.app, &mut old, "/whoami").await, "guest");
}

#[tokio::test]
async fn without_a_registry_on_the_layer_the_row_outlives_revocation() {
    // The behaviour the registry option exists to fix: documented here so a
    // change in it is deliberate.
    let clock = common::test_clock();
    let store = MemorySessionStore::new().with_clock(Arc::new(clock.clone()));
    let registry: Arc<dyn SessionRegistryHandle> = Arc::new(SessionRegistryAdapter(
        MemorySessionRegistry::new().with_clock(Arc::new(clock.clone())),
    ));
    let reg = registry.clone();
    let app = Router::new()
        .route(
            "/login",
            get(move |s: AuthSession| {
                let reg = reg.clone();
                async move {
                    let u = testing::user("u1");
                    s.set_authenticated(u, testing::tenant("t1"), common::start())
                        .await;
                    reg.register(&u, &s.session_key().await).await;
                    "in"
                }
            }),
        )
        .route(
            "/whoami",
            get(|s: AuthSession| async move { s.is_authenticated().await.to_string() }),
        )
        .layer(
            SessionLayer::without_registry_insecure(
                store,
                axess_core::testing::test_key(9),
                Arc::new(UnrecordedSessionEnds),
            )
            .with_clock(clock)
            .with_secure(false),
        );
    let mut jar = None;
    get_as(&app, &mut jar, "/login").await;
    registry
        .invalidate_user(&testing::user("u1"))
        .await
        .expect("revoke");
    assert_eq!(get_as(&app, &mut jar, "/whoami").await, "true");
}

#[tokio::test]
async fn a_handler_regenerate_keeps_a_registry_backed_session_alive() {
    let w = world(None);
    let mut jar = None;
    get_as(&w.app, &mut jar, "/login").await;
    let before = get_as(&w.app, &mut jar, "/whoami").await;
    get_as(&w.app, &mut jar, "/regen").await;
    let after = get_as(&w.app, &mut jar, "/whoami").await;
    assert_ne!(after, "guest", "the rotated session stays signed in");
    assert_ne!(before, after, "the id really changed");
    let old: SessionKey = before.parse().unwrap();
    let user = testing::user("u1");
    assert_eq!(
        w.registry.liveness(&user, &old).await,
        axess_core::session::store::SessionLiveness::Gone,
        "the old id left the registry"
    );
}

#[tokio::test]
async fn a_session_older_than_the_absolute_cap_is_ended_however_active() {
    let w = world(Some(Duration::from_secs(3600)));
    let mut jar = None;
    get_as(&w.app, &mut jar, "/login").await;
    w.clock.advance_secs(1800);
    assert_ne!(get_as(&w.app, &mut jar, "/whoami").await, "guest");
    w.clock.advance_secs(1801);
    assert_eq!(get_as(&w.app, &mut jar, "/whoami").await, "guest");
}

const DAY: i64 = 24 * 3600;
/// Half the default idle lifetime: a session used this often never idles out,
/// now that the store judges its rows on the test's clock too.
const HALF_DAY: i64 = DAY / 2;

#[tokio::test]
async fn a_session_is_ended_after_seven_days_by_default_however_active() {
    let w = world_with(|layer| layer);
    let mut jar = None;
    get_as(&w.app, &mut jar, "/login").await;
    for _ in 0..13 {
        w.clock.advance_secs(HALF_DAY);
        assert_ne!(get_as(&w.app, &mut jar, "/whoami").await, "guest");
    }
    w.clock.advance_secs(HALF_DAY + 1);
    assert_eq!(get_as(&w.app, &mut jar, "/whoami").await, "guest");
}

#[tokio::test]
async fn lifting_the_session_age_cap_keeps_an_active_session_past_seven_days() {
    let w = world_with(|layer| layer.with_max_session_age(None));
    let mut jar = None;
    get_as(&w.app, &mut jar, "/login").await;
    for _ in 0..20 {
        w.clock.advance_secs(HALF_DAY);
        assert_ne!(get_as(&w.app, &mut jar, "/whoami").await, "guest");
    }
}

/// The cookie of an ended session is of no further use to the client: the
/// response that refuses it replaces it with the cookie of the fresh guest
/// session, though the handler changed nothing.
#[tokio::test]
async fn the_response_that_ends_a_session_replaces_its_cookie() {
    let w = world(None);
    let mut jar = None;
    assert_eq!(get_as(&w.app, &mut jar, "/login").await, "in");
    assert_ne!(get_as(&w.app, &mut jar, "/whoami").await, "guest");
    w.registry
        .invalidate_user(&testing::user("u1"))
        .await
        .expect("revoke");

    let ended = jar.clone();
    assert_eq!(get_as(&w.app, &mut jar, "/whoami").await, "guest");
    assert!(jar.is_some());
    assert_ne!(
        jar, ended,
        "the client was left holding the ended session's cookie"
    );
}

// ── The audit row of a session the layer ends ───────────────────────────────

/// A world whose layer records the sessions it ends through an
/// authentication service's sink, with the identity store the rows land in.
/// The store knows no user: the rows are built from the sessions alone.
fn audited_world(max_age: Option<Duration>) -> (World, MockIdentityStore) {
    let clock = common::test_clock();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(common::test_tenant());
    let authn = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .build();
    let world = world_on(clock, authn.session_end_audit(), |layer| {
        layer.with_max_session_age(max_age)
    });
    (world, identity)
}

/// The rows about sessions in `identity`'s trail.
fn session_rows(identity: &MockIdentityStore) -> Vec<AuthEvent> {
    identity
        .events()
        .into_iter()
        .filter(|e| {
            matches!(
                e.event_type,
                AuthEventType::SessionExpired | AuthEventType::SessionInvalidated
            )
        })
        .collect()
}

/// A session that outlives the absolute age cap is ended by the layer on
/// its next request, and the layer's sink writes the row: `SessionExpired`,
/// `Expired`, naming the user, the tenant and the session, stamped at the
/// moment of the request on the world's clock. The next request of the same
/// client is a guest's and writes nothing more.
#[tokio::test]
async fn a_session_ended_by_the_age_cap_leaves_a_session_expired_row() {
    let (w, identity) = audited_world(Some(Duration::from_secs(3600)));
    let mut jar = None;
    get_as(&w.app, &mut jar, "/login").await;
    let sid: SessionKey = get_as(&w.app, &mut jar, "/whoami").await.parse().unwrap();

    w.clock.advance_secs(3600);
    assert_ne!(get_as(&w.app, &mut jar, "/whoami").await, "guest");
    assert!(session_rows(&identity).is_empty(), "at the cap it stands");

    w.clock.advance_secs(1);
    assert_eq!(get_as(&w.app, &mut jar, "/whoami").await, "guest");
    let rows = session_rows(&identity);
    assert_eq!(rows.len(), 1, "{rows:?}");
    let row = &rows[0];
    assert_eq!(row.event_type, AuthEventType::SessionExpired);
    assert_eq!(row.event_status, AuthEventStatus::Expired);
    assert_eq!(row.user_id, Some(testing::user("u1")));
    assert_eq!(row.tenant_id, Some(testing::tenant("t1")));
    assert_eq!(row.session_id, Some(sid));
    assert_eq!(
        row.error.as_ref().map(|e| e.as_str()),
        Some(SessionEndReason::AgeCap.as_str())
    );
    assert_eq!(
        row.event_time,
        axess_clock::Clock::now(&w.clock).unix_micros()
    );
    assert!(row.actor_id.is_none() && row.ip_address.is_none());

    w.clock.advance_secs(60);
    assert_eq!(get_as(&w.app, &mut jar, "/whoami").await, "guest");
    assert_eq!(session_rows(&identity).len(), 1, "one row per ending");
}

/// A session the registry dropped is ended by the layer on its next
/// request, and the sink writes a `SessionInvalidated` row naming it.
#[tokio::test]
async fn a_session_the_registry_dropped_leaves_a_session_invalidated_row() {
    let (w, identity) = audited_world(None);
    let mut jar = None;
    get_as(&w.app, &mut jar, "/login").await;
    let sid: SessionKey = get_as(&w.app, &mut jar, "/whoami").await.parse().unwrap();
    assert!(session_rows(&identity).is_empty());

    w.registry
        .invalidate_user(&testing::user("u1"))
        .await
        .expect("revoke");
    assert!(
        session_rows(&identity).is_empty(),
        "the registry call writes no row of its own"
    );

    assert_eq!(get_as(&w.app, &mut jar, "/whoami").await, "guest");
    let rows = session_rows(&identity);
    assert_eq!(rows.len(), 1, "{rows:?}");
    let row = &rows[0];
    assert_eq!(row.event_type, AuthEventType::SessionInvalidated);
    assert_eq!(row.event_status, AuthEventStatus::Success);
    assert_eq!(row.user_id, Some(testing::user("u1")));
    assert_eq!(row.tenant_id, Some(testing::tenant("t1")));
    assert_eq!(row.session_id, Some(sid));
    assert_eq!(
        row.error.as_ref().map(|e| e.as_str()),
        Some(SessionEndReason::NotRegistered.as_str())
    );
    assert!(row.actor_id.is_none() && row.ip_address.is_none());
}

/// Requests that carry one over-age session at the same moment (a page
/// that fires several at once) leave one row between them, and every one
/// of them runs as a guest.
#[tokio::test]
async fn requests_that_meet_one_ended_session_together_leave_one_row() {
    let (w, identity) = audited_world(Some(Duration::from_secs(3600)));
    let mut jar = None;
    get_as(&w.app, &mut jar, "/login").await;
    w.clock.advance_secs(3601);

    let (mut a, mut b, mut c) = (jar.clone(), jar.clone(), jar.clone());
    let bodies = tokio::join!(
        get_as(&w.app, &mut a, "/whoami"),
        get_as(&w.app, &mut b, "/whoami"),
        get_as(&w.app, &mut c, "/whoami"),
    );

    let guest = String::from("guest");
    assert_eq!(bodies, (guest.clone(), guest.clone(), guest));
    let rows = session_rows(&identity);
    assert_eq!(rows.len(), 1, "one row per ending: {rows:?}");
}

/// The row comes first. While the audit store refuses it, the session is
/// refused but not ended: its row stays in the session store and the
/// client keeps its cookie. The first request after the audit store is
/// back ends the session, and writes its one row.
#[tokio::test]
async fn a_session_whose_row_cannot_be_written_is_refused_and_not_ended() {
    let (w, identity) = audited_world(Some(Duration::from_secs(3600)));
    let mut jar = None;
    get_as(&w.app, &mut jar, "/login").await;
    let sid: SessionKey = get_as(&w.app, &mut jar, "/whoami").await.parse().unwrap();
    let cookie = jar.clone();
    w.clock.advance_secs(3601);

    identity.arm_record_event_failure();
    for _ in 0..2 {
        assert_eq!(get_as(&w.app, &mut jar, "/whoami").await, "guest");
        assert_eq!(jar, cookie, "the cookie of an unended session stands");
        assert!(
            w.store.load(&sid).await.unwrap().is_some(),
            "a session is not removed before its row is written"
        );
        assert!(session_rows(&identity).is_empty());
    }

    identity.disarm_record_event_failure();
    assert_eq!(get_as(&w.app, &mut jar, "/whoami").await, "guest");
    assert_ne!(jar, cookie, "the ended session's cookie is replaced");
    assert!(w.store.load(&sid).await.unwrap().is_none());
    assert_eq!(session_rows(&identity).len(), 1);
}

/// A session revoked while a request rotates its id is ended at the end of
/// that request, and that ending has its row too: `SessionInvalidated`,
/// with the reason, the user, the tenant and the rotated id, which no row
/// in the session store holds any more.
#[tokio::test]
async fn a_session_revoked_while_its_id_rotates_leaves_a_row() {
    let (w, identity) = audited_world(None);
    let mut jar = None;
    get_as(&w.app, &mut jar, "/login").await;
    let old: SessionKey = get_as(&w.app, &mut jar, "/whoami").await.parse().unwrap();
    let cookie = jar.clone();

    assert_eq!(
        get_as(&w.app, &mut jar, "/regen-while-revoked").await,
        "regen"
    );

    assert_eq!(jar, cookie, "an ended session gets no cookie");
    let rows = session_rows(&identity);
    assert_eq!(rows.len(), 1, "{rows:?}");
    let row = &rows[0];
    assert_eq!(row.event_type, AuthEventType::SessionInvalidated);
    assert_eq!(row.event_status, AuthEventStatus::Success);
    assert_eq!(row.user_id, Some(testing::user("u1")));
    assert_eq!(row.tenant_id, Some(testing::tenant("t1")));
    assert_eq!(
        row.error.as_ref().map(|e| e.as_str()),
        Some(SessionEndReason::RevokedDuringRotation.as_str())
    );
    let rotated = row.session_id.expect("the row names the session");
    assert_ne!(rotated, old, "by the key its row was stored under");
    assert!(w.store.load(&rotated).await.unwrap().is_none());
    assert!(w.store.load(&old).await.unwrap().is_none());

    assert_eq!(get_as(&w.app, &mut jar, "/whoami").await, "guest");
    assert_eq!(session_rows(&identity).len(), 1, "one row per ending");
}

/// The row of an ended impersonation names the administrator as its actor,
/// so the end of an impersonation does not read as the end of the user's
/// own session.
#[tokio::test]
async fn the_row_of_an_ended_impersonation_names_the_administrator() {
    let (w, identity) = audited_world(None);
    let mut jar = None;
    assert_eq!(get_as(&w.app, &mut jar, "/impersonated").await, "in");

    assert_eq!(get_as(&w.app, &mut jar, "/whoami").await, "guest");

    let rows = session_rows(&identity);
    assert_eq!(rows.len(), 1, "{rows:?}");
    let row = &rows[0];
    assert_eq!(row.event_type, AuthEventType::SessionInvalidated);
    assert_eq!(row.user_id, Some(testing::user("u1")));
    assert_eq!(row.actor_id, Some(testing::user("a1")));
    assert_eq!(
        row.error.as_ref().map(|e| e.as_str()),
        Some(SessionEndReason::ImpersonationNotRegistered.as_str())
    );
}
