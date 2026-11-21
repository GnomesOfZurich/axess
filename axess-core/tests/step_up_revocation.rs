//! A session in the middle of a step-up is still the signed-in session it
//! began from. A revocation, or the absolute age cap of its login, ends it
//! as it ends that session, so the request that would finish the step-up is
//! refused instead of signing the session back in. A finished step-up is a
//! proof of presence, not a new login: recency checks read its time, and the
//! absolute cap still counts from the login.

#![cfg(all(feature = "memory", feature = "testing"))]

use axess_core::testing::fixtures as common;

use axess_clock::{Clock, testing::MockClock};
use axess_core::authn::AuditContext;
use axess_core::authn::error::AuthnError;
use axess_core::authn::factor::{FactorCredential, FactorKind, ZeroizedString};
use axess_core::authn::service::{AuthnService, RequestAuthnService};
use axess_core::blocking::KdfExecutor;
use axess_core::session::{
    extractor::AuthSession,
    layer::SessionLayer,
    store::{MemorySessionRegistry, MemorySessionStore, SessionRegistryHandle},
};
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axum::{
    Router,
    body::Body,
    http::{Request, header},
    routing::get,
};
use common::{password_config, password_method, test_tenant, test_user, uid, user_scope};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

const KEY: [u8; 32] = [
    3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3, 2, 3, 8, 4, 6, 2, 6, 4, 3, 3, 8, 3, 2, 7, 9, 5,
];
const PASSWORD: &str = "Sample2+";

type Service = RequestAuthnService<MockIdentityStore, MockFactorStore>;

fn password() -> FactorCredential {
    FactorCredential::Password(ZeroizedString::new(PASSWORD))
}

/// The application: a password login, a password step-up, a route that
/// rotates the session id, and one that reports who the session is. With
/// `max_age`, the layer caps an authenticated session's age at it.
fn app(clock: &MockClock, max_age: Option<Duration>) -> (Router, Arc<dyn SessionRegistryHandle>) {
    let registry = MemorySessionRegistry::new().with_clock(Arc::new(clock.clone()));
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config(PASSWORD))
        .with_method(&uid("u1"), password_method());
    let svc: Arc<Service> = Arc::new(
        AuthnService::builder(identity, factors)
            .with_clock(clock.clone())
            .with_kdf_executor(Arc::new(KdfExecutor::inline()))
            .with_registry(registry.clone())
            .build()
            .with_audit_context(AuditContext::default()),
    );
    let handle = registry.handle();
    let mut layer = SessionLayer::new(
        MemorySessionStore::new().with_clock(Arc::new(clock.clone())),
        KEY,
        handle.clone(),
        std::sync::Arc::new(axess_core::session::UnrecordedSessionEnds),
    )
    .with_clock(clock.clone())
    .with_secure(false);
    if max_age.is_some() {
        layer = layer.with_max_session_age(max_age);
    }

    let (login, begin, finish) = (svc.clone(), svc.clone(), svc.clone());
    let recent_clock = clock.clone();
    let (finish_revoked, revoker) = (svc, handle.clone());
    let router = Router::new()
        .route(
            "/login",
            get(move |s: AuthSession| {
                let svc = login.clone();
                async move {
                    svc.begin_login("alice", "default", &s).await.unwrap();
                    format!("{:?}", svc.verify_factor(&password(), &s).await.unwrap())
                }
            }),
        )
        .route(
            "/step-up/begin",
            get(move |s: AuthSession| {
                let svc = begin.clone();
                async move {
                    match svc.begin_step_up(&s, vec![FactorKind::Password]).await {
                        Ok(_) => "open".to_owned(),
                        Err(e) => format!("refused: {e}"),
                    }
                }
            }),
        )
        .route(
            "/step-up/finish",
            get(move |s: AuthSession| {
                let svc = finish.clone();
                async move { finish_step_up(&svc, &s).await }
            }),
        )
        .route(
            "/step-up/finish-while-revoked",
            get(move |s: AuthSession| {
                let (svc, revoker) = (finish_revoked.clone(), revoker.clone());
                async move {
                    // The revocation lands after this request loaded the
                    // session and before the step-up is verified.
                    revoker.invalidate_user(&uid("u1")).await.unwrap();
                    finish_step_up(&svc, &s).await
                }
            }),
        )
        .route(
            "/rotate",
            get(|s: AuthSession| async move {
                s.regenerate().await;
                "rotated"
            }),
        )
        .route(
            "/times",
            get(|s: AuthSession| async move {
                match s.snapshot().await {
                    Some(snap) => format!(
                        "{} {}",
                        snap.signed_in_at.to_rfc3339_numeric_offset(),
                        snap.authn_time.to_rfc3339_numeric_offset()
                    ),
                    None => "not signed in".to_owned(),
                }
            }),
        )
        .route(
            "/recent",
            get(move |s: AuthSession| {
                let clock = recent_clock.clone();
                async move {
                    if s.authenticated_within(Duration::from_secs(300), clock.now())
                        .await
                    {
                        "recent"
                    } else {
                        "stale"
                    }
                }
            }),
        )
        .route(
            "/whoami",
            get(|s: AuthSession| async move {
                if s.is_authenticated().await {
                    "user"
                } else if s.step_up_pending().await {
                    "step-up"
                } else {
                    "guest"
                }
            }),
        )
        .layer(layer);
    (router, handle)
}

/// Answer the step-up with the right password. The route does not ask
/// `step_up_pending` first, so what refuses a session the load ended is the
/// service itself: that session has no pending step left to verify.
async fn finish_step_up(svc: &Service, s: &AuthSession) -> String {
    match svc.verify_factor(&password(), s).await {
        Ok(outcome) => format!("{outcome:?}"),
        Err(AuthnError::NoFlow) => "no pending step".to_owned(),
        Err(e) => format!("refused: {e}"),
    }
}

async fn call(app: &Router, jar: &mut Option<String>, path: &str) -> String {
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

/// Sign in and open a step-up.
async fn signed_in_with_a_step_up_open(app: &Router, jar: &mut Option<String>) {
    assert_eq!(call(app, jar, "/login").await, "Authenticated");
    assert_eq!(call(app, jar, "/step-up/begin").await, "open");
    assert_eq!(call(app, jar, "/whoami").await, "step-up");
}

/// Neither revoked nor too old, an open step-up finishes and the session is
/// signed in.
#[tokio::test]
async fn an_open_step_up_of_a_live_session_finishes() {
    let clock = common::test_clock();
    let (app, _) = app(&clock, None);
    let mut jar = None;
    signed_in_with_a_step_up_open(&app, &mut jar).await;
    assert_eq!(
        call(&app, &mut jar, "/step-up/finish").await,
        "Authenticated"
    );
    assert_eq!(call(&app, &mut jar, "/whoami").await, "user");
}

/// A session revoked while its step-up is open is ended by the next load:
/// the finish is refused and the session is a guest.
#[tokio::test]
async fn a_step_up_of_a_revoked_session_cannot_be_finished() {
    let clock = common::test_clock();
    let (app, registry) = app(&clock, None);
    let mut jar = None;
    signed_in_with_a_step_up_open(&app, &mut jar).await;

    registry.invalidate_user(&uid("u1")).await.unwrap();

    assert_eq!(
        call(&app, &mut jar, "/step-up/finish").await,
        "no pending step"
    );
    assert_eq!(call(&app, &mut jar, "/whoami").await, "guest");
}

/// A revocation that lands while the finishing request runs ends the session
/// too: the step-up held its registry entry, so an entry gone by the end of
/// the request is a revocation, whatever the finish registered.
#[tokio::test]
async fn a_revocation_while_the_step_up_is_finished_ends_the_session() {
    let clock = common::test_clock();
    let (app, _) = app(&clock, None);
    let mut jar = None;
    signed_in_with_a_step_up_open(&app, &mut jar).await;

    call(&app, &mut jar, "/step-up/finish-while-revoked").await;

    assert_eq!(call(&app, &mut jar, "/whoami").await, "guest");
}

/// A step-up does not stop the clock of the login it began from: past the
/// absolute age cap the next load ends the session, so the finish is refused
/// rather than signing the session in afresh.
#[tokio::test]
async fn a_step_up_past_the_absolute_age_cap_cannot_be_finished() {
    let clock = common::test_clock();
    let (app, _) = app(&clock, Some(Duration::from_secs(3600)));
    let mut jar = None;
    assert_eq!(call(&app, &mut jar, "/login").await, "Authenticated");
    clock.advance(axess_clock::SignedDuration::minutes(58));
    assert_eq!(call(&app, &mut jar, "/step-up/begin").await, "open");
    clock.advance(axess_clock::SignedDuration::minutes(4));

    assert_eq!(
        call(&app, &mut jar, "/step-up/finish").await,
        "no pending step"
    );
    assert_eq!(call(&app, &mut jar, "/whoami").await, "guest");
}

/// The session layer moves the registry entry when a handler rotates the id
/// of a session in a step-up, as it does for a signed-in one, so the step-up
/// still finishes under the new id.
#[tokio::test]
async fn a_step_up_whose_id_is_rotated_still_finishes() {
    let clock = common::test_clock();
    let (app, _) = app(&clock, None);
    let mut jar = None;
    signed_in_with_a_step_up_open(&app, &mut jar).await;
    let before = jar.clone();

    assert_eq!(call(&app, &mut jar, "/rotate").await, "rotated");
    assert_ne!(jar, before, "the id changed");

    assert_eq!(
        call(&app, &mut jar, "/step-up/finish").await,
        "Authenticated"
    );
    assert_eq!(call(&app, &mut jar, "/whoami").await, "user");
}

/// A step-up proves presence again, but it is not a new login: a session
/// that steps up every fifty minutes is still ended at a sixty-minute
/// absolute cap counted from its login.
#[tokio::test]
async fn a_session_that_steps_up_every_fifty_minutes_ends_at_its_logins_cap() {
    let clock = common::test_clock();
    let (app, _) = app(&clock, Some(Duration::from_secs(3600)));
    let mut jar = None;
    assert_eq!(call(&app, &mut jar, "/login").await, "Authenticated");

    clock.advance(axess_clock::SignedDuration::minutes(50));
    assert_eq!(call(&app, &mut jar, "/step-up/begin").await, "open");
    assert_eq!(
        call(&app, &mut jar, "/step-up/finish").await,
        "Authenticated"
    );
    clock.advance(axess_clock::SignedDuration::minutes(5));
    assert_eq!(
        call(&app, &mut jar, "/whoami").await,
        "user",
        "55 minutes after the login"
    );

    clock.advance(axess_clock::SignedDuration::minutes(6));
    assert_eq!(
        call(&app, &mut jar, "/whoami").await,
        "guest",
        "61 minutes after the login, 11 after the step-up"
    );
}

/// An id rotation, by the step-up's finish and by a handler after it, keeps
/// the login's time: the session still names its login as when it signed
/// in, and the step-up as its last proof of presence.
#[tokio::test]
async fn a_rotation_keeps_the_logins_time() {
    let clock = common::test_clock();
    let (app, _) = app(&clock, None);
    let mut jar = None;
    let login = clock.now();
    assert_eq!(call(&app, &mut jar, "/login").await, "Authenticated");

    clock.advance(axess_clock::SignedDuration::minutes(50));
    let stepped_up = clock.now();
    assert_eq!(call(&app, &mut jar, "/step-up/begin").await, "open");
    assert_eq!(
        call(&app, &mut jar, "/step-up/finish").await,
        "Authenticated"
    );
    clock.advance(axess_clock::SignedDuration::minutes(5));
    let before = jar.clone();
    assert_eq!(call(&app, &mut jar, "/rotate").await, "rotated");
    assert_ne!(jar, before, "the id changed");

    assert_eq!(
        call(&app, &mut jar, "/times").await,
        format!(
            "{} {}",
            login.to_rfc3339_numeric_offset(),
            stepped_up.to_rfc3339_numeric_offset()
        )
    );
}

/// What a recency check reads is the step-up's own time: a session whose
/// login is fifty minutes old is not recent, and right after a step-up it
/// is, for the window the check allows.
#[tokio::test]
async fn a_step_up_satisfies_a_recency_check_for_the_minutes_after_it() {
    let clock = common::test_clock();
    let (app, _) = app(&clock, Some(Duration::from_secs(3600)));
    let mut jar = None;
    assert_eq!(call(&app, &mut jar, "/login").await, "Authenticated");
    assert_eq!(call(&app, &mut jar, "/recent").await, "recent");

    clock.advance(axess_clock::SignedDuration::minutes(50));
    assert_eq!(call(&app, &mut jar, "/recent").await, "stale");
    assert_eq!(call(&app, &mut jar, "/step-up/begin").await, "open");
    assert_eq!(
        call(&app, &mut jar, "/step-up/finish").await,
        "Authenticated"
    );

    clock.advance(axess_clock::SignedDuration::minutes(4));
    assert_eq!(call(&app, &mut jar, "/recent").await, "recent");
    clock.advance(axess_clock::SignedDuration::minutes(2));
    assert_eq!(
        call(&app, &mut jar, "/recent").await,
        "stale",
        "six minutes after the step-up, past the five the check allows"
    );
}
