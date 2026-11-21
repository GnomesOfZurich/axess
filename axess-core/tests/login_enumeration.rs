#![cfg(feature = "testing")]
//! What the combined login entry point and the failure pipeline tell a caller
//! who has proved nothing: a lock is never shown by the password form.

use axess_core::testing::fixtures as common;

use axess_core::authn::AuditContext;
use axess_core::authn::service::{AuthnService, FactorOutcome, RequestAuthnService};
use axess_core::authn::types::LockoutPolicy;
use axess_core::blocking::KdfExecutor;
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axess_core::testing::test_session;
use common::{password_config, password_method, test_tenant, test_user, uid, user_scope};
use std::time::Duration;

type Svc = RequestAuthnService<MockIdentityStore, MockFactorStore>;

fn rig(policy: LockoutPolicy) -> (Svc, MockIdentityStore) {
    rig_on(common::test_clock(), policy)
}

/// [`rig`], on the clock the test built.
fn rig_on(
    clock: axess_core::testing::MockClock,
    policy: LockoutPolicy,
) -> (Svc, MockIdentityStore) {
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"))
        .with_lockout_policy(policy)
        .with_clock(clock.clone());
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Sample2+"))
        .with_method(&uid("u1"), password_method());
    let svc = AuthnService::builder(identity.clone(), factors)
        .with_clock(clock)
        .with_kdf_executor(std::sync::Arc::new(KdfExecutor::inline()))
        .build()
        .with_audit_context(AuditContext::default());
    (svc, identity)
}

#[tokio::test]
async fn the_password_form_answers_the_guess_that_locks_the_account_as_a_wrong_password() {
    let (svc, _) = rig(LockoutPolicy {
        max_attempts: 3,
        duration: Some(Duration::from_secs(900)),
        ..LockoutPolicy::default().without_throttle()
    });
    let mut answers = Vec::new();
    for _ in 0..4 {
        answers.push(
            svc.login_with_password("alice", "default", "wrong", &test_session())
                .await,
        );
    }
    for answer in &answers {
        assert!(
            matches!(answer, Ok(FactorOutcome::InvalidCredential)),
            "an existing account must answer as an unknown one does: {answers:?}"
        );
    }
}

/// What a refused password entry leaves in `session`: its stored data, and
/// whether the id it carries was rotated.
async fn left_by(svc: &Svc, identifier: &str) -> (serde_json::Value, bool) {
    let session = test_session();
    let arrived_with = session.session_key().await;
    let outcome = svc
        .login_with_password(identifier, "default", "wrong", &session)
        .await;
    assert!(
        matches!(outcome, Ok(FactorOutcome::InvalidCredential)),
        "{identifier}: {outcome:?}"
    );
    (
        serde_json::to_value(session.data().await).expect("session data"),
        session.session_key().await != arrived_with,
    )
}

/// A wrong password for an account that exists ends the login it began, as
/// an unknown identifier never begins one: both leave a cleared guest session
/// under a rotated id, so the session does not say which identifiers exist.
#[tokio::test]
async fn a_refused_password_leaves_one_session_for_a_known_and_an_unknown_identifier() {
    let (svc, _) = rig(LockoutPolicy::default().without_throttle());
    let known = left_by(&svc, "alice").await;
    let unknown = left_by(&svc, "nobody").await;

    let guest = serde_json::to_value(axess_core::session::data::SessionData::default())
        .expect("session data");
    assert_eq!(known.0, guest, "the refused login is not left open");
    assert!(known.1, "the id the login was begun under is retired");
    assert_eq!(known, unknown);
}

/// The same on a locked account and on a throttled guess: neither leaves a
/// login open.
#[tokio::test]
async fn a_locked_and_a_throttled_entry_leave_the_session_an_unknown_identifier_leaves() {
    let clock = common::test_clock();
    let (locked, _) = rig_on(
        clock.clone(),
        LockoutPolicy {
            max_attempts: 1,
            duration: Some(Duration::from_secs(900)),
            ..LockoutPolicy::default().without_throttle()
        },
    );
    let unknown = left_by(&locked, "nobody").await;
    // The first wrong password locks the account; the second meets the lock.
    assert_eq!(left_by(&locked, "alice").await, unknown);
    assert_eq!(left_by(&locked, "alice").await, unknown);

    // A second guess inside the delay the first one started is throttled.
    let (throttled, _) = rig_on(clock, LockoutPolicy::default());
    assert_eq!(left_by(&throttled, "alice").await, unknown);
    assert_eq!(left_by(&throttled, "alice").await, unknown);
}

mod on_the_wire {
    //! The same comparison where a client sees it: through the session
    //! layer, in the cookie a response sets and in what the session holds on
    //! the next request.

    use super::{Svc, rig_on};
    use axess_core::authn::types::LockoutPolicy;
    use axess_core::session::{
        extractor::AuthSession, layer::SessionLayer, store::MemorySessionStore,
    };
    use axess_core::testing::MockClock;
    use axum::{
        Router,
        body::Body,
        extract::Path,
        http::{Request, header},
        routing::get,
    };
    use std::sync::Arc;
    use tower::ServiceExt;

    fn app(svc: Svc, clock: MockClock) -> Router {
        Router::new()
            // A visit that leaves something in the session, so the visitor
            // holds a session cookie before any login.
            .route(
                "/visit",
                get(|session: AuthSession| async move {
                    session
                        .set_custom("visited", serde_json::Value::Bool(true))
                        .await;
                    "visited"
                }),
            )
            .route(
                "/login/{identifier}",
                get(
                    move |session: AuthSession, Path(identifier): Path<String>| {
                        let svc = svc.clone();
                        async move {
                            let outcome = svc
                                .login_with_password(&identifier, "default", "wrong", &session)
                                .await;
                            format!("{outcome:?}")
                        }
                    },
                ),
            )
            .route(
                "/session",
                get(|session: AuthSession| async move {
                    serde_json::to_string(&session.data().await).expect("session data")
                }),
            )
            .layer(
                SessionLayer::without_registry_insecure(
                    MemorySessionStore::new().with_clock(Arc::new(clock.clone())),
                    axess_core::testing::test_key(7),
                    std::sync::Arc::new(axess_core::session::UnrecordedSessionEnds),
                )
                .with_clock(clock)
                .with_secure(false),
            )
    }

    /// The answer to `uri` sent with `cookie`: its body, and the cookies it
    /// sets as `name=value` pairs and as shapes with the value blanked.
    async fn ask(
        app: &Router,
        uri: &str,
        cookie: Option<&str>,
    ) -> (String, Vec<String>, Vec<String>) {
        let mut request = Request::get(uri);
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let set: Vec<String> = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap().to_string())
            .collect();
        let pairs = set
            .iter()
            .map(|cookie| cookie.split(';').next().unwrap_or_default().to_string())
            .collect();
        let shapes = set
            .iter()
            .map(|cookie| {
                let (pair, attributes) = cookie.split_once(';').unwrap_or((cookie, ""));
                let name = pair.split('=').next().unwrap_or_default();
                format!("{name}=<value>;{attributes}")
            })
            .collect();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .unwrap();
        (String::from_utf8(bytes.to_vec()).unwrap(), pairs, shapes)
    }

    /// One refused entry for `identifier`, from a visitor with no cookie or
    /// with the cookie of an earlier visit: the answer, the shape of the
    /// cookie it sets, and the session the next request finds.
    async fn refused(
        clock: &MockClock,
        identifier: &str,
        visited_first: bool,
    ) -> (String, Vec<String>, String) {
        let (svc, _) = rig_on(clock.clone(), LockoutPolicy::default().without_throttle());
        let app = app(svc, clock.clone());
        let arrived_with = if visited_first {
            let (_, pairs, _) = ask(&app, "/visit", None).await;
            Some(pairs.join("; "))
        } else {
            None
        };
        let (answer, pairs, shapes) = ask(
            &app,
            &format!("/login/{identifier}"),
            arrived_with.as_deref(),
        )
        .await;
        assert_eq!(answer, "Ok(InvalidCredential)", "{identifier}");
        assert_eq!(
            pairs.len(),
            1,
            "{identifier}: a refused entry sets the session cookie anew"
        );
        assert_ne!(
            Some(pairs[0].as_str()),
            arrived_with.as_deref(),
            "{identifier}: under a new id"
        );
        let (session, _, _) = ask(&app, "/session", Some(&pairs[0])).await;
        (answer, shapes, session)
    }

    #[tokio::test]
    async fn a_refused_password_sets_the_same_cookie_and_leaves_the_same_session() {
        let clock = super::common::test_clock();
        for visited_first in [false, true] {
            let known = refused(&clock, "alice", visited_first).await;
            let unknown = refused(&clock, "nobody", visited_first).await;
            assert!(
                !known.2.contains("visited") && !known.2.contains("Authenticating"),
                "the session a refused entry leaves is a fresh guest: {}",
                known.2
            );
            assert_eq!(known, unknown, "visited first: {visited_first}");
        }
    }
}
