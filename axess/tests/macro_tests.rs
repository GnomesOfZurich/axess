//! Tests for require_authn!() and require_partial_authn!() macros.
//!
//! These must live in the `axess` crate (not `axess-core`) because the macros
//! are defined in `axess-macros` and re-exported via `axess`.

#![cfg(all(feature = "memory", feature = "testing"))]

#[cfg(feature = "authz")]
use axess::testing::AuthSessionTestExt;
use axess::{MemorySessionStore, SessionLayer, require_authn, require_partial_authn};
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::get,
};
use std::time::Duration;
use tower::ServiceExt;

fn session_layer(clock: &axess::testing::MockClock) -> SessionLayer<MemorySessionStore> {
    SessionLayer::without_registry_insecure(
        MemorySessionStore::new().with_clock(std::sync::Arc::new(clock.clone())),
        axess::testing::test_key(42),
        std::sync::Arc::new(axess::session::UnrecordedSessionEnds),
    )
    .with_clock(clock.clone())
    .with_ttl(Duration::from_secs(3600))
    .with_secure(false)
}

// ── require_authn!() ────────────────────────────────────────────────────────

#[tokio::test]
async fn require_authn_returns_401_for_unauthenticated() {
    let clock = axess::testing::MockClock::at_reference();
    let app = Router::new()
        .route("/protected", get(|| async { "secret" }))
        .layer(require_authn!())
        .layer(session_layer(&clock));

    let response = app
        .oneshot(Request::get("/protected").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn require_authn_with_redirect_returns_307() {
    let clock = axess::testing::MockClock::at_reference();
    let app = Router::new()
        .route("/protected", get(|| async { "secret" }))
        .layer(require_authn!("/login"))
        .layer(session_layer(&clock));

    let response = app
        .oneshot(Request::get("/protected").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.contains("/login"), "should redirect to /login");
    assert!(
        location.contains("next="),
        "should include next query param"
    );
}

#[tokio::test]
async fn require_authn_with_redirect_and_custom_field() {
    let clock = axess::testing::MockClock::at_reference();
    let app = Router::new()
        .route("/protected", get(|| async { "secret" }))
        .layer(require_authn!("/auth/login", "return_to"))
        .layer(session_layer(&clock));

    let response = app
        .oneshot(Request::get("/protected").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        location.contains("return_to="),
        "should use custom redirect field name"
    );
}

// ── require_partial_authn!() ─────────────────────────────────────────────────

#[tokio::test]
async fn require_partial_authn_returns_401_for_guest() {
    let clock = axess::testing::MockClock::at_reference();
    let app = Router::new()
        .route("/mfa", get(|| async { "mfa page" }))
        .layer(require_partial_authn!())
        .layer(session_layer(&clock));

    let response = app
        .oneshot(Request::get("/mfa").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ── require_authz!() ─────────────────────────────────────────────────────────

#[cfg(feature = "authz")]
mod authz_tests {
    use super::*;
    use axess::authz::{AuthzInstallation, PolicyStore, RequestEntityProvider};

    use axess::require_authz;
    use axess_core::authz::AuthzError;
    use axum::{Extension, http::Method};
    use cedar_policy::{Entities, Entity, EntityUid, RestrictedExpression};
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    /// A validator without a registry: the session record decides, which is
    /// all these tests exercise.
    fn session_validator(clock: &axess::testing::MockClock) -> axess::authn::SessionValidator {
        axess::authn::AuthnService::builder(
            axess::testing::MockIdentityStore::new().with_clock(clock.clone()),
            axess::testing::MockFactorStore::new(),
        )
        .with_clock(clock.clone())
        .build()
        .session_validator()
    }

    // The policy pins a single principal id; must match the v5-derived
    // hyphenated UUID that `axess::testing::user("alice")` produces, since
    // `UserId` is a Uuid newtype and the macro injects `principal.to_string()`
    // (hyphenated UUID) as the Cedar entity uid.
    fn policy_text() -> String {
        let alice = axess::testing::user("alice").to_string();
        format!(
            r#"
            permit (
                principal == App::User::"{alice}",
                action    == App::Action::"View",
                resource  == App::Doc::"doc-1"
            );
            permit (
                principal == App::User::"{alice}",
                action    == App::Action::"Manage",
                resource  == App::Platform::"global"
            );
            "#,
        )
    }

    const SCHEMA: &str = r#"{
        "App": {
            "entityTypes": {
                "User":   { "shape": { "type": "Record", "attributes": {} } },
                "Doc":    { "shape": { "type": "Record", "attributes": {} } },
                "Platform": { "shape": { "type": "Record", "attributes": {} } }
            },
            "actions": {
                "View": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes":  ["Doc"]
                    }
                },
                "Manage": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes":  ["Platform"]
                    }
                }
            }
        }
    }"#;

    fn policy_store() -> Arc<PolicyStore> {
        Arc::new(PolicyStore::from_text(&policy_text(), SCHEMA).expect("policy parse"))
    }

    /// Test entity provider; builds the entity set on each call (no
    /// cache decorator wrapped, since the test exercises the macro's
    /// extension lookup, not caching).
    struct TestProvider;

    impl RequestEntityProvider for TestProvider {
        fn entities_for<'a>(
            &'a self,
            session: &'a axess::AuthSession,
            principal: &'a EntityUid,
            resource: &'a EntityUid,
            action: &'a EntityUid,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Entities, AuthzError>> + Send + 'a>,
        > {
            // Synthetic test fixture; doesn't read session/action; explicit
            // acknowledgment per the axess no-`_`-prefix convention.
            let _ = (session, action);
            let principal = principal.clone();
            let resource = resource.clone();
            Box::pin(async move {
                let user = Entity::new(
                    principal,
                    HashMap::<String, RestrictedExpression>::new(),
                    HashSet::new(),
                )
                .map_err(|e| AuthzError::EntityBuild(format!("{e:?}")))?;
                let res = Entity::new(resource, HashMap::new(), HashSet::new())
                    .map_err(|e| AuthzError::EntityBuild(format!("{e:?}")))?;
                Entities::from_entities(vec![user, res], None)
                    .map_err(|e| AuthzError::EntityBuild(format!("{e:?}")))
            })
        }
    }

    fn provider() -> Arc<dyn RequestEntityProvider> {
        Arc::new(TestProvider)
    }

    /// What the gates decide with. The policies never read `context`, so no
    /// context provider is given.
    fn installation() -> AuthzInstallation {
        AuthzInstallation::new(policy_store(), provider(), None)
            .expect("the policies do not read `context`")
    }

    /// One-step helper: log in via `/login`, then call the protected
    /// route reusing the session cookie.
    async fn call_protected(app: Router, path: &str) -> (StatusCode, Vec<u8>) {
        let login_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login_resp.status(), StatusCode::NO_CONTENT, "login fixture");

        let cookie = login_resp
            .headers()
            .get(header::SET_COOKIE)
            .expect("login should set cookie")
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();

        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(path)
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        (status, body)
    }

    fn build_app(clock: &axess::testing::MockClock, user_id: &'static str) -> Router {
        let app = Router::new()
            .route(
                "/docs/{id}",
                get(|| async { "doc body" }).layer(require_authz!(
                    "App",
                    "View",
                    "Doc:{id}",
                    validator = session_validator(clock)
                )),
            )
            .route(
                "/admin",
                get(|| async { "admin body" }).layer(require_authz!(
                    "App",
                    "Manage",
                    "Platform:global",
                    validator = session_validator(clock)
                )),
            )
            .fallback(get(|| async { "fallback body" }).layer(require_authz!(
                "App",
                "Manage",
                "Platform:global",
                validator = session_validator(clock)
            )))
            .route(
                "/login",
                axum::routing::post(move |session: axess::AuthSession| async move {
                    session
                        .set_authenticated(
                            axess::testing::user(user_id),
                            axess::testing::tenant("t1"),
                            axess::testing::MockClock::reference_time(),
                        )
                        .await;
                    StatusCode::NO_CONTENT
                }),
            )
            .layer(installation())
            .layer(session_layer(clock));
        let _ = user_id; // used only inside the login closure capture
        app
    }

    #[tokio::test]
    async fn require_authz_allows_when_cedar_permits() {
        let clock = axess::testing::MockClock::at_reference();
        let app = build_app(&clock, "alice");
        let (status, _) = call_protected(app, "/docs/doc-1").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "alice on doc-1 is permitted by the policy"
        );
    }

    #[tokio::test]
    async fn require_authz_denies_with_403_when_cedar_forbids() {
        let clock = axess::testing::MockClock::at_reference();
        let app = build_app(&clock, "alice");
        // Policy only permits doc-1; doc-2 should deny.
        let (status, _) = call_protected(app, "/docs/doc-2").await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "alice on doc-2 should be denied"
        );
    }

    #[tokio::test]
    async fn require_authz_denies_with_403_for_other_user() {
        let clock = axess::testing::MockClock::at_reference();
        let app = build_app(&clock, "bob");
        // Bob is not in the policy's permit; should deny even on doc-1.
        let (status, _) = call_protected(app, "/docs/doc-1").await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "bob on doc-1 should be denied (not in policy)"
        );
    }

    #[tokio::test]
    async fn require_authz_path_param_escape_does_not_decode_into_another_resource() {
        let clock = axess::testing::MockClock::at_reference();
        let app = build_app(&clock, "alice");
        // `doc-\u{31}` would parse as `doc-1` if the id were spliced into
        // UID text; as an opaque id it is a different, unpermitted resource.
        let (status, _) = call_protected(app, "/docs/doc-%5Cu%7B31%7D").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn require_authz_quote_in_path_param_is_denied_not_an_error() {
        let clock = axess::testing::MockClock::at_reference();
        let app = build_app(&clock, "alice");
        let (status, _) = call_protected(app, "/docs/x%22%20or%20%22").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn require_authz_returns_401_for_unauthenticated() {
        let clock = axess::testing::MockClock::at_reference();
        let app = build_app(&clock, "alice");
        // Skip the /login step → no session cookie → should 401.
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/docs/doc-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// A malformed path parameter does not tell an anonymous caller more
    /// than a well-formed one: not authenticated is 401 either way.
    #[tokio::test]
    async fn require_authz_answers_an_anonymous_caller_401_for_a_malformed_path_parameter() {
        let clock = axess::testing::MockClock::at_reference();
        let resp = build_app(&clock, "alice")
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/docs/%FF")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn require_authz_answers_an_authenticated_caller_400_for_a_malformed_path_parameter() {
        let clock = axess::testing::MockClock::at_reference();
        let (status, _) = call_protected(build_app(&clock, "alice"), "/docs/%FF").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// A router with the gated route and the login route, and nothing a
    /// gate decides with: the caller adds what it wants to try.
    fn bare_router(clock: &axess::testing::MockClock) -> Router {
        Router::new()
            .route(
                "/docs/{id}",
                get(|| async { "doc body" }).layer(require_authz!(
                    "App",
                    "View",
                    "Doc:{id}",
                    validator = session_validator(clock)
                )),
            )
            .route(
                "/login",
                axum::routing::post(|session: axess::AuthSession| async move {
                    session
                        .set_authenticated(
                            axess::testing::user("alice"),
                            axess::testing::tenant("t1"),
                            axess::testing::MockClock::reference_time(),
                        )
                        .await;
                    StatusCode::NO_CONTENT
                }),
            )
    }

    #[tokio::test]
    async fn require_authz_returns_500_when_no_installation_is_in_the_request() {
        let clock = axess::testing::MockClock::at_reference();
        let app = bare_router(&clock).layer(session_layer(&clock));

        let capture = axess_testing::mock_tracing::TracingCapture::install();
        let (status, _) = call_protected(app, "/docs/doc-1").await;
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "a gate with nothing to decide with answers 500, it does not allow"
        );
        assert!(
            capture.contains_at_level(
                axess_core::tracing::Level::ERROR,
                "no AuthzInstallation in the request"
            ),
            "the error names what is missing: {:?}",
            capture.events()
        );
    }

    /// The gate reads the installation and nothing else. A policy store and
    /// an entity provider put into the request extensions on their own, the
    /// way a gate once read them, do not reach it: the request the
    /// installation allows (the test above this group) is answered 500.
    #[tokio::test]
    async fn require_authz_does_not_read_a_store_and_a_provider_installed_on_their_own() {
        let clock = axess::testing::MockClock::at_reference();
        let app = bare_router(&clock)
            .layer(Extension(policy_store()))
            .layer(Extension(provider()))
            .layer(session_layer(&clock));

        let (status, _) = call_protected(app, "/docs/doc-1").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// The same route with the same store and provider, handed over as the
    /// installation, is allowed: the 500 above is the missing installation
    /// and nothing about the policies.
    #[tokio::test]
    async fn require_authz_decides_with_the_installation() {
        let clock = axess::testing::MockClock::at_reference();
        let app = bare_router(&clock)
            .layer(installation())
            .layer(session_layer(&clock));

        let (status, _) = call_protected(app, "/docs/doc-1").await;
        assert_eq!(status, StatusCode::OK);
    }

    /// An `Extension` holding the installation is the installation's own
    /// layer written out: both put the one value into the request.
    #[tokio::test]
    async fn require_authz_reads_the_installation_from_an_extension_layer_too() {
        let clock = axess::testing::MockClock::at_reference();
        let app = bare_router(&clock)
            .layer(Extension(installation()))
            .layer(session_layer(&clock));

        let (status, _) = call_protected(app, "/docs/doc-1").await;
        assert_eq!(status, StatusCode::OK);
    }

    /// A resource template that names a path parameter the route does not
    /// have cannot be turned into a UID. The gate answers 500 (a
    /// configuration error the operator must see) and the audit trail
    /// still records the denial, with the principal and action as strings.
    #[tokio::test]
    async fn require_authz_audits_the_denial_when_the_resource_uid_cannot_be_built() {
        let clock = axess::testing::MockClock::at_reference();
        let app = Router::new()
            .route(
                "/docs/{id}",
                get(|| async { "doc body" }).layer(require_authz!(
                    "App",
                    "View",
                    "Doc:{slug}",
                    validator = session_validator(&clock)
                )),
            )
            .route(
                "/login",
                axum::routing::post(|session: axess::AuthSession| async move {
                    session
                        .set_authenticated(
                            axess::testing::user("alice"),
                            axess::testing::tenant("t1"),
                            axess::testing::MockClock::reference_time(),
                        )
                        .await;
                    StatusCode::NO_CONTENT
                }),
            )
            .layer(installation())
            .layer(session_layer(&clock));
        let capture = axess_testing::mock_tracing::TracingCapture::install();
        let (status, _) = call_protected(app, "/docs/doc-1").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let decisions: Vec<_> = capture
            .events()
            .into_iter()
            .filter(|e| e.target == "axess::authz::decision")
            .collect();
        assert_eq!(decisions.len(), 1, "one decision event: {decisions:?}");
        let event = &decisions[0].message;
        for needle in [
            "decision=deny",
            "reason=invalid_resource",
            &format!("principal={}", axess::testing::user("alice")),
            "action=View",
        ] {
            assert!(event.contains(needle), "{needle} not in {event}");
        }
    }

    #[tokio::test]
    async fn require_authz_route_without_path_params_authorizes() {
        let clock = axess::testing::MockClock::at_reference();
        let (status, body) = call_protected(build_app(&clock, "alice"), "/admin").await;
        assert_eq!(status, StatusCode::OK, "body: {body:?}");
        let (status, _) = call_protected(build_app(&clock, "bob"), "/admin").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    /// The type comes from the attribute (`App::Doc`); a path value naming
    /// another type never reaches the policy. It holds `:`, which a value
    /// under a template's only placeholder may not, so the id is refused
    /// as one that could be read as other values, and the gate answers as
    /// it does for every id it cannot build: 500 and a recorded denial.
    #[tokio::test]
    async fn require_authz_path_value_cannot_choose_the_entity_type() {
        let clock = axess::testing::MockClock::at_reference();
        for path in [
            "/docs/Platform::global",
            "/docs/App::Platform::%22global%22",
        ] {
            let capture = axess_testing::mock_tracing::TracingCapture::install();
            let (status, _) = call_protected(build_app(&clock, "alice"), path).await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{path}");
            let decisions: Vec<_> = capture
                .events()
                .into_iter()
                .filter(|e| e.target == "axess::authz::decision")
                .collect();
            assert_eq!(
                decisions.len(),
                1,
                "one decision event for {path}: {decisions:?}"
            );
            let event = &decisions[0].message;
            for needle in ["decision=deny", "reason=invalid_resource"] {
                assert!(event.contains(needle), "{needle} not in {event}");
            }
        }
    }

    #[tokio::test]
    async fn require_authz_service_without_matched_route_params_authorizes() {
        let clock = axess::testing::MockClock::at_reference();
        // A fallback service is reached without any matched-route
        // parameters at all; the gate must still evaluate, not 500.
        let (status, body) = call_protected(build_app(&clock, "alice"), "/nowhere").await;
        assert_eq!(status, StatusCode::OK, "body: {body:?}");
        let (status, _) = call_protected(build_app(&clock, "bob"), "/nowhere").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn require_authz_service_called_outside_a_router_authorizes() {
        let clock = axess::testing::MockClock::at_reference();
        // No router means no path-parameter extension on the request. The
        // gate must evaluate from the attribute alone rather than 500.
        let store = MemorySessionStore::new().with_clock(std::sync::Arc::new(clock.clone()));
        let layer = || {
            SessionLayer::without_registry_insecure(
                store.clone(),
                axess::testing::test_key(42),
                std::sync::Arc::new(axess::session::UnrecordedSessionEnds),
            )
            .with_clock(clock.clone())
            .with_ttl(Duration::from_secs(3600))
            .with_secure(false)
        };
        let login = Router::new()
            .route(
                "/login",
                axum::routing::post(|session: axess::AuthSession| async move {
                    session
                        .set_authenticated(
                            axess::testing::user("alice"),
                            axess::testing::tenant("t1"),
                            axess::testing::MockClock::reference_time(),
                        )
                        .await;
                    StatusCode::NO_CONTENT
                }),
            )
            .layer(layer());
        let resp = login
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let cookie = resp.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let bare = get(|| async { "admin body" })
            .layer::<_, std::convert::Infallible>(require_authz!(
                "App",
                "Manage",
                "Platform:global",
                validator = session_validator(&clock)
            ))
            .layer::<_, std::convert::Infallible>(installation())
            .layer::<_, std::convert::Infallible>(layer());
        let resp = bare
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
