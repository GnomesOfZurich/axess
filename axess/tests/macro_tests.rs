//! Tests for require_authn!() and require_partial_authn!() macros.
//!
//! These must live in the `axess` crate (not `axess-core`) because the macros
//! are defined in `axess-macros` and re-exported via `axess`.

#![cfg(feature = "memory")]

use axess::{MemorySessionStore, SessionLayer, require_authn, require_partial_authn};
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::get,
};
use std::time::Duration;
use tower::ServiceExt;

fn session_layer() -> SessionLayer<MemorySessionStore> {
    SessionLayer::new(MemorySessionStore::new(), [42u8; 32])
        .with_ttl(Duration::from_secs(3600))
        .with_secure(false)
}

// ── require_authn!() ────────────────────────────────────────────────────────

#[tokio::test]
async fn require_authn_returns_401_for_unauthenticated() {
    let app = Router::new()
        .route("/protected", get(|| async { "secret" }))
        .layer(require_authn!())
        .layer(session_layer());

    let response = app
        .oneshot(Request::get("/protected").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn require_authn_with_redirect_returns_307() {
    let app = Router::new()
        .route("/protected", get(|| async { "secret" }))
        .layer(require_authn!("/login"))
        .layer(session_layer());

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
    let app = Router::new()
        .route("/protected", get(|| async { "secret" }))
        .layer(require_authn!("/auth/login", "return_to"))
        .layer(session_layer());

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
    let app = Router::new()
        .route("/mfa", get(|| async { "mfa page" }))
        .layer(require_partial_authn!())
        .layer(session_layer());

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
    use axess::authz::{PolicyStore, RequestEntityProvider};
    use axess::require_authz;
    use axess_core::authz::AuthzError;
    use axum::{Extension, http::Method};
    use cedar_policy::{Entities, Entity, EntityUid, RestrictedExpression};
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

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
            "#,
        )
    }

    const SCHEMA: &str = r#"{
        "App": {
            "entityTypes": {
                "User":   { "shape": { "type": "Record", "attributes": {} } },
                "Doc":    { "shape": { "type": "Record", "attributes": {} } }
            },
            "actions": {
                "View": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes":  ["Doc"]
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

    fn build_app(user_id: &'static str) -> Router {
        let app = Router::new()
            .route(
                "/docs/{id}",
                get(|| async { "doc body" }).layer(require_authz!("App", "View", "Doc:{id}")),
            )
            .route(
                "/login",
                axum::routing::post(move |session: axess::AuthSession| async move {
                    session
                        .set_authenticated(
                            axess::testing::user(user_id),
                            axess::testing::tenant("t1"),
                            chrono::Utc::now(),
                        )
                        .await;
                    StatusCode::NO_CONTENT
                }),
            )
            .layer(Extension(policy_store()))
            .layer(Extension(provider()))
            .layer(session_layer());
        let _ = user_id; // used only inside the login closure capture
        app
    }

    #[tokio::test]
    async fn require_authz_allows_when_cedar_permits() {
        let app = build_app("alice");
        let (status, _) = call_protected(app, "/docs/doc-1").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "alice on doc-1 is permitted by the policy"
        );
    }

    #[tokio::test]
    async fn require_authz_denies_with_403_when_cedar_forbids() {
        let app = build_app("alice");
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
        let app = build_app("bob");
        // Bob is not in the policy's permit; should deny even on doc-1.
        let (status, _) = call_protected(app, "/docs/doc-1").await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "bob on doc-1 should be denied (not in policy)"
        );
    }

    #[tokio::test]
    async fn require_authz_returns_401_for_unauthenticated() {
        let app = build_app("alice");
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

    #[tokio::test]
    async fn require_authz_returns_500_when_policy_store_extension_missing() {
        // Build the app WITHOUT the PolicyStore extension to exercise the
        // misconfiguration path.
        let app = Router::new()
            .route(
                "/docs/{id}",
                get(|| async { "doc body" }).layer(require_authz!("App", "View", "Doc:{id}")),
            )
            .route(
                "/login",
                axum::routing::post(|session: axess::AuthSession| async move {
                    session
                        .set_authenticated(
                            axess::testing::user("alice"),
                            axess::testing::tenant("t1"),
                            chrono::Utc::now(),
                        )
                        .await;
                    StatusCode::NO_CONTENT
                }),
            )
            // No PolicyStore extension, no Entities extension.
            .layer(session_layer());

        let (status, _) = call_protected(app, "/docs/doc-1").await;
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing extensions should yield 500, not silently allow"
        );
    }
}
