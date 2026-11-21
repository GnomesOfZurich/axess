//! `require_authz!` over a policy that requires a fresh, user-verified,
//! device-bound passkey: it lets that session through, and answers every
//! other one with the step-up the policy's annotation names.

#![cfg(all(feature = "memory", feature = "authz", feature = "testing"))]

use axess::testing::AuthSessionTestExt;
use std::sync::Arc;

use axess::authz::{
    AssuranceContextProvider, AuthzInstallation, PolicyStore, RequestEntityProvider,
    merge_assurance_schema,
};
use axess::{MemorySessionStore, SessionLayer, require_authz};
use axess_core::authn::assurance::FactorAssurance;
use axess_core::authn::factor::FactorKind;
use axess_core::authz::AuthzError;
use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
    routing::{get, post},
};
use cedar_policy::{Entities, EntityUid};
use tower::ServiceExt;

const RULE: &str = r#"
@step_up("passkey")
permit (principal, action == App::Action::"ApprovePayment", resource)
when {
    context.assurance has fido2 &&
    context.assurance.fido2.user_verified &&
    context.assurance.fido2.credential == "device_bound" &&
    context.assurance.fido2.age_seconds <= 300
};
"#;

fn schema() -> String {
    let mut schema = serde_json::json!({
        "App": {
            "entityTypes": { "User": {}, "Payment": {} },
            "actions": {
                "ApprovePayment": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["Payment"],
                        "context": {
                            "type": "Record",
                            "attributes": { "assurance": { "type": "AxessAssurance" } }
                        }
                    }
                }
            }
        }
    });
    merge_assurance_schema(&mut schema, "App").unwrap();
    schema.to_string()
}

fn session_validator(clock: &axess::testing::MockClock) -> axess::authn::SessionValidator {
    axess::authn::AuthnService::builder(
        axess::testing::MockIdentityStore::new().with_clock(clock.clone()),
        axess::testing::MockFactorStore::new(),
    )
    .with_clock(clock.clone())
    .build()
    .session_validator()
}

struct NoEntities;

impl RequestEntityProvider for NoEntities {
    fn entities_for<'a>(
        &'a self,
        session: &'a axess::AuthSession,
        principal: &'a EntityUid,
        resource: &'a EntityUid,
        action: &'a EntityUid,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Entities, AuthzError>> + Send + 'a>,
    > {
        let _ = (session, principal, resource, action);
        Box::pin(async { Ok(Entities::empty()) })
    }
}

/// A login that verifies one factor with `proof`'s properties, `age`
/// seconds ago.
async fn log_in(session: axess::AuthSession, proof: FactorAssurance) -> StatusCode {
    session
        .begin_authenticating(
            axess::testing::user("acme-approver"),
            axess::testing::tenant("acme"),
            Arc::from("one-factor"),
            vec![proof.kind.clone()],
        )
        .await;
    session.advance_factor_with(proof).await;
    StatusCode::NO_CONTENT
}

fn ago(seconds: i64) -> axess::Timestamp {
    use axess::testing::Shift as _;
    axess::testing::MockClock::reference_time().minus(axess::SignedDuration::seconds(seconds))
}

fn app() -> Router {
    let clock = axess::testing::MockClock::at_reference();
    let store = Arc::new(PolicyStore::from_text(RULE, &schema()).expect("policies"));
    // The rule reads `context.assurance`, so the installation is given the
    // provider that supplies it.
    let installation = AuthzInstallation::new(
        store,
        Arc::new(NoEntities),
        Some(Arc::new(AssuranceContextProvider::new(Arc::new(
            clock.clone(),
        )))),
    )
    .expect("the provider is given");
    Router::new()
        .route(
            "/payments/{id}/approve",
            get(|| async { "approved" }).layer(require_authz!(
                "App",
                "ApprovePayment",
                "Payment:{id}",
                validator = session_validator(&clock)
            )),
        )
        .route(
            "/login/passkey",
            post(|s: axess::AuthSession| {
                log_in(s, FactorAssurance::fido2(true, false, false, None, ago(10)))
            }),
        )
        .route(
            "/login/old-passkey",
            post(|s: axess::AuthSession| {
                log_in(
                    s,
                    FactorAssurance::fido2(true, false, false, None, ago(600)),
                )
            }),
        )
        .route(
            "/login/synced-passkey",
            post(|s: axess::AuthSession| {
                log_in(s, FactorAssurance::fido2(true, true, true, None, ago(10)))
            }),
        )
        .route(
            "/login/password",
            post(|s: axess::AuthSession| {
                log_in(s, FactorAssurance::for_kind(FactorKind::Password, ago(10)))
            }),
        )
        .layer(installation)
        .layer(
            SessionLayer::without_registry_insecure(
                MemorySessionStore::new().with_clock(std::sync::Arc::new(clock.clone())),
                axess::testing::test_key(42),
                std::sync::Arc::new(axess::session::UnrecordedSessionEnds),
            )
            .with_clock(clock.clone())
            .with_ttl(std::time::Duration::from_secs(3600))
            .with_secure(false),
        )
}

/// Log in through `login`, then approve; the status and the body.
async fn approve_after(login: &str) -> (StatusCode, serde_json::Value) {
    let app = app();
    let logged_in = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(login)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logged_in.status(), StatusCode::NO_CONTENT, "login fixture");
    let cookie = logged_in.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let response = app
        .oneshot(
            Request::get("/payments/p1/approve")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn a_fresh_device_bound_passkey_passes_the_gate() {
    assert_eq!(approve_after("/login/passkey").await.0, StatusCode::OK);
}

#[tokio::test]
async fn every_other_session_is_told_which_step_up_it_needs() {
    for login in [
        "/login/password",
        "/login/old-passkey",
        "/login/synced-passkey",
    ] {
        assert_eq!(
            approve_after(login).await,
            (
                StatusCode::FORBIDDEN,
                serde_json::json!({ "error": "step_up_required", "step_up": "passkey" })
            ),
            "{login}"
        );
    }
}
