//! The shared-secret recipe end to end: the caller signs, the route
//! verifies, and what a captured request can no longer do.

use axess::service_secret::{ServiceSecret, ServiceSecrets};
use axess_example_workload_identity::shared_secret::{BounceReport, bounce_routes, signed_bounce};
use axum::{body::Body, http::StatusCode};
use tower::ServiceExt;

const SECRET: &str = "4f1c0d9a7e2b4c6d8e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b";

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn report() -> BounceReport {
    BounceReport {
        address: "someone@example.org".into(),
        reason: "550 5.1.1 user unknown".into(),
    }
}

fn configured() -> ServiceSecrets {
    ServiceSecrets::new().with(ServiceSecret::new("intake", SECRET).expect("long enough"))
}

fn signer() -> axess::service_secret::ServiceSigner {
    ServiceSecret::new("intake", SECRET)
        .expect("long enough")
        .signer()
}

#[tokio::test]
async fn a_signed_report_is_accepted() {
    let res = bounce_routes(configured())
        .oneshot(signed_bounce(&signer(), now(), &report()))
        .await
        .expect("infallible");
    assert_eq!(res.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn a_captured_request_cannot_be_altered_or_replayed() {
    let routes = bounce_routes(configured());
    let at = now();

    let mut altered = signed_bounce(&signer(), at, &report());
    *altered.body_mut() = Body::from(r#"{"address":"ceo@example.org","reason":"x"}"#);
    let res = routes.clone().oneshot(altered).await.expect("infallible");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let first = routes
        .clone()
        .oneshot(signed_bounce(&signer(), at, &report()))
        .await
        .expect("infallible");
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    let replay = routes
        .oneshot(signed_bounce(&signer(), at, &report()))
        .await
        .expect("infallible");
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_route_without_a_secret_does_not_exist() {
    let res = bounce_routes(ServiceSecrets::new())
        .oneshot(signed_bounce(&signer(), now(), &report()))
        .await
        .expect("infallible");
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
