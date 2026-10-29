#![cfg(feature = "service-secret")]
//! What the service-secret middleware logs about a refusal, and what it keeps
//! out of the log. Its own test binary: these assertions read a thread-scoped
//! tracing capture, and sibling tests in a shared binary can disturb the
//! thread-local dispatch state between the capture's install and the event
//! (measured 2026-10-29: the callsite read enabled before the replay and
//! disabled inside the logger, on one thread, with the capture alive).

use std::sync::Arc;

use axess_clock::testing::MockClock;
use axess_core::middleware::service_secret::{
    SIGNATURE_HEADER, ServiceCaller, ServiceSecret, ServiceSecretLayer, ServiceSecrets,
    SignedRequests,
};
use axess_core::testing::mock_tracing::TracingCapture;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::{Router, routing::post};
use chrono::{TimeZone, Utc};
use tower::ServiceExt;

const RELAY: &str = "relay-secret-0123456789abcdef0123456789";
const OTHER: &str = "other-secret-0123456789abcdef0123456789";
const EPOCH: i64 = 1_790_000_000;
const AUDIENCE: &str = "billing";

fn addressed() -> SignedRequests {
    SignedRequests::default().audience(AUDIENCE)
}

fn secret(name: &str, value: &str) -> ServiceSecret {
    ServiceSecret::new(name, value).expect("long enough")
}

async fn echo(caller: ServiceCaller, body: String) -> String {
    format!("{}:{body}", caller.name())
}

fn app(layer: ServiceSecretLayer) -> Router {
    Router::new().route("/hook", post(echo)).layer(layer)
}

async fn send(app: &Router, req: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let res = app.clone().oneshot(req).await.expect("infallible");
    let status = res.status();
    let headers = res.headers().clone();
    let body = axum::body::to_bytes(res.into_body(), 1024)
        .await
        .expect("body");
    (
        status,
        headers,
        String::from_utf8(body.to_vec()).expect("utf8"),
    )
}

fn post_with(header: Option<(&str, &str)>) -> Request<Body> {
    let mut builder = Request::builder().method(Method::POST).uri("/hook");
    if let Some((name, value)) = header {
        builder = builder.header(name, value);
    }
    builder.body(Body::from("x")).expect("request")
}

fn clock() -> MockClock {
    MockClock::at(Utc.timestamp_opt(EPOCH, 0).single().expect("valid"))
}

fn signed_app(clock: &MockClock, config: SignedRequests) -> Router {
    let secrets: ServiceSecrets = [secret("relay", RELAY), secret("other", OTHER)]
        .into_iter()
        .collect();
    app(
        ServiceSecretLayer::signed(secrets, config.clock(Arc::new(clock.clone())))
            .expect("addressed"),
    )
}

fn signed(value: &str, at: i64, method: Method, target: &str, body: &str) -> Request<Body> {
    let header =
        secret("caller", value)
            .signer()
            .sign_for(AUDIENCE, at, &method, target, body.as_bytes());
    Request::builder()
        .method(Method::POST)
        .uri("/hook")
        .header(SIGNATURE_HEADER, header)
        .body(Body::from(body.to_owned()))
        .expect("request")
}

fn service_events(capture: &TracingCapture) -> Vec<String> {
    capture
        .events()
        .iter()
        .filter(|e| e.target == "axess::service_secret")
        .map(|e| format!("{} {}", e.level, e.message))
        .collect()
}

/// A replayed signature is refused and leaves exactly one warning naming the
/// reason and the caller, and nothing that could replay or forge a request.
#[tokio::test]
async fn a_replay_is_logged_once_with_the_caller_and_no_secret_material() {
    let capture = TracingCapture::install();
    let clock = clock();
    let app = signed_app(&clock, addressed());
    let req = || signed(RELAY, EPOCH, Method::POST, "/hook", "x");
    assert_eq!(send(&app, req()).await.0, StatusCode::OK);
    assert_eq!(send(&app, req()).await.0, StatusCode::UNAUTHORIZED);

    let events = service_events(&capture);
    let warns: Vec<_> = events.iter().filter(|e| e.starts_with("WARN")).collect();
    assert_eq!(warns.len(), 1, "{events:?}");
    assert!(
        warns[0].contains("replay") && warns[0].contains("relay"),
        "{warns:?}"
    );
    let header =
        secret("relay", RELAY)
            .signer()
            .sign_for(AUDIENCE, EPOCH, &Method::POST, "/hook", b"x");
    let header = header.to_str().expect("ascii").to_owned();
    let tag = header.split("v2=").nth(1).expect("tag");
    for event in &events {
        assert!(!event.contains(tag) && !event.contains(RELAY), "{event}");
    }
}

/// Routine refusals are `debug`, each with its reason.
#[tokio::test]
async fn bad_credentials_are_logged_at_debug_with_their_reason() {
    let capture = TracingCapture::install();
    let clock = clock();
    let signed_app = signed_app(&clock, addressed());
    let stale = signed(RELAY, EPOCH - 3600, Method::POST, "/hook", "x");
    assert_eq!(send(&signed_app, stale).await.0, StatusCode::UNAUTHORIZED);
    let forged = signed(
        "wrong-secret-0123456789abcdef0123456789",
        EPOCH,
        Method::POST,
        "/hook",
        "x",
    );
    assert_eq!(send(&signed_app, forged).await.0, StatusCode::UNAUTHORIZED);

    let secrets: ServiceSecrets = [secret("relay", RELAY)].into_iter().collect();
    let bearer = app(ServiceSecretLayer::bearer(secrets));
    assert_eq!(
        send(&bearer, post_with(None)).await.0,
        StatusCode::UNAUTHORIZED
    );
    let wrong = post_with(Some(("authorization", "Bearer nope")));
    assert_eq!(send(&bearer, wrong).await.0, StatusCode::UNAUTHORIZED);

    let events = service_events(&capture);
    for reason in [
        "stale_stamp",
        "bad_signature",
        "no_credential",
        "bad_secret",
    ] {
        assert!(
            events
                .iter()
                .any(|e| e.starts_with("DEBUG") && e.contains(reason)),
            "{reason} in {events:?}"
        );
    }
    assert!(events.iter().all(|e| !e.starts_with("WARN")), "{events:?}");
}
