//! `tests`: extracted from `service_secret.rs` per the
//! 200-LoC inline-test rule in AGENTS.md.

use super::*;
use axess_clock::testing::MockClock;
use axum::{Router, http::Method, routing::post};
use chrono::{TimeZone, Utc};
use std::time::Duration;
use tower::ServiceExt;

const RELAY: &str = "relay-secret-0123456789abcdef0123456789";
const OTHER: &str = "other-secret-0123456789abcdef0123456789";
const EPOCH: i64 = 1_790_000_000;

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
    let mut req = Request::post("/hook");
    if let Some((name, value)) = header {
        req = req.header(name, value);
    }
    req.body(Body::empty()).expect("request")
}

#[tokio::test]
async fn a_matching_bearer_secret_names_its_caller() {
    let app = app(ServiceSecretLayer::bearer(
        ServiceSecrets::new().with(secret("mail-relay", RELAY)),
    ));
    let auth = format!("bearer {RELAY}");
    let (status, _, body) = send(&app, post_with(Some(("authorization", &auth)))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "mail-relay:");
}

#[tokio::test]
async fn a_wrong_or_missing_secret_is_unauthorized_with_a_bearer_challenge() {
    let app = app(ServiceSecretLayer::bearer(
        ServiceSecrets::new().with(secret("mail-relay", RELAY)),
    ));
    let basic = format!("Basic {RELAY}");
    for header in [
        None,
        Some(("authorization", "Bearer wrong")),
        Some(("authorization", basic.as_str())),
        Some(("authorization", "Bearer")),
    ] {
        let (status, headers, _) = send(&app, post_with(header)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{header:?}");
        assert_eq!(
            headers.get(WWW_AUTHENTICATE).map(HeaderValue::as_bytes),
            Some(&b"Bearer"[..]),
            "{header:?}"
        );
    }
}

#[tokio::test]
async fn an_unconfigured_route_answers_not_found_in_every_mode() {
    for layer in [
        ServiceSecretLayer::bearer(ServiceSecrets::new()),
        ServiceSecretLayer::signed(ServiceSecrets::new(), SignedRequests::default()),
    ] {
        let (status, _, _) =
            send(&app(layer), post_with(Some(("authorization", "Bearer x")))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn a_named_header_carries_the_whole_secret_without_a_challenge() {
    let layer = ServiceSecretLayer::header(
        ServiceSecrets::new().with(secret("intake", RELAY)),
        HeaderName::from_static("x-intake-secret"),
    );
    let app = app(layer);
    let padded = format!(" {RELAY} ");
    let (status, _, body) = send(&app, post_with(Some(("x-intake-secret", &padded)))).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "intake:"));

    let bearer = format!("Bearer {RELAY}");
    let (status, headers, _) = send(&app, post_with(Some(("authorization", &bearer)))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(headers.get(WWW_AUTHENTICATE).is_none());
}

#[test]
fn rotation_accepts_old_and_new_and_tells_them_apart() {
    let secrets: ServiceSecrets = [secret("relay-old", RELAY), secret("relay-new", OTHER)]
        .into_iter()
        .collect();
    let name = |s: &str| secrets.identify(s.as_bytes()).map(|c| c.name().to_owned());
    assert_eq!(name(RELAY).as_deref(), Some("relay-old"));
    assert_eq!(name(OTHER).as_deref(), Some("relay-new"));
    assert!(name("neither").is_none());
    assert!(name("").is_none());
}

#[test]
fn a_short_secret_is_refused_and_surrounding_whitespace_is_trimmed() {
    let short = "x".repeat(MIN_SECRET_LEN - 1);
    assert!(matches!(
        ServiceSecret::new("x", &format!(" {short}\n")),
        Err(ServiceSecretError::TooShort { len, .. }) if len == MIN_SECRET_LEN - 1
    ));
    let secrets = ServiceSecrets::new().with(secret("x", &format!("{RELAY}\n")));
    assert!(secrets.identify(RELAY.as_bytes()).is_some());
}

#[test]
fn debug_output_names_the_caller_but_not_the_secret() {
    let rendered = format!(
        "{:?} {:?}",
        secret("relay", RELAY),
        secret("relay", RELAY).signer()
    );
    assert!(rendered.contains("relay"));
    assert!(!rendered.contains(RELAY));
}

#[test]
fn a_secret_file_is_read_and_a_missing_one_is_an_error() {
    let dir = std::env::temp_dir().join(format!("axess-service-secret-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("secret");
    std::fs::write(&path, format!("{RELAY}\n")).expect("write");
    let loaded = ServiceSecret::from_file("relay", &path).expect("readable");
    assert!(
        ServiceSecrets::new()
            .with(loaded)
            .identify(RELAY.as_bytes())
            .is_some()
    );

    assert!(matches!(
        ServiceSecret::from_file("relay", dir.join("absent")),
        Err(ServiceSecretError::Read { .. })
    ));
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[tokio::test]
async fn extracting_a_caller_without_the_layer_is_a_server_error() {
    let app = Router::new().route("/hook", post(echo));
    let (status, _, _) = send(&app, post_with(None)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

// ── Signed requests ───────────────────────────────────────────────────────

fn signed_app(clock: &MockClock, config: SignedRequests) -> Router {
    let secrets: ServiceSecrets = [secret("relay", RELAY), secret("other", OTHER)]
        .into_iter()
        .collect();
    app(ServiceSecretLayer::signed(
        secrets,
        config.clock(Arc::new(clock.clone())),
    ))
}

fn signed(value: &str, at: i64, method: Method, target: &str, body: &str) -> Request<Body> {
    let header = secret("caller", value)
        .signer()
        .sign(at, &method, target, body.as_bytes());
    Request::builder()
        .method(Method::POST)
        .uri("/hook")
        .header(SIGNATURE_HEADER, header)
        .body(Body::from(body.to_owned()))
        .expect("request")
}

fn clock() -> MockClock {
    MockClock::at(Utc.timestamp_opt(EPOCH, 0).single().expect("valid"))
}

#[tokio::test]
async fn a_signed_request_reaches_the_handler_with_its_body_and_caller() {
    let app = signed_app(&clock(), SignedRequests::default());
    let (status, _, body) = send(&app, signed(OTHER, EPOCH, Method::POST, "/hook", "{}")).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "other:{}"));
}

#[tokio::test]
async fn a_signature_over_anything_else_is_refused() {
    let app = signed_app(&clock(), SignedRequests::default());
    let tampered = {
        let mut req = signed(RELAY, EPOCH, Method::POST, "/hook", "{}");
        *req.body_mut() = Body::from("{\"x\":1}");
        req
    };
    for req in [
        tampered,
        signed(RELAY, EPOCH, Method::PUT, "/hook", "{}"),
        signed(RELAY, EPOCH, Method::POST, "/other", "{}"),
        signed(
            "not-a-configured-secret-0123456789abcdef",
            EPOCH,
            Method::POST,
            "/hook",
            "{}",
        ),
        post_with(Some(("x-axess-signature", "t=1,v1=zz"))),
        post_with(None),
    ] {
        assert_eq!(send(&app, req).await.0, StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn a_signature_outside_the_tolerance_is_refused_either_side() {
    let config = SignedRequests::default().tolerance(Duration::from_secs(60));
    let app = signed_app(&clock(), config);
    for at in [EPOCH - 61, EPOCH + 61] {
        let req = signed(RELAY, at, Method::POST, "/hook", "");
        assert_eq!(send(&app, req).await.0, StatusCode::UNAUTHORIZED, "{at}");
    }
    let req = signed(RELAY, EPOCH - 60, Method::POST, "/hook", "");
    assert_eq!(send(&app, req).await.0, StatusCode::OK);
}

#[tokio::test]
async fn a_replayed_signature_is_refused_and_forgotten_after_the_tolerance() {
    let clock = clock();
    let app = signed_app(&clock, SignedRequests::default());
    let first = send(&app, signed(RELAY, EPOCH, Method::POST, "/hook", "x")).await;
    assert_eq!(first.0, StatusCode::OK);
    let again = send(&app, signed(RELAY, EPOCH, Method::POST, "/hook", "x")).await;
    assert_eq!(again.0, StatusCode::UNAUTHORIZED);
    // A fresh timestamp is a fresh signature.
    let later = send(&app, signed(RELAY, EPOCH + 1, Method::POST, "/hook", "x")).await;
    assert_eq!(later.0, StatusCode::OK);
}

#[tokio::test]
async fn a_body_over_the_limit_is_refused_before_the_signature_is_checked() {
    let app = signed_app(&clock(), SignedRequests::default().max_body_bytes(4));
    let req = signed(RELAY, EPOCH, Method::POST, "/hook", "12345");
    assert_eq!(send(&app, req).await.0, StatusCode::PAYLOAD_TOO_LARGE);
}

#[test]
fn the_signature_header_follows_the_documented_recipe() {
    let header = secret("relay", RELAY)
        .signer()
        .sign(EPOCH, &Method::POST, "/hook?a=1", b"body");

    let mut key = crate::session::hmac::new_signer(RELAY.as_bytes());
    hmac::Mac::update(&mut key, b"axess-service-signature-v1");
    let key = hmac::Mac::finalize(key).into_bytes();
    let mut mac = crate::session::hmac::new_signer(&key);
    hmac::Mac::update(
        &mut mac,
        format!("v1\n{EPOCH}\nPOST\n/hook?a=1\nbody").as_bytes(),
    );
    let expected: String = hmac::Mac::finalize(mac)
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    assert_eq!(
        header.to_str().expect("ascii"),
        format!("t={EPOCH},v1={expected}")
    );
}
