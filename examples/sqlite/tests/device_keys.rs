#![cfg(feature = "device-keys")]
//! Device keys where a person signs in: once the browser has registered its
//! key, the session cookie and the device cookie copied to another machine
//! open nothing without the proof cookie only the key can renew.

use axess::device_key::key_proof::testing::SoftwareKey;
use axess::device_key::key_proof::{KeyProofShape, ProofTarget, browser_draft as draft};
use axess_clock::testing::MockClock;
use axess_example_sqlite::models::backend::{SEED_PASSWORD, seed};
use axess_example_sqlite::web::app::{Serving, build_router_serving, factor_secret_cipher_on};
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;
use tower::ServiceExt;

const UA: &str = "Mozilla/5.0 (the owner's browser)";
/// The origin the test's deployment is reached at.
const ORIGIN: &str = "https://app.example";
const PROOF: &str = "__Host-axess_device_proof";

/// What a browser holds: its cookies and the registration it was offered as
/// `(path, offer)`.
#[derive(Default)]
struct Browser {
    cookies: BTreeMap<String, String>,
    offered: Option<(String, String)>,
}

struct Page {
    status: StatusCode,
    location: Option<String>,
    body: String,
}

async fn app() -> axum::Router {
    let clock = MockClock::at_reference();
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")
        .expect("url")
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("connect");
    sqlx::migrate!().run(&pool).await.expect("migrations");
    seed(
        &clock,
        &pool,
        &factor_secret_cipher_on(Arc::new(clock.clone())),
    )
    .await
    .expect("seed");
    let serving = Serving {
        secure: true,
        origin: Some(ORIGIN.to_owned()),
    };
    build_router_serving(pool, Arc::new(clock), serving).await.0
}

/// Send a request with the browser's cookies and keep what the answer sets.
async fn send(
    router: &axum::Router,
    browser: &mut Browser,
    request: axum::http::request::Builder,
    body: Body,
) -> Page {
    let jar = browser
        .cookies
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ");
    let mut request = request.header(header::USER_AGENT, UA);
    if !jar.is_empty() {
        request = request.header(header::COOKIE, jar);
    }
    let mut request = request.body(body).expect("request");
    request.extensions_mut().insert(ConnectInfo(
        "192.0.2.7:50000".parse::<std::net::SocketAddr>().unwrap(),
    ));
    let response = router.clone().oneshot(request).await.expect("infallible");
    for set in response.headers().get_all(header::SET_COOKIE) {
        let text = set.to_str().expect("cookie");
        let (pair, attributes) = text.split_once(';').unwrap_or((text, ""));
        let (name, value) = pair.split_once('=').expect("name=value");
        if attributes.contains("Max-Age=0") {
            browser.cookies.remove(name);
        } else {
            browser.cookies.insert(name.to_owned(), value.to_owned());
        }
    }
    if let Some(value) = response.headers().get(draft::REGISTRATION_HEADER) {
        // `(ES256);path="<path>";challenge="<offer>"`
        let parts: Vec<&str> = value.to_str().expect("offer").split('"').collect();
        browser.offered = Some((parts[1].to_owned(), parts[3].to_owned()));
    }
    let status = response.status();
    let location = response
        .headers()
        .get(header::LOCATION)
        .map(|v| v.to_str().expect("location").to_owned());
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    Page {
        status,
        location,
        body: String::from_utf8(bytes.to_vec()).expect("utf8"),
    }
}

async fn get(router: &axum::Router, browser: &mut Browser, uri: &str) -> Page {
    send(router, browser, Request::get(uri), Body::empty()).await
}

/// Alice signs in with her password and opens the dashboard, whose answer
/// offers her browser a key.
async fn signed_in(router: &axum::Router) -> Browser {
    let mut browser = Browser::default();
    let page = get(router, &mut browser, "/login").await;
    let marker = r#"name="_csrf" value=""#;
    let start = page.body.find(marker).expect("csrf input") + marker.len();
    let token = page.body[start..]
        .split('"')
        .next()
        .expect("quote")
        .to_owned();
    let form = serde_urlencoded::to_string([
        ("identifier", "alice"),
        ("password", SEED_PASSWORD),
        ("_csrf", token.as_str()),
    ])
    .expect("form");
    let login = send(
        router,
        &mut browser,
        Request::post("/login").header(header::CONTENT_TYPE, "application/x-www-form-urlencoded"),
        Body::from(form),
    )
    .await;
    assert_eq!(
        login.location.as_deref(),
        Some("/dashboard"),
        "{}",
        login.body
    );
    let dashboard = get(router, &mut browser, "/dashboard").await;
    assert_eq!(dashboard.status, StatusCode::OK, "{}", dashboard.body);
    assert!(
        browser.offered.is_some(),
        "a keyless browser is offered a key"
    );
    browser
}

/// The counters `/metrics` exports, by name.
async fn counters(router: &axum::Router) -> serde_json::Value {
    let page = get(router, &mut Browser::default(), "/metrics").await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    serde_json::from_str(&page.body).expect("a JSON object")
}

/// The browser registers `key` against the offer it was handed.
async fn register(router: &axum::Router, browser: &mut Browser, key: &SoftwareKey) -> StatusCode {
    let (path, offer) = browser.offered.clone().expect("an offer");
    let url = format!("{ORIGIN}{path}");
    let target = ProofTarget {
        method: "POST",
        url: &url,
    };
    let proof = key.sign(KeyProofShape::Browser, target, &offer, true);
    let request = Request::post(path.as_str()).header(draft::RESPONSE_HEADER, proof);
    send(router, browser, request, Body::empty()).await.status
}

/// A session cookie copied with the device cookie beside it, but without the
/// proof cookie the key renews, is served as a guest and sent to the login,
/// while the owner's browser, which holds the key, keeps its session.
#[tokio::test]
async fn a_copied_session_cookie_without_the_key_opens_nothing() {
    let router = app().await;
    let mut owner = signed_in(&router).await;
    let key = SoftwareKey::from_seed([5; 32]);
    assert_eq!(register(&router, &mut owner, &key).await, StatusCode::OK);
    assert!(
        owner.cookies.keys().any(|name| name.starts_with(PROOF)),
        "the registration sets a proof cookie: {:?}",
        owner.cookies.keys()
    );

    let mut thief = Browser {
        cookies: owner
            .cookies
            .iter()
            .filter(|(name, _)| !name.starts_with(PROOF))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
        offered: None,
    };
    let stolen = get(&router, &mut thief, "/dashboard").await;
    assert!(stolen.status.is_redirection(), "{}", stolen.body);
    assert!(
        stolen
            .location
            .as_deref()
            .is_some_and(|to| to.starts_with("/login")),
        "{:?}",
        stolen.location
    );

    let own = get(&router, &mut owner, "/dashboard").await;
    assert_eq!(own.status, StatusCode::OK, "{}", own.body);
}

/// A browser that never registers a key signs in as before: the policy
/// prefers a key and does not require one.
#[tokio::test]
async fn a_browser_without_a_key_store_still_signs_in() {
    let router = app().await;
    let mut browser = signed_in(&router).await;
    let page = get(&router, &mut browser, "/dashboard").await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
}

/// `/metrics` exports the offers beside the registrations: the two an
/// operator reads against each other before requiring keys.
#[tokio::test]
async fn the_offers_and_the_registrations_are_exported() {
    let router = app().await;
    let mut browser = signed_in(&router).await;
    let offered = counters(&router).await;
    assert_eq!(offered["axess_device_keys_offered_total"], 1, "{offered}");
    assert_eq!(
        offered["axess_device_keys_registered_total"], 0,
        "{offered}"
    );
    let key = SoftwareKey::from_seed([6; 32]);
    assert_eq!(register(&router, &mut browser, &key).await, StatusCode::OK);
    let registered = counters(&router).await;
    assert_eq!(
        registered["axess_device_keys_offered_total"], 1,
        "{registered}"
    );
    assert_eq!(
        registered["axess_device_keys_registered_total"], 1,
        "{registered}"
    );
}
