//! Where a login that still needs a factor is sent: to that factor's page,
//! never to the dashboard, which a partly authenticated session cannot open.

use axess::SystemClock;
use axess::authn::FactorKind;
use axess_example_sqlite::models::backend::{SEED_PASSWORD, seed};
use axess_example_sqlite::web::app::build_router;
use axess_example_sqlite::web::auth::next_factor_response;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::collections::BTreeMap;
use std::str::FromStr;
use tower::ServiceExt;

struct Page {
    status: StatusCode,
    location: Option<String>,
    body: String,
}

/// Bob's method asks for a password, then TOTP, then a passkey. Returns the
/// router and bob's TOTP secret.
async fn app_with_a_three_step_method() -> (axum::Router, String) {
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")
        .expect("url")
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("connect");
    sqlx::migrate!().run(&pool).await.expect("migrations");
    let secret = seed(
        &SystemClock,
        &pool,
        &axess_example_sqlite::web::app::factor_secret_cipher(),
    )
    .await
    .expect("seed");
    sqlx::query(
        "UPDATE auth_methods
         SET steps_json = '[{\"Required\":\"Password\"},{\"Required\":\"Totp\"},{\"Required\":\"Password\"}]'
         WHERE name = 'password+totp'",
    )
    .execute(&pool)
    .await
    .expect("three steps");
    (build_router(pool).await.0, secret)
}

async fn send(
    router: &axum::Router,
    cookies: &mut BTreeMap<String, String>,
    method: &str,
    uri: &str,
    form: Option<Vec<(&str, &str)>>,
) -> Page {
    let jar = cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ");
    let mut req = Request::builder().method(method).uri(uri);
    if !jar.is_empty() {
        req = req.header(header::COOKIE, jar);
    }
    let body = match form {
        Some(fields) => {
            req = req.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            Body::from(serde_urlencoded::to_string(fields).expect("form"))
        }
        None => Body::empty(),
    };
    let mut req = req.body(body).expect("request");
    req.extensions_mut().insert(ConnectInfo(
        "192.0.2.7:50000".parse::<std::net::SocketAddr>().unwrap(),
    ));
    let res = router.clone().oneshot(req).await.expect("infallible");
    for set in res.headers().get_all(header::SET_COOKIE) {
        let pair = set
            .to_str()
            .expect("cookie")
            .split(';')
            .next()
            .expect("pair");
        let (name, value) = pair.split_once('=').expect("name=value");
        cookies.insert(name.to_owned(), value.to_owned());
    }
    let status = res.status();
    let location = res
        .headers()
        .get(header::LOCATION)
        .map(|v| v.to_str().expect("location").to_owned());
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .expect("body");
    Page {
        status,
        location,
        body: String::from_utf8(bytes.to_vec()).expect("utf8"),
    }
}

/// The CSRF token of the first form on `uri`.
async fn token_from(
    router: &axum::Router,
    cookies: &mut BTreeMap<String, String>,
    uri: &str,
) -> String {
    let page = send(router, cookies, "GET", uri, None).await;
    let marker = r#"name="_csrf" value=""#;
    let start = page.body.find(marker).expect("csrf input") + marker.len();
    page.body[start..]
        .split('"')
        .next()
        .expect("quote")
        .to_owned()
}

fn totp_code(secret: &str) -> String {
    let secret = totp_rs::Secret::try_from_base32(secret).expect("base32");
    totp_rs::Builder::new()
        .with_algorithm(totp_rs::Algorithm::SHA1)
        .with_digits(6)
        .with_step_duration(30)
        .with_secret(secret)
        .build()
        .expect("totp")
        .generate_current()
        .to_string()
}

/// A login whose method has a third step: after the password and a valid
/// TOTP code the user is not sent to `/dashboard`, and the dashboard stays
/// closed to the half-finished session.
#[tokio::test]
async fn a_login_with_a_third_step_does_not_end_at_the_dashboard() {
    let (router, secret) = app_with_a_three_step_method().await;
    let mut cookies = BTreeMap::new();

    let token = token_from(&router, &mut cookies, "/login").await;
    let login = send(
        &router,
        &mut cookies,
        "POST",
        "/login",
        Some(vec![
            ("identifier", "bob"),
            ("password", SEED_PASSWORD),
            ("_csrf", token.as_str()),
        ]),
    )
    .await;
    assert_eq!(login.location.as_deref(), Some("/totp"), "{}", login.body);

    let token = token_from(&router, &mut cookies, "/totp").await;
    let code = totp_code(&secret);
    let second = send(
        &router,
        &mut cookies,
        "POST",
        "/totp",
        Some(vec![("code", code.as_str()), ("_csrf", token.as_str())]),
    )
    .await;
    assert_ne!(
        second.location.as_deref(),
        Some("/dashboard"),
        "{}",
        second.body
    );
    assert!(
        second.body.contains("Unsupported factor type"),
        "the third step is named, not skipped: {}",
        second.body
    );

    let dashboard = send(&router, &mut cookies, "GET", "/dashboard", None).await;
    assert_ne!(dashboard.status, StatusCode::OK);
}

/// A further TOTP step goes to the TOTP page.
#[test]
fn a_required_totp_goes_to_the_totp_page() {
    let reply = next_factor_response(FactorKind::Totp);
    assert!(reply.status().is_redirection());
    assert_eq!(reply.headers()[header::LOCATION], "/totp");
}

/// A further factor the example has no page for is refused by name, not sent
/// to `/dashboard`.
#[test]
fn a_required_factor_without_a_page_does_not_go_to_the_dashboard() {
    for kind in [
        FactorKind::EmailOtp,
        FactorKind::RecoveryCode,
        FactorKind::Fido2,
    ] {
        let reply = next_factor_response(kind.clone());
        assert!(
            !reply.status().is_redirection(),
            "{kind:?} was redirected to {:?}",
            reply.headers().get(header::LOCATION)
        );
        assert_eq!(reply.status(), StatusCode::OK);
        assert_ne!(
            reply
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("/dashboard")
        );
    }
}
