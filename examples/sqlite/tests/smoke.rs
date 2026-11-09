//! End-to-end smoke tests for the SQLite example.
//!
//! Each test pins one slice of the example's startup + visible-surface
//! contract: idempotent seeding, persisted-shape round-trip through the
//! runtime load path, the `/` redirect, the unauthenticated surface
//! routes (`/login`, `/signup`, `/healthz`, `/metrics`,
//! `/forgot-password`), and the bare `OurBackend::new` construction.

use axess::SystemClock;
use axess_example_sqlite::{
    models::backend::{OurBackend, seed},
    web::app::build_router,
};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;
use tower::ServiceExt;

/// In-memory SQLite pool. Single connection so every query sees the
/// same `:memory:` DB (each new SQLite connection to `:memory:` would
/// otherwise get its own empty DB).
async fn fresh_pool() -> sqlx::SqlitePool {
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")
        .unwrap()
        .create_if_missing(true);
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("connect in-memory sqlite")
}

/// Apply all migrations from `examples/sqlite/migrations/`.
async fn migrate(pool: &sqlx::SqlitePool) {
    sqlx::migrate!()
        .run(pool)
        .await
        .expect("migrations apply cleanly");
}

#[tokio::test]
async fn seed_is_idempotent_across_startups() {
    // `seed()` must be safe to run on every startup, so the second
    // invocation on the same pool MUST NOT raise a UNIQUE-constraint
    // error. A schema or shape mismatch surfaces first as a panic
    // inside the initial `seed()` before this assertion is reached.
    let pool = fresh_pool().await;
    migrate(&pool).await;

    seed(
        &SystemClock,
        &pool,
        &axess::authn::FactorSecretCipher::new(*b"0123456789abcdef0123456789abcdeF"),
    )
    .await
    .expect("first seed");
    seed(
        &SystemClock,
        &pool,
        &axess::authn::FactorSecretCipher::new(*b"0123456789abcdef0123456789abcdeF"),
    )
    .await
    .expect("second seed must be a no-op, not a constraint violation");
}

#[tokio::test]
async fn seeded_methods_load_back_through_runtime_path() {
    // `seed()` writes the tagged-enum form
    // (`[{"Required":"Password"}]`); the runtime load path
    // deserializes into `Vec<FactorStep>`. Either side drifting
    // breaks this round-trip.
    let pool = fresh_pool().await;
    migrate(&pool).await;
    seed(
        &SystemClock,
        &pool,
        &axess::authn::FactorSecretCipher::new(*b"0123456789abcdef0123456789abcdeF"),
    )
    .await
    .expect("seed");

    // Pull alice's row through the same SELECT the load path uses,
    // and deserialize via the production code's serde shape. We
    // can't easily wire FactorStore here without more state, so we
    // assert the raw JSON parses as the expected enum form.
    let steps_json: String = sqlx::query_scalar(
        "SELECT steps_json FROM auth_methods
         WHERE name = 'password' AND user_id = ?1",
    )
    .bind("00000000-0000-0000-0000-000000000010")
    .fetch_one(&pool)
    .await
    .expect("alice's method row");
    let parsed: serde_json::Value =
        serde_json::from_str(&steps_json).expect("steps_json must be valid JSON");
    let arr = parsed.as_array().expect("steps_json must be an array");
    assert_eq!(arr.len(), 1, "password method has one step");
    let step = &arr[0];
    assert!(
        step.get("Required").is_some(),
        "step must be the tagged-enum form `{{\"Required\": \"Password\"}}`, got {step}"
    );
    assert_eq!(
        step.get("Required").and_then(|v| v.as_str()),
        Some("Password"),
        "Required variant carries the factor kind as a string"
    );
}

#[tokio::test]
async fn root_redirects_to_login_when_unauthenticated() {
    // `GET /` for a guest MUST land on `/login`. Without an explicit
    // redirect the bare app returns 404 + empty body; a blank page
    // in a browser.
    let pool = fresh_pool().await;
    migrate(&pool).await;
    seed(
        &SystemClock,
        &pool,
        &axess::authn::FactorSecretCipher::new(*b"0123456789abcdef0123456789abcdeF"),
    )
    .await
    .expect("seed");
    let (router, _store) = build_router(pool).await;

    let resp = router
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .expect("router handles GET /");

    // axum::response::Redirect::to defaults to 303 See Other.
    assert!(
        resp.status().is_redirection(),
        "GET / must redirect (got {})",
        resp.status()
    );
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("Location header present on redirect");
    assert_eq!(location, "/login", "guests land on /login");
}

#[tokio::test]
async fn key_surface_routes_respond() {
    // Sanity check that the routes a new visitor or operator
    // hits actually return non-error responses. Doesn't assert
    // body content (HTML pages drift); only that the route is
    // wired and produces a meaningful status.
    let pool = fresh_pool().await;
    migrate(&pool).await;
    seed(
        &SystemClock,
        &pool,
        &axess::authn::FactorSecretCipher::new(*b"0123456789abcdef0123456789abcdeF"),
    )
    .await
    .expect("seed");
    let (router, _store) = build_router(pool).await;

    for (uri, name) in [
        ("/login", "login page"),
        ("/signup", "signup page"),
        ("/healthz", "health endpoint"),
        ("/metrics", "metrics endpoint"),
        ("/forgot-password", "password-reset entry"),
    ] {
        let resp = router
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap_or_else(|e| panic!("{name} ({uri}) failed: {e}"));
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "{name} ({uri}) must return 200, got {}",
            resp.status()
        );
    }
}

#[tokio::test]
async fn backend_construction_does_not_panic() {
    // `OurBackend::new` MUST succeed against a freshly migrated pool.
    // Reading a schema column that doesn't yet exist would otherwise
    // surface as a panic at init time.
    let pool = fresh_pool().await;
    migrate(&pool).await;
    let _ = OurBackend::new(pool);
}

async fn app() -> axum::Router {
    app_with_pool().await.0
}

async fn app_with_pool() -> (axum::Router, sqlx::SqlitePool) {
    let pool = fresh_pool().await;
    migrate(&pool).await;
    seed(
        &SystemClock,
        &pool,
        &axess::authn::FactorSecretCipher::new(*b"0123456789abcdef0123456789abcdeF"),
    )
    .await
    .expect("seed");
    (build_router(pool.clone()).await.0, pool)
}

#[tokio::test]
async fn dashboard_redirects_a_guest_to_login() {
    let resp = app()
        .await
        .oneshot(
            Request::builder()
                .uri("/dashboard")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status().is_redirection(),
        "a guest must not be served the dashboard (got {})",
        resp.status()
    );
    assert!(
        resp.headers()["location"]
            .to_str()
            .unwrap()
            .starts_with("/login")
    );
}

/// GET `/signup`, returning the cookies it set and the CSRF token it
/// rendered, so a POST can present both as a browser would.
async fn signup_form(router: &axum::Router) -> (String, String) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/signup")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let cookies = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|v| v.split(';').next())
        .collect::<Vec<_>>()
        .join("; ");
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();
    let marker = r#"name="_csrf" value=""#;
    let start = html.find(marker).expect("csrf input rendered") + marker.len();
    let token = html[start..].split('"').next().unwrap().to_string();
    (cookies, token)
}

async fn post_signup(router: &axum::Router, password: &str) -> String {
    post_signup_as(router, "carol", password).await
}

async fn post_signup_as(router: &axum::Router, username: &str, password: &str) -> String {
    let (cookies, token) = signup_form(router).await;
    let body = format!(
        "_csrf={token}&username={username}&fullname=Carol+Example&email=carol%40example.com&password={password}"
    );
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/signup")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("cookie", cookies)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    if resp.status().is_redirection() {
        return format!("redirect {}", resp.headers()["location"].to_str().unwrap());
    }
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn signup_enforces_the_password_rules_on_the_server() {
    let router = app().await;
    let outcome = post_signup(&router, "short").await;
    assert!(
        outcome.contains("at least 12 characters"),
        "a weak password must be refused by the server, got: {outcome}"
    );
    let outcome = post_signup(&router, "Gnomes2%2BLongEnough").await;
    assert!(outcome.contains("Check your email"), "{outcome}");
}

/// A password on the breached list meets the rules and is still refused,
/// with the library's sentence on the signup page; nothing is created.
#[tokio::test]
async fn signup_refuses_a_breached_password_by_name() {
    let router = app().await;
    let outcome = post_signup(&router, "Password1234").await;
    assert!(
        outcome.contains("known from a data breach"),
        "a breached password must be refused by name, got: {outcome}"
    );
    assert!(
        !outcome.contains("at least 12 characters"),
        "the refusal must be the breach check's, not the rules': {outcome}"
    );
}

/// Signing up with a username somebody already has gets the same page as a
/// fresh signup that awaits its mail would: the form is not a way to learn
/// who has an account.
#[tokio::test]
async fn signup_with_a_taken_username_does_not_say_so() {
    let router = app().await;
    let outcome = post_signup_as(&router, "alice", "Gnomes2%2BLongEnough").await;
    assert!(
        !outcome.to_lowercase().contains("already exists"),
        "the response named the conflict: {outcome}"
    );
    assert!(
        outcome.contains("Check your email"),
        "the generic answer is shown instead: {outcome}"
    );
}

#[tokio::test]
async fn bobs_seeded_totp_secret_is_sealed_at_rest() {
    let pool = fresh_pool().await;
    migrate(&pool).await;
    seed(
        &SystemClock,
        &pool,
        &axess::authn::FactorSecretCipher::new(*b"0123456789abcdef0123456789abcdeF"),
    )
    .await
    .expect("seed");

    let json: String = sqlx::query_scalar(
        "SELECT config_json FROM factor_configs
         WHERE kind = 'totp' AND user_id = '00000000-0000-0000-0000-000000000020'",
    )
    .fetch_one(&pool)
    .await
    .expect("bob's totp row");
    let config: axess::authn::FactorConfig = serde_json::from_str(&json).expect("config");
    let axess::authn::FactorConfig::Totp(totp) = config else {
        panic!("bob's factor is not TOTP");
    };
    assert!(
        totp.secret.plain().is_none(),
        "bob's secret is stored plain"
    );
}

/// A signup that fails part-way leaves nothing behind: no half-built user
/// holding the username, so the same person can try again.
#[tokio::test]
async fn a_failed_signup_leaves_no_half_built_user() {
    let (router, pool) = app_with_pool().await;
    sqlx::query(
        "CREATE TRIGGER refuse_methods BEFORE INSERT ON auth_methods
         BEGIN SELECT RAISE(ABORT, 'refused'); END",
    )
    .execute(&pool)
    .await
    .expect("trigger");

    let outcome = post_signup(&router, "Gnomes2%2BLongEnough").await;
    assert!(
        !outcome.starts_with("redirect"),
        "the signup should have failed: {outcome}"
    );
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE identifier = 'carol'")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(left, 0, "the failed signup left its user behind");
    let creds: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM factor_configs WHERE user_id NOT IN (SELECT id FROM users)",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(creds, 0, "credentials were left without a user");
}

/// Whatever password the login page offers for the test accounts meets the
/// rules the example enforces on every other password.
#[tokio::test]
async fn the_login_page_offers_no_password_weaker_than_the_rules() {
    let resp = app()
        .await
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();
    let marker = "<code>alice</code> / <code>";
    let start = html.find(marker).expect("alice's password is listed") + marker.len();
    let password = html[start..].split("</code>").next().unwrap();
    let rules = axess::authn::PasswordRules::default();
    assert!(
        password.chars().count() >= rules.min_length,
        "{password:?} is too short"
    );
    assert!(
        password.chars().any(|c| c.is_uppercase()),
        "{password:?}: no upper case"
    );
    assert!(
        password.chars().any(|c| c.is_lowercase()),
        "{password:?}: no lower case"
    );
    assert!(
        password.chars().any(|c| c.is_ascii_digit()),
        "{password:?}: no digit"
    );
}

/// Send `method path` with the cookies and CSRF token of a signup form, from
/// one fixed client address, and return the status.
async fn from_one_address(
    router: &axum::Router,
    method: &str,
    path: &str,
    csrf: &(String, String),
) -> StatusCode {
    let (cookies, token) = csrf;
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("cookie", cookies.as_str());
    let body = if method == "POST" {
        request = request.header("content-type", "application/x-www-form-urlencoded");
        Body::from(format!("_csrf={token}&code=000000&username=x&password=x"))
    } else {
        Body::empty()
    };
    let mut request = request.body(body).unwrap();
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [203, 0, 113, 9],
            40_000,
        ))));
    router.clone().oneshot(request).await.unwrap().status()
}

/// Spend the ten submissions one form allows a minute from one address.
async fn fill(router: &axum::Router, path: &str, csrf: &(String, String)) {
    for i in 0..10 {
        let status = from_one_address(router, "POST", path, csrf).await;
        assert_ne!(status, StatusCode::TOO_MANY_REQUESTS, "{path} request {i}");
    }
    let status = from_one_address(router, "POST", path, csrf).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{path} is limited");
}

/// Each sensitive form has a rate-limit bucket of its own: a client address
/// that has used up one form's budget is still served by the others.
#[tokio::test]
async fn auth_forms_have_independent_rate_limit_buckets() {
    for (full, others) in [
        (
            "/recovery-code",
            ["/signup", "/reset-password", "/totp"].as_slice(),
        ),
        (
            "/reset-password",
            ["/recovery-code", "/signup", "/totp"].as_slice(),
        ),
        ("/signup", ["/recovery-code", "/totp"].as_slice()),
    ] {
        let router = app().await;
        let csrf = signup_form(&router).await;
        fill(&router, full, &csrf).await;
        for other in others {
            let status = from_one_address(&router, "POST", other, &csrf).await;
            assert_ne!(
                status,
                StatusCode::TOO_MANY_REQUESTS,
                "{other} shares the bucket of {full}"
            );
        }
        let status = from_one_address(&router, "GET", "/verify-email", &csrf).await;
        assert_ne!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "/verify-email shares the bucket of {full}"
        );
    }
}

/// Markup in what a visitor typed does not come back as markup in an error
/// message: every message is escaped where the page is built.
#[tokio::test]
async fn an_error_message_never_carries_markup_back() {
    let router = app().await;
    let outcome = post_signup_as(&router, "%3Cscript%3Ealert(1)%3C%2Fscript%3E", "short").await;
    assert!(!outcome.contains("<script>alert"), "{outcome}");
}
