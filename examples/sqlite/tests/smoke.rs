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

    seed(&SystemClock, &pool).await.expect("first seed");
    seed(&SystemClock, &pool)
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
    seed(&SystemClock, &pool).await.expect("seed");

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
    seed(&SystemClock, &pool).await.expect("seed");
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
    seed(&SystemClock, &pool).await.expect("seed");
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
