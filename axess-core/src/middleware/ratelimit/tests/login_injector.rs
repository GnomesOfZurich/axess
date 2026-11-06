//! The injector a login route puts outside its `LoginIdentifier` limiter.

use super::*;
use axum::{Router, middleware::from_fn, routing::post};

fn username_of(body: &[u8]) -> Option<RateLimitLoginIdentifier> {
    let text = std::str::from_utf8(body).ok()?;
    let name = text.strip_prefix("username=")?;
    RateLimitLoginIdentifier::new(name)
}

fn login_router() -> Router {
    let per_username = RateLimitLayer::new(
        RateLimitConfig::builder()
            .max_requests(1)
            .window(Duration::from_secs(60))
            .key(KeyExtractor::LoginIdentifier)
            .build(),
    );
    Router::new()
        .route("/login", post(|| async { "ok" }))
        .layer(per_username)
        .layer(from_fn(
            |request: Request<Body>, next: axum::middleware::Next| async move {
                match inject_login_identifier(request, 4096, username_of).await {
                    Ok(request) => next.run(request).await,
                    Err(status) => axum::response::IntoResponse::into_response(status),
                }
            },
        ))
}

fn login(body: &'static str) -> Request<Body> {
    Request::post("/login").body(Body::from(body)).unwrap()
}

#[tokio::test]
async fn each_username_gets_its_own_bucket_and_the_handler_still_reads_the_body() {
    let app = login_router();
    let first = ServiceExt::oneshot(app.clone(), login("username=alice"))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let other = ServiceExt::oneshot(app.clone(), login("username=bob"))
        .await
        .unwrap();
    assert_eq!(other.status(), StatusCode::OK, "bob shares alice's bucket");
    let again = ServiceExt::oneshot(app, login("username=ALICE"))
        .await
        .unwrap();
    assert_eq!(again.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn the_rebuilt_request_carries_the_original_body() {
    let request = login("username=alice&password=x");
    let request = inject_login_identifier(request, 4096, username_of)
        .await
        .unwrap();
    assert!(
        request
            .extensions()
            .get::<RateLimitLoginIdentifier>()
            .is_some()
    );
    let bytes = axum::body::to_bytes(request.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(&bytes[..], b"username=alice&password=x");
}

#[tokio::test]
async fn a_body_over_the_limit_is_refused_with_413() {
    let status = inject_login_identifier(login("username=alice"), 4, username_of)
        .await
        .map(|_| ())
        .unwrap_err();
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}
