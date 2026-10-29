//! CSRF token nonces come from the config's RNG.

use super::*;
use crate::session::id::SessionId;
use crate::session::layer::SessionLayer;
use crate::session::store::MemorySessionStore;
use axess_rng::testing::MockRng;
use axum::Router;
use axum::http::Request;
use axum::routing::get;
use tower::ServiceExt;

fn csrf_cookie(resp: &Response<Body>) -> String {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|hv| hv.to_str().ok())
        .find_map(|c| {
            let (k, v) = c.split(';').next()?.split_once('=')?;
            (k.trim() == DEFAULT_CSRF_COOKIE).then(|| v.trim().to_string())
        })
        .expect("the GET must mint the CSRF cookie")
}

#[tokio::test]
async fn the_minted_token_is_the_seeded_rngs_nonce_bound_to_the_session() {
    let app = Router::new()
        .route(
            "/safe",
            get(
                |axum::Extension(token): axum::Extension<CsrfToken>| async move {
                    // Using the token is what asks for the session to be stored.
                    assert!(!token.as_str().is_empty());
                    "ok"
                },
            ),
        )
        .layer(CsrfLayer::new(
            CsrfConfig::new([7u8; 32])
                .secure(false)
                .rng(MockRng::new(2)),
        ))
        .layer(
            SessionLayer::new(MemorySessionStore::new(), [42u8; 32])
                .with_secure(false)
                .with_rng(MockRng::new(1)),
        );

    let resp = app
        .oneshot(Request::get("/safe").body(Body::empty()).unwrap())
        .await
        .unwrap();

    let session_id = SessionId::new(&MockRng::new(1));
    let expected = mint_token(session_id.as_bytes(), &[7u8; 32], &MockRng::new(2));
    assert_eq!(csrf_cookie(&resp), expected);
}
