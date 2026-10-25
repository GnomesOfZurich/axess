//! A handler that rotates the session and embeds a CSRF token in the page it
//! renders must embed the token the response cookie carries.

use super::*;
use crate::session::data::SessionData;
use crate::session::id::SessionId;
use crate::session::layer::SessionInner;
use crate::testing::mock_random::MockRng;
use axum::http::Method;
use std::convert::Infallible;
use tokio::sync::RwLock;
use tower::{Layer, ServiceExt, service_fn};

fn handle(seed: u64) -> SessionHandle {
    let rng = MockRng::new(seed);
    SessionHandle(Arc::new(RwLock::new(SessionInner {
        id: SessionId::new(&rng),
        data: SessionData::default(),
        modified: false,
        needs_persist: false,
        regenerate: false,
        pre_cycle_id: None,
        rng: std::sync::Arc::new(axess_rng::SystemRng),
        pending_fingerprint: None,
        max_custom_bytes: 64 * 1024,
    })))
}

fn set_cookie_value(resp: &Response<Body>) -> String {
    let raw = resp
        .headers()
        .get(header::SET_COOKIE)
        .expect("rotation must set a fresh csrf cookie")
        .to_str()
        .unwrap();
    raw.split('=')
        .nth(1)
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

/// The handler rotates, then renders the issuer's token plus the stale
/// extension token, separated by a newline.
fn rotate_then_render()
-> impl tower::Service<Request<Body>, Response = Response<Body>, Error = Infallible, Future: Send>
+ Clone {
    service_fn(|req: Request<Body>| async move {
        if req.method() != Method::GET {
            return Ok(Response::builder().status(200).body(Body::empty()).unwrap());
        }
        let stale = req.extensions().get::<CsrfToken>().unwrap().0.clone();
        let issuer = req.extensions().get::<CsrfIssuer>().unwrap().clone();
        let before = issuer.token().await.0;
        req.extensions()
            .get::<SessionHandle>()
            .unwrap()
            .0
            .write()
            .await
            .rotate_id();
        let after = issuer.token().await.0;
        let again = issuer.token().await.0;
        let body = format!("{stale}\n{before}\n{after}\n{again}");
        Ok(Response::builder()
            .status(200)
            .body(Body::from(body))
            .unwrap())
    })
}

#[tokio::test]
async fn rotated_token_is_reachable_in_the_same_request_and_matches_the_cookie() {
    let key = [41u8; 32];
    let config = CsrfConfig::new(key);
    let service = CsrfLayer::new(config.clone()).layer(rotate_then_render());
    let h = handle(3);
    let sid_before = h.0.read().await.id;

    let req = Request::builder()
        .method(Method::GET)
        .uri("/login-done")
        .extension(h.clone())
        .body(Body::empty())
        .unwrap();
    let resp = service.clone().oneshot(req).await.unwrap();
    let cookie = set_cookie_value(&resp);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    let [stale, before, after, again]: [&str; 4] =
        body.split('\n').collect::<Vec<_>>().try_into().unwrap();

    let sid_after = h.0.read().await.id;
    assert_ne!(sid_before, sid_after, "precondition: the handler rotated");
    assert_eq!(
        before, stale,
        "before rotation the issuer matches the extension"
    );
    assert_ne!(after, stale, "after rotation the token must change");
    assert_eq!(after, again, "the rotated token is minted once");
    assert_eq!(
        after, cookie,
        "the embedded token is the cookie the response sets"
    );
    assert!(validate_token(after, sid_after.as_bytes(), &key));
    assert!(
        !validate_token(stale, sid_after.as_bytes(), &key),
        "the extension token is bound to the pre-rotation id"
    );

    // The rotate-then-check path: a client that submits the embedded token
    // alongside the cookie passes the check under the rotated id.
    let post = Request::builder()
        .method(Method::POST)
        .uri("/next")
        .header("cookie", format!("{}={cookie}", config.cookie_name))
        .header(DEFAULT_CSRF_HEADER, after)
        .extension(h.clone())
        .body(Body::empty())
        .unwrap();
    assert_eq!(service.oneshot(post).await.unwrap().status(), 200);
}
