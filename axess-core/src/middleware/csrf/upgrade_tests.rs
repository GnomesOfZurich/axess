//! WebSocket upgrades and cookie-name prefix rules of the CSRF layer.

use super::*;
use std::convert::Infallible;
use tower::{Layer, ServiceExt, service_fn};

fn ok()
-> impl tower::Service<Request<Body>, Response = Response<Body>, Error = Infallible, Future: Send>
+ Clone {
    service_fn(|_req: Request<Body>| async {
        Ok(Response::builder().status(200).body(Body::empty()).unwrap())
    })
}

fn upgrade(origin: Option<&str>) -> Request<Body> {
    let mut req = Request::get("/ws")
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "keep-alive, Upgrade");
    if let Some(origin) = origin {
        req = req.header(header::ORIGIN, origin);
    }
    req.body(Body::empty()).unwrap()
}

fn layer(
    origins: &[&str],
) -> impl tower::Service<Request<Body>, Response = Response<Body>, Error = Infallible, Future: Send>
+ Clone {
    let mut config = CsrfConfig::new([3u8; 32]);
    if !origins.is_empty() {
        config = config.require_origin(origins);
    }
    CsrfLayer::new(config).layer(ok())
}

/// A cross-site page can open a WebSocket with the user's cookies. With an
/// allow-list, the upgrade from an origin outside it is refused.
#[tokio::test]
async fn a_websocket_upgrade_from_a_foreign_origin_is_refused() {
    let service = layer(&["https://app.example.com"]);
    let foreign = service
        .clone()
        .oneshot(upgrade(Some("https://evil.example.net")))
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::FORBIDDEN);
    let none = service.clone().oneshot(upgrade(None)).await.unwrap();
    assert_eq!(none.status(), StatusCode::FORBIDDEN);
    let own = service
        .oneshot(upgrade(Some("https://APP.example.com:443")))
        .await
        .unwrap();
    assert_eq!(own.status(), StatusCode::OK);
}

/// Without an allow-list nothing changes, and a plain GET is never an
/// upgrade.
#[tokio::test]
async fn upgrades_pass_without_an_allow_list_and_plain_gets_are_untouched() {
    let open = layer(&[]);
    let res = open
        .oneshot(upgrade(Some("https://evil.example.net")))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let guarded = layer(&["https://app.example.com"]);
    let plain = Request::get("/page")
        .header(header::ORIGIN, "https://evil.example.net")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        guarded.oneshot(plain).await.unwrap().status(),
        StatusCode::OK
    );
}

#[test]
fn only_a_complete_upgrade_request_counts() {
    let no_connection = Request::get("/ws")
        .header(header::UPGRADE, "websocket")
        .body(Body::empty())
        .unwrap();
    assert!(!is_websocket_upgrade(&no_connection));
    let h2c = Request::get("/ws")
        .header(header::UPGRADE, "h2c")
        .header(header::CONNECTION, "upgrade")
        .body(Body::empty())
        .unwrap();
    assert!(!is_websocket_upgrade(&h2c));
    assert!(is_websocket_upgrade(&upgrade(None)));
}

#[test]
#[should_panic(expected = "requires `secure = true`")]
fn a_host_prefix_without_secure_is_refused() {
    let config = CsrfConfig::new([3u8; 32])
        .cookie_name("__Host-csrf")
        .secure(false);
    let _ = CsrfLayer::new(config);
}

#[test]
#[should_panic(expected = "requires `secure = true`")]
fn a_secure_prefix_without_secure_is_refused() {
    let config = CsrfConfig::new([3u8; 32])
        .cookie_name("__Secure-csrf")
        .secure(false);
    let _ = CsrfLayer::new(config);
}

#[test]
fn prefixed_names_with_secure_and_plain_names_are_accepted() {
    let _ = CsrfLayer::new(CsrfConfig::new([3u8; 32]).cookie_name("__Host-csrf"));
    let _ = CsrfLayer::new(CsrfConfig::new([3u8; 32]).cookie_name("__Secure-csrf"));
    let _ = CsrfLayer::new(CsrfConfig::new([3u8; 32]).cookie_name("csrf").secure(false));
}
