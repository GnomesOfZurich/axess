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
    upgrade_to("app.example.com", origin)
}

/// An upgrade request to `host`, as a browser sends it, with `origin`.
fn upgrade_to(host: &str, origin: Option<&str>) -> Request<Body> {
    let mut req = Request::get("/ws")
        .header(header::HOST, host)
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

/// Without an allow-list the request's own `Host` is the one origin an
/// upgrade may come from: a cross-site page cannot open a socket with the
/// user's cookies. The scheme must be the one the deployment serves
/// (`https` under the default `secure`), a client that sends no `Origin`
/// is not a browser and passes, and the gate can be turned off.
#[tokio::test]
async fn an_upgrade_without_an_allow_list_must_come_from_the_requests_own_host() {
    let open = layer(&[]);
    let foreign = open
        .clone()
        .oneshot(upgrade_to(
            "app.example.com",
            Some("https://evil.example.net"),
        ))
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::FORBIDDEN, "a foreign origin");
    let downgraded = open
        .clone()
        .oneshot(upgrade_to(
            "app.example.com",
            Some("http://app.example.com"),
        ))
        .await
        .unwrap();
    assert_eq!(
        downgraded.status(),
        StatusCode::FORBIDDEN,
        "the wrong scheme"
    );
    let own = open
        .clone()
        .oneshot(upgrade_to(
            "app.example.com",
            Some("https://APP.example.com:443"),
        ))
        .await
        .unwrap();
    assert_eq!(own.status(), StatusCode::OK, "the request's own origin");
    let with_port = open
        .clone()
        .oneshot(upgrade_to(
            "app.example.com:8443",
            Some("https://app.example.com:8443"),
        ))
        .await
        .unwrap();
    assert_eq!(
        with_port.status(),
        StatusCode::OK,
        "a non-default port, on both"
    );
    let no_origin = open
        .clone()
        .oneshot(upgrade_to("app.example.com", None))
        .await
        .unwrap();
    assert_eq!(no_origin.status(), StatusCode::OK, "not a browser");

    let plain_http = CsrfLayer::new(CsrfConfig::new([3u8; 32]).secure(false)).layer(ok());
    let own_http = plain_http
        .oneshot(upgrade_to("localhost:3000", Some("http://localhost:3000")))
        .await
        .unwrap();
    assert_eq!(
        own_http.status(),
        StatusCode::OK,
        "http when the cookies are not Secure"
    );

    let opted_out =
        CsrfLayer::new(CsrfConfig::new([3u8; 32]).websocket_origin_check(false)).layer(ok());
    let res = opted_out
        .oneshot(upgrade_to(
            "app.example.com",
            Some("https://evil.example.net"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "the opt-out");
}

/// A plain GET is never an upgrade.
#[tokio::test]
async fn plain_gets_are_untouched() {
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
#[should_panic(expected = "requires `secure = true`")]
fn a_host_prefix_in_another_case_without_secure_is_refused() {
    let config = CsrfConfig::new([3u8; 32])
        .cookie_name("__HOST-csrf")
        .secure(false);
    let _ = CsrfLayer::new(config);
}

#[test]
#[should_panic(expected = "requires `secure = true`")]
fn a_secure_prefix_in_another_case_without_secure_is_refused() {
    let config = CsrfConfig::new([3u8; 32])
        .cookie_name("__secure-csrf")
        .secure(false);
    let _ = CsrfLayer::new(config);
}

#[test]
fn prefixed_names_with_secure_and_plain_names_are_accepted() {
    let _ = CsrfLayer::new(CsrfConfig::new([3u8; 32]).cookie_name("__Host-csrf"));
    let _ = CsrfLayer::new(CsrfConfig::new([3u8; 32]).cookie_name("__Secure-csrf"));
    let _ = CsrfLayer::new(CsrfConfig::new([3u8; 32]).cookie_name("csrf").secure(false));
}

#[test]
fn a_cookie_path_that_could_inject_attributes_is_refused() {
    for bad in ["/; Domain=example.com", "app", "/a\r\nX: y", ""] {
        let refused = std::panic::catch_unwind(|| {
            check_cookie_rules("csrf", true, bad, cookie::SameSite::Lax)
        });
        assert!(refused.is_err(), "path {bad:?} was accepted");
    }
    check_cookie_rules("csrf", true, "/app", cookie::SameSite::Lax);
}
