//! The session layer checks its whole configuration once, when it becomes a
//! service, whatever order the setters ran in.

#![cfg(feature = "memory")]

use axess_core::session::{
    config::{SameSite, SessionConfig},
    layer::SessionLayer,
    store::MemorySessionStore,
};
use std::convert::Infallible;
use std::time::Duration;
use tower::{Layer, service_fn};

fn base() -> SessionLayer<MemorySessionStore> {
    SessionLayer::new(MemorySessionStore::new(), [1u8; 32])
}

fn build(layer: &SessionLayer<MemorySessionStore>) {
    let inner = service_fn(|_req: axum::http::Request<axum::body::Body>| async {
        Ok::<_, Infallible>(axum::http::Response::new(axum::body::Body::empty()))
    });
    let _ = layer.layer(inner);
}

#[test]
fn the_default_layer_builds() {
    build(&base());
}

#[test]
fn a_config_from_the_builder_builds() {
    build(&base().with_config(SessionConfig::builder().build()));
}

#[test]
fn a_dev_layer_without_secure_falls_back_to_the_unprefixed_name() {
    build(&base().with_secure(false));
    build(&base().with_path("/app"));
}

#[test]
fn setter_order_does_not_matter() {
    build(&base().with_cookie_name("__Host-a").with_secure(true));
    build(
        &base()
            .with_secure(false)
            .with_cookie_name("plain")
            .with_secure(true),
    );
}

#[test]
#[should_panic(expected = "requires `path")]
fn host_prefix_with_a_path_panics() {
    build(&base().with_cookie_name("__Host-a").with_path("/app"));
}

#[test]
#[should_panic(expected = "requires `secure = true`")]
fn secure_prefix_without_secure_panics() {
    build(&base().with_cookie_name("__Secure-a").with_secure(false));
}

#[test]
#[should_panic(expected = "requires `secure = true`")]
fn host_prefix_without_secure_panics() {
    build(&base().with_cookie_name("__Host-a").with_secure(false));
}

#[test]
#[should_panic(expected = "ttl must be > 0")]
fn zero_ttl_panics() {
    build(&base().with_ttl(Duration::ZERO));
}

#[test]
#[should_panic(expected = "must not be empty")]
fn empty_cookie_name_panics() {
    build(&base().with_cookie_name(""));
}

#[test]
#[should_panic(expected = "not valid in a cookie name")]
fn a_cookie_name_with_a_separator_panics() {
    build(&base().with_cookie_name("a;b"));
}

#[test]
#[should_panic(expected = "SameSite=None")]
fn same_site_none_without_secure_panics() {
    build(&base().with_same_site(SameSite::None).with_secure(false));
}

#[test]
#[should_panic(expected = "max_authenticated_age must be > 0")]
fn zero_session_age_panics() {
    build(&base().with_max_session_age(Duration::ZERO));
}
