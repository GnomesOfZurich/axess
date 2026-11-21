//! The session layer checks its whole configuration once, when it becomes a
//! service, whatever order the setters ran in.

#![cfg(all(feature = "memory", feature = "testing"))]

use axess_core::testing::fixtures as common;

use axess_clock::testing::MockClock;
use axess_core::session::{
    config::{SameSite, SessionConfig},
    layer::SessionLayer,
    store::MemorySessionStore,
};
use std::convert::Infallible;
use std::time::Duration;
use tower::{Layer, service_fn};

fn base(clock: &MockClock) -> SessionLayer<MemorySessionStore> {
    SessionLayer::new(
        MemorySessionStore::new().with_clock(std::sync::Arc::new(clock.clone())),
        axess_core::testing::test_key(1),
        axess_core::MemorySessionRegistry::new()
            .with_clock(std::sync::Arc::new(clock.clone()))
            .handle(),
        std::sync::Arc::new(axess_core::session::UnrecordedSessionEnds),
    )
    .with_clock(clock.clone())
}

fn build(layer: &SessionLayer<MemorySessionStore>) {
    let inner = service_fn(|_: axum::http::Request<axum::body::Body>| async {
        Ok::<_, Infallible>(axum::http::Response::new(axum::body::Body::empty()))
    });
    let _ = layer.layer(inner);
}

#[test]
fn the_default_layer_builds() {
    let clock = common::test_clock();
    build(&base(&clock));
}

#[test]
fn a_config_from_the_builder_builds() {
    let clock = common::test_clock();
    build(&base(&clock).with_config(SessionConfig::builder().build()));
}

#[test]
fn a_dev_layer_without_secure_falls_back_to_the_unprefixed_name() {
    let clock = common::test_clock();
    build(&base(&clock).with_secure(false));
    build(&base(&clock).with_path("/app"));
}

#[test]
fn setter_order_does_not_matter() {
    let clock = common::test_clock();
    build(&base(&clock).with_cookie_name("__Host-a").with_secure(true));
    build(
        &base(&clock)
            .with_secure(false)
            .with_cookie_name("plain")
            .with_secure(true),
    );
}

#[test]
#[should_panic(expected = "requires `path")]
fn host_prefix_with_a_path_panics() {
    let clock = common::test_clock();
    build(&base(&clock).with_cookie_name("__Host-a").with_path("/app"));
}

#[test]
#[should_panic(expected = "requires `secure = true`")]
fn secure_prefix_without_secure_panics() {
    let clock = common::test_clock();
    build(
        &base(&clock)
            .with_cookie_name("__Secure-a")
            .with_secure(false),
    );
}

#[test]
#[should_panic(expected = "requires `secure = true`")]
fn host_prefix_without_secure_panics() {
    let clock = common::test_clock();
    build(&base(&clock).with_cookie_name("__Host-a").with_secure(false));
}

#[test]
#[should_panic(expected = "ttl must be > 0")]
fn zero_ttl_panics() {
    let clock = common::test_clock();
    build(&base(&clock).with_ttl(Duration::ZERO));
}

#[test]
#[should_panic(expected = "must not be empty")]
fn empty_cookie_name_panics() {
    let clock = common::test_clock();
    build(&base(&clock).with_cookie_name(""));
}

#[test]
#[should_panic(expected = "not valid in a cookie name")]
fn a_cookie_name_with_a_separator_panics() {
    let clock = common::test_clock();
    build(&base(&clock).with_cookie_name("a;b"));
}

#[test]
#[should_panic(expected = "SameSite=None")]
fn same_site_none_without_secure_panics() {
    let clock = common::test_clock();
    build(
        &base(&clock)
            .with_same_site(SameSite::None)
            .with_secure(false),
    );
}

#[test]
#[should_panic(expected = "max_authenticated_age must be > 0")]
fn zero_session_age_panics() {
    let clock = common::test_clock();
    build(&base(&clock).with_max_session_age(Some(Duration::ZERO)));
}

#[test]
#[should_panic(expected = "max_impersonation_age must be > 0")]
fn zero_impersonation_age_panics() {
    let clock = common::test_clock();
    build(&base(&clock).with_max_impersonation_age(Some(Duration::ZERO)));
}

#[test]
fn the_default_config_caps_a_session_at_seven_days_and_an_impersonation_at_an_hour() {
    let config = SessionConfig::default();
    assert_eq!(
        config.max_authenticated_age(),
        Some(Duration::from_secs(7 * 24 * 3600))
    );
    assert_eq!(
        config.max_impersonation_age(),
        Some(Duration::from_secs(3600))
    );
}
