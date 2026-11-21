#![cfg(feature = "bearer")]
//! The bearer-token middleware passes its inner service's readiness on:
//! pending while the inner service is pending, and the inner service's
//! error when its readiness fails.

use axess_clock::testing::MockClock;
use axess_factors::bearer::{BearerConfig, BearerTokenLayer};
use axess_testing::readiness::{NotReady, Unready, poll_ready_once};
use axum::body::Body;
use axum::http::Request;
use axum::response::Response;
use std::sync::Arc;
use std::task::Poll;
use tower::Layer;

#[test]
fn the_bearer_middleware_passes_readiness_through() {
    let clock = MockClock::at_reference();
    let layer = BearerTokenLayer::new(BearerConfig::new(Vec::new()).with_clock(Arc::new(clock)));

    let inner = Unready::<Response>::pending();
    let mut service = layer.layer(inner.clone());
    assert!(
        poll_ready_once::<_, Request<Body>>(&mut service).is_pending(),
        "a pending inner service leaves the middleware pending"
    );
    assert_eq!(inner.polls(), 1, "the inner service was asked");

    let inner = Unready::<Response>::failing();
    let mut service = layer.layer(inner.clone());
    assert_eq!(
        poll_ready_once::<_, Request<Body>>(&mut service),
        Poll::Ready(Err(NotReady::Failed)),
        "the inner service's readiness error is the middleware's"
    );
    assert_eq!(inner.polls(), 1, "the inner service was asked");
}
