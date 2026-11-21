#![cfg(feature = "testing")]
//! Each middleware passes its inner service's readiness on: pending while
//! the inner service is pending, and the inner service's error when its
//! readiness fails. A middleware that answered `Ready` by itself would take
//! requests its inner service has no room for.

use axess_core::testing::fixtures as common;

use axess_core::middleware::csrf::{CsrfConfig, CsrfLayer};
use axess_core::session::{layer::SessionLayer, store::MemorySessionStore};
use axess_core::{KeyExtractor, RateLimitConfig, RateLimitLayer};
use axess_testing::readiness::{NotReady, Unready, poll_ready_once};
use axum::body::Body;
use axum::http::{Request, Response};
use std::task::Poll;
use tower::{Layer, Service};

/// The inner service every middleware here wraps.
type Inner = Unready<Response<Body>>;

/// `layer` asks the inner service whether it is ready and answers what it
/// answers, pending and failed alike.
fn assert_readiness_passes_through<L>(layer: &L)
where
    L: Layer<Inner>,
    L::Service: Service<Request<Body>, Error = NotReady>,
{
    let inner = Inner::pending();
    let mut service = layer.layer(inner.clone());
    assert!(
        poll_ready_once::<_, Request<Body>>(&mut service).is_pending(),
        "a pending inner service leaves the middleware pending"
    );
    assert_eq!(inner.polls(), 1, "the inner service was asked");

    let inner = Inner::failing();
    let mut service = layer.layer(inner.clone());
    assert_eq!(
        poll_ready_once::<_, Request<Body>>(&mut service),
        Poll::Ready(Err(NotReady::Failed)),
        "the inner service's readiness error is the middleware's"
    );
    assert_eq!(inner.polls(), 1, "the inner service was asked");
}

#[test]
fn the_csrf_middleware_passes_readiness_through() {
    assert_readiness_passes_through(&CsrfLayer::new(CsrfConfig::new([42u8; 32])));
}

#[test]
fn the_rate_limit_middleware_passes_readiness_through() {
    let clock = common::test_clock();
    let layer = RateLimitLayer::new(
        RateLimitConfig::builder()
            .clock(clock.clone())
            .key(KeyExtractor::PeerIp)
            .build(),
    );
    assert_readiness_passes_through(&layer);
}

#[cfg(feature = "request-id")]
#[test]
fn the_request_id_middleware_passes_readiness_through() {
    use axess_core::middleware::request_id::{RequestIdLayer, RngUuidGenerator};
    let layer = RequestIdLayer::new(RngUuidGenerator::new(axess_core::testing::MockRng::new(7)));
    assert_readiness_passes_through(&layer);
}

#[cfg(feature = "trace-context")]
#[test]
fn the_trace_context_middleware_passes_readiness_through() {
    use axess_core::middleware::trace_context::TraceContextLayer;
    let layer = TraceContextLayer::new().with_rng(axess_core::testing::MockRng::new(7));
    assert_readiness_passes_through(&layer);
}

#[cfg(feature = "service-secret")]
#[test]
fn the_service_secret_middleware_passes_readiness_through() {
    use axess_core::middleware::service_secret::{
        ServiceSecret, ServiceSecretLayer, ServiceSecrets,
    };
    let secrets: ServiceSecrets =
        [
            ServiceSecret::new("relay", "relay-secret-0123456789abcdef0123456789")
                .expect("long enough"),
        ]
        .into_iter()
        .collect();
    assert_readiness_passes_through(&ServiceSecretLayer::bearer(secrets));
}

#[test]
fn the_session_middleware_passes_readiness_through() {
    let clock = common::test_clock();
    let layer = SessionLayer::without_registry_insecure(
        MemorySessionStore::new().with_clock(std::sync::Arc::new(clock.clone())),
        axess_core::testing::test_key(42),
        std::sync::Arc::new(axess_core::session::UnrecordedSessionEnds),
    )
    .with_clock(clock.clone());
    assert_readiness_passes_through(&layer);
}
