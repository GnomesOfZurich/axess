//! Trace and span IDs come from the layer's RNG.

use super::*;
use axess_rng::testing::MockRng;

fn app(seed: u64) -> TraceContextMiddleware<axum::Router> {
    TraceContextLayer::new()
        .with_rng(MockRng::new(seed))
        .layer(axum::Router::new().route("/", axum::routing::get(|| async { "ok" })))
}

fn hex(bytes: &[u8]) -> String {
    to_hex(bytes)
}

async fn traceparent(app: TraceContextMiddleware<axum::Router>, incoming: Option<&str>) -> String {
    let mut req = Request::get("/");
    if let Some(v) = incoming {
        req = req.header("traceparent", v);
    }
    let res = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
    res.headers()
        .get("traceparent")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn a_new_root_takes_trace_then_span_bytes_from_the_rng() {
    let rng = MockRng::new(9);
    let (mut trace, mut span) = ([0u8; 16], [0u8; 8]);
    rng.fill_bytes(&mut trace);
    rng.fill_bytes(&mut span);

    assert_eq!(
        traceparent(app(9), None).await,
        format!("00-{}-{}-01", hex(&trace), hex(&span))
    );
}

#[tokio::test]
async fn a_child_span_takes_its_id_from_the_rng_and_keeps_the_trace() {
    let rng = MockRng::new(9);
    let mut span = [0u8; 8];
    rng.fill_bytes(&mut span);
    let incoming = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    assert_eq!(
        traceparent(app(9), Some(incoming)).await,
        format!("00-4bf92f3577b34da6a3ce929d0e0e4736-{}-01", hex(&span))
    );
}
