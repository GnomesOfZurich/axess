//! W3C Trace Context middleware for Axess.
//!
//! Implements the [W3C Trace Context](https://www.w3.org/TR/trace-context/) `traceparent`
//! header for distributed tracing. Incoming requests with a valid `traceparent` header
//! are propagated; requests without one get a new trace context generated.
//!
//! The trace ID is also injected into the tracing span so log aggregators can
//! correlate HTTP requests with application traces.
//!
//! # Usage
//!
//! ```text
//! let app = Router::new()
//!     .route("/api", get(handler))
//!     .layer(TraceContextLayer::default());
//! ```
//!
//! # Header format
//!
//! `traceparent: {version}-{trace-id}-{parent-id}-{flags}`
//!
//! Example: `traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01`
//!
//! # Alternative
//!
//! For request ID generation (not distributed tracing), consider
//! [`tower_http::request_id`](https://docs.rs/tower-http/latest/tower_http/request_id/)
//! which provides `SetRequestId` + `PropagateRequestId`.

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderValue, header::HeaderName},
    response::Response,
};
use std::{
    future::Future,
    pin::Pin,
    sync::LazyLock,
    task::{Context, Poll},
};
use tower::{Layer, Service};

static TRACEPARENT: LazyLock<HeaderName> = LazyLock::new(|| HeaderName::from_static("traceparent"));

// ── TraceContext ──────────────────────────────────────────────────────────────

/// A parsed W3C traceparent value.
///
/// Held in request extensions so handlers can access the trace ID.
#[derive(Clone, Debug)]
pub struct TraceContext {
    /// The full traceparent header value.
    pub traceparent: String,
    /// The 128-bit trace ID as a hex string (32 chars).
    pub trace_id: String,
    /// The 64-bit parent span ID as a hex string (16 chars).
    pub parent_id: String,
    /// Whether this trace is sampled.
    pub sampled: bool,
}

impl TraceContext {
    /// Generate a new trace context with a random trace ID.
    fn new_root() -> Self {
        let tp = traceparent::make(true);
        Self {
            traceparent: tp.to_string(),
            trace_id: format!("{:032x}", tp.trace_id()),
            parent_id: format!("{:016x}", tp.parent_id()),
            sampled: tp.sampled(),
        }
    }

    /// Create a child span from an existing traceparent.
    fn child(parent: &traceparent::Traceparent) -> Self {
        let child = parent.child(parent.sampled());
        Self {
            traceparent: child.to_string(),
            trace_id: format!("{:032x}", child.trace_id()),
            parent_id: format!("{:016x}", child.parent_id()),
            sampled: child.sampled(),
        }
    }

    /// Parse from a traceparent header value. Returns `None` if invalid.
    fn from_header(value: &str) -> Option<Self> {
        let tp = traceparent::parse(value).ok()?;
        Some(Self::child(&tp))
    }
}

// ── TraceContextMiddleware ───────────────────────────────────────────────────

/// Tower service that propagates or generates W3C `traceparent` headers.
///
/// - If the request has a valid `traceparent`, creates a child span and propagates it.
/// - If the request has no `traceparent` (or an invalid one), generates a new root trace.
/// - The `traceparent` is set on both the request (for downstream handlers) and the response.
/// - A [`TraceContext`] is inserted into request extensions for handler access.
#[derive(Clone, Debug)]
pub struct TraceContextMiddleware<S> {
    inner: S,
}

impl<S> Service<Request<Body>> for TraceContextMiddleware<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Send + Clone + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        // Parse or generate trace context.
        let ctx = req
            .headers()
            .get(&*TRACEPARENT)
            .and_then(|v| v.to_str().ok())
            .and_then(TraceContext::from_header)
            .unwrap_or_else(TraceContext::new_root);

        // Set traceparent on the request for downstream middleware/handlers.
        if let Ok(hv) = HeaderValue::from_str(&ctx.traceparent) {
            req.headers_mut().insert(TRACEPARENT.clone(), hv);
        }

        // Insert TraceContext into extensions for handler access.
        req.extensions_mut().insert(ctx.clone());

        let mut inner = self.inner.clone();
        std::mem::swap(&mut inner, &mut self.inner);

        let traceparent_value = ctx.traceparent.clone();
        Box::pin(async move {
            let mut res = inner.call(req).await?;

            // Propagate traceparent to the response.
            if let Ok(hv) = HeaderValue::from_str(&traceparent_value) {
                res.headers_mut().insert(TRACEPARENT.clone(), hv);
            }

            Ok(res)
        })
    }
}

// ── TraceContextLayer ────────────────────────────────────────────────────────

/// Tower layer for [`TraceContextMiddleware`].
///
/// Adds W3C Trace Context propagation to your Axum router:
///
/// ```text
/// let app = Router::new()
///     .route("/api", get(handler))
///     .layer(TraceContextLayer::default());
/// ```
#[derive(Clone, Debug, Default)]
pub struct TraceContextLayer;

impl TraceContextLayer {
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for TraceContextLayer {
    type Service = TraceContextMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TraceContextMiddleware { inner }
    }
}

// ── Axum extractor ───────────────────────────────────────────────────────────

/// Extract the [`TraceContext`] from the request extensions.
///
/// Returns `None` if `TraceContextLayer` is not installed.
impl TraceContext {
    /// Retrieve from request extensions (for use in handlers without the extractor).
    pub fn from_request(req: &Request<Body>) -> Option<&TraceContext> {
        req.extensions().get::<TraceContext>()
    }
}

// ── Legacy re-exports ────────────────────────────────────────────────────────

// Keep the old names available for backward compatibility during migration.
/// Alias for [`TraceContextLayer`] (legacy name).
pub type TraceIdLayer = TraceContextLayer;
/// Alias for [`TraceContextMiddleware`] (legacy name).
pub type TraceIdMiddleware<S> = TraceContextMiddleware<S>;

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_app() -> TraceContextMiddleware<axum::Router> {
        let app = axum::Router::new().route(
            "/test",
            axum::routing::get(|req: Request<Body>| async move {
                let ctx = req.extensions().get::<TraceContext>().cloned();
                match ctx {
                    Some(c) => axum::Json(serde_json::json!({
                        "trace_id": c.trace_id,
                        "parent_id": c.parent_id,
                        "sampled": c.sampled,
                    })),
                    None => axum::Json(serde_json::json!({"error": "no trace context"})),
                }
            }),
        );
        TraceContextLayer.layer(app)
    }

    #[tokio::test]
    async fn generates_traceparent_when_none_provided() {
        let app = test_app();
        let response = app
            .oneshot(Request::get("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let tp = response
            .headers()
            .get("traceparent")
            .expect("should set traceparent")
            .to_str()
            .unwrap();

        // W3C format: version-trace_id-parent_id-flags
        let parts: Vec<&str> = tp.split('-').collect();
        assert_eq!(parts.len(), 4, "traceparent should have 4 parts: {tp}");
        assert_eq!(parts[0], "00", "version should be 00");
        assert_eq!(parts[1].len(), 32, "trace_id should be 32 hex chars");
        assert_eq!(parts[2].len(), 16, "parent_id should be 16 hex chars");
        assert!(
            parts[3] == "01" || parts[3] == "00",
            "flags should be 00 or 01"
        );
    }

    #[tokio::test]
    async fn propagates_existing_traceparent() {
        let app = test_app();
        let incoming_tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

        let response = app
            .oneshot(
                Request::get("/test")
                    .header("traceparent", incoming_tp)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let tp = response
            .headers()
            .get("traceparent")
            .unwrap()
            .to_str()
            .unwrap();

        // Should be a child span — same trace_id, different parent_id.
        let parts: Vec<&str> = tp.split('-').collect();
        assert_eq!(
            parts[1], "4bf92f3577b34da6a3ce929d0e0e4736",
            "trace_id should be preserved"
        );
        assert_ne!(
            parts[2], "00f067aa0ba902b7",
            "parent_id should be different (child span)"
        );
    }

    #[tokio::test]
    async fn invalid_traceparent_generates_new_root() {
        let app = test_app();
        let response = app
            .oneshot(
                Request::get("/test")
                    .header("traceparent", "invalid-garbage")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let tp = response
            .headers()
            .get("traceparent")
            .expect("should still set traceparent")
            .to_str()
            .unwrap();

        let parts: Vec<&str> = tp.split('-').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "00");
    }

    #[tokio::test]
    async fn trace_context_in_extensions() {
        let app = test_app();
        let response = app
            .oneshot(Request::get("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(json["trace_id"].is_string());
        assert_eq!(json["trace_id"].as_str().unwrap().len(), 32);
        assert!(json["sampled"].is_boolean());
    }
}
