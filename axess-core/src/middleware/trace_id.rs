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

use axess_rng::SecureRng;
use axum::{
    body::Body,
    extract::Request,
    http::{HeaderValue, header::HeaderName},
    response::Response,
};
use std::{
    fmt::Write as _,
    future::Future,
    pin::Pin,
    sync::LazyLock,
    task::{Context, Poll},
};
use tower::{Layer, Service};

static TRACEPARENT: LazyLock<HeaderName> = LazyLock::new(|| HeaderName::from_static("traceparent"));

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{:02x}", b).expect("writing into a String never fails");
    }
    s
}

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
        let mut trace_bytes = [0u8; 16];
        let mut span_bytes = [0u8; 8];
        axess_rng::SystemRng.fill_bytes(&mut trace_bytes);
        axess_rng::SystemRng.fill_bytes(&mut span_bytes);
        let trace_id = to_hex(&trace_bytes);
        let parent_id = to_hex(&span_bytes);
        let traceparent = format!("00-{trace_id}-{parent_id}-01");
        Self {
            traceparent,
            trace_id,
            parent_id,
            sampled: true,
        }
    }

    /// Parse from a traceparent header value and create a child span.
    /// Returns `None` if the header is invalid.
    ///
    /// W3C format: `{version:2}-{trace-id:32}-{parent-id:16}-{flags:2}`
    fn from_header(value: &str) -> Option<Self> {
        let parts: Vec<&str> = value.trim().split('-').collect();
        if parts.len() != 4 {
            return None;
        }
        let version = parts[0];
        let trace_id = parts[1];
        let flags = parts[3];

        // Validate field lengths and hex content.
        if version.len() != 2 || trace_id.len() != 32 || parts[2].len() != 16 || flags.len() != 2 {
            return None;
        }
        if !trace_id.chars().all(|c| c.is_ascii_hexdigit())
            || !flags.chars().all(|c| c.is_ascii_hexdigit())
        {
            return None;
        }

        let sampled = u8::from_str_radix(flags, 16).ok()? & 0x01 == 0x01;

        // Generate a new parent-id for the child span.
        let mut span_bytes = [0u8; 8];
        axess_rng::SystemRng.fill_bytes(&mut span_bytes);
        let parent_id = to_hex(&span_bytes);

        let traceparent = format!("00-{trace_id}-{parent_id}-{flags}");
        Some(Self {
            traceparent,
            trace_id: trace_id.to_string(),
            parent_id,
            sampled,
        })
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
    /// Construct a default `TraceContextLayer` (zero-sized, no configuration).
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
mod tests;
