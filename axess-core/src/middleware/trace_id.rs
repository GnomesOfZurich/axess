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

        // Should be a child span; same trace_id, different parent_id.
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

    // ── Mutation-coverage tests ────────────────────────────────────────

    /// `from_header` rejects each individual length mismatch
    /// (version, trace_id, parts[2], flags); pins all four `||` →
    /// `&&` mutations on line 96. Under a `&&` mutant, only headers
    /// where ALL fields are wrong are rejected; a single bad field
    /// would slip through. Each subtest constructs a header where
    /// exactly one field has the wrong length.
    #[test]
    fn from_header_rejects_each_individual_length_mismatch() {
        // Reference good fields: 2 / 32 / 16 / 2 chars.
        let good_version = "00";
        let good_trace = "4bf92f3577b34da6a3ce929d0e0e4736";
        let good_parent = "00f067aa0ba902b7";
        let good_flags = "01";

        // Bad version: 3 chars instead of 2.
        let bad = format!("000-{good_trace}-{good_parent}-{good_flags}");
        assert!(
            TraceContext::from_header(&bad).is_none(),
            "3-char version must reject (kills `||` -> `&&` at line 96:31)"
        );

        // Bad trace_id: 31 chars instead of 32.
        let short_trace = "4bf92f3577b34da6a3ce929d0e0e473"; // 31 chars
        let bad = format!("{good_version}-{short_trace}-{good_parent}-{good_flags}");
        assert!(
            TraceContext::from_header(&bad).is_none(),
            "31-char trace_id must reject (kills `||` -> `&&` at line 96:55)"
        );

        // Bad parent_id: 15 chars instead of 16.
        let short_parent = "00f067aa0ba902b"; // 15 chars
        let bad = format!("{good_version}-{good_trace}-{short_parent}-{good_flags}");
        assert!(
            TraceContext::from_header(&bad).is_none(),
            "15-char parent_id must reject (kills `||` -> `&&` at line 96:73)"
        );

        // Bad flags: 1 char instead of 2.
        let bad = format!("{good_version}-{good_trace}-{good_parent}-1");
        assert!(
            TraceContext::from_header(&bad).is_none(),
            "1-char flags must reject (kills `||` -> `&&` at line 96:79)"
        );

        // Sanity: all-good still accepts.
        let good = format!("{good_version}-{good_trace}-{good_parent}-{good_flags}");
        assert!(
            TraceContext::from_header(&good).is_some(),
            "well-formed traceparent must parse"
        );
    }

    /// `from_header` rejects non-hex characters in either
    /// `trace_id` or `flags` independently; pins the `||` → `&&`
    /// mutation on line 100. Under a `&&` mutant, BOTH would have to
    /// be non-hex to reject; a header with non-hex trace_id but hex
    /// flags would slip through.
    #[test]
    fn from_header_rejects_non_hex_independently() {
        // Non-hex trace_id (contains 'g'), valid flags.
        let bad = "00-gbf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        assert!(
            TraceContext::from_header(bad).is_none(),
            "non-hex trace_id must reject even when flags are hex \
             (kills `||` -> `&&` at line 100:13)"
        );

        // Valid trace_id, non-hex flags. Flags has 2 chars but 'g' is non-hex.
        let bad = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0g";
        assert!(
            TraceContext::from_header(bad).is_none(),
            "non-hex flags must reject"
        );
    }

    /// The `sampled` flag is decoded from the lowest bit of
    /// the parsed flags byte: `flags_byte & 0x01 == 0x01`. Pins three
    /// mutations on line 105:
    /// - `==` → `!=`: would invert sampled across all flag values.
    /// - `&` → `|`: would treat any flags value with bit-0 set or
    ///   bit-1 set as "sampled"; discriminates on `flags="00"`
    ///   (original false, mutant `|` true) and `flags="03"` (mutant
    ///   `|` 3==1 false vs original 1==1 true; but easier to use
    ///   `flags="00"`).
    /// - `&` → `^`: at `flags="01"` mutant computes 1^1=0 ≠ 1 →
    ///   false; original 1&1=1 == 1 → true. Discriminates.
    #[test]
    fn from_header_decodes_sampled_bit_correctly() {
        let trace = "4bf92f3577b34da6a3ce929d0e0e4736";
        let parent = "00f067aa0ba902b7";

        // flags=01 → sampled=true. Kills `& → ^` (1^1=0 ≠ 1) and
        // `== → !=` (false instead of true).
        let header = format!("00-{trace}-{parent}-01");
        let ctx = TraceContext::from_header(&header).expect("01 must parse");
        assert!(
            ctx.sampled,
            "flags=01 must yield sampled=true (kills `& -> ^` and `== -> !=`)"
        );

        // flags=00 → sampled=false. Kills `& → |` (0|1=1 == 1 → true,
        // mutant says sampled when original says not-sampled) and
        // `== → !=` symmetrically.
        let header = format!("00-{trace}-{parent}-00");
        let ctx = TraceContext::from_header(&header).expect("00 must parse");
        assert!(
            !ctx.sampled,
            "flags=00 must yield sampled=false (kills `& -> |`)"
        );
    }

    /// `TraceContext::from_request` returns the `TraceContext`
    /// inserted into request extensions. Pins `from_request -> None`
    /// (would hide a properly-installed context from handlers, making
    /// the layer effectively a no-op for any code using this accessor).
    #[test]
    fn from_request_returns_extension_value() {
        let mut req = Request::new(Body::empty());
        let ctx = TraceContext::new_root();
        let trace_id = ctx.trace_id.clone();
        req.extensions_mut().insert(ctx);

        let got = TraceContext::from_request(&req)
            .expect("from_request must surface the inserted TraceContext, not None");
        assert_eq!(
            got.trace_id, trace_id,
            "from_request must return the actual inserted context"
        );

        // No extension → None.
        let req = Request::new(Body::empty());
        assert!(
            TraceContext::from_request(&req).is_none(),
            "missing extension must yield None"
        );
    }
}
