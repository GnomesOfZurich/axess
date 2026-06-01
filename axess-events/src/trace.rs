//! [`TraceContext`]: W3C Trace Context for cross-service span
//! correlation.
//!
//! The axess `trace-id` middleware populates this from the inbound
//! `traceparent` header; subscribers can join an event back onto its
//! originating request span.

/// W3C Trace Context fields. Self-contained so the envelope crate
/// doesn't pull in `opentelemetry` as a dependency; adopters wiring
/// OTEL translate the fields at their edge via
/// [`opentelemetry-http`](https://docs.rs/opentelemetry-http) +
/// [`tracing-opentelemetry`](https://docs.rs/tracing-opentelemetry).
///
/// Field shapes match the W3C `traceparent` header:
///   `00-<trace_id 32 hex>-<span_id 16 hex>-<flags 2 hex>`.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TraceContext {
    /// 128-bit trace identifier (W3C trace-id).
    pub trace_id: [u8; 16],
    /// 64-bit span identifier (W3C parent-id).
    pub span_id: [u8; 8],
    /// W3C trace-flags byte (sampled bit, etc.).
    pub flags: u8,
}

impl TraceContext {
    /// All-zero trace context, represents "no upstream context".
    pub const NIL: Self = Self {
        trace_id: [0; 16],
        span_id: [0; 8],
        flags: 0,
    };
}

impl Default for TraceContext {
    fn default() -> Self {
        Self::NIL
    }
}
