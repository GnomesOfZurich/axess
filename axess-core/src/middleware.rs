//! Optional axum/tower middleware that sits outside the core auth flow:
//! request ID, W3C trace context, rate limiting, CSRF.
//!
//! Each middleware is independently useful; adopters mix and match.

/// `X-Request-Id` middleware (`request-id` feature).
#[cfg(feature = "request-id")]
pub mod request_id;

/// W3C Trace Context (`traceparent`) middleware (`trace-id` feature).
#[cfg(feature = "trace-id")]
pub mod trace_id;

/// Composable token-bucket rate limiting.
pub mod ratelimit;

/// CSRF protection (signed double-submit cookie).
pub mod csrf;

/// WebSocket helpers: revocation-aware connection wrapper (`ws` feature).
#[cfg(feature = "ws")]
pub mod ws;
