//! Optional axum/tower middleware that sits outside the core auth flow:
//! request ID, W3C trace context, rate limiting, CSRF, shared-secret
//! service callers.
//!
//! Each middleware is independently useful; adopters mix and match.

/// `X-Request-Id` middleware (`request-id` feature).
#[cfg(feature = "request-id")]
pub mod request_id;

/// W3C Trace Context (`traceparent`) middleware (`trace-id` feature).
#[cfg(feature = "trace-id")]
pub mod trace_id;

/// Shared-secret authentication for internal machine callers
/// (`service-secret` feature).
#[cfg(feature = "service-secret")]
pub mod service_secret;

/// Composable sliding-window rate limiting.
pub mod ratelimit;

/// CSRF protection (signed double-submit cookie).
pub mod csrf;

/// WebSocket helpers: revocation-aware connection wrapper (`ws` feature).
#[cfg(feature = "ws")]
pub mod ws;
