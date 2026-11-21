//! Optional axum/tower middleware that sits outside the core auth flow:
//! request ID, W3C trace context, rate limiting, CSRF, shared-secret
//! service callers.
//!
//! Each middleware is independently useful; adopters mix and match.

#[cfg(feature = "request-id")]
pub mod request_id;

/// W3C Trace Context (`traceparent`) middleware (`trace-context` feature).
#[cfg(feature = "trace-context")]
pub mod trace_context;

#[cfg(feature = "service-secret")]
pub mod service_secret;

pub mod ratelimit;

pub mod csrf;

#[cfg(feature = "ws")]
pub mod ws;
