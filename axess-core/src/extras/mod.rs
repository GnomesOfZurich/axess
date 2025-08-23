/// The Extras module contains a collection of middlewares that can be used for
/// adding potentially useful features to your project that isn't necessarily
/// tightly linked to authentication and authorization.
///

/// Module for adding request ID to all requests
#[cfg(feature = "request_id")]
pub mod request_id;

/// Module for adding trace ID to all requests
#[cfg(feature = "trace_id")]
pub mod trace_id;
