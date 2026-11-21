#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Test fixtures for applications built on axess, kept out of every
//! production dependency graph.
//!
//! Take this crate as a **dev-dependency** only. It carries a mock HTTP server
//! (`wiremock`) and an RSA implementation with a published timing advisory
//! (`rsa`), neither of which belongs in a release build; the workspace's
//! dependency policy admits `wiremock` only through dev-dependency edges.
//!
//! - [`durations`]: durations at the edges of a signed span's range, the
//!   time types' and the one earlier releases held, for table-driven tests
//!   of every TTL and interval.
//! - [`ipv6_forms`]: the IPv6 address forms that carry an IPv4 address or
//!   share a `/64`, for address screens and throttles.
//! - [`mock_tracing`]: capture `tracing` events, or the lines a formatter
//!   prints, and assert on them.
//! - [`oauth_wiremock`]: an OIDC discovery document, a JWKS endpoint and an
//!   RSA key pair for a `wiremock` identity provider.
//! - [`readiness`]: an inner `tower` service that is pending or fails when
//!   asked whether it is ready, for a test that a middleware passes that on.
//! - [`stall`]: a gate and a never-completing future, for tests that cancel
//!   a request at a chosen await point.
//! - [`stopwatch`]: the real duration of real work, the one reading of the
//!   machine's clock a test makes.

pub mod durations;
pub mod ipv6_forms;
pub mod mock_tracing;
pub mod oauth_wiremock;
pub mod readiness;
pub mod stall;
pub mod stopwatch;
