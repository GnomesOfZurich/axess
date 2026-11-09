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
//! - [`durations`]: durations at the edges of `chrono`'s range, for
//!   table-driven tests of every TTL and interval.
//! - [`ipv6_forms`]: the IPv6 address forms that carry an IPv4 address or
//!   share a `/64`, for address screens and throttles.
//! - [`mock_tracing`]: capture `tracing` events and assert on them.
//! - [`oauth_wiremock`]: an OIDC discovery document, a JWKS endpoint and an
//!   RSA key pair for a `wiremock` identity provider.
//! - [`stall`]: a gate and a never-completing future, for tests that cancel
//!   a request at a chosen await point.

pub mod durations;
pub mod ipv6_forms;
pub mod mock_tracing;
pub mod oauth_wiremock;
pub mod stall;
