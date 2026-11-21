//! SPIFFE Workload API client: SVIDs and trust bundles from a local SPIRE
//! agent, kept current.
//!
//! A workload on a node with a SPIRE agent has no credential of its own on
//! disk. It asks the agent, over a local socket, who it is: the agent
//! attests the calling process and answers with the X.509 SVID and the JWT
//! SVIDs it is entitled to, and with the trust bundles it needs to verify
//! its peers. The agent rotates all of them, so a client's work is mostly
//! to keep up. [`SpireClient`] is that client.
//!
//! # What is here
//!
//! - **One call each** for the five methods of the Workload API:
//!   [`SpireClient::fetch_x509_context`] and
//!   [`fetch_x509_svid`](SpireClient::fetch_x509_svid),
//!   [`fetch_x509_bundles`](SpireClient::fetch_x509_bundles),
//!   [`fetch_jwt_svid`](SpireClient::fetch_jwt_svid),
//!   [`fetch_jwt_bundles`](SpireClient::fetch_jwt_bundles) and
//!   [`validate_jwt_svid`](SpireClient::validate_jwt_svid).
//! - **Sources**, each a watcher task and a slot: [`X509Source`],
//!   [`JwtSvidSource`], [`X509BundleSource`] and [`JwtBundleSource`]. A read
//!   never waits for the agent, a failed refresh keeps serving what is
//!   still valid, an expired SVID is never served, a bundle set the agent
//!   has stopped confirming is served only up to a maximum age, and what
//!   the agent withdraws is served no longer.
//! - **The pieces that plug into the rest of the crate.** With
//!   `outbound-mtls`: an [`OutboundMtlsClient`](crate::workload::outbound)
//!   from an SVID, and rustls configurations whose certificate and trust
//!   bundles follow the agent. With `jwt`: key sets for `JwtVerifier` that
//!   follow the agent's JWT bundles. [`AgentJwtSvidResolver`] resolves a
//!   `Principal::Workload` from a token the agent validated.
//!
//! # What decides when
//!
//! Every decision about time (is this SVID due for a refresh, has it
//! expired, is this certificate valid) reads the [`Clock`](axess_clock::Clock)
//! the client was built with, and the back-off's jitter comes from its
//! [`SecureRng`](axess_rng::SecureRng). The waits themselves are
//! `tokio::time` timers. A test builds the client on a `MockClock` with a
//! short check interval: it moves the clock, and the watcher acts at its
//! next check.
//!
//! # The wire
//!
//! The client speaks gRPC over HTTP/2 directly, on `h2`, and reads the
//! Workload API's messages with a small protobuf reader of its own. The
//! messages are five, each a few strings and byte strings; a generated gRPC
//! stack would bring more code into the build than it would replace. The
//! fake agent below writes the field numbers in encoders of its own, so the
//! tests show that the two agree, and tests hold the five method paths and
//! the metadata key to their literal values. No test runs against a
//! SPIRE agent; the book page on the client lists what such a test would
//! confirm.
//!
//! The connection is clear text and the agent is not authenticated: the
//! socket is the boundary. [`Endpoint`] says what that means for a TCP
//! address, and refuses one off the loopback interface unless it is asked
//! for by name.
//!
//! # Testing against it
//!
//! `axess_core::testing::spire_agent::FakeSpireAgent` (features `spire` and
//! `testing`, on Unix) serves the Workload API on a Unix socket or a
//! loopback TCP port in the test process, from answers the test sets, so a
//! test of an application's SPIRE wiring needs no SPIRE.

mod backoff;
mod bundle;
mod client;
mod endpoint;
mod error;
mod feed;
#[cfg(feature = "jwt")]
mod jwks;
mod key;
mod observe;
pub(crate) mod proto;
mod resolver;
mod slot;
mod source;
mod svid;
#[cfg(test)]
mod test_support;
#[cfg(feature = "outbound-mtls")]
mod tls;
pub(crate) mod transport;
mod watcher;
pub(crate) mod wire;

pub use backoff::BackoffPolicy;
pub use bundle::{JwtBundle, JwtBundleSet, SkippedBundle, X509Bundle, X509BundleSet};
pub use client::{DEFAULT_MAX_MESSAGE_BYTES, SpireClient, SpireClientBuilder, ValidatedJwtSvid};
pub use endpoint::{ENDPOINT_SOCKET_ENV, Endpoint};
pub use error::{GrpcCode, SpireError};
pub use observe::{NoopWorkloadApiListener, WorkloadApiEvent, WorkloadApiListener};
pub use resolver::AgentJwtSvidResolver;
pub use source::{
    JwtBundleSource, JwtSvidSource, X509BundleProvider, X509BundleSource, X509Source,
};
pub use svid::{JwtSvid, SvidSelector, X509Context, X509Svid};
#[cfg(feature = "outbound-mtls")]
pub use tls::{
    ClockTimeProvider, SpiffeClientCertVerifier, SpiffeServerCertVerifier, SvidCertResolver,
    installed_provider,
};

pub use crate::metrics::WorkloadCredentialKind;
