//! Outbound workload identity. axess as the *initiator* of an
//! authentication interaction, presenting its own credentials to a 3rd
//! party. Where the inbound resolvers under
//! [`axess_factors::jwt::svid`], [`axess_factors::mtls`], and
//! [`axess_factors::federation`] verify incoming workload
//! credentials, this module mints and presents axess's own.
//!
//! - `oauth_client::OutboundOAuthClient`: OAuth `client_credentials`
//!   with optional `private_key_jwt` (RFC 7523) client assertion. Gated
//!   on `outbound-oauth`.
//! - `mtls_client::OutboundMtlsClient`: present axess's own X509
//!   client cert on outbound TLS handshakes. Constructs a
//!   `rustls::ClientConfig` ready for reqwest / hyper / tokio-rustls.
//!   Gated on `outbound-mtls`.
//! - `cloud_sts`: exchange a federated workload-identity token for
//!   cloud-provider temporary credentials (AWS STS, GCP WIF, Azure
//!   FIC). Per-cloud flags `aws-sts`, `gcp-wif`, `azure-fic`; umbrella
//!   `cloud-sts` enables all three.
//!
//! Adopters with market-data vendors, broker REST APIs (PSD2 / FAPI
//! 2.0), webhook receivers, or any 3rd-party API that wants axess to
//! authenticate as itself reach for these primitives. For "act on a
//! user's behalf at a 3rd party" (mailbox / calendar / CRM delegation),
//! see [`crate::delegated`].

#[cfg(any(feature = "aws-sts", feature = "gcp-wif", feature = "azure-fic"))]
pub mod cloud_sts;
#[cfg(feature = "outbound-mtls")]
pub mod mtls_client;
#[cfg(feature = "outbound-oauth")]
pub mod oauth_client;
