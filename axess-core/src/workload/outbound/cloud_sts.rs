//! Cloud STS adapters: exchange a federated workload-identity token
//! (K8s SA, GitHub Actions OIDC, axess `LocalIdP`, any other JWT-shaped
//! workload credential) for cloud-provider temporary credentials.
//!
//! Where [`super::oauth_client`] handles axess as an OAuth client
//! against a generic 3rd-party AS, and [`super::mtls_client`] handles
//! axess presenting an X509 client cert, these adapters specifically
//! target the **cloud STS** flows that turn a federated OIDC token
//! into provider-native credentials usable by the cloud's SDKs / IAM
//! enforcement:
//!
//! - [`aws`] (feature `aws-sts`): AWS STS `AssumeRoleWithWebIdentity`.
//!   Returns short-lived `(AccessKeyId, SecretAccessKey, SessionToken,
//!   Expiration)` per IAM role. The federated token is the credential
//!   with no transport-layer auth.
//! - [`gcp`] (feature `gcp-wif`, planned): GCP Workload Identity
//!   Federation. RFC 8693 token exchange (reuses
//!   [`crate::delegated::exchange`]) plus optional service-account
//!   impersonation.
//! - [`azure`] (feature `azure-fic`, planned): Azure AD Federated
//!   Identity Credentials. OAuth `client_credentials` grant with
//!   `client_assertion_type=jwt-bearer` and the federated token as
//!   `client_assertion`.
//!
//! # Why these aren't just "OAuth clients"
//!
//! Each cloud invented a different shape before the industry settled
//! on RFC 8693:
//! - AWS uses **XML over query-string POST**, no client auth (token
//!   is the credential).
//! - GCP uses **RFC 8693 token exchange** (modern), then a separate
//!   service-account impersonation hop.
//! - Azure uses **OAuth 2.0 `client_credentials`** with the federated
//!   token in `client_assertion`.
//!
//! Hand-rolled per-adapter is correct: trying to force them through a
//! single trait surface would hide the protocol differences that
//! matter when adopters need to debug "why does my AssumeRole fail
//! but my Azure FIC succeed."

#[cfg(feature = "aws-sts")]
pub mod aws;
#[cfg(feature = "azure-fic")]
pub mod azure;
#[cfg(feature = "gcp-wif")]
pub mod gcp;
