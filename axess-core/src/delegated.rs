//! On-behalf-of (OBO) access: axess acting *as a user* at a downstream
//! service.
//!
//! Distinct from [`crate::workload`], where axess proves *its own*
//! identity to a 3rd party. Here the access token returned carries
//! claims that identify the user, not axess.
//!
//! The OBO pattern shows up in two shapes that share one conceptual
//! abstraction but very different storage + flow mechanics:
//!
//! - `stored`: long-lived user authorization with a refresh token
//!   persisted at rest. User clicks "Connect my Gmail / Outlook / Zoho
//!   mailbox", completes an OAuth `authorization_code` grant
//!   (RFC 6749 §4.1) with PKCE, axess persists the resulting refresh
//!   token, and uses it on demand to mint fresh access tokens for
//!   downstream calls. Kerberos analogue: a forwardable TGT held by a
//!   service.
//! - `exchange`: on-demand token exchange (RFC 8693) with no
//!   persistent storage. axess receives the user's current token
//!   (their axess session JWT, an inbound JWT-SVID, …), POSTs it to a
//!   configured token endpoint as the `subject_token`, and gets back a
//!   downstream-scoped token. Used inside platform code for
//!   service-to-service calls carrying user identity, and against
//!   external IdPs (Azure AD's "on-behalf-of" flow is RFC-8693-adjacent).
//!   Kerberos analogue: S4U2Proxy / constrained delegation.
//!
//! # When to reach for which
//!
//! - **Stored**: when the user explicitly grants axess long-lived
//!   permission to act on their behalf (mail integration, calendar,
//!   CRM). User-visible consent screen, revocable in the user's
//!   account settings at the provider.
//! - **Exchange**: when axess is mid-request and needs to call a
//!   downstream service "as the user" using the user's existing token.
//!   No consent UX, no long-lived secrets at rest, scoped to the user's
//!   current session.
//!
//! Both produce a fresh access token; downstream callers don't care
//! which shape the OBO came from.

/// Error type shared by `stored` + `exchange`.
#[cfg(any(feature = "delegated-stored", feature = "delegated-exchange"))]
pub mod error;

/// Stored delegation: refresh token persisted at rest
/// (`delegated-stored` feature).
#[cfg(feature = "delegated-stored")]
pub mod stored;

/// RFC 8693 Token Exchange (`delegated-exchange` feature).
#[cfg(feature = "delegated-exchange")]
pub mod exchange;
