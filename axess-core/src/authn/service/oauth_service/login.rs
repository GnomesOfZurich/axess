//! OAuth/OIDC login ceremony, three-step flow:
//!
//! 1. [`AuthnService::begin_oauth_login`]: generate PKCE / state / nonce,
//!    stash in the session, return the IdP authorization URL.
//! 2. [`AuthnService::finish_oauth_login`]: handle the callback, validate
//!    state + PKCE + provider issuer, exchange the code for OIDC claims,
//!    mint the claim-binding lock.
//! 3. [`AuthnService::complete_oauth_login`]: verify the claim lock,
//!    enforce the tenant rail, transition the session to Authenticated,
//!    register in the session registry, install the OIDC `sid` mapping for
//!    back-channel logout.
//!
//! Plus the supporting helpers (`is_oauth_expired`, `record_oauth_failure`,
//! `clear_oauth_state`) and the three free functions used only by this
//! module (`normalize_issuer`, `is_valid_pkce_verifier`, `compute_claim_lock`).
//!
//! [`AuthnService`]: crate::authn::service::AuthnService

mod begin;
mod complete;
mod finish;
mod helpers;
mod state;
