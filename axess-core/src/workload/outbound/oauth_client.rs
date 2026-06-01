//! Re-export of the outbound OAuth client (`client_credentials` grant
//! with optional `private_key_jwt` client assertion). The implementation
//! lives in [`axess_factors::outbound_oauth_client`], co-located with
//! the JWT signing primitives and shared secret types it depends on;
//! see that module for the full documentation.

pub use axess_factors::outbound_oauth_client::{
    ClientAuthMethod, OAuthClientError, OutboundOAuthClient,
};
