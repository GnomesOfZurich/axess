//! Shared error type for the delegated (OBO) module.
//!
//! Both [`super::stored`](crate::delegated::stored) and [`super::exchange`](crate::delegated::exchange) surface failures
//! through the same `DelegatedError` so adopter code consuming both
//! shapes can match on one enum.

/// Errors surfaced by the [`crate::delegated`] module.
#[derive(Debug, thiserror::Error)]
pub enum DelegatedError {
    /// Transport-level failure talking to the IdP / token endpoint:
    /// connection refused, DNS, TLS, timeout.
    #[error("HTTP transport error: {0}")]
    Transport(String),
    /// Token endpoint returned a non-2xx response. Carries status + body.
    #[error("token endpoint returned {status}: {body}")]
    TokenEndpoint {
        /// HTTP status code from the upstream token endpoint.
        status: u16,
        /// Best-effort response body for adopter logging.
        body: String,
    },
    /// 2xx response body failed to deserialise as an RFC 6749 / RFC 8693
    /// token response (missing `access_token`, malformed JSON, …).
    #[error("malformed token response: {0}")]
    MalformedResponse(String),
    /// The OAuth `state` returned by the IdP did not match the value
    /// axess minted at `begin_grant` time. Indicates a CSRF / cross-flow
    /// confusion and rejects the entire callback.
    #[error("OAuth state mismatch; possible CSRF")]
    StateMismatch,
    /// The grant flow's `code_verifier` was missing or malformed when
    /// passed back through the [`GrantContext`](super::stored::GrantContext).
    #[error("PKCE code verifier missing or malformed")]
    PkceVerifier,
    /// Credential store read / write failed. Adopter-defined error
    /// message bubbles up; the trait surface erases the concrete
    /// store error type to keep [`DelegatedError`] adopter-agnostic.
    #[error("credential store error: {0}")]
    Store(String),
    /// Asked for a delegated session for a user / provider combination
    /// that has no credential in the store. Adopters surface this to
    /// users as "you need to (re)connect your `<provider>` account".
    #[error("no delegated credential for this (tenant, user, provider)")]
    NotConnected,
    /// The stored refresh token was rejected by the IdP; typically
    /// because the user revoked the grant in their account settings,
    /// or the provider's refresh-token TTL elapsed. Adopters should
    /// surface this as "your `<provider>` connection expired, please
    /// reconnect".
    #[error("refresh token rejected by IdP; user must re-authorize")]
    RefreshRejected,
}
