//! Shared error type for the delegated (OBO) module.
//!
//! Both [the stored module](crate::delegated::stored) and [the exchange module](crate::delegated::exchange) surface failures
//! through the same `DelegatedError` so adopter code consuming both
//! shapes can match on one enum.

/// Errors surfaced by the [`crate::delegated`] module.
#[derive(Debug, thiserror::Error)]
pub enum DelegatedError {
    /// Transport-level failure talking to the IdP / token endpoint:
    /// connection refused, DNS, TLS, timeout. The endpoint URL is not
    /// echoed: a configured endpoint can carry a tenant path or a key in
    /// its query.
    #[error("HTTP transport error: {0}")]
    Transport(String),
    /// Token endpoint returned a non-2xx response. Carries status + body.
    #[error("token endpoint returned {status}: {body}")]
    TokenEndpoint {
        /// HTTP status code from the upstream token endpoint.
        status: u16,
        /// Best-effort response body for adopter logging: the first 1 KiB,
        /// with `…[truncated]` appended when the body was longer, and every
        /// character [`escapes`](axess_identity::log_text::escapes) names
        /// (control characters, the line and paragraph separators,
        /// bidirectional controls, zero-width characters, the byte order mark,
        /// the Hangul fillers) escaped, so the endpoint cannot forge a log
        /// line through it.
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

    /// A registration other than the one a grant or a credential belongs
    /// to: `complete_grant` was handed another provider than the grant began
    /// with, or a `StoredDelegationSession` was built with another provider
    /// than the stored credential was granted through, or the credential was
    /// stored with no registration (by a release before 0.20.0). "Another"
    /// includes one of the same name with another client id or endpoint
    /// (see [`GrantRegistration`](super::stored::GrantRegistration)).
    /// Nothing is sent; for a stored credential the user grants again.
    /// `provider` is the name of the provider the call was given, the
    /// application's own configuration.
    #[error(
        "this registration of provider `{provider}` is not the one the grant or credential belongs to"
    )]
    RegistrationMismatch {
        /// The `name` of the provider the call was given.
        provider: String,
    },
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
    /// The credential's `token_type` is not `Bearer`. A bearer string cannot
    /// carry a sender-constrained token (DPoP, MAC): sent as a plain bearer it
    /// would be rejected downstream or, worse, used without its binding.
    /// Read the credential from the store to handle such a token.
    #[error("delegated credential has token_type `{0}`, not Bearer")]
    UnsupportedTokenType(String),
    /// The stored refresh token was rejected by the IdP; typically
    /// because the user revoked the grant in their account settings,
    /// or the provider's refresh-token TTL elapsed. Adopters should
    /// surface this as "your `<provider>` connection expired, please
    /// reconnect".
    #[error("refresh token rejected by IdP; user must re-authorize")]
    RefreshRejected,
    /// The default HTTP client could not be built; nothing is sent. See
    /// [`ClientBuildError`](crate::ClientBuildError).
    #[error(transparent)]
    ClientBuild(#[from] crate::ClientBuildError),
    /// The client id and secret did not make an `Authorization` header
    /// value: a configuration fault, not a transport one. Their base64
    /// encoding is always a valid header value, so this is not expected; it
    /// is kept so building the header has no panic path.
    #[error("client credentials do not make an Authorization header: {0}")]
    ClientCredentials(#[source] reqwest::header::InvalidHeaderValue),
}
