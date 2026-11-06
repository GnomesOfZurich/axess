//! Errors from [`LocalIdp`](super::LocalIdp) issuance and key-store operations.

use chrono::Duration;

/// Why a lifetime is refused as unusable, as opposed to over the cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LifetimeFault {
    /// `max_ttl` is zero or negative, so no token fits under it.
    #[error("the max-TTL cap is zero or negative")]
    NonPositiveCap,
    /// `exp` is not after the IdP clock's now: the token is born expired.
    #[error("the token expires at or before now")]
    AlreadyExpired,
    /// `nbf` is after `exp`: the token is never valid.
    #[error("not-before is after expiry")]
    NotBeforeAfterExpiry,
}

/// Errors from `LocalIdp` issuance and key-store operations.
///
/// Parameterised over the key store's error type so that backend
/// errors propagate with their original type, mirroring the shape of
/// [`crate::authn::error::AuthnError`].
#[derive(Debug, thiserror::Error)]
pub enum IssuanceError<KE: std::error::Error + Send + Sync + 'static> {
    /// The claim set's lifetime, `exp` less the IdP clock's now, exceeds
    /// the configured `max_ttl` cap. The lifetime is never measured from
    /// the claim set's `iat`, so a backdated `iat` cannot stretch it.
    /// Production refuses the mint rather than producing a token a
    /// downstream verifier would honour despite the policy.
    #[error("token lifetime {observed} exceeds configured max-TTL {max}")]
    LifetimeExceedsCap {
        /// The computed lifetime of the proposed token.
        observed: Duration,
        /// The configured cap.
        max: Duration,
    },
    /// The cap or the claim set cannot produce a usable token: the cap is zero
    /// or negative, `exp` is not after the IdP clock's now, or `nbf` is after
    /// `exp`. The reason says which.
    #[error("invalid token lifetime: {0}")]
    InvalidLifetime(LifetimeFault),
    /// The claim set names no audience and the IdP was not told to allow
    /// that. A token without `aud` is accepted by every verifier that does
    /// not pin an audience, so minting one is an explicit choice
    /// ([`LocalIdp::allow_no_audience`](super::LocalIdp::allow_no_audience)).
    /// An `aud` entry that is the empty string names nobody and is refused on
    /// the same terms, whatever else the list holds.
    #[error("refusing to mint a token with no audience")]
    MissingAudience,
    /// The key asked to be retired is the current signing key. Rotate to a
    /// new key first, then retire the old one.
    #[error("the current signing key cannot be retired")]
    RetireCurrentKey,
    /// The underlying `LocalIdpKeyStore` surfaced an error during
    /// load or rotation. The original backend error is preserved
    /// as `#[source]`.
    #[error("key store error")]
    KeyStore(#[source] KE),
    /// A rotation offered a key whose `kid` is already in the JWKS (the
    /// current key or a historical one). Two keys under one `kid` make
    /// verifiers pick either, so the rotation is refused and nothing
    /// changes.
    #[error("signing key id {kid:?} is already in use")]
    DuplicateKeyId {
        /// The `kid` that collided.
        kid: String,
    },
    /// A key offered for rotation, or loaded from the store, has an empty
    /// `kid`. No token header can name it, so the key set is refused and
    /// nothing changes.
    #[error("signing key id is empty")]
    EmptyKeyId,
    /// JWT encoding failed. In practice this never fires for valid
    /// `LocalIdpSigningKey` material plus a well-formed `MintClaims`,
    /// but the `jsonwebtoken::encode` return type forces the path.
    #[error("JWT encoding error: {0}")]
    Encoding(String),
}
