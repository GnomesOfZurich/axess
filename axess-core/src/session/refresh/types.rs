//! Refresh token records, configuration and errors.

use crate::authn::ids::{DeviceId, TenantId, UserId};
use axess_identity::define_id;
use chrono::{DateTime, Duration, Utc};
use zeroize::Zeroizing;

define_id! {
    /// Opaque identifier for a single [`RefreshToken`] record. Uuid v4
    /// newtype: 16 bytes, `Copy`, hyphenated string on the wire. Mint
    /// via [`Self::new`]`(&mut rng)`; validate user-supplied strings via
    /// [`Self::try_new`].
    pub RefreshTokenId
}

define_id! {
    /// Opaque identifier for a token rotation family. All tokens in a single
    /// rotation chain share the same family id (the original token's id), so
    /// reuse of any rotated-out member can revoke the entire chain. Same
    /// Uuid-newtype shape as [`RefreshTokenId`].
    pub TokenFamilyId
}

/// A refresh token record. Long-lived, stored server-side, used to
/// obtain new access/session tokens.
#[derive(Debug, Clone)]
pub struct RefreshToken {
    /// Unique token ID.
    pub id: RefreshTokenId,
    /// The user this token belongs to.
    pub user_id: UserId,
    /// The tenant context for the session.
    pub tenant_id: TenantId,
    /// Hash of the actual token (never store plaintext): SHA-256, or
    /// HMAC-SHA256 under `RefreshTokenConfig::hash_pepper` when one is set.
    pub token_hash: String,
    /// When this token was created.
    pub issued_at: DateTime<Utc>,
    /// When this token expires.
    pub expires_at: DateTime<Utc>,
    /// Whether this token has been revoked.
    pub revoked: bool,
    /// Optional device fingerprint (User-Agent or custom identifier).
    pub device_info: Option<String>,
    /// Family ID for token rotation tracking.
    ///
    /// All tokens in a rotation chain share the same family ID (the original
    /// token's ID). If a revoked token is reused, the entire family can be
    /// revoked as a compromise signal.
    pub family_id: Option<TokenFamilyId>,
    /// Opaque [`DeviceId`] this token was issued to.
    ///
    /// Carried through rotation so every member of a rotation family
    /// retains the link back to the originating
    /// [`Device`](crate::device::Device). When family revocation
    /// fires (rotated-out token reused, a compromise signal), the set of
    /// `device_id` values across the family identifies which devices to
    /// transition to [`DeviceTrustLevel::Revoked`] via
    /// [`cascade_revoke_devices`].
    ///
    /// `None` for tokens issued before device support landed or for clients that
    /// chose not to associate the token with a device.
    ///
    /// [`DeviceTrustLevel::Revoked`]: crate::device::DeviceTrustLevel::Revoked
    /// [`cascade_revoke_devices`]: crate::device::cascade_revoke_devices
    pub device_id: Option<DeviceId>,
    /// When the user last proved who they are, as opposed to when this
    /// token was minted.
    ///
    /// Rotation mints a new token every time one is used, so `issued_at`
    /// moves forward with each refresh while the person has not signed in
    /// again. A session built from a refresh carries this instant as its
    /// `authn_time`, which is what "recent login" and step-up freshness
    /// checks read. Rotation copies it from parent to child unchanged.
    ///
    /// `None` for a token issued at login (its `issued_at` is the login) and
    /// for rows written before this field existed; both read as `issued_at`.
    /// A store that does not persist the field therefore degrades towards a
    /// later `authn_time`, never an earlier one than the last rotation, so
    /// persist it.
    pub authn_time: Option<DateTime<Utc>>,
}

impl RefreshToken {
    /// The time of the authentication this token descends from: the carried
    /// [`authn_time`](Self::authn_time), else when the token was issued.
    pub fn authenticated_at(&self) -> DateTime<Utc> {
        self.authn_time.unwrap_or(self.issued_at)
    }
}

/// Configuration for refresh token behavior.
///
/// [`Debug`] is implemented manually so `hash_pepper` prints as
/// `Some(<redacted N bytes>)` rather than leaking the pepper via
/// `tracing::debug!(?config)` / `dbg!`.
#[derive(Clone)]
pub struct RefreshTokenConfig {
    /// Token time-to-live. Default: 30 days.
    pub ttl: Duration,
    /// Maximum active tokens per user. Default: 10. The minimum is 1: a
    /// cap of 0 is refused with [`RefreshError::InvalidConfig`] by every
    /// issuing and refreshing function (a token cannot be both issued and
    /// kept under a cap of zero). When the cap is reached, the oldest token
    /// is auto-revoked.
    pub max_per_user: usize,
    /// Whether to rotate tokens on each use. Default: true.
    /// When enabled, each refresh invalidates the old token and issues a new one.
    pub rotation: bool,
    /// HMAC pepper used to derive the stored token hash. When
    /// set, the on-disk hash is `HMAC-SHA256(pepper, plaintext)` rather
    /// than the unsalted `SHA-256(plaintext)` fallback. The pepper is a
    /// per-deployment secret stored in application config (NOT in the
    /// database); a leaked refresh-token-hash table cannot be pre-image
    /// scanned without it.
    ///
    /// An empty pepper is a configuration error
    /// ([`RefreshError::InvalidConfig`]): `Some` always means keyed hashing,
    /// never a silent fall back to the unkeyed hash.
    ///
    /// **Migration:** changing the pepper (including switching from
    /// `None` to `Some`) invalidates every existing refresh token. Plan
    /// the rollout accordingly. Default `None` for backward compat.
    ///
    /// Held in [`Zeroizing`] so every copy of the config wipes its pepper
    /// when it drops.
    pub hash_pepper: Option<Zeroizing<Vec<u8>>>,
}

impl RefreshTokenConfig {
    /// Check the invariants every issuing and refreshing function relies on:
    /// `max_per_user` is at least 1 and a configured `hash_pepper` is not
    /// empty. Those functions call this first and return
    /// [`RefreshError::InvalidConfig`] with the same message; call it at
    /// start-up to fail early.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_per_user == 0 {
            return Err("max_per_user must be at least 1");
        }
        if self.hash_pepper.as_ref().is_some_and(|p| p.is_empty()) {
            return Err("hash_pepper must not be empty; use None for the unkeyed hash");
        }
        Ok(())
    }

    /// [`validate`](Self::validate) as the error the refresh functions return.
    pub(super) fn check<E: std::error::Error + Send + Sync + 'static>(
        &self,
    ) -> Result<(), RefreshError<E>> {
        self.validate().map_err(RefreshError::InvalidConfig)
    }

    /// The pepper bytes, when one is configured.
    pub fn pepper(&self) -> Option<&[u8]> {
        self.hash_pepper.as_deref().map(Vec::as_slice)
    }
}

impl std::fmt::Debug for RefreshTokenConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `hash_pepper` is a deployment secret whose leak enables
        // offline pre-image scans of the token-hash table; the manual
        // Debug redacts it while preserving structural context.
        struct RedactedPepper<'a>(&'a Option<Zeroizing<Vec<u8>>>);
        impl<'a> std::fmt::Debug for RedactedPepper<'a> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self.0 {
                    Some(p) => write!(f, "Some(<redacted {} bytes>)", p.len()),
                    None => f.write_str("None"),
                }
            }
        }
        f.debug_struct("RefreshTokenConfig")
            .field("ttl", &self.ttl)
            .field("max_per_user", &self.max_per_user)
            .field("rotation", &self.rotation)
            .field("hash_pepper", &RedactedPepper(&self.hash_pepper))
            .finish()
    }
}

impl Default for RefreshTokenConfig {
    fn default() -> Self {
        Self {
            ttl: Duration::days(30),
            max_per_user: 10,
            rotation: true,
            hash_pepper: None,
        }
    }
}

/// Errors from refresh token operations.
#[derive(Debug, thiserror::Error)]
pub enum RefreshError<E: std::error::Error + Send + Sync + 'static> {
    /// The token was not found in the store.
    #[error("refresh token not found")]
    NotFound,

    /// The token has expired.
    #[error("refresh token expired")]
    Expired,

    /// The token has been revoked.
    #[error("refresh token revoked")]
    Revoked,

    /// The device fingerprint does not match.
    #[error("device mismatch")]
    DeviceMismatch,

    /// The caller-supplied account-status check returned `false`
    /// for the user the token belongs to (suspended, terminated, etc.).
    /// Returned only by [`refresh_session_with_status_check`](super::refresh_session_with_status_check);
    /// the bare [`refresh_session`](super::refresh_session) never produces it because it has no
    /// [`IdentityStore`](crate::authn::store::IdentityStore) reference.
    #[error("account is not active")]
    AccountInactive,

    /// The [`RefreshTokenConfig`] is unusable (see
    /// [`RefreshTokenConfig::validate`]); nothing was read or written.
    #[error("invalid refresh token configuration: {0}")]
    InvalidConfig(&'static str),

    /// An error from the underlying store.
    #[error("store error: {0}")]
    Store(#[source] E),
}
