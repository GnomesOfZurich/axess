//! Refresh token records, configuration and errors.

use crate::authn::ids::{DeviceId, TenantId, UserId};
use axess_clock::{SignedDuration, Timestamp, Until};
use axess_identity::define_id;
use std::time::Duration;
use zeroize::Zeroizing;

define_id! {
    /// Opaque identifier for a single [`RefreshToken`] record. Uuid v4
    /// newtype: 16 bytes, `Copy`, hyphenated string on the wire. Mint
    /// via [`Self::new`]`(&rng)`; validate user-supplied strings via
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

/// Why a refresh token was revoked.
///
/// Only a token that was rotated out ([`Rotated`](Self::Rotated)) and then
/// presented again is evidence of theft. A token a user logged out, one the
/// per-user cap evicted, one revoked with its device, and one a family
/// revocation already killed are all revoked on purpose, and presenting them
/// again is a stale client rather than an attacker. Every revoking method of
/// a [`RefreshTokenStore`](super::RefreshTokenStore) persists the reason and
/// the time next to `revoked`.
///
/// A row whose reason reads as `None` (revoked by a release that recorded
/// none, or by a store that does not persist the column) is handled as
/// [`Rotated`](Self::Rotated), the strictest reading: its reuse revokes the
/// family. That is deliberate. Such a row may be a rotated-out token, and
/// reading it as benign would blind the reuse detection for every token
/// revoked before the upgrade; the cost is that a stale client presenting a
/// pre-upgrade logout token once more is answered as a compromise, which
/// only ends a family that was already revoked or about to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationReason {
    /// Replaced by its child in a rotation. Reuse is a compromise signal.
    Rotated,
    /// Revoked by an explicit call: a logout, or a user-wide revocation.
    Explicit,
    /// Revoked to make room under `RefreshTokenConfig::max_per_user`.
    Evicted,
    /// Revoked as part of a family revocation after a reuse was detected.
    Compromise,
    /// Revoked together with the device it was issued to
    /// ([`RefreshTokenStore::revoke_device_tokens`](super::RefreshTokenStore::revoke_device_tokens)).
    Device,
}

impl RevocationReason {
    /// The stable lower-case spelling stores persist.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rotated => "rotated",
            Self::Explicit => "explicit",
            Self::Evicted => "evicted",
            Self::Compromise => "compromise",
            Self::Device => "device",
        }
    }

    /// Parse the spelling [`as_str`](Self::as_str) produced. An unknown
    /// spelling reads as `None`, which the refresh path treats as a
    /// rotation (the strictest reading).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "rotated" => Some(Self::Rotated),
            "explicit" => Some(Self::Explicit),
            "evicted" => Some(Self::Evicted),
            "compromise" => Some(Self::Compromise),
            "device" => Some(Self::Device),
            _ => None,
        }
    }
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
    pub issued_at: Timestamp,
    /// When this token expires: never, for a configured lifetime that runs
    /// past the range of a reading.
    pub expires_at: Until,
    /// Whether this token has been revoked.
    pub revoked: bool,
    /// The token's device binding: a digest of the device string the
    /// caller gave when the token was issued (keyed with the refresh
    /// pepper when one is set), never the string itself. A token issued by
    /// an earlier release holds the raw string until it is next rotated.
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
    /// [`cascade_revoke_devices_and_tokens`].
    ///
    /// `None` for tokens issued before device support landed or for clients that
    /// chose not to associate the token with a device.
    ///
    /// [`DeviceTrustLevel::Revoked`]: crate::device::DeviceTrustLevel::Revoked
    /// [`cascade_revoke_devices_and_tokens`]: crate::device::cascade_revoke_devices_and_tokens
    pub device_id: Option<DeviceId>,
    /// When the login the token descends from completed, as opposed to when
    /// this token was minted. A token issued from a session carries the
    /// session's `signed_in_at`, so a step-up before the issue does not move
    /// it.
    ///
    /// Rotation mints a new token every time one is used, so `issued_at`
    /// moves forward with each refresh while the person has not signed in
    /// again. A session built from a refresh carries this instant as its
    /// `authn_time` and its `signed_in_at`: what "recent login" and step-up
    /// freshness checks read, and what its absolute age cap counts from.
    /// Rotation copies it from parent to child unchanged.
    ///
    /// `None` for a token issued at login (its `issued_at` is the login) and
    /// for rows written before this field existed; both read as `issued_at`.
    /// A store that does not persist the field therefore degrades towards a
    /// later `authn_time`, never an earlier one than the last rotation, so
    /// persist it.
    pub authn_time: Option<Timestamp>,
    /// Why the token was revoked, when it was. `None` while live, and for
    /// rows revoked before the reason was recorded (read as a rotation).
    pub revoked_reason: Option<RevocationReason>,
    /// When the token was revoked. For a rotation this is the instant the
    /// child was issued, which the reuse grace window is measured from.
    pub revoked_at: Option<Timestamp>,
}

impl RefreshToken {
    /// The time of the authentication this token descends from: the carried
    /// [`authn_time`](Self::authn_time), else when the token was issued.
    pub fn authenticated_at(&self) -> Timestamp {
        self.authn_time.unwrap_or(self.issued_at)
    }
}

/// The pepper a [`RefreshTokenConfig`] replaced, kept for the rotation window.
#[derive(Clone)]
pub enum PreviousPepper {
    /// A keyed pepper, held in [`Zeroizing`] so every copy wipes it on drop.
    Keyed(Zeroizing<Vec<u8>>),
    /// The unkeyed hash: the deployment ran without a pepper and now sets one.
    Unkeyed,
}

impl PreviousPepper {
    /// A keyed previous pepper.
    pub fn keyed(pepper: impl Into<Vec<u8>>) -> Self {
        Self::Keyed(Zeroizing::new(pepper.into()))
    }

    /// The pepper bytes, or `None` for the unkeyed state.
    pub fn keyed_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Keyed(pepper) => Some(pepper.as_slice()),
            Self::Unkeyed => None,
        }
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
    /// The pepper also keys the digest a token stores of its `device_info`.
    /// Without one that digest is unkeyed, so a reader of the store can
    /// confirm a guessed device string against a row (a `User-Agent` has
    /// little entropy); it still never lets a caller pass with the wrong
    /// string. Set a pepper wherever device binding is used.
    ///
    /// An empty pepper is a configuration error
    /// ([`RefreshError::InvalidConfig`]): `Some` always means keyed hashing,
    /// never a silent fall back to the unkeyed hash.
    ///
    /// **Migration:** changing the pepper invalidates every existing refresh
    /// token unless the old pepper is moved to
    /// [`previous_hash_pepper`](Self::previous_hash_pepper) for the rotation
    /// window. A deployment that has no pepper yet moves to one by naming the
    /// unkeyed state as the previous pepper, [`PreviousPepper::Unkeyed`].
    /// Default `None`: unkeyed hashes. Supplying a `device_info` with no pepper
    /// is refused as [`RefreshError::InvalidConfig`] unless
    /// [`allow_unkeyed_hashes`](Self::allow_unkeyed_hashes) says the unkeyed
    /// digest is meant.
    ///
    /// Held in [`Zeroizing`] so every copy of the config wipes its pepper
    /// when it drops.
    pub hash_pepper: Option<Zeroizing<Vec<u8>>>,
    /// The pepper `hash_pepper` replaced, kept for the rotation window.
    ///
    /// When a presented token is not found under the current hash, the
    /// lookup retries under `HMAC-SHA256(previous_hash_pepper, plaintext)`.
    /// A token found that way is moved to the current pepper on that
    /// refresh: with `rotation` on, the replacement token is stored under
    /// `hash_pepper` as any replacement is; with `rotation` off, the same
    /// token is re-stored under `hash_pepper` (and its device binding keyed
    /// by it), the client is handed nothing and keeps presenting the token
    /// it has. Reuse detection is unchanged: the record under the old hash
    /// is revoked as rotated and is reached only when the current-pepper
    /// lookup misses, which for a re-stored token it does not. Once every
    /// live token has been refreshed (one `ttl`, at most `max_lifetime` for
    /// tokens that are never used), set this back to `None`.
    ///
    /// [`PreviousPepper::Unkeyed`] names the unkeyed hash as the one being
    /// replaced, so a deployment that ran without a pepper moves to
    /// `hash_pepper: Some(..)` without invalidating a token; it needs a
    /// `hash_pepper`, since a current pepper of `None` is the same state. An
    /// empty keyed value is a configuration error, like an empty
    /// `hash_pepper`. The keyed value is held in [`Zeroizing`] for the same
    /// reason.
    pub previous_hash_pepper: Option<PreviousPepper>,
    /// Absolute lifetime of a token family, counted from the authentication
    /// the family descends from. Default 90 days. A refresh at or after
    /// `authenticated_at + max_lifetime` returns [`RefreshError::Expired`]
    /// and every token's `expires_at` is clamped to that instant, so a stolen
    /// family cannot be rotated for ever. Must be at least `ttl`. `None`
    /// (see [`with_max_lifetime`](Self::with_max_lifetime)) leaves expiry
    /// sliding only: a token refreshed at least once per `ttl` never expires.
    pub max_lifetime: Option<Duration>,
    /// Whether a token may store the unkeyed digest of its `device_info`
    /// (no `hash_pepper`). Default `false`: a `device_info` with no pepper is
    /// refused as [`RefreshError::InvalidConfig`], because the unkeyed digest
    /// lets a reader of the store confirm a guessed device string. Set with
    /// [`allow_unkeyed_hashes`](Self::allow_unkeyed_hashes).
    pub allow_unkeyed_hashes: bool,
    /// How long after a rotation a second presentation of the rotated-out
    /// token is read as two parallel refreshes by one client rather than as
    /// theft. Default zero: any reuse of a rotated-out token revokes the
    /// family. Within the window the second caller gets
    /// [`RefreshError::ConcurrentRefresh`] and nothing is revoked, so the
    /// client can retry with the token the first refresh returned. The
    /// window is measured as the distance between the rotation's
    /// `revoked_at` and this node's clock, in either direction, so a
    /// rotation stamped by a node whose clock runs ahead is not read as
    /// theft. Keep it to a few seconds: the window is also open to a thief
    /// who replays the token just after the victim used it.
    pub reuse_grace: Duration,
}

impl RefreshTokenConfig {
    /// The shortest `hash_pepper` accepted: 32 bytes, the HMAC-SHA256 output
    /// size, as the recovery-code pepper requires. A `previous_hash_pepper`
    /// has no minimum beyond non-empty, so a deployment rotates away from a
    /// shorter pepper rather than being locked out of its tokens.
    pub const MIN_PEPPER_LEN: usize = 32;

    /// Check the invariants every issuing and refreshing function relies on:
    /// `ttl` is positive, `max_per_user` is at least 1 and a configured
    /// `hash_pepper` is at least [`MIN_PEPPER_LEN`](Self::MIN_PEPPER_LEN)
    /// bytes. Those functions call this first and return
    /// [`RefreshError::InvalidConfig`] with the same message; call it at
    /// start-up to fail early.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.ttl.is_zero() {
            return Err("ttl must be positive");
        }
        if self.max_per_user == 0 {
            return Err("max_per_user must be at least 1");
        }
        if self.hash_pepper.as_ref().is_some_and(|p| p.is_empty()) {
            return Err("hash_pepper must not be empty; use None for the unkeyed hash");
        }
        if self
            .hash_pepper
            .as_ref()
            .is_some_and(|p| p.len() < Self::MIN_PEPPER_LEN)
        {
            return Err(
                "hash_pepper must be at least 32 bytes (the HMAC-SHA256 output size); a shorter \
                 key confirms guessable device-binding inputs once a dump is in hand",
            );
        }
        if self
            .previous_hash_pepper
            .as_ref()
            .and_then(PreviousPepper::keyed_bytes)
            .is_some_and(<[u8]>::is_empty)
        {
            return Err("previous_hash_pepper must not be empty; use None to stop accepting it");
        }
        if matches!(self.previous_hash_pepper, Some(PreviousPepper::Unkeyed))
            && self.hash_pepper.is_none()
        {
            return Err(
                "previous_hash_pepper Unkeyed needs a hash_pepper: without one the current hash is unkeyed too",
            );
        }
        if let Some(max) = self.max_lifetime {
            if max.is_zero() {
                return Err("max_lifetime must be positive");
            }
            if max < self.ttl {
                return Err("max_lifetime must be at least ttl");
            }
        }
        Ok(())
    }

    /// The instant a token descending from `authenticated_at` can no longer
    /// be refreshed: `authenticated_at + max_lifetime`, or `None` without a
    /// cap (or when the sum is out of range, which reads as no cap).
    pub fn lifetime_end(&self, authenticated_at: Timestamp) -> Option<Timestamp> {
        self.max_lifetime
            .and_then(|max| SignedDuration::try_from(max).ok())
            .and_then(|max| authenticated_at.checked_add(max))
    }

    /// Refuse a `device_info` that would be stored (or compared) as an
    /// unkeyed digest: the config has no `hash_pepper` and has not allowed
    /// unkeyed hashes.
    ///
    /// # Errors
    ///
    /// The reason, when `has_device_info` and the hash is unkeyed without
    /// [`allow_unkeyed_hashes`](Self::allow_unkeyed_hashes).
    pub fn validate_device_info(&self, has_device_info: bool) -> Result<(), &'static str> {
        if has_device_info && self.hash_pepper.is_none() && !self.allow_unkeyed_hashes {
            return Err(
                "device_info needs a hash_pepper: without one its digest is unkeyed (set hash_pepper, or allow_unkeyed_hashes)",
            );
        }
        Ok(())
    }

    /// Set the absolute lifetime of a token family; `None` lifts the cap
    /// (see [`max_lifetime`](Self::max_lifetime)).
    #[must_use]
    pub fn with_max_lifetime(mut self, max_lifetime: Option<Duration>) -> Self {
        self.max_lifetime = max_lifetime;
        self
    }

    /// Allow tokens to store an unkeyed digest of `device_info` when no
    /// `hash_pepper` is set (see
    /// [`allow_unkeyed_hashes`](Self::allow_unkeyed_hashes), the field).
    #[must_use]
    pub fn allow_unkeyed_hashes(mut self) -> Self {
        self.allow_unkeyed_hashes = true;
        self
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

    /// The pepper `hash_pepper` replaced, when the rotation window is open:
    /// `None` outside it, `Some(None)` when the replaced hash was unkeyed,
    /// `Some(Some(bytes))` when it was keyed.
    pub fn previous_pepper(&self) -> Option<Option<&[u8]>> {
        self.previous_hash_pepper
            .as_ref()
            .map(PreviousPepper::keyed_bytes)
    }
}

impl std::fmt::Debug for RefreshTokenConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `hash_pepper` is a deployment secret whose leak enables
        // offline pre-image scans of the token-hash table; the manual
        // Debug redacts it while preserving structural context.
        struct RedactedPepper<'a>(Option<Option<&'a [u8]>>);
        impl<'a> std::fmt::Debug for RedactedPepper<'a> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self.0 {
                    Some(Some(p)) => write!(f, "Some(<redacted {} bytes>)", p.len()),
                    Some(None) => f.write_str("Some(Unkeyed)"),
                    None => f.write_str("None"),
                }
            }
        }
        f.debug_struct("RefreshTokenConfig")
            .field("ttl", &self.ttl)
            .field("max_per_user", &self.max_per_user)
            .field("rotation", &self.rotation)
            .field(
                "hash_pepper",
                &RedactedPepper(self.hash_pepper.as_deref().map(|p| Some(p.as_slice()))),
            )
            .field(
                "previous_hash_pepper",
                &RedactedPepper(self.previous_pepper()),
            )
            .field("max_lifetime", &self.max_lifetime)
            .field("allow_unkeyed_hashes", &self.allow_unkeyed_hashes)
            .field("reuse_grace", &self.reuse_grace)
            .finish()
    }
}

impl Default for RefreshTokenConfig {
    /// 30-day sliding `ttl`, rotation on, ten tokens per user and a
    /// [`max_lifetime`](RefreshTokenConfig::max_lifetime) of 90 days: a family
    /// ends that long after the authentication it descends from, however
    /// often it is refreshed. `.with_max_lifetime(None)` lifts the cap, for
    /// users meant to stay signed in indefinitely. There is no pepper: set
    /// `hash_pepper`, or the config refuses a `device_info` (see
    /// [`allow_unkeyed_hashes`](RefreshTokenConfig::allow_unkeyed_hashes)).
    fn default() -> Self {
        Self {
            ttl: Duration::from_hours(30 * 24),
            max_per_user: 10,
            rotation: true,
            hash_pepper: None,
            previous_hash_pepper: None,
            max_lifetime: Some(Duration::from_hours(90 * 24)),
            allow_unkeyed_hashes: false,
            reuse_grace: Duration::ZERO,
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

    /// The token was rotated a moment ago and presented again inside
    /// [`RefreshTokenConfig::reuse_grace`]: two parallel refreshes by one
    /// client. Also answered when the store refused the rotation because the
    /// parent was no longer live, yet still reads it as live: a parallel
    /// refresh this node cannot see yet. Nothing was revoked; retry with the
    /// token the first refresh returned.
    #[error("refresh token was just rotated by a concurrent refresh")]
    ConcurrentRefresh,

    /// The device fingerprint presented does not match the token's binding,
    /// or, on the device-checked refreshes, the token's device now belongs
    /// to another user. Nothing was rotated.
    #[error("device mismatch")]
    DeviceMismatch,

    /// The caller-supplied account-status check returned `false`
    /// for the user the token belongs to (suspended, terminated, etc.).
    /// Returned by [`Refresh::run`](super::Refresh::run) when the status
    /// predicate given to [`Refresh::new`](super::Refresh::new) refuses;
    /// nothing was rotated.
    #[error("account is not active")]
    AccountInactive,

    /// The [`RefreshTokenConfig`] is unusable (see
    /// [`RefreshTokenConfig::validate`]); nothing was read or written.
    #[error("invalid refresh token configuration: {0}")]
    InvalidConfig(&'static str),

    /// The device the token was issued to is revoked or no longer exists.
    /// Returned only by a refresh with a device check
    /// ([`Refresh::device_store`](super::Refresh::device_store)), before
    /// anything is rotated; the token is left as it is.
    #[error("device revoked")]
    DeviceRevoked,

    /// The device store could not answer the device check, so the refresh
    /// was refused rather than allowed unchecked. Carries the store's
    /// message. Returned only by a refresh with a device check
    /// ([`Refresh::device_store`](super::Refresh::device_store)).
    #[error("device store error: {0}")]
    DeviceStore(String),

    /// The token's device has a key, and the proof presented with the token
    /// is the key's but answers a challenge that is not the current one (or
    /// one that has expired). Nothing was rotated or revoked; sign
    /// `challenge` and refresh again. Returned only by a refresh given the
    /// device-key service (`Refresh::device_key`, with the `device-keys`
    /// feature).
    #[error("the device key must sign the current challenge")]
    KeyProofRequired {
        /// The challenge to sign, as the text a client signs.
        challenge: String,
    },

    /// The token's device has a key and the token was presented without a
    /// proof by it: the token is held by someone who does not hold the key.
    /// The token's family was revoked and the compromise hook ran, as for a
    /// rotated-out token that comes back. Returned only by a refresh given
    /// the device-key service.
    #[error("the refresh token was presented without its device key")]
    KeyProofInvalid,

    /// The token's device has a key and this refresh cannot check it: it was
    /// given the device store ([`Refresh::device_store`](super::Refresh::device_store))
    /// and not the device-key service (`Refresh::device_key`), or the build
    /// has no `device-keys` feature. Nothing was rotated or revoked. A keyed
    /// device's token is never refreshed into a session that is not bound
    /// to the key, so give the refresh the key service.
    #[error(
        "the token's device has a key and this refresh was not given the device-key service \
         (Refresh::device_key)"
    )]
    KeyCheckMissing,

    /// An error from the underlying store.
    #[error("store error: {0}")]
    Store(#[source] E),
}
