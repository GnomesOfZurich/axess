//! The storage trait refresh tokens are persisted through.

use super::types::{RefreshToken, RefreshTokenId, TokenFamilyId};
use crate::authn::ids::{DeviceId, TenantId, UserId};

/// What [`RefreshTokenStore::rotate_token`] found when it revoked the parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationOutcome {
    /// The parent was live, is now revoked, and the child is stored.
    Rotated,
    /// The parent was already revoked when the rotation ran: a parallel
    /// refresh won, nothing was stored, and the caller treats this
    /// presentation as a reuse.
    ParentAlreadyRevoked,
}

/// What [`RefreshTokenStore::revoke_device_tokens`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "an unsupported revocation left every token of the device usable"]
pub enum DeviceTokenRevocation {
    /// The store has no revoke-by-device operation: nothing was revoked.
    Unsupported,
    /// Every live token issued to the device is now revoked; `tokens` is
    /// how many this call revoked (tokens already revoked are not counted).
    Revoked {
        /// Number of tokens this call revoked.
        tokens: u64,
    },
}

/// Async storage backend for refresh tokens.
///
/// All methods accept `&self`; implementations use interior mutability.
///
/// # Revocation reasons
///
/// Every revocation records why, in [`RefreshToken::revoked_reason`] and
/// [`RefreshToken::revoked_at`], because only the reuse of a rotated-out
/// token is a theft signal:
///
/// | Method | Reason | `revoked_at` |
/// |---|---|---|
/// | [`rotate_token`](Self::rotate_token) (the parent) | `Rotated` | the new token's `issued_at` |
/// | [`revoke_token`](Self::revoke_token), [`revoke_user_tokens`](Self::revoke_user_tokens) | `Explicit` | the store's now |
/// | [`issue_capped`](Self::issue_capped) (the evicted) | `Evicted` | the store's now |
/// | [`revoke_family`](Self::revoke_family) | `Compromise` | the store's now |
///
/// A revocation never overwrites the reason of a token that is already
/// revoked (a rotated token later swept by a family revocation stays
/// `Rotated`). A store that cannot persist the fields reads every revoked
/// token as rotated, which is the strictest behaviour (any reuse revokes the
/// family).
///
/// [`RefreshToken::revoked_reason`]: super::RefreshToken::revoked_reason
/// [`RefreshToken::revoked_at`]: super::RefreshToken::revoked_at
pub trait RefreshTokenStore: Send + Sync {
    /// The error type returned by storage operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Persist a new refresh token record.
    fn store_token(
        &self,
        token: &RefreshToken,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Look up a token by its hash. Returns `None` if not found.
    fn find_token(
        &self,
        token_hash: &str,
    ) -> impl std::future::Future<Output = Result<Option<RefreshToken>, Self::Error>> + Send;

    /// Mark a token as revoked by its ID.
    fn revoke_token(
        &self,
        token_id: &RefreshTokenId,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Revoke all tokens for a user (e.g. global logout, credential rotation).
    fn revoke_user_tokens(
        &self,
        user_id: &UserId,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Revoke every token issued to `device_id` in `tenant_id`, whatever
    /// user or family it belongs to. The revoke-by-device counterpart of
    /// [`revoke_user_tokens`](Self::revoke_user_tokens): what "this device was
    /// lost" needs, and what
    /// [`revoke_device`](crate::device::revoke_device) calls after it marks
    /// the device revoked.
    ///
    /// Implementations MUST scope by tenant and perform it as one statement
    /// (or script), like [`revoke_family`](Self::revoke_family), so a
    /// rotation racing with it cannot escape: `UPDATE ... SET revoked = 1
    /// WHERE tenant_id = ? AND device_id = ? AND revoked = 0`.
    ///
    /// The provided body returns [`DeviceTokenRevocation::Unsupported`] and
    /// revokes nothing, so a store written before this method existed
    /// compiles and says plainly that it cannot do it; the caller must not
    /// treat that as a revocation.
    fn revoke_device_tokens(
        &self,
        tenant_id: &TenantId,
        device_id: &DeviceId,
    ) -> impl std::future::Future<Output = Result<DeviceTokenRevocation, Self::Error>> + Send {
        let _ = (tenant_id, device_id);
        async { Ok(DeviceTokenRevocation::Unsupported) }
    }

    /// Return all non-revoked tokens for a user, ordered by `issued_at` ascending.
    fn active_tokens(
        &self,
        user_id: &UserId,
    ) -> impl std::future::Future<Output = Result<Vec<RefreshToken>, Self::Error>> + Send;

    /// Revoke all tokens in a family (same `family_id`).
    ///
    /// Called when a rotated-out (already revoked) token is reused. This is
    /// a compromise signal indicating the original token was stolen. All
    /// tokens descending from the original issuance must be revoked
    /// immediately so that neither the attacker nor the legitimate user can
    /// continue refreshing.
    ///
    /// # Contract
    ///
    /// Implementations MUST perform the revocation as a **single atomic
    /// statement** scoped to `family_id`, e.g.:
    ///
    /// ```sql
    /// UPDATE refresh_tokens
    ///    SET revoked_at = NOW()
    ///  WHERE user_id = $1
    ///    AND family_id = $2
    ///    AND revoked_at IS NULL
    /// ```
    ///
    /// Two failure modes the contract is meant to prevent:
    ///
    /// 1. **Non-atomic load+update**: a backend that lists active tokens
    ///    and then revokes them one-by-one races with a parallel
    ///    `refresh_session` call from the attacker; the attacker may
    ///    succeed in rotating an unrevoked sibling between the list and
    ///    the per-row revoke, escaping the family invalidation.
    /// 2. **Family scope ignored**: delegating to `revoke_user_tokens`
    ///    would over-revoke (safe, but boots the legitimate user out of
    ///    every other concurrent device). With per-family scoping, only
    ///    the compromised device chain is killed.
    fn revoke_family(
        &self,
        user_id: &UserId,
        family_id: &TokenFamilyId,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Atomically issue a new refresh token under the per-user cap: store
    /// `new_token` and revoke the user's oldest active tokens (by
    /// `issued_at`) until at most `max_per_user` remain, **counted inside the
    /// same transaction as the insert**.
    ///
    /// # Why the cap is a parameter
    ///
    /// A caller that read [`active_tokens`](Self::active_tokens), chose the
    /// surplus and then wrote would race with a concurrent issue for the same
    /// user: both see the same count, each evicts for itself, and the user
    /// ends above the cap. Counting and evicting must therefore happen in the
    /// store's own atomic step, which needs the cap.
    ///
    /// # Requirement
    ///
    /// This method is **required**. Implementations MUST serialise
    /// concurrent issues for one user (a transaction whose first statement
    /// is the eviction `UPDATE`, a row lock on the user, a per-user lock, or
    /// a server-side script) and MUST make the evictions and the insert land
    /// together or not at all, so a failed insert never costs the user
    /// tokens. `max_per_user` is at least 1: the caller validates the
    /// configuration before it gets here.
    fn issue_capped(
        &self,
        new_token: &RefreshToken,
        max_per_user: usize,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Atomically rotate a refresh token: revoke `parent_id` and insert
    /// `new_token` in a **single transaction**.
    ///
    /// # Why this exists
    ///
    /// The naive sequence (`revoke_token(parent)` followed by
    /// `store_token(new)`) is not atomic. If the second call fails (network
    /// blip, DB write error, process crash between the two), the parent is
    /// already revoked and no replacement was issued. The user is silently
    /// logged out across every device using that token family, with no
    /// recovery path short of re-authentication.
    ///
    /// # Contract
    ///
    /// Implementations MUST wrap the parent-revoke and the new-token
    /// insert in a single transaction (or equivalent atomic primitive),
    /// e.g.:
    ///
    /// 1. A single SQL transaction wrapping `UPDATE … SET revoked_at` +
    ///    `INSERT INTO refresh_tokens`.
    /// 2. A Lua/Redis MULTI/EXEC block on Valkey-class stores.
    /// 3. Any equivalent atomic primitive provided by the backend.
    ///
    /// A naive serial revoke + store can leave a user silently logged out
    /// across every device in the family if the second call fails
    /// mid-flight.
    ///
    /// # The revoke is conditional
    ///
    /// The parent is revoked only if it is NOT yet revoked (`UPDATE … SET
    /// revoked = 1 WHERE id = ? AND revoked = 0`, or the backend's
    /// compare-and-set). When that changes no row, another refresh of the
    /// same token won the race: the implementation stores nothing and answers
    /// [`RotationOutcome::ParentAlreadyRevoked`], which the caller treats as
    /// a reuse of a rotated-out token. Without this, two parallel refreshes
    /// with one token both succeeded and left two live children, and the
    /// reuse detection never fired.
    fn rotate_token(
        &self,
        parent_id: &RefreshTokenId,
        new_token: &RefreshToken,
    ) -> impl std::future::Future<Output = Result<RotationOutcome, Self::Error>> + Send;

    /// Called when a rotated-out token is reused (a token compromise signal).
    ///
    /// Override this to alert operators (e.g. send to a SIEM, page on-call,
    /// or log at a higher severity). The default implementation logs a warning.
    ///
    /// This is called after `revoke_family` ran. If that call failed, the
    /// failure is logged and the hook runs anyway, so a store fault cannot
    /// skip the device cascade; the family may then still be live, and the
    /// hook is the place to react to that.
    ///
    /// # Device cascade
    ///
    /// `compromised_devices` carries every `(TenantId, DeviceId)` pair
    /// linked to refresh tokens in the compromised family: the
    /// already-revoked token under reuse plus any sibling members that
    /// were still active when reuse was detected. Production overrides
    /// SHOULD pass these to
    /// [`cascade_revoke_devices`](crate::device::cascade_revoke_devices)
    /// so every device that participated in the family transitions to
    /// [`DeviceTrustLevel::Revoked`](crate::device::DeviceTrustLevel::Revoked).
    /// The default implementation logs the device list alongside the
    /// family id; it does NOT perform the cascade itself because the
    /// trait has no access to a [`DeviceStore`](crate::device::DeviceStore).
    /// The cascade primitive lives outside the refresh path so a single
    /// application can wire its own DeviceStore once and reuse it from
    /// any number of compromise hooks.
    fn on_token_compromise(
        &self,
        user_id: &UserId,
        family_id: &TokenFamilyId,
        compromised_devices: &[(TenantId, DeviceId)],
    ) -> impl std::future::Future<Output = ()> + Send {
        tracing::warn!(
            %user_id,
            %family_id,
            device_count = compromised_devices.len(),
            "refresh token compromise detected (rotated-out token was reused); \
             override on_token_compromise + call cascade_revoke_devices to revoke linked devices"
        );
        async {}
    }
}
