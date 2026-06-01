//! Refresh token support for mobile/SPA clients.
//!
//! Provides long-lived refresh tokens that can be exchanged for new sessions.
//! Designed for clients that cannot use HTTP-only cookies (mobile apps, SPAs).
//!
//! # Security model
//!
//! - **Hash-only storage:** Only the SHA-256 hash of the token is persisted;
//!   the plaintext is returned exactly once at issuance.
//! - **Token rotation:** Each use of a refresh token invalidates the old one
//!   and issues a new one, making stolen tokens single-use.
//! - **Device binding:** Optional device fingerprint is stored with the token
//!   and checked on refresh to detect cross-device replay.
//! - **Per-user cap:** A configurable maximum number of active tokens per user
//!   prevents unbounded accumulation; the oldest tokens are auto-revoked.

use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::session::data::{AuthState, SessionData};
use axess_identity::define_id;
use axess_rng::SecureRng;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

// ── Types ────────────────────────────────────────────────────────────────────

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
    /// SHA-256 hash of the actual token (never store plaintext).
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
}

/// Configuration for refresh token behavior.
#[derive(Debug, Clone)]
pub struct RefreshTokenConfig {
    /// Token time-to-live. Default: 30 days.
    pub ttl: Duration,
    /// Maximum active tokens per user. Default: 10.
    /// When exceeded, the oldest token is auto-revoked.
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
    /// **Migration:** changing the pepper (including switching from
    /// `None` to `Some`) invalidates every existing refresh token. Plan
    /// the rollout accordingly. Default `None` for backward compat.
    pub hash_pepper: Option<Vec<u8>>,
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

// ── Errors ───────────────────────────────────────────────────────────────────

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
    /// Returned only by [`refresh_session_with_status_check`]; the bare
    /// [`refresh_session`] never produces it because it has no
    /// [`IdentityStore`](crate::authn::store::IdentityStore) reference.
    #[error("account is not active")]
    AccountInactive,

    /// An error from the underlying store.
    #[error("store error: {0}")]
    Store(#[source] E),
}

// ── Store trait ──────────────────────────────────────────────────────────────

/// Async storage backend for refresh tokens.
///
/// All methods accept `&self`; implementations use interior mutability.
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

    /// Atomically issue a new refresh token while evicting the
    /// per-user cap-overflow set in a **single transaction**.
    ///
    /// The naive sequence (`revoke_token(evict[i])` ... then
    /// `store_token(new)`) is not atomic. If a `store_token` failure
    /// arrives after the evictions, the user has just lost N legitimate
    /// active tokens for nothing; if it arrives before, an in-flight
    /// concurrent issue could push the active set above the cap.
    ///
    /// # Requirement
    ///
    /// This method is **required**: implementations MUST wrap the
    /// per-id revocations and the new-token insert in a single transaction
    /// (or equivalent atomic primitive) so partial-failure semantics
    /// match; either all evictions land and the new token is stored, or
    /// nothing changes.
    fn issue_with_eviction(
        &self,
        evict_ids: &[RefreshTokenId],
        new_token: &RefreshToken,
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
    fn rotate_token(
        &self,
        parent_id: &RefreshTokenId,
        new_token: &RefreshToken,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Called when a rotated-out token is reused (a token compromise signal).
    ///
    /// Override this to alert operators (e.g. send to a SIEM, page on-call,
    /// or log at a higher severity). The default implementation logs a warning.
    ///
    /// This is called *after* `revoke_family` has already revoked the
    /// compromised token family.
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

// ── Core functions ───────────────────────────────────────────────────────────

/// Compute the storage-side hash of a plaintext refresh token, returned
/// as URL-safe base64.
///
/// When `pepper` is `Some`, computes `HMAC-SHA256(pepper, plaintext)`,
/// so a pre-image scan of the resulting hash table cannot be carried
/// out without knowing the pepper (which lives in application config
/// rather than the DB). When `None`, falls back to the previous
/// unsalted `SHA-256(plaintext)` for backward compat.
fn hash_token(plaintext: &str, pepper: Option<&[u8]>) -> String {
    match pepper {
        Some(pep) if !pep.is_empty() => {
            use hmac::Mac;
            let mut mac = crate::hmac::new_signer(pep);
            mac.update(plaintext.as_bytes());
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        }
        _ => {
            let digest = Sha256::digest(plaintext.as_bytes());
            URL_SAFE_NO_PAD.encode(digest)
        }
    }
}

/// Generate a cryptographically random plaintext token (32 bytes, URL-safe base64).
fn generate_token_value(rng: &impl SecureRng) -> String {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Per-issuance parameters for [`issue_refresh_token`].
pub struct IssueRequest<'a> {
    /// The user receiving the token.
    pub user_id: &'a UserId,
    /// The tenant context.
    pub tenant_id: &'a TenantId,
    /// Optional device/client identifier for token binding.
    pub device_info: Option<String>,
    /// Token family for rotation tracking. `None` starts a new family;
    /// `Some(parent_family_id)` inherits from the rotated-out token.
    pub family_id: Option<TokenFamilyId>,
    /// Opaque [`DeviceId`] to associate with this token.
    ///
    /// Threaded into the persisted record so that family revocation can
    /// drive a cascade revoke of the linked devices via
    /// [`cascade_revoke_devices`](crate::device::cascade_revoke_devices).
    /// Inherited unchanged across rotation.
    pub device_id: Option<DeviceId>,
}

/// Issue a new refresh token for the given user/tenant.
///
/// Returns `(plaintext_token, stored_record)`. The plaintext is
/// returned exactly once; only the hash is persisted. Callers must
/// transmit the plaintext to the client over a secure channel.
///
/// If the user already has `config.max_per_user` active tokens, the oldest ones
/// are revoked to make room.
pub async fn issue_refresh_token<S: RefreshTokenStore>(
    req: IssueRequest<'_>,
    config: &RefreshTokenConfig,
    store: &S,
    rng: &impl SecureRng,
    now: DateTime<Utc>,
) -> Result<(String, RefreshToken), RefreshError<S::Error>> {
    // Enforce per-user cap by revoking oldest tokens.
    let active = store
        .active_tokens(req.user_id)
        .await
        .map_err(RefreshError::Store)?;

    let evict_ids: Vec<RefreshTokenId> = if active.len() >= config.max_per_user {
        let to_revoke = active.len() - config.max_per_user + 1;
        active.iter().take(to_revoke).map(|t| t.id).collect()
    } else {
        Vec::new()
    };

    let (plaintext, record) = build_refresh_token(req, config, rng, now);

    // Cap-eviction + insert in one trait call so production
    // backends can wrap them in a single transaction. The naive
    // `for revoke; … store` had a window where a mid-sequence failure
    // could leave the user under-revoked or with no replacement token.
    store
        .issue_with_eviction(&evict_ids, &record)
        .await
        .map_err(RefreshError::Store)?;

    Ok((plaintext, record))
}

/// Validate a refresh token and produce a new session.
///
/// On success returns `(SessionData, Option<(new_plaintext, new_record)>)`.
/// The optional second element is present when token rotation is
/// enabled: the old token is revoked and a fresh one issued.
///
/// # Security: account status and registry registration
///
/// This function performs **token CRUD only**. It does NOT consult any
/// [`IdentityStore`](crate::authn::store::IdentityStore) or
/// [`SessionRegistry`](crate::session::store::SessionRegistry). Two
/// caller responsibilities the library cannot enforce here:
///
/// 1. **Account status**: a refresh token from a user who has been
///    suspended/terminated since issuance is still valid for rotation.
///    Use [`refresh_session_with_status_check`] to thread an
///    `account_status` predicate through the validation; on `false`
///    the helper returns [`RefreshError::AccountInactive`] WITHOUT
///    rotating, so the legitimate user's family stays intact for
///    later un-suspension.
///
/// 2. **Registry registration**: the returned `SessionData` is
///    `Authenticated` but is NOT registered with any
///    [`crate::session::SessionRegistry`]. A refresh-rotated session that the
///    application doesn't `register` is the same anti-pattern in
///    miniature: `invalidate_user` cannot reach it. Callers who use
///    a `SessionRegistry` MUST register the new session id before
///    returning the response.
pub async fn refresh_session<S: RefreshTokenStore>(
    plaintext: &str,
    store: &S,
    config: &RefreshTokenConfig,
    rng: &impl SecureRng,
    now: DateTime<Utc>,
    device_info: Option<&str>,
) -> Result<(SessionData, Option<(String, RefreshToken)>), RefreshError<S::Error>> {
    let token_hash = hash_token(plaintext, config.hash_pepper.as_deref());

    let record = store
        .find_token(&token_hash)
        .await
        .map_err(RefreshError::Store)?
        .ok_or(RefreshError::NotFound)?;

    if record.revoked {
        // Reuse of a revoked token is a compromise signal; revoke the
        // entire token family so the attacker's stolen token (and any
        // rotated descendant) becomes useless.
        if let Some(ref fid) = record.family_id {
            tracing::warn!(
                family_id = %fid,
                user_id = %record.user_id,
                "revoked refresh token reused; revoking entire family (compromise signal)"
            );

            // Collect the (tenant, device) pairs linked to every
            // member of the family BEFORE revoke_family runs. Backends
            // that implement the contract atomically (single SQL UPDATE)
            // would otherwise leave the device set inferable only from
            // their own audit trail; gathering here keeps the cascade
            // primitive backend-agnostic.
            let compromised_devices = collect_family_device_targets(store, fid, &record).await;

            store
                .revoke_family(&record.user_id, fid)
                .await
                .map_err(RefreshError::Store)?;

            store
                .on_token_compromise(&record.user_id, fid, &compromised_devices)
                .await;
        }
        return Err(RefreshError::Revoked);
    }

    if now >= record.expires_at {
        return Err(RefreshError::Expired);
    }

    // Device binding check: if the stored record has device info, the caller
    // must present a matching fingerprint.
    //
    // Both sides are first hashed with SHA-256 before comparison. Plain
    // `ct_eq(a.as_bytes(), b.as_bytes())` returns `Choice(0)` immediately
    // when the byte lengths differ; that early return is itself a timing
    // signal that leaks the stored fingerprint's length, and (over many
    // requests) lets an attacker brute-force a plausible User-Agent prefix.
    // Hashing first puts both inputs at a fixed 32 bytes so the comparison
    // is uniformly constant-time regardless of the original input lengths.
    if let Some(ref stored_device) = record.device_info {
        let Some(current) = device_info else {
            return Err(RefreshError::DeviceMismatch);
        };
        let stored_hash = Sha256::digest(stored_device.as_bytes());
        let current_hash = Sha256::digest(current.as_bytes());
        if !bool::from(stored_hash.ct_eq(&current_hash)) {
            return Err(RefreshError::DeviceMismatch);
        }
    }

    // Build session data from the token's user/tenant. user_id/tenant_id
    // are now typed at the trait surface, so the previous `try_new` parsing
    // (and `RefreshError::InvalidToken`) are no longer needed; the
    // RefreshTokenStore trait promises validated values come back.
    let session = SessionData {
        version: crate::session::data::SESSION_DATA_VERSION,
        auth_state: AuthState::Authenticated {
            user_id: record.user_id,
            tenant_id: record.tenant_id,
            authn_time: now,
            // Refresh-token rotation re-establishes the same authn level
            // implicitly; no per-factor record carried across rotation.
            factors_completed: Vec::new(),
        },
        fingerprint: None,
        // Rotated session inherits the device link from the token
        // record. Without this, refresh-driven session resumption would
        // appear as a "device-less" session and the layer would re-resolve
        // it from request headers; typically yielding the same id, but
        // an unnecessary round-trip and a lost association on the gap.
        device_id: record.device_id,
        custom: serde_json::Value::default(),
    };

    // Token rotation: atomically revoke old + insert new in a single
    // backend transaction so a mid-rotation crash never leaves the user
    // both un-rotated and un-authenticated.
    let new_token = if config.rotation {
        let (new_plaintext, new_record) = build_refresh_token(
            IssueRequest {
                user_id: &record.user_id,
                tenant_id: &record.tenant_id,
                device_info: record.device_info.clone(),
                family_id: record.family_id, // Inherit family from parent.
                device_id: record.device_id, // Inherit device link.
            },
            config,
            rng,
            now,
        );

        store
            .rotate_token(&record.id, &new_record)
            .await
            .map_err(RefreshError::Store)?;

        Some((new_plaintext, new_record))
    } else {
        None
    };

    Ok((session, new_token))
}

/// Refresh a session, threading a caller-supplied
/// `account_status` predicate through the validation.
///
/// Same contract as [`refresh_session`] except the refresh is gated by
/// `status_check(&user_id)`: if the predicate returns `false`, the
/// helper returns [`RefreshError::AccountInactive`] WITHOUT calling
/// [`RefreshTokenStore::rotate_token`]; the legitimate user's token
/// family is preserved unchanged so a later un-suspension restores
/// access without forcing a full re-login.
///
/// The status check runs AFTER the token is found-and-not-expired-not-
/// revoked-not-device-mismatched but BEFORE the rotation: same
/// ordering rationale as the cascade in
/// `complete_factor_step`: a mid-flight suspension lands its
/// `invalidate_user` against an empty registry slot (the new session
/// id has not been registered yet) and the post-check refusal closes
/// the race that would otherwise produce an authenticated-but-
/// unregistered session.
///
/// # When to use this vs [`refresh_session`]
///
/// Pick this whenever the application carries an
/// [`IdentityStore`](crate::authn::store::IdentityStore) (or any
/// equivalent source of truth for "is this account allowed to
/// authenticate right now"). The bare [`refresh_session`] is for
/// applications that have already gated the refresh route by their
/// own status check upstream.
///
/// # TOCTOU window
///
/// Between `status_check` and `rotate_token` a concurrent suspend
/// could land. The window is closed by the
/// [`SessionRegistry`](crate::session::store::SessionRegistry)
/// invalidation cascade: the suspend's `invalidate_user` evicts
/// every registered session, and the next request through
/// [`AuthnService::check_session`](crate::authn::service::AuthnService::check_session)
/// observes the rotated session as invalid. Same trade-off as
/// `complete_factor_step`'s post-register re-check covers for
/// the factor flow.
///
/// # Example
///
/// ```ignore
/// use axess_core::session::refresh::{refresh_session_with_status_check, RefreshError};
/// use axess_core::authn::store::IdentityStore;
///
/// let result = refresh_session_with_status_check(
///     &plaintext, &refresh_store, &config, &mut rng, now, device_info,
///     |user_id| async move {
///         // `identity` here is the application's IdentityStore.
///         identity
///             .account_status(user_id)
///             .await
///             .map(|status| status.allows_login())
///             .unwrap_or(false) // fail closed on store errors
///     },
/// ).await;
/// ```
pub async fn refresh_session_with_status_check<S, FStat, Fut>(
    plaintext: &str,
    store: &S,
    config: &RefreshTokenConfig,
    rng: &impl SecureRng,
    now: DateTime<Utc>,
    device_info: Option<&str>,
    status_check: FStat,
) -> Result<(SessionData, Option<(String, RefreshToken)>), RefreshError<S::Error>>
where
    S: RefreshTokenStore,
    FStat: FnOnce(&UserId) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let token_hash = hash_token(plaintext, config.hash_pepper.as_deref());

    // Resolve the user_id from the token without touching rotation
    // state. Reusing `find_token` rather than threading the result into
    // `refresh_session` keeps the rotation atomicity owned by
    // `refresh_session`'s own `rotate_token` call.
    let record = store
        .find_token(&token_hash)
        .await
        .map_err(RefreshError::Store)?
        .ok_or(RefreshError::NotFound)?;

    // Mirror the early-return ordering of `refresh_session` so a
    // suspended-user check on a revoked token still surfaces the
    // compromise signal (Revoked) rather than masking it as
    // AccountInactive. Pre-rotation refusals only.
    if record.revoked {
        // Defer to refresh_session so its family-revocation cascade
        // (and the device cascade) runs unchanged. The status
        // check is intentionally skipped on this branch; the priority
        // is the compromise response, not the account state.
        return refresh_session(plaintext, store, config, rng, now, device_info).await;
    }
    if now >= record.expires_at {
        return Err(RefreshError::Expired);
    }

    if !status_check(&record.user_id).await {
        tracing::warn!(
            user_id = %record.user_id,
            "refresh refused; caller-supplied status check returned false"
        );
        return Err(RefreshError::AccountInactive);
    }

    // Status OK: continue with the standard validate-and-rotate path.
    // `find_token` will run again here, but it's a hash lookup;
    // amortized cost is negligible compared to the network round-trip
    // the rotation itself implies, and the duplicated read keeps the
    // rotation atomicity owned by `refresh_session` rather than
    // re-implementing it inline here.
    refresh_session(plaintext, store, config, rng, now, device_info).await
}

/// Gather the unique `(tenant, device)` pairs participating in a
/// compromised refresh-token family.
///
/// Combines the just-loaded already-revoked record (the token under reuse)
/// with currently-active siblings returned by
/// [`RefreshTokenStore::active_tokens`]. The active list excludes the
/// reused token itself by definition; `record` carries that one's
/// device link explicitly.
///
/// Errors from the active-tokens query are swallowed to a `tracing::warn!`:
/// the cascade is best-effort, and the family revocation that called
/// this helper is the request-failing operation. We never let device-
/// gathering bubble up and mask the actual compromise signal.
async fn collect_family_device_targets<S: RefreshTokenStore>(
    store: &S,
    family_id: &TokenFamilyId,
    seen_record: &RefreshToken,
) -> Vec<(TenantId, DeviceId)> {
    let mut targets: Vec<(TenantId, DeviceId)> = Vec::new();
    if let Some(did) = seen_record.device_id.as_ref() {
        targets.push((seen_record.tenant_id, *did));
    }
    match store.active_tokens(&seen_record.user_id).await {
        Ok(active) => {
            for token in active {
                if token.family_id.as_ref() != Some(family_id) {
                    continue;
                }
                let Some(did) = token.device_id else { continue };
                let pair = (token.tenant_id, did);
                if !targets.contains(&pair) {
                    targets.push(pair);
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                family_id = %family_id,
                user_id = %seen_record.user_id,
                "failed to enumerate active siblings for device cascade; \
                 family revocation will proceed with the seen-record device only"
            );
        }
    }
    targets
}

/// Pure (no-I/O) builder for a refresh token record.
///
/// Splits the random/clock-dependent record construction out of
/// [`issue_refresh_token`] so callers that need to swap one token for
/// another atomically (see [`RefreshTokenStore::rotate_token`]) can build
/// the new record up-front and persist it inside the rotation transaction.
fn build_refresh_token(
    req: IssueRequest<'_>,
    config: &RefreshTokenConfig,
    rng: &impl SecureRng,
    now: DateTime<Utc>,
) -> (String, RefreshToken) {
    let plaintext = generate_token_value(rng);
    let token_hash = hash_token(&plaintext, config.hash_pepper.as_deref());

    let mut id_bytes = [0u8; 16];
    rng.fill_bytes(&mut id_bytes);
    let id = RefreshTokenId::try_new(uuid::Uuid::from_bytes(id_bytes).to_string())
        .expect("UUID is non-empty");

    let effective_family = req.family_id.unwrap_or_else(|| {
        TokenFamilyId::try_new(id.to_string()).expect("UUID-derived family id is non-empty")
    });

    let record = RefreshToken {
        id,
        user_id: *req.user_id,
        tenant_id: *req.tenant_id,
        token_hash,
        issued_at: now,
        expires_at: now + config.ttl,
        revoked: false,
        device_info: req.device_info,
        family_id: Some(effective_family),
        device_id: req.device_id,
    };

    (plaintext, record)
}

/// Revoke a single refresh token by its plaintext value.
///
/// Takes the [`RefreshTokenConfig`] so the lookup hash is
/// computed with the same pepper that issuance used.
pub async fn revoke_refresh_token<S: RefreshTokenStore>(
    plaintext: &str,
    store: &S,
    config: &RefreshTokenConfig,
) -> Result<(), RefreshError<S::Error>> {
    let token_hash = hash_token(plaintext, config.hash_pepper.as_deref());

    let record = store
        .find_token(&token_hash)
        .await
        .map_err(RefreshError::Store)?
        .ok_or(RefreshError::NotFound)?;

    store
        .revoke_token(&record.id)
        .await
        .map_err(RefreshError::Store)?;

    Ok(())
}

#[cfg(test)]
mod atomic_rotation;
#[cfg(test)]
mod basics;
#[cfg(all(test, feature = "device"))]
mod device_cascade;
#[cfg(test)]
mod status_check;
#[cfg(test)]
mod test_support;

#[cfg(test)]
mod refresh_unit_tests {
    use super::*;
    use crate::testing::mock_random::MockRng;

    // ── hash_token ──────────────────────────────────────────────────────

    /// Pin: hash_token without pepper produces a SHA-256 hash.
    #[test]
    fn hash_token_no_pepper_is_sha256() {
        let h1 = hash_token("test-token-value", None);
        let h2 = hash_token("test-token-value", None);
        assert_eq!(h1, h2, "hash must be deterministic");
        assert!(!h1.is_empty());
    }

    /// Pin: hash_token with pepper produces a different hash than without.
    #[test]
    fn hash_token_with_pepper_differs_from_without() {
        let without = hash_token("test-token", None);
        let with = hash_token("test-token", Some(b"my-secret-pepper"));
        assert_ne!(without, with, "peppered hash must differ from unpeppered");
    }

    /// Pin: hash_token with empty pepper falls back to SHA-256 (same as None).
    #[test]
    fn hash_token_empty_pepper_falls_back_to_sha256() {
        let none_pepper = hash_token("token", None);
        let empty_pepper = hash_token("token", Some(b""));
        assert_eq!(
            none_pepper, empty_pepper,
            "empty pepper must fall back to SHA-256 path"
        );
    }

    /// Pin: different inputs produce different hashes (collision resistance).
    #[test]
    fn hash_token_different_inputs_different_hashes() {
        let h1 = hash_token("token-a", None);
        let h2 = hash_token("token-b", None);
        assert_ne!(h1, h2);
    }

    /// Pin: different peppers produce different hashes.
    #[test]
    fn hash_token_different_peppers_different_hashes() {
        let h1 = hash_token("same-token", Some(b"pepper-1"));
        let h2 = hash_token("same-token", Some(b"pepper-2"));
        assert_ne!(h1, h2);
    }

    // ── generate_token_value ─────────────────────────────────────────────

    /// Pin: generate_token_value produces a non-empty base64 string.
    #[test]
    fn generate_token_value_produces_nonempty_base64() {
        let rng = MockRng::new(42);
        let token = generate_token_value(&rng);
        assert!(!token.is_empty());
        // Should be URL-safe base64 of 32 bytes = 43 chars.
        assert_eq!(token.len(), 43, "32 bytes → 43 base64url chars");
    }

    /// Pin: generate_token_value is deterministic with MockRng.
    #[test]
    fn generate_token_value_is_deterministic() {
        let t1 = generate_token_value(&MockRng::new(99));
        let t2 = generate_token_value(&MockRng::new(99));
        assert_eq!(t1, t2);
    }

    /// Pin: different seeds produce different tokens.
    #[test]
    fn generate_token_value_different_seeds_differ() {
        let t1 = generate_token_value(&MockRng::new(1));
        let t2 = generate_token_value(&MockRng::new(2));
        assert_ne!(t1, t2);
    }

    // ── RefreshTokenConfig::default ──────────────────────────────────────

    /// Pin: default config has production-safe values.
    #[test]
    fn default_config_has_safe_defaults() {
        let cfg = RefreshTokenConfig::default();
        assert_eq!(cfg.ttl, Duration::days(30));
        assert_eq!(cfg.max_per_user, 10);
        assert!(cfg.rotation, "rotation must be on by default");
        assert!(cfg.hash_pepper.is_none(), "no pepper by default");
    }

    // ── RefreshError Display ─────────────────────────────────────────────

    /// Pin: each RefreshError variant produces a distinct non-empty message.
    #[test]
    fn refresh_error_display_per_variant() {
        use std::io;
        let variants: Vec<(RefreshError<io::Error>, &str)> = vec![
            (RefreshError::NotFound, "not found"),
            (RefreshError::Expired, "expired"),
            (RefreshError::Revoked, "revoked"),
            (RefreshError::DeviceMismatch, "device mismatch"),
            (RefreshError::AccountInactive, "not active"),
            (RefreshError::Store(io::Error::other("boom")), "store error"),
        ];
        for (err, expected_substr) in variants {
            let msg = err.to_string();
            assert!(
                msg.contains(expected_substr),
                "RefreshError display for {:?} must contain {expected_substr:?}, got {msg:?}",
                std::mem::discriminant(&err)
            );
        }
    }
}
