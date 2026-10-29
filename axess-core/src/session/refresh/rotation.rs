//! Issuing, rotating and revoking refresh tokens.

use super::device_binding;
use super::store::{RefreshTokenStore, RotationOutcome};
use super::types::*;
use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::session::data::{AuthState, SessionData};
use axess_rng::SecureRng;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

/// Compute the storage-side hash of a plaintext refresh token, returned
/// as URL-safe base64.
///
/// When `pepper` is `Some`, computes `HMAC-SHA256(pepper, plaintext)`,
/// so a pre-image scan of the resulting hash table cannot be carried
/// out without knowing the pepper (which lives in application config
/// rather than the DB). When `None`, falls back to the previous
/// unsalted `SHA-256(plaintext)` for backward compat. `Some` is always
/// keyed: an empty pepper is refused earlier, by
/// [`RefreshTokenConfig::validate`].
pub(super) fn hash_token(plaintext: &str, pepper: Option<&[u8]>) -> String {
    match pepper {
        Some(pep) => {
            use hmac::Mac;
            let mut mac = crate::hmac::new_signer(pep);
            mac.update(plaintext.as_bytes());
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        }
        None => {
            let digest = Sha256::digest(plaintext.as_bytes());
            URL_SAFE_NO_PAD.encode(digest)
        }
    }
}

/// A refresh record found by its plaintext, and under which pepper.
pub(super) struct Located {
    pub(super) record: RefreshToken,
    /// Found only under `previous_hash_pepper`: the record still carries the
    /// retired hash and has to be re-stored under the current one.
    pub(super) under_previous_pepper: bool,
}

/// Look a token up by its plaintext: under the current pepper, then, when a
/// previous pepper is configured and the first lookup missed, under that one.
pub(super) async fn locate<S: RefreshTokenStore>(
    plaintext: &str,
    store: &S,
    config: &RefreshTokenConfig,
) -> Result<Option<Located>, S::Error> {
    if let Some(record) = store
        .find_token(&hash_token(plaintext, config.pepper()))
        .await?
    {
        return Ok(Some(Located {
            record,
            under_previous_pepper: false,
        }));
    }
    let Some(previous) = config.previous_pepper() else {
        return Ok(None);
    };
    Ok(store
        .find_token(&hash_token(plaintext, Some(previous)))
        .await?
        .map(|record| Located {
            record,
            under_previous_pepper: true,
        }))
}

/// The config a refresh of `found` runs under. A token still stored under the
/// previous pepper is rotated even when `rotation` is off, because rotation
/// is what writes the replacement under the current pepper.
pub(super) fn config_for<'a>(
    config: &'a RefreshTokenConfig,
    found: &Located,
) -> std::borrow::Cow<'a, RefreshTokenConfig> {
    if found.under_previous_pepper && !config.rotation {
        std::borrow::Cow::Owned(RefreshTokenConfig {
            rotation: true,
            ..config.clone()
        })
    } else {
        std::borrow::Cow::Borrowed(config)
    }
}

/// Generate a cryptographically random plaintext token (32 bytes, URL-safe base64).
pub(super) fn generate_token_value(rng: &impl SecureRng) -> String {
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
/// are revoked to make room, atomically with the insert
/// ([`RefreshTokenStore::issue_capped`]). A config that fails
/// [`RefreshTokenConfig::validate`] is refused before the store is touched.
pub async fn issue_refresh_token<S: RefreshTokenStore>(
    req: IssueRequest<'_>,
    config: &RefreshTokenConfig,
    store: &S,
    rng: &impl SecureRng,
    now: DateTime<Utc>,
) -> Result<(String, RefreshToken), RefreshError<S::Error>> {
    config.check()?;
    // The record stores a keyed digest of the device string, not the string.
    let req = IssueRequest {
        device_info: req
            .device_info
            .map(|raw| device_binding::bind(&raw, req.device_id.as_ref(), config.pepper())),
        ..req
    };
    let (plaintext, record) = build_refresh_token(req, config, rng, now, None);

    // The cap is enforced by the store, in the same transaction as the
    // insert: a count read here and acted on afterwards would let two
    // concurrent issues for one user both pass and exceed the cap.
    store
        .issue_capped(&record, config.max_per_user)
        .await
        .map_err(RefreshError::Store)?;

    Ok((plaintext, record))
}

/// Validate a refresh token and produce a new session.
///
/// **Deprecated**: this rotates a token for an account that may have been
/// suspended or terminated since the token was issued. Use
/// [`refresh_session_with_status_check`] (or its tenant form), passing a
/// predicate that reads the account's status; a caller that really has no
/// status to consult passes `|_| async { true }` and says so.
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
#[deprecated(
    since = "0.13.0",
    note = "rotates a token without checking that the account may still log in; \
            use refresh_session_with_status_check, or the tenant form"
)]
pub async fn refresh_session<S: RefreshTokenStore>(
    plaintext: &str,
    store: &S,
    config: &RefreshTokenConfig,
    rng: &impl SecureRng,
    now: DateTime<Utc>,
    device_info: Option<&str>,
) -> Result<(SessionData, Option<(String, RefreshToken)>), RefreshError<S::Error>> {
    refresh_scoped(plaintext, store, config, rng, now, device_info, None).await
}

/// [`refresh_session`] for a request that belongs to one tenant.
///
/// A token that belongs to another tenant answers [`RefreshError::NotFound`]
/// without being rotated, revoked or otherwise touched, exactly as an
/// unknown token does. Use it when the tenant comes from the request (a
/// host name, a path segment) so a token cannot be redeemed against a
/// tenant it was not issued for.
pub async fn refresh_session_in_tenant<S: RefreshTokenStore>(
    plaintext: &str,
    tenant: &TenantId,
    store: &S,
    config: &RefreshTokenConfig,
    rng: &impl SecureRng,
    now: DateTime<Utc>,
    device_info: Option<&str>,
) -> Result<(SessionData, Option<(String, RefreshToken)>), RefreshError<S::Error>> {
    refresh_scoped(
        plaintext,
        store,
        config,
        rng,
        now,
        device_info,
        Some(tenant),
    )
    .await
}

async fn refresh_scoped<S: RefreshTokenStore>(
    plaintext: &str,
    store: &S,
    config: &RefreshTokenConfig,
    rng: &impl SecureRng,
    now: DateTime<Utc>,
    device_info: Option<&str>,
    tenant: Option<&TenantId>,
) -> Result<(SessionData, Option<(String, RefreshToken)>), RefreshError<S::Error>> {
    config.check()?;
    let found = locate(plaintext, store, config)
        .await
        .map_err(RefreshError::Store)?
        .ok_or(RefreshError::NotFound)?;
    let config = config_for(config, &found);

    refresh_session_from_record(found.record, store, &config, rng, now, device_info, tenant).await
}

/// Validate + rotate a refresh token given an already-loaded
/// [`RefreshToken`] record.
///
/// Extracted from [`refresh_session`] so
/// [`refresh_session_with_status_check`] can gate on `user_id` without
/// having to re-run `find_token` on the happy path.
pub(super) async fn refresh_session_from_record<S: RefreshTokenStore>(
    record: RefreshToken,
    store: &S,
    config: &RefreshTokenConfig,
    rng: &impl SecureRng,
    now: DateTime<Utc>,
    device_info: Option<&str>,
    expected_tenant: Option<&TenantId>,
) -> Result<(SessionData, Option<(String, RefreshToken)>), RefreshError<S::Error>> {
    if let Some(tenant) = expected_tenant
        && record.tenant_id != *tenant
    {
        // A token of another tenant is indistinguishable from an unknown
        // one, and nothing is rotated or revoked on its behalf.
        return Err(RefreshError::NotFound);
    }

    if record.revoked {
        return Err(handle_revoked_reuse(&record, store, config, now).await);
    }

    if token_expired(&record, config, now) {
        return Err(RefreshError::Expired);
    }

    // Device binding check: if the stored record has device info, the caller
    // must present a matching one. See `device_binding` for what is stored
    // and how it is compared. The value the replacement token stores comes
    // back with the verdict, so a token of an earlier release upgrades.
    let child_device_info = device_binding::verify(&record, device_info, config.pepper())
        .map_err(|()| RefreshError::DeviceMismatch)?;

    // Build session data from the token's user/tenant. user_id/tenant_id
    // are now typed at the trait surface, so the previous `try_new` parsing
    // (and `RefreshError::InvalidToken`) are no longer needed; the
    // RefreshTokenStore trait promises validated values come back.
    let session = SessionData {
        version: crate::session::data::SESSION_DATA_VERSION,
        auth_state: AuthState::Authenticated {
            user_id: record.user_id,
            tenant_id: record.tenant_id,
            // The authentication the token descends from, not the refresh:
            // a 29-day-old token must not yield a session that passes
            // "recent login".
            authn_time: record.authenticated_at(),
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
        revision: 0,
        touched_at: None,
    };

    // Token rotation: atomically revoke old + insert new in a single
    // backend transaction so a mid-rotation crash never leaves the user
    // both un-rotated and un-authenticated.
    let new_token = if config.rotation {
        let (new_plaintext, new_record) = build_refresh_token(
            IssueRequest {
                user_id: &record.user_id,
                tenant_id: &record.tenant_id,
                device_info: child_device_info,
                family_id: Some(family_of(&record)), // Inherit (or derive) the family.
                device_id: record.device_id,         // Inherit device link.
            },
            config,
            rng,
            now,
            Some(record.authenticated_at()),
        );

        match store
            .rotate_token(&record.id, &new_record)
            .await
            .map_err(RefreshError::Store)?
        {
            RotationOutcome::Rotated => {}
            RotationOutcome::ParentAlreadyRevoked => {
                // A parallel refresh (or a revocation) got to the parent
                // first. Re-read it for the reason: the copy in hand was
                // loaded while it was still live.
                let current = match store.find_token(&record.token_hash).await {
                    Ok(Some(found)) if found.revoked => found,
                    _ => RefreshToken {
                        revoked: true,
                        revoked_reason: Some(RevocationReason::Rotated),
                        revoked_at: None,
                        ..record
                    },
                };
                return Err(handle_revoked_reuse(&current, store, config, now).await);
            }
        }

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
/// Ordering: `Revoked` → `Expired` → `status_check` →
/// device-binding → rotation. `Revoked` runs first so a compromise
/// signal on a revoked token still triggers the family-revocation
/// cascade even for an inactive account. `status_check` runs before
/// the device-binding check, so a token holder with both a mismatched
/// device fingerprint AND an inactive account surfaces as
/// [`RefreshError::AccountInactive`]; revealing device-binding state
/// to a caller whose account is already refused has no upside.
/// Rotation is last, giving the same
/// [`SessionRegistry`](crate::session::store::SessionRegistry)-
/// invalidation-cascade protection as
/// `complete_factor_step` (see the TOCTOU note below).
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
///             // `effective_at` ends a timed suspension whose `until` has passed.
///             .map(|status| status.effective_at(now).allows_login())
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
    status_checked(
        plaintext,
        store,
        config,
        rng,
        now,
        (None, device_info),
        status_check,
    )
    .await
}

/// Where a tenant-scoped refresh comes from: the tenant the request belongs
/// to, and the device fingerprint it presents.
pub struct RefreshScope<'a> {
    /// The tenant the request belongs to.
    pub tenant: &'a TenantId,
    /// The device fingerprint presented, as for [`refresh_session`].
    pub device_info: Option<&'a str>,
}

/// [`refresh_session_with_status_check`] for a request that belongs to one
/// tenant; a token of another tenant answers [`RefreshError::NotFound`]
/// before the status predicate runs and before anything is rotated. See
/// [`refresh_session_in_tenant`].
pub async fn refresh_session_with_status_check_in_tenant<S, FStat, Fut>(
    plaintext: &str,
    scope: RefreshScope<'_>,
    store: &S,
    config: &RefreshTokenConfig,
    rng: &impl SecureRng,
    now: DateTime<Utc>,
    status_check: FStat,
) -> Result<(SessionData, Option<(String, RefreshToken)>), RefreshError<S::Error>>
where
    S: RefreshTokenStore,
    FStat: FnOnce(&UserId) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    status_checked(
        plaintext,
        store,
        config,
        rng,
        now,
        (Some(scope.tenant), scope.device_info),
        status_check,
    )
    .await
}

async fn status_checked<S, FStat, Fut>(
    plaintext: &str,
    store: &S,
    config: &RefreshTokenConfig,
    rng: &impl SecureRng,
    now: DateTime<Utc>,
    (tenant, device_info): (Option<&TenantId>, Option<&str>),
    status_check: FStat,
) -> Result<(SessionData, Option<(String, RefreshToken)>), RefreshError<S::Error>>
where
    S: RefreshTokenStore,
    FStat: FnOnce(&UserId) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    config.check()?;
    let found = locate(plaintext, store, config)
        .await
        .map_err(RefreshError::Store)?
        .ok_or(RefreshError::NotFound)?;
    let config = &*config_for(config, &found);
    let record = found.record;

    // A revoked token (or one of another tenant) takes the shared path first,
    // so the compromise response is not masked as AccountInactive.
    if record.revoked || tenant.is_some_and(|t| record.tenant_id != *t) {
        return refresh_session_from_record(record, store, config, rng, now, device_info, tenant)
            .await;
    }
    if token_expired(&record, config, now) {
        return Err(RefreshError::Expired);
    }

    if !status_check(&record.user_id).await {
        tracing::warn!(
            user_id = %record.user_id,
            "refresh refused; caller-supplied status check returned false"
        );
        return Err(RefreshError::AccountInactive);
    }

    refresh_session_from_record(record, store, config, rng, now, device_info, tenant).await
}

/// Whether `record` can no longer be refreshed at `now`: past its own
/// `expires_at`, or past the family's absolute
/// [`RefreshTokenConfig::max_lifetime`].
fn token_expired(record: &RefreshToken, config: &RefreshTokenConfig, now: DateTime<Utc>) -> bool {
    now >= record.expires_at
        || config
            .lifetime_end(record.authenticated_at())
            .is_some_and(|end| now >= end)
}

/// The family a token's descendants carry: its own, or for a token issued
/// without one (rows written before families existed) the token's own id,
/// so reuse of that token can still find and revoke what descends from it.
fn family_of(record: &RefreshToken) -> TokenFamilyId {
    record.family_id.unwrap_or_else(|| {
        TokenFamilyId::try_new(record.id.to_string())
            .expect("a RefreshTokenId renders as a non-empty UUID, which is a valid family id")
    })
}

/// What a revoked token's presentation means, and the response to it.
///
/// Only a rotated-out token is evidence of theft. A token revoked by a
/// logout, a cap eviction or an earlier family revocation is refused as
/// [`RefreshError::Revoked`] and revokes nothing further. A rotated-out token
/// presented inside [`RefreshTokenConfig::reuse_grace`] of its rotation is
/// [`RefreshError::ConcurrentRefresh`]. Anything else is a compromise: the
/// family is revoked, and `on_token_compromise` runs whether or not the
/// revocation succeeded, so the device cascade is never skipped by a store
/// fault (the failure is logged, and the caller still sees `Revoked`).
async fn handle_revoked_reuse<S: RefreshTokenStore>(
    record: &RefreshToken,
    store: &S,
    config: &RefreshTokenConfig,
    now: DateTime<Utc>,
) -> RefreshError<S::Error> {
    match record.revoked_reason {
        Some(
            RevocationReason::Explicit | RevocationReason::Evicted | RevocationReason::Compromise,
        ) => return RefreshError::Revoked,
        Some(RevocationReason::Rotated) | None => {}
    }
    if let Some(at) = record.revoked_at
        && now >= at
        && now - at < config.reuse_grace
    {
        return RefreshError::ConcurrentRefresh;
    }

    let fid = family_of(record);
    tracing::warn!(
        family_id = %fid,
        user_id = %record.user_id,
        "rotated-out refresh token reused; revoking entire family (compromise signal)"
    );
    // Collect the (tenant, device) pairs linked to every member of the
    // family BEFORE revoke_family runs, so the cascade primitive stays
    // backend-agnostic.
    let compromised_devices = collect_family_device_targets(store, &fid, record).await;
    if let Err(e) = store.revoke_family(&record.user_id, &fid).await {
        tracing::error!(
            error = %e,
            family_id = %fid,
            user_id = %record.user_id,
            "revoke_family failed after a refresh token reuse; running the compromise hook anyway"
        );
    }
    store
        .on_token_compromise(&record.user_id, &fid, &compromised_devices)
        .await;
    RefreshError::Revoked
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
pub(super) async fn collect_family_device_targets<S: RefreshTokenStore>(
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
pub(super) fn build_refresh_token(
    req: IssueRequest<'_>,
    config: &RefreshTokenConfig,
    rng: &impl SecureRng,
    now: DateTime<Utc>,
    authn_time: Option<DateTime<Utc>>,
) -> (String, RefreshToken) {
    let plaintext = generate_token_value(rng);
    let token_hash = hash_token(&plaintext, config.pepper());

    let mut id_bytes = [0u8; 16];
    rng.fill_bytes(&mut id_bytes);
    let id = RefreshTokenId::try_new(uuid::Uuid::from_bytes(id_bytes).to_string())
        .expect("UUID is non-empty");

    let effective_family = req.family_id.unwrap_or_else(|| {
        TokenFamilyId::try_new(id.to_string()).expect("UUID-derived family id is non-empty")
    });

    // Sliding expiry, capped by the family's absolute lifetime when one is
    // configured. A token issued at login descends from `now`.
    let mut expires_at = now + config.ttl;
    if let Some(end) = config.lifetime_end(authn_time.unwrap_or(now)) {
        expires_at = expires_at.min(end);
    }

    let record = RefreshToken {
        id,
        user_id: *req.user_id,
        tenant_id: *req.tenant_id,
        token_hash,
        issued_at: now,
        expires_at,
        revoked: false,
        device_info: req.device_info,
        family_id: Some(effective_family),
        device_id: req.device_id,
        authn_time,
        revoked_reason: None,
        revoked_at: None,
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
    config.check()?;
    let record = locate(plaintext, store, config)
        .await
        .map_err(RefreshError::Store)?
        .ok_or(RefreshError::NotFound)?
        .record;

    store
        .revoke_token(&record.id)
        .await
        .map_err(RefreshError::Store)?;

    Ok(())
}
