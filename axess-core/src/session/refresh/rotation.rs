//! Issuing, rotating and revoking refresh tokens.

use super::device_binding;
use super::store::RefreshTokenStore;
use super::types::*;
use crate::authn::ids::{DeviceId, TenantId, UserId};
use axess_rng::SecureRng;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

mod pipeline;

pub use pipeline::Refresh;
#[cfg(feature = "device")]
pub(super) use pipeline::{DeviceGate, DeviceRefusal};

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
struct Located {
    record: RefreshToken,
    /// Found only under `previous_hash_pepper`: the record still carries the
    /// retired hash, and a device binding keyed by it, and has to be
    /// re-stored under the current one.
    under_previous_pepper: bool,
}

impl Located {
    /// The pepper the record was found under, which its token hash and its
    /// device binding are keyed with.
    fn stored_under<'a>(&self, config: &'a RefreshTokenConfig) -> Option<&'a [u8]> {
        if self.under_previous_pepper {
            config.previous_pepper().flatten()
        } else {
            config.pepper()
        }
    }
}

/// Look a token up by its plaintext: under the current pepper, then, when a
/// previous pepper is configured and the first lookup missed, under that one.
async fn locate<S: RefreshTokenStore>(
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
        .find_token(&hash_token(plaintext, previous))
        .await?
        .map(|record| Located {
            record,
            under_previous_pepper: true,
        }))
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
    /// [`cascade_revoke_devices_and_tokens`](crate::device::cascade_revoke_devices_and_tokens).
    /// Inherited unchanged across rotation.
    pub device_id: Option<DeviceId>,
}

/// Issue a new refresh token for the given user/tenant.
///
/// Returns `(plaintext_token, stored_record)`. The plaintext is
/// returned exactly once; only the hash is persisted. Callers must
/// transmit the plaintext to the client over a secure channel.
///
/// The token is anchored at `now`: use this at the moment of a login. A token
/// issued from a session that authenticated earlier is issued with
/// [`issue_refresh_token_from_login`], which anchors it at that login.
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
    issue_anchored(req, config, store, rng, now, None).await
}

/// Issue a refresh token to a user whose session authenticated at
/// `authenticated_at`, which may be well before `now`.
///
/// The record carries `authenticated_at`: the family's absolute lifetime
/// ([`RefreshTokenConfig::max_lifetime`]) counts from it, and every session
/// rotated from the token has it as its `authn_time`. A refresh token is
/// therefore never a way to make an old authentication look new.
///
/// A session whose authentication is already past the family's lifetime
/// gets [`RefreshError::Expired`] and nothing is stored. Otherwise as
/// [`issue_refresh_token`].
pub async fn issue_refresh_token_from_login<S: RefreshTokenStore>(
    req: IssueRequest<'_>,
    config: &RefreshTokenConfig,
    store: &S,
    rng: &impl SecureRng,
    now: DateTime<Utc>,
    authenticated_at: DateTime<Utc>,
) -> Result<(String, RefreshToken), RefreshError<S::Error>> {
    config.check()?;
    if config
        .lifetime_end(authenticated_at)
        .is_some_and(|end| end <= now)
    {
        return Err(RefreshError::Expired);
    }
    issue_anchored(req, config, store, rng, now, Some(authenticated_at)).await
}

async fn issue_anchored<S: RefreshTokenStore>(
    req: IssueRequest<'_>,
    config: &RefreshTokenConfig,
    store: &S,
    rng: &impl SecureRng,
    now: DateTime<Utc>,
    authn_time: Option<DateTime<Utc>>,
) -> Result<(String, RefreshToken), RefreshError<S::Error>> {
    config.check()?;
    config
        .validate_device_info(req.device_info.is_some())
        .map_err(RefreshError::InvalidConfig)?;
    // The record stores a keyed digest of the device string, not the string.
    let req = IssueRequest {
        device_info: req
            .device_info
            .map(|raw| device_binding::bind(&raw, req.device_id.as_ref(), config.pepper())),
        ..req
    };
    let (plaintext, record) = build_refresh_token(req, config, rng, now, authn_time);

    // The cap is enforced by the store, in the same transaction as the
    // insert: a count read here and acted on afterwards would let two
    // concurrent issues for one user both pass and exceed the cap.
    store
        .issue_capped(&record, config.max_per_user)
        .await
        .map_err(RefreshError::Store)?;

    Ok((plaintext, record))
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
/// logout, a cap eviction, a device revocation or an earlier family
/// revocation is refused as [`RefreshError::Revoked`] and revokes nothing
/// further. A rotated-out token
/// presented inside [`RefreshTokenConfig::reuse_grace`] of its rotation is
/// [`RefreshError::ConcurrentRefresh`]; the distance is measured either way,
/// since `revoked_at` was written by whichever node rotated the token and
/// its clock may be ahead of this one's. Anything else is a compromise: the
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
            RevocationReason::Explicit
            | RevocationReason::Evicted
            | RevocationReason::Compromise
            | RevocationReason::Device,
        ) => return RefreshError::Revoked,
        Some(RevocationReason::Rotated) | None => {}
    }
    if let Some(at) = record.revoked_at
        && (now - at).abs() < config.reuse_grace
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

/// Pure (no-I/O) builder for a refresh token record with a fresh plaintext.
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
    build_refresh_token_for(generate_token_value(rng), req, config, rng, now, authn_time)
}

/// [`build_refresh_token`] for a given `plaintext`: the record that stores
/// it under the current pepper. Used to re-store a token a non-rotating
/// client keeps, so it is found under the current pepper from then on.
fn build_refresh_token_for(
    plaintext: String,
    req: IssueRequest<'_>,
    config: &RefreshTokenConfig,
    rng: &impl SecureRng,
    now: DateTime<Utc>,
    authn_time: Option<DateTime<Utc>>,
) -> (String, RefreshToken) {
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
    let mut expires_at = crate::lifetime::expiry_after_signed(now, config.ttl);
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
/// computed with the same pepper that issuance used. The store records the
/// revocation as [`RevocationReason::Explicit`], so a later presentation of
/// the token is refused as [`RefreshError::Revoked`] and is not read as
/// theft.
pub async fn revoke_refresh_token<S: RefreshTokenStore>(
    plaintext: &str,
    store: &S,
    config: &RefreshTokenConfig,
) -> Result<(), RefreshError<S::Error>> {
    revoke_scoped(plaintext, None, store, config).await
}

/// [`revoke_refresh_token`] for a request that belongs to one tenant.
///
/// A token of another tenant answers [`RefreshError::NotFound`] and is left
/// as it is, exactly as an unknown token is, so a logout route that takes
/// its tenant from the request cannot revoke a token issued elsewhere.
pub async fn revoke_refresh_token_in_tenant<S: RefreshTokenStore>(
    plaintext: &str,
    tenant: &TenantId,
    store: &S,
    config: &RefreshTokenConfig,
) -> Result<(), RefreshError<S::Error>> {
    revoke_scoped(plaintext, Some(tenant), store, config).await
}

async fn revoke_scoped<S: RefreshTokenStore>(
    plaintext: &str,
    tenant: Option<&TenantId>,
    store: &S,
    config: &RefreshTokenConfig,
) -> Result<(), RefreshError<S::Error>> {
    config.check()?;
    let record = locate(plaintext, store, config)
        .await
        .map_err(RefreshError::Store)?
        .ok_or(RefreshError::NotFound)?
        .record;
    if tenant.is_some_and(|t| record.tenant_id != *t) {
        return Err(RefreshError::NotFound);
    }

    store
        .revoke_token(&record.id)
        .await
        .map_err(RefreshError::Store)?;

    Ok(())
}
