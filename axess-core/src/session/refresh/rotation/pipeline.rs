//! The one refresh entry point, [`Refresh`], and what it checks beyond the
//! token itself: the tenant, the account-status predicate a caller
//! supplies, the device gate and the device binding.

use super::super::device_binding;
use super::super::store::{RefreshTokenStore, RotationOutcome};
use super::super::types::{RefreshError, RefreshToken, RefreshTokenConfig};
use super::{
    IssueRequest, build_refresh_token, build_refresh_token_for, family_of, handle_revoked_reuse,
    locate,
};
#[cfg(feature = "device")]
use crate::authn::ids::DeviceId;
use crate::authn::ids::{TenantId, UserId};
use crate::session::data::{AuthState, SessionData};
use axess_rng::SecureRng;
use chrono::{DateTime, Utc};
use std::future::Future;
#[cfg(feature = "device")]
use std::pin::Pin;

/// The device check a refresh runs on a token that carries a device id: the
/// device must exist, not be `Revoked`, and be unowned or owned by the
/// token's user. Implemented by the device-store gate of
/// [`Refresh::device_store`]. Only with the `device` feature, which carries
/// the device store.
#[cfg(feature = "device")]
pub(in crate::session::refresh) trait DeviceGate: Send + Sync {
    /// Refuse the refresh when the token's device may no longer refresh for
    /// `user`.
    fn check<'a>(
        &'a self,
        tenant: &'a TenantId,
        device: &'a DeviceId,
        user: &'a UserId,
    ) -> Pin<Box<dyn Future<Output = Result<(), DeviceRefusal>> + Send + 'a>>;
}

/// Why a [`DeviceGate`] refused.
#[cfg(feature = "device")]
pub(in crate::session::refresh) enum DeviceRefusal {
    /// The device is revoked or no longer exists.
    Revoked,
    /// The device belongs to another user than the token's.
    OtherOwner,
    /// The device store could not answer; carries its message.
    Store(String),
}

/// A refresh of a session from a refresh token: the one entry point.
///
/// Build it with [`new`](Self::new), which takes the token, the tenant the
/// request belongs to and the account-status predicate, add the checks the
/// request needs ([`device_info`](Self::device_info),
/// [`device_store`](Self::device_store)), and [`run`](Self::run) it. A route
/// that really serves every tenant builds it with
/// [`any_tenant`](Self::any_tenant) instead, which says so:
///
/// ```ignore
/// use axess_core::session::refresh::Refresh;
///
/// let (session, rotated) = Refresh::new(&plaintext, &tenant, |user_id| async move {
///         // `identity` is the application's IdentityStore.
///         identity
///             .account_status(user_id)
///             .await
///             // `effective_at` ends a timed suspension whose `until` has passed.
///             .map(|status| status.effective_at(now).allows_login())
///             .unwrap_or(false) // fail closed on store errors
///     })
///     .device_info(Some(fingerprint))
///     .device_store(&devices)
///     .run(&refresh_store, &config, &rng, now)
///     .await?;
/// ```
///
/// # Order of the checks
///
/// The config is checked; the token is located under the current pepper,
/// then the previous one; a token of another tenant than
/// [`new`](Self::new)'s is [`RefreshError::NotFound`]; a revoked
/// token takes the reuse response (a rotated-out token revokes its family);
/// an expired token is [`RefreshError::Expired`]; the status predicate
/// refuses with [`RefreshError::AccountInactive`]; the device gate refuses
/// with [`RefreshError::DeviceRevoked`], [`RefreshError::DeviceMismatch`] (a
/// device of another user) or [`RefreshError::DeviceStore`]; the device
/// binding refuses with [`RefreshError::DeviceMismatch`]; then the session
/// is built and the token rotated (or, without rotation, re-stored under the
/// current pepper when it was found under the previous one). Every refusal
/// before the rotation leaves the token as it was: an inactive account's
/// family is kept for a later reactivation.
///
/// `Revoked` runs first so a compromise signal on a revoked token still
/// triggers the family revocation even for an inactive account. The status
/// check runs before the device checks, so a holder with both a mismatched
/// device and an inactive account learns only that the account is refused.
///
/// # What the caller still owes
///
/// The returned `SessionData` is `Authenticated` but registered with no
/// [`SessionRegistry`](crate::session::store::SessionRegistry): a caller
/// that uses one registers the new session id before answering, or
/// `invalidate_user` cannot reach it. Between the status check and the
/// rotation a concurrent suspension can land; its `invalidate_user` evicts
/// every registered session, and the next request through
/// [`AuthnService::check_session`](crate::authn::service::AuthnService::check_session)
/// sees the rotated session as invalid.
pub struct Refresh<'a, F> {
    plaintext: &'a str,
    tenant: Option<&'a TenantId>,
    device_info: Option<&'a str>,
    #[cfg(feature = "device")]
    device: Option<Box<dyn DeviceGate + 'a>>,
    status: F,
}

impl<'a, F> Refresh<'a, F> {
    /// A refresh of the session `plaintext` (the refresh token the client
    /// presented) for a request that belongs to `tenant` (a host name, a path
    /// segment), gated by `status_check(&user_id)`: a `false` refuses with
    /// [`RefreshError::AccountInactive`] without rotating.
    ///
    /// A token of another tenant answers [`RefreshError::NotFound`] before
    /// anything else is read or written, exactly as an unknown token does,
    /// so a token cannot be redeemed against a tenant it was not issued for.
    ///
    /// Pass a predicate that reads the account's status (suspended,
    /// terminated) from the application's identity store and fails closed
    /// on its errors. A caller that really has nothing to consult (its
    /// route is gated upstream) passes `|_| async { true }` and says so.
    pub fn new<Fut>(plaintext: &'a str, tenant: &'a TenantId, status_check: F) -> Self
    where
        F: FnOnce(&UserId) -> Fut,
        Fut: Future<Output = bool>,
    {
        Self {
            plaintext,
            tenant: Some(tenant),
            device_info: None,
            #[cfg(feature = "device")]
            device: None,
            status: status_check,
        }
    }

    /// [`new`](Self::new) for a route that serves every tenant: the token's
    /// own tenant is not compared with the request's, so a token issued to
    /// any tenant is redeemed here. The opt-out of the tenant check; use it
    /// only where the token alone names the tenant (a single-tenant
    /// deployment, a tenant-less host) and say so.
    pub fn any_tenant<Fut>(plaintext: &'a str, status_check: F) -> Self
    where
        F: FnOnce(&UserId) -> Fut,
        Fut: Future<Output = bool>,
    {
        Self {
            plaintext,
            tenant: None,
            device_info: None,
            #[cfg(feature = "device")]
            device: None,
            status: status_check,
        }
    }

    /// The device fingerprint the request presents. A token issued with a
    /// device binding refreshes only for a matching one
    /// ([`RefreshError::DeviceMismatch`] otherwise); the replacement token
    /// carries the binding on.
    pub fn device_info(mut self, device_info: Option<&'a str>) -> Self {
        self.device_info = device_info;
        self
    }

    /// Check, before anything is rotated, the device a token was issued to,
    /// against the gate the device-check module builds.
    #[cfg(feature = "device")]
    pub(in crate::session::refresh) fn device_gate(
        mut self,
        gate: Box<dyn DeviceGate + 'a>,
    ) -> Self {
        self.device = Some(gate);
        self
    }

    /// Validate the token, run the checks, and produce the new session, with
    /// the replacement token when rotation is on (the old token is then
    /// revoked atomically with the replacement's insert). See the
    /// [type-level documentation](Self) for the order of the checks.
    ///
    /// # Errors
    ///
    /// Every [`RefreshError`] the checks above name, [`RefreshError::InvalidConfig`]
    /// for a configuration that fails
    /// [`RefreshTokenConfig::validate`], and [`RefreshError::Store`] when the
    /// token store fails.
    pub async fn run<S, Fut>(
        self,
        store: &S,
        config: &RefreshTokenConfig,
        rng: &impl SecureRng,
        now: DateTime<Utc>,
    ) -> Result<(SessionData, Option<(String, RefreshToken)>), RefreshError<S::Error>>
    where
        S: RefreshTokenStore,
        F: FnOnce(&UserId) -> Fut,
        Fut: Future<Output = bool>,
    {
        config.check()?;
        config
            .validate_device_info(self.device_info.is_some())
            .map_err(RefreshError::InvalidConfig)?;
        let found = locate(self.plaintext, store, config)
            .await
            .map_err(RefreshError::Store)?
            .ok_or(RefreshError::NotFound)?;
        let stored_under = found.stored_under(config);
        let under_previous_pepper = found.under_previous_pepper;
        let record = found.record;

        check_tenant(&record, self.tenant)?;
        check_revoked(&record, store, config, now).await?;
        check_expiry(&record, config, now)?;
        check_status(&record, self.status).await?;
        #[cfg(feature = "device")]
        check_device(&record, self.device.as_deref()).await?;
        let child_device_info = check_binding(&record, self.device_info, stored_under, config)?;

        let session = session_for(&record);
        let Some((new_plaintext, new_record)) = replacement_for(
            self.plaintext,
            config,
            rng,
            now,
            &record,
            child_device_info,
            under_previous_pepper,
        ) else {
            return Ok((session, None));
        };
        rotate(store, config, now, &record, &new_record).await?;

        Ok((
            session,
            config.rotation.then_some((new_plaintext, new_record)),
        ))
    }
}

/// A token of another tenant than the request's is indistinguishable from an
/// unknown one, and nothing is rotated or revoked on its behalf.
fn check_tenant<E>(record: &RefreshToken, tenant: Option<&TenantId>) -> Result<(), RefreshError<E>>
where
    E: std::error::Error + Send + Sync + 'static,
{
    if let Some(tenant) = tenant
        && record.tenant_id != *tenant
    {
        return Err(RefreshError::NotFound);
    }
    Ok(())
}

/// A revoked token takes the reuse response before any other check, so
/// the compromise signal is never masked as an expiry, an inactive
/// account or a revoked device.
async fn check_revoked<S: RefreshTokenStore>(
    record: &RefreshToken,
    store: &S,
    config: &RefreshTokenConfig,
    now: DateTime<Utc>,
) -> Result<(), RefreshError<S::Error>> {
    if record.revoked {
        return Err(handle_revoked_reuse(record, store, config, now).await);
    }
    Ok(())
}

/// An expired token is refused.
fn check_expiry<E>(
    record: &RefreshToken,
    config: &RefreshTokenConfig,
    now: DateTime<Utc>,
) -> Result<(), RefreshError<E>>
where
    E: std::error::Error + Send + Sync + 'static,
{
    if token_expired(record, config, now) {
        return Err(RefreshError::Expired);
    }
    Ok(())
}

/// The caller's account-status predicate refuses the refresh of an account
/// that may no longer log in.
async fn check_status<E, FStat, Fut>(
    record: &RefreshToken,
    status: FStat,
) -> Result<(), RefreshError<E>>
where
    E: std::error::Error + Send + Sync + 'static,
    FStat: FnOnce(&UserId) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    if !status(&record.user_id).await {
        tracing::warn!(
            user_id = %record.user_id,
            "refresh refused; caller-supplied status check returned false"
        );
        return Err(RefreshError::AccountInactive);
    }
    Ok(())
}

/// A token that carries a device id is refused when the device gate, if the
/// refresh has one, refuses that device for the token's user.
#[cfg(feature = "device")]
async fn check_device<E>(
    record: &RefreshToken,
    device: Option<&(dyn DeviceGate + '_)>,
) -> Result<(), RefreshError<E>>
where
    E: std::error::Error + Send + Sync + 'static,
{
    if let (Some(device_id), Some(device)) = (record.device_id.as_ref(), device) {
        device
            .check(&record.tenant_id, device_id, &record.user_id)
            .await
            .map_err(|refusal| match refusal {
                DeviceRefusal::Revoked => RefreshError::DeviceRevoked,
                DeviceRefusal::OtherOwner => RefreshError::DeviceMismatch,
                DeviceRefusal::Store(message) => RefreshError::DeviceStore(message),
            })?;
    }
    Ok(())
}

/// Device binding check: if the stored record has device info, the caller
/// must present a matching one. See `device_binding` for what is stored
/// and how it is compared. The value the replacement token stores comes
/// back with the verdict, so a token of an earlier release, or one bound
/// under the previous pepper, upgrades.
fn check_binding<E>(
    record: &RefreshToken,
    device_info: Option<&str>,
    stored_under: Option<&[u8]>,
    config: &RefreshTokenConfig,
) -> Result<Option<String>, RefreshError<E>>
where
    E: std::error::Error + Send + Sync + 'static,
{
    device_binding::verify(
        record,
        device_info,
        device_binding::Peppers {
            stored_under,
            current: config.pepper(),
        },
    )
    .map_err(|()| RefreshError::DeviceMismatch)
}

/// Build session data from the token's user/tenant. user_id/tenant_id
/// are typed at the trait surface; the RefreshTokenStore trait promises
/// validated values come back.
fn session_for(record: &RefreshToken) -> SessionData {
    SessionData {
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
            impersonator: None,
            ldap_groups: None,
            assurance: Vec::new(),
        },
        fingerprint: None,
        // Rotated session inherits the device link from the token
        // record. Without this, refresh-driven session resumption would
        // appear as a "device-less" session and the layer would re-resolve
        // it from request headers; typically yielding the same id, but
        // an unnecessary round-trip and a lost association on the gap.
        device_id: record.device_id,
        // A refresh token record says which device it was issued to, not
        // that this request proved it; the next request resolves it again.
        device_proven: false,
        custom: serde_json::Value::default(),
        revision: 0,
        touched_at: None,
    }
}

/// The record the client holds from here on. With rotation, a fresh
/// token replaces the one presented. Without it the token stays, except
/// that one found under the previous pepper is re-stored under the
/// current one with the same plaintext, so the client keeps its token
/// and the chain survives the previous pepper being dropped; the
/// client is handed nothing, since it has nothing to change.
fn replacement_for(
    plaintext: &str,
    config: &RefreshTokenConfig,
    rng: &impl SecureRng,
    now: DateTime<Utc>,
    record: &RefreshToken,
    child_device_info: Option<String>,
    under_previous_pepper: bool,
) -> Option<(String, RefreshToken)> {
    if config.rotation {
        Some(build_refresh_token(
            child_of(record, child_device_info),
            config,
            rng,
            now,
            Some(record.authenticated_at()),
        ))
    } else if under_previous_pepper {
        let (plaintext, mut moved) = build_refresh_token_for(
            plaintext.to_string(),
            child_of(record, child_device_info),
            config,
            rng,
            now,
            Some(record.authenticated_at()),
        );
        // A change of key, not a new grant: the token ends when it was due
        // to, however often a pepper rotation re-stores it.
        moved.expires_at = record.expires_at;
        Some((plaintext, moved))
    } else {
        None
    }
}

/// Atomically revoke old + insert new in a single backend transaction so
/// a mid-rotation crash never leaves the user both un-rotated and
/// un-authenticated. Without rotation, a parent that a parallel refresh has
/// already re-stored under the current pepper is a success too: that row
/// serves the client, which is handed nothing.
async fn rotate<S: RefreshTokenStore>(
    store: &S,
    config: &RefreshTokenConfig,
    now: DateTime<Utc>,
    record: &RefreshToken,
    new_record: &RefreshToken,
) -> Result<(), RefreshError<S::Error>> {
    match store
        .rotate_token(&record.id, new_record)
        .await
        .map_err(RefreshError::Store)?
    {
        RotationOutcome::Rotated => {}
        RotationOutcome::ParentAlreadyRevoked => {
            // A parallel refresh (or a revocation) got to the parent first.
            // Without rotation the parallel refresh stored this very token
            // under the current pepper, and that row serves the client; a
            // parent revoked by anything else takes the reuse response.
            if !config.rotation
                && let Some(current) = store
                    .find_token(&new_record.token_hash)
                    .await
                    .map_err(RefreshError::Store)?
                && !current.revoked
            {
                return Ok(());
            }
            // Re-read the parent for the reason and the time: the copy in
            // hand was loaded while it was still live. Only what the store
            // says is acted on. A failed re-read is a store error, a row
            // that is gone is an unknown token, and a row still live is a
            // rotation this node cannot see yet (a replica behind the
            // writer); none of those is evidence of theft, and a synthesised
            // "rotated" record would revoke the family on a store blip.
            let current = store
                .find_token(&record.token_hash)
                .await
                .map_err(RefreshError::Store)?
                .ok_or(RefreshError::NotFound)?;
            if !current.revoked {
                return Err(RefreshError::ConcurrentRefresh);
            }
            return Err(handle_revoked_reuse(&current, store, config, now).await);
        }
    }
    Ok(())
}

/// The issue request for the token that replaces `record` in its family,
/// carrying `device_info` (the binding as the replacement should store it).
fn child_of(record: &RefreshToken, device_info: Option<String>) -> IssueRequest<'_> {
    IssueRequest {
        user_id: &record.user_id,
        tenant_id: &record.tenant_id,
        device_info,
        family_id: Some(family_of(record)), // Inherit (or derive) the family.
        device_id: record.device_id,        // Inherit device link.
    }
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
