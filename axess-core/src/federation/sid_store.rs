//! [`SidStore`]: where the OIDC `sid` map lives, so back-channel logout can
//! work across instances.
//!
//! [`SidMap`] is the in-process implementation and stays the default: one
//! process, one map. A deployment with several instances behind a load
//! balancer needs the instance that receives the IdP's logout token to find
//! the session another instance established, and the in-process map cannot:
//! the token is answered `200` (the OIDC-conformant answer for a session the
//! endpoint does not know) and the session stays valid. The Valkey
//! implementation, `ValkeySidStore` (behind the `valkey` feature), keeps the
//! same records where every instance reads them.
//!
//! Wire it on both sides: `AuthnServiceBuilder::with_sid_store` for the
//! login path that writes, and `with_sid_store` on each logout handler for
//! the paths that read (pass
//! [`AuthnService::sid_store`](crate::authn::service::AuthnService::sid_store)).
//! A handler left with the `authn.sid_map()` its constructor took reads the
//! in-process map and nothing else.
//!
//! # What a shared store does not do
//!
//! The in-process map ages out and caps its entries from the login path
//! (`with_sid_map_capacity`, a 24 hour prune). A shared store ages its keys
//! out with a time to live instead, so [`mapping_count`](SidStore::mapping_count), the sweep and
//! the evictions answer empty: the capacity setting does not apply to it.
//!
//! # Errors
//!
//! Every method can fail with [`SidStoreError`] when the backing store does.
//! A login that cannot write its mapping is still a login (the mapping is
//! best effort, as it is when the in-process map is at capacity) and logs
//! it; a logout that cannot read answers a retryable `503`, so the IdP sends
//! the token again.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use chrono::{DateTime, Utc};

use super::sid_map::{DisplacedSid, SidEntry, SidKey, SidMap};
use crate::authn::ids::{TenantId, UserId};
use crate::session::id::SessionId;

/// A [`SidStore`] call in flight.
pub type SidFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, SidStoreError>> + Send + 'a>>;

/// The backing store of a [`SidStore`] failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("sid store: {0}")]
pub struct SidStoreError(pub String);

/// The `sid` map and subject registry, behind a trait so a deployment can
/// share them between instances. See the [module docs](self); the methods
/// mean what the same-named methods of [`SidMap`] mean.
///
/// `scope` on a read is the tenant whose provider verified the logout
/// token: a mapping or session is returned only if it was recorded for that
/// tenant. `None` (a global provider) matches every mapping. A mapping
/// recorded for a global provider (`None`) is never matched by a tenant
/// scope.
pub trait SidStore: Send + Sync + 'static {
    /// Map `key` to `session`, returning the mapping it displaced.
    fn insert_displacing<'a>(
        &'a self,
        key: SidKey,
        subject: &'a str,
        tenant: Option<TenantId>,
        user: UserId,
        session: SessionId,
        inserted_at: DateTime<Utc>,
    ) -> SidFuture<'a, Option<DisplacedSid>>;

    /// Put a displaced mapping back if its key is still vacant and its
    /// session is still in the subject registry.
    fn restore_if_vacant(&self, key: SidKey, displaced: DisplacedSid) -> SidFuture<'_, bool>;

    /// The mapping for `key`, if it was recorded for `scope`.
    fn get<'a>(
        &'a self,
        key: &'a SidKey,
        scope: Option<&'a TenantId>,
    ) -> SidFuture<'a, Option<SidEntry>>;

    /// Remove the mapping for `key`, and its session from the subject
    /// registry, only if it still maps to `session`.
    fn remove_if_session<'a>(
        &'a self,
        key: &'a SidKey,
        session: &'a SessionId,
    ) -> SidFuture<'a, Option<SidEntry>>;

    /// Record that `session` was established for `user`, who logged in under
    /// `issuer` as the IdP subject `subject`, in `tenant`.
    fn register_subject_session<'a>(
        &'a self,
        issuer: &'a str,
        subject: &'a str,
        tenant: Option<TenantId>,
        user: UserId,
        session: SessionId,
    ) -> SidFuture<'a, ()>;

    /// Drop one session from the subject registry; whether it was there.
    fn forget_subject_session<'a>(
        &'a self,
        issuer: &'a str,
        user: &'a UserId,
        session: &'a SessionId,
    ) -> SidFuture<'a, bool>;

    /// Every session of `subject` under `issuer` that was recorded for
    /// `scope`, each with its local user. Nothing is removed.
    fn subject_sessions<'a>(
        &'a self,
        issuer: &'a str,
        subject: &'a str,
        scope: Option<&'a TenantId>,
    ) -> SidFuture<'a, Vec<(UserId, SessionId)>>;

    /// Up to `max` subject records to check for liveness.
    fn sweep_subject_candidates(
        &self,
        max: usize,
    ) -> SidFuture<'_, Vec<(String, UserId, SessionId)>>;

    /// Remove every mapping of `session`, and its subject record; returns
    /// how many `sid` mappings went.
    fn remove_session<'a>(&'a self, session: &'a SessionId) -> SidFuture<'a, usize>;

    /// Remove up to `max` mappings inserted before `cutoff`, oldest first.
    fn evict_inserted_before(
        &self,
        cutoff: DateTime<Utc>,
        max: usize,
    ) -> SidFuture<'_, Vec<(SidKey, SidEntry)>>;

    /// Remove up to `max` of the oldest mappings.
    fn evict_oldest(&self, max: usize) -> SidFuture<'_, Vec<(SidKey, SidEntry)>>;

    /// The number of mappings, for the capacity check. A store that ages its
    /// keys out by time answers `0`.
    fn mapping_count(&self) -> SidFuture<'_, usize>;
}

impl SidStore for SidMap {
    fn insert_displacing<'a>(
        &'a self,
        key: SidKey,
        subject: &'a str,
        tenant: Option<TenantId>,
        user: UserId,
        session: SessionId,
        inserted_at: DateTime<Utc>,
    ) -> SidFuture<'a, Option<DisplacedSid>> {
        Box::pin(async move {
            Ok(SidMap::insert_displacing(
                self,
                key,
                subject,
                tenant,
                user,
                session,
                inserted_at,
            ))
        })
    }

    fn restore_if_vacant(&self, key: SidKey, displaced: DisplacedSid) -> SidFuture<'_, bool> {
        Box::pin(async move { Ok(SidMap::restore_if_vacant(self, key, displaced)) })
    }

    fn get<'a>(
        &'a self,
        key: &'a SidKey,
        scope: Option<&'a TenantId>,
    ) -> SidFuture<'a, Option<SidEntry>> {
        Box::pin(async move { Ok(SidMap::get_in(self, key, scope)) })
    }

    fn remove_if_session<'a>(
        &'a self,
        key: &'a SidKey,
        session: &'a SessionId,
    ) -> SidFuture<'a, Option<SidEntry>> {
        Box::pin(async move { Ok(SidMap::remove_if(self, key, |entry| entry.1 == *session)) })
    }

    fn register_subject_session<'a>(
        &'a self,
        issuer: &'a str,
        subject: &'a str,
        tenant: Option<TenantId>,
        user: UserId,
        session: SessionId,
    ) -> SidFuture<'a, ()> {
        Box::pin(async move {
            SidMap::register_subject_session(self, issuer, subject, tenant, user, session);
            Ok(())
        })
    }

    fn forget_subject_session<'a>(
        &'a self,
        issuer: &'a str,
        user: &'a UserId,
        session: &'a SessionId,
    ) -> SidFuture<'a, bool> {
        Box::pin(async move { Ok(SidMap::forget_subject_session(self, issuer, user, session)) })
    }

    fn subject_sessions<'a>(
        &'a self,
        issuer: &'a str,
        subject: &'a str,
        scope: Option<&'a TenantId>,
    ) -> SidFuture<'a, Vec<(UserId, SessionId)>> {
        Box::pin(async move { Ok(SidMap::subject_sessions_in(self, issuer, subject, scope)) })
    }

    fn sweep_subject_candidates(
        &self,
        max: usize,
    ) -> SidFuture<'_, Vec<(String, UserId, SessionId)>> {
        Box::pin(async move { Ok(SidMap::sweep_subject_candidates(self, max)) })
    }

    fn remove_session<'a>(&'a self, session: &'a SessionId) -> SidFuture<'a, usize> {
        Box::pin(async move { Ok(SidMap::remove_session(self, session)) })
    }

    fn evict_inserted_before(
        &self,
        cutoff: DateTime<Utc>,
        max: usize,
    ) -> SidFuture<'_, Vec<(SidKey, SidEntry)>> {
        Box::pin(async move { Ok(SidMap::evict_inserted_before(self, cutoff, max)) })
    }

    fn evict_oldest(&self, max: usize) -> SidFuture<'_, Vec<(SidKey, SidEntry)>> {
        Box::pin(async move { Ok(SidMap::evict_oldest(self, max)) })
    }

    fn mapping_count(&self) -> SidFuture<'_, usize> {
        Box::pin(async move { Ok(SidMap::len(self)) })
    }
}

impl From<SidMap> for Arc<dyn SidStore> {
    fn from(map: SidMap) -> Self {
        Arc::new(map)
    }
}
