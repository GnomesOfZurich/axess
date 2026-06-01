//! Stored delegated credential + persistence trait.
//!
//! `StoredDelegation` carries the (access_token, refresh_token,
//! expires_at, scopes) tuple resulting from a successful
//! `complete_grant` or subsequent refresh. The
//! `DelegatedCredentialStore` trait is the persistence boundary;
//! adopters implement against their existing storage (SQL / Valkey /
//! HSM-backed vault). `MemoryDelegatedCredentialStore` is provided
//! for dev / test only; it stores plaintext refresh tokens in
//! memory, which is **not acceptable for production**: refresh
//! tokens are long-lived secrets and MUST be encrypted at rest by
//! the adopter's real storage backend.

use std::collections::HashMap;
use std::sync::Mutex;

use axess_identity::{TenantId, UserId};
use chrono::{DateTime, Utc};

use crate::delegated::error::DelegatedError;
use axess_factors::ZeroizedString;

/// A stored delegated credential: the result of a completed
/// authorization-code grant, plus everything needed to drive
/// refresh-token rotation later.
///
/// Both `access_token` and (when present) `refresh_token` are held in
/// [`ZeroizedString`]s so the in-memory copy is zeroed on drop. The
/// adopter's store impl is responsible for encryption-at-rest before
/// these strings touch durable storage.
#[derive(Debug, Clone)]
pub struct StoredDelegation {
    /// Provider this credential belongs to; matches the
    /// `DelegatedProvider::name` field of the originating grant.
    pub provider: String,
    /// Current access token. Use via
    /// [`StoredDelegationSession::get_access_token`](super::session::StoredDelegationSession::get_access_token);
    /// don't reach into `access_token` directly because the session
    /// owns refresh-before-expiry semantics.
    pub access_token: ZeroizedString,
    /// Refresh token granted at `complete_grant` time, if any. Some
    /// IdPs only return a refresh token on the first authorization;
    /// subsequent refreshes may or may not rotate it (RFC 6749 §6).
    pub refresh_token: Option<ZeroizedString>,
    /// When the `access_token` becomes invalid. `None` means the IdP
    /// did not return `expires_in`; treat as "unknown, refresh on
    /// every use" (conservative) or "long-lived, never refresh"
    /// (provider-specific knowledge required).
    pub expires_at: Option<DateTime<Utc>>,
    /// Scopes the IdP actually granted. May be a subset of those
    /// requested at `begin_grant`; some IdPs only echo scopes the
    /// user actively consented to.
    pub scopes: Vec<String>,
    /// `token_type` per RFC 6749 §5.1; almost always `Bearer`.
    /// Captured verbatim so adopters that talk to a provider using
    /// `MAC` / DPoP can route accordingly.
    pub token_type: String,
}

impl StoredDelegation {
    /// Whether this credential's `access_token` is still considered
    /// fresh against `now`. `None` `expires_at` is treated as fresh
    /// (caller decides whether to refresh proactively); a Some
    /// expiry compares directly.
    pub fn is_fresh(&self, now: DateTime<Utc>, skew: chrono::Duration) -> bool {
        match self.expires_at {
            Some(exp) => now < exp - skew,
            None => true,
        }
    }
}

/// Persistence boundary for stored delegated credentials.
///
/// Adopters implement against their preferred storage. Each method
/// is keyed by `(tenant_id, user_id, provider_name)`; the same
/// (tenant, user) tuple can hold credentials for multiple providers
/// (e.g. Gmail + Salesforce + Zoho simultaneously).
///
/// **Encryption-at-rest is the implementor's responsibility.** The
/// refresh token is the long-lived secret; storing it plaintext in
/// any production backend is a credential-stuffing time-bomb.
/// `MemoryDelegatedCredentialStore` deliberately does not encrypt;
/// it is for tests + dev only.
pub trait DelegatedCredentialStore: Send + Sync + 'static {
    /// Load the credential for `(tenant, user, provider)`. `Ok(None)`
    /// means "user hasn't connected this provider yet". Errors are
    /// surfaced as a free-form string so the trait doesn't constrain
    /// the implementor's concrete error type.
    fn load(
        &self,
        tenant: &TenantId,
        user: &UserId,
        provider: &str,
    ) -> impl std::future::Future<Output = Result<Option<StoredDelegation>, String>> + Send;

    /// Persist a credential for `(tenant, user, provider)`. Overwrites
    /// any existing record (refresh-token rotation lands here, not as
    /// a separate update path; the store treats the full
    /// credential as the unit of write).
    fn save(
        &self,
        tenant: &TenantId,
        user: &UserId,
        credential: StoredDelegation,
    ) -> impl std::future::Future<Output = Result<(), String>> + Send;

    /// Remove the credential for `(tenant, user, provider)`. Idempotent
    /// removing a non-existent record returns `Ok(())`. Adopters
    /// surface "user disconnected their Gmail account" through this
    /// path.
    fn revoke(
        &self,
        tenant: &TenantId,
        user: &UserId,
        provider: &str,
    ) -> impl std::future::Future<Output = Result<(), String>> + Send;
}

/// In-memory `DelegatedCredentialStore` for dev + test. Holds
/// plaintext refresh tokens; **do not use in production**.
#[derive(Debug, Default)]
pub struct MemoryDelegatedCredentialStore {
    inner: Mutex<HashMap<(TenantId, UserId, String), StoredDelegation>>,
}

impl MemoryDelegatedCredentialStore {
    /// Construct an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl DelegatedCredentialStore for MemoryDelegatedCredentialStore {
    async fn load(
        &self,
        tenant: &TenantId,
        user: &UserId,
        provider: &str,
    ) -> Result<Option<StoredDelegation>, String> {
        let guard = self.inner.lock().map_err(|e| e.to_string())?;
        Ok(guard.get(&(*tenant, *user, provider.to_string())).cloned())
    }

    async fn save(
        &self,
        tenant: &TenantId,
        user: &UserId,
        credential: StoredDelegation,
    ) -> Result<(), String> {
        let mut guard = self.inner.lock().map_err(|e| e.to_string())?;
        let key = (*tenant, *user, credential.provider.clone());
        guard.insert(key, credential);
        Ok(())
    }

    async fn revoke(&self, tenant: &TenantId, user: &UserId, provider: &str) -> Result<(), String> {
        let mut guard = self.inner.lock().map_err(|e| e.to_string())?;
        guard.remove(&(*tenant, *user, provider.to_string()));
        Ok(())
    }
}

/// Convert a `String` store-error into [`DelegatedError::Store`]. The
/// trait surface uses a free-form string so each implementor can carry
/// its own error type; the runtime path normalises here.
pub(crate) fn store_err(e: String) -> DelegatedError {
    DelegatedError::Store(e)
}
