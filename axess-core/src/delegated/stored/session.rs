//! `StoredDelegationSession`: runtime accessor for a user's
//! delegated credential. Loads from the store, refreshes the access
//! token if it's near expiry, and returns a plaintext bearer string
//! to the caller.

use std::sync::Arc;

use axess_clock::{Clock, SystemClock};
use axess_identity::{TenantId, UserId};

use crate::delegated::error::DelegatedError;

use super::credential::{DelegatedCredentialStore, store_err};
use super::grant::refresh_token_grant;
use super::provider::DelegatedProvider;

/// Default skew applied to `expires_at` when deciding "refresh now?".
/// Refreshing 60 s before true expiry gives the downstream call
/// headroom for clock drift between axess and the IdP plus normal
/// network latency.
const DEFAULT_REFRESH_SKEW_SECS: i64 = 60;

/// Per-request handle to a user's delegated credential.
///
/// Construct one per outbound call; the wrapped store, provider, and
/// HTTP client are long-lived and shared via `Arc`. Calling
/// [`get_access_token`](Self::get_access_token) loads the credential,
/// refreshes it transparently if needed, and returns a fresh bearer
/// string.
pub struct StoredDelegationSession<S>
where
    S: DelegatedCredentialStore,
{
    provider: Arc<DelegatedProvider>,
    store: Arc<S>,
    tenant: TenantId,
    user: UserId,
    http: reqwest::Client,
    clock: Arc<dyn Clock>,
    refresh_skew_secs: i64,
}

impl<S> StoredDelegationSession<S>
where
    S: DelegatedCredentialStore,
{
    /// Build a session. Defaults: [`SystemClock`], default
    /// [`reqwest::Client`], 60-second refresh skew.
    pub fn new(
        provider: Arc<DelegatedProvider>,
        store: Arc<S>,
        tenant: TenantId,
        user: UserId,
    ) -> Self {
        Self {
            provider,
            store,
            tenant,
            user,
            http: reqwest::Client::new(),
            clock: Arc::new(SystemClock),
            refresh_skew_secs: DEFAULT_REFRESH_SKEW_SECS,
        }
    }

    /// Override the HTTP client; useful for adopter-side TLS / proxy
    /// / timeout configuration.
    pub fn with_http_client(mut self, http: reqwest::Client) -> Self {
        self.http = http;
        self
    }

    /// Inject a clock for deterministic simulation testing.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Override the refresh-skew (default: 60 s). Refresh triggers
    /// when `now >= expires_at - skew`.
    pub fn with_refresh_skew_secs(mut self, secs: i64) -> Self {
        self.refresh_skew_secs = secs;
        self
    }

    /// Load the credential, refresh if needed, return a bearer string.
    ///
    /// Returns [`DelegatedError::NotConnected`] if the user has not
    /// granted axess access to this provider (no record in the
    /// store). Returns [`DelegatedError::RefreshRejected`] if the
    /// stored refresh token was rejected by the IdP; the adopter
    /// surfaces this to the user as "your `<provider>` connection
    /// expired, please reconnect".
    pub async fn get_access_token(&self) -> Result<String, DelegatedError> {
        let cred = self
            .store
            .load(&self.tenant, &self.user, &self.provider.name)
            .await
            .map_err(store_err)?
            .ok_or(DelegatedError::NotConnected)?;

        let now = self.clock.now();
        let skew = chrono::Duration::seconds(self.refresh_skew_secs);
        if cred.is_fresh(now, skew) {
            return Ok((*cred.access_token).to_string());
        }

        // Stale; refresh. Without a refresh_token there's nothing
        // we can do; surface as RefreshRejected so adopter UX routes
        // to the reconnect flow.
        let refresh_token = cred
            .refresh_token
            .as_deref()
            .ok_or(DelegatedError::RefreshRejected)?
            .to_string();

        let refreshed = refresh_token_grant(&self.provider, &refresh_token, &self.http).await?;

        // RFC 6749 §6: some IdPs rotate the refresh token (return a
        // new one in the response), others keep the existing one
        // valid (omit it). Preserve the original on omission.
        let final_credential = super::credential::StoredDelegation {
            refresh_token: refreshed.refresh_token.or(cred.refresh_token),
            ..refreshed
        };
        let access = (*final_credential.access_token).to_string();
        self.store
            .save(&self.tenant, &self.user, final_credential)
            .await
            .map_err(store_err)?;
        Ok(access)
    }

    /// Revoke the user's connection to this provider; removes the
    /// credential from the store. Best-effort: does not attempt to
    /// inform the IdP. Adopters wanting server-side revocation should
    /// POST to the provider's revocation endpoint separately (out of
    /// scope for this module; semantics vary per provider).
    pub async fn revoke(&self) -> Result<(), DelegatedError> {
        self.store
            .revoke(&self.tenant, &self.user, &self.provider.name)
            .await
            .map_err(store_err)
    }
}
