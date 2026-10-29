//! `StoredDelegationSession`: runtime accessor for a user's
//! delegated credential. Loads from the store, refreshes the access
//! token if it's near expiry, and returns a plaintext bearer string
//! to the caller.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axess_clock::{Clock, SystemClock};
use axess_identity::{TenantId, UserId};

use crate::delegated::error::DelegatedError;

use super::credential::{DelegatedCredentialStore, StoredDelegation, store_err};
use super::grant::refresh_token_grant;
use super::provider::DelegatedProvider;

/// Default skew applied to `expires_at` when deciding "refresh now?".
/// Refreshing 60 s before true expiry gives the downstream call
/// headroom for clock drift between axess and the IdP plus normal
/// network latency.
const DEFAULT_REFRESH_SKEW_SECS: i64 = 60;

/// Connect timeout of the process-wide default HTTP client.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Overall timeout of the process-wide default HTTP client.
const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Idle entries are pruned from the single-flight registry once it
/// holds more than this many keys.
const REFRESH_LOCK_PRUNE_THRESHOLD: usize = 1024;

/// The process-wide default HTTP client: built once, so every session
/// that does not call [`StoredDelegationSession::with_http_client`]
/// shares one connection pool. A clone is a reference-count bump.
fn default_http_client() -> reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            // No redirects: the refresh POST carries the client credentials
            // and the refresh token, and a 307 or 308 would repeat it.
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
                .timeout(DEFAULT_HTTP_TIMEOUT)
                .build()
                .unwrap_or_default()
        })
        .clone()
}

/// The access token as a bearer string, for a `Bearer` credential only. A
/// sender-constrained token (DPoP, MAC) cannot be used as a bare bearer.
fn bearer(cred: &StoredDelegation) -> Result<String, DelegatedError> {
    if cred.token_type.eq_ignore_ascii_case("Bearer") {
        Ok((*cred.access_token).to_string())
    } else {
        Err(DelegatedError::UnsupportedTokenType(
            cred.token_type.clone(),
        ))
    }
}

type RefreshKey = (TenantId, UserId, String);

/// The lock serialising refreshes of one `(tenant, user, provider)`
/// credential across every session in the process. Sessions are built
/// per request, so the registry cannot live on them.
fn refresh_lock(key: RefreshKey) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<RefreshKey, Arc<tokio::sync::Mutex<()>>>>> =
        OnceLock::new();
    let mut map = LOCKS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if map.len() > REFRESH_LOCK_PRUNE_THRESHOLD {
        // An entry only the registry references has no refresh in
        // flight or waiting.
        map.retain(|_, lock| Arc::strong_count(lock) > 1);
    }
    Arc::clone(map.entry(key).or_default())
}

/// Per-request handle to a user's delegated credential.
///
/// Construct one per outbound call; the wrapped store and provider
/// are long-lived and shared via `Arc`. Unless overridden with
/// [`with_http_client`](Self::with_http_client), every session uses
/// one process-wide [`reqwest::Client`] (a single connection pool,
/// 30-second timeout). Concurrent refreshes of the same credential
/// are serialised process-wide, so a rotating refresh token is
/// redeemed once and the other callers pick up the stored result.
/// Calling
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
    /// Build a session. Defaults: [`SystemClock`], the shared default
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
            http: default_http_client(),
            clock: Arc::new(SystemClock),
            refresh_skew_secs: DEFAULT_REFRESH_SKEW_SECS,
        }
    }

    /// Override the HTTP client; useful for adopter-side TLS / proxy
    /// / timeout configuration.
    ///
    /// A replacement client drops the default client's protections: it must
    /// be built with `redirect(reqwest::redirect::Policy::none())` and a
    /// connect and request timeout, or a redirect re-sends the client
    /// credentials and refresh token to wherever it points. The provider's
    /// token endpoint check (HTTPS, or HTTP to a loopback host) still
    /// applies.
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
    ///
    /// Cancelling the returned future (a request timeout, a client that
    /// hangs up) never loses a rotated refresh token: once the IdP has been
    /// asked to redeem the token, the redeem-and-save step runs to the end in
    /// its own task that holds the single-flight lock, whether or not anyone
    /// is still waiting for the result.
    pub async fn get_access_token(&self) -> Result<String, DelegatedError> {
        let job = self.job();
        let skew = chrono::Duration::seconds(self.refresh_skew_secs);
        let cred = job.load_credential().await?;
        if cred.is_fresh(self.clock.now(), skew) {
            return bearer(&cred);
        }

        // Stale. Only one refresh per credential runs at a time: a
        // rotating refresh token can be redeemed once, and some IdPs
        // revoke the whole grant when a spent token is replayed. The guard
        // is owned so the task below can hold it past this future.
        let lock = refresh_lock((self.tenant, self.user, self.provider.name.clone()));
        let guard = lock.lock_owned().await;

        // A caller ahead of us may have refreshed while we waited.
        let cred = job.load_credential().await?;
        if cred.is_fresh(self.clock.now(), skew) {
            return bearer(&cred);
        }

        tokio::spawn(async move {
            let _guard = guard;
            job.redeem_and_save(cred, skew).await
        })
        .await
        .map_err(|e| DelegatedError::Transport(format!("refresh task failed: {e}")))?
    }

    /// The owned parts of a refresh, for the task that outlives a cancelled
    /// caller.
    fn job(&self) -> RefreshJob<S> {
        RefreshJob {
            provider: Arc::clone(&self.provider),
            store: Arc::clone(&self.store),
            tenant: self.tenant,
            user: self.user,
            http: self.http.clone(),
            clock: Arc::clone(&self.clock),
        }
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

/// Everything a refresh needs, owned, so it can run in a spawned task.
struct RefreshJob<S>
where
    S: DelegatedCredentialStore,
{
    provider: Arc<DelegatedProvider>,
    store: Arc<S>,
    tenant: TenantId,
    user: UserId,
    http: reqwest::Client,
    clock: Arc<dyn Clock>,
}

impl<S> RefreshJob<S>
where
    S: DelegatedCredentialStore,
{
    async fn load_credential(&self) -> Result<StoredDelegation, DelegatedError> {
        self.store
            .load(&self.tenant, &self.user, &self.provider.name)
            .await
            .map_err(store_err)?
            .ok_or(DelegatedError::NotConnected)
    }

    /// Redeem `cred`'s refresh token and persist the result. The caller
    /// holds the single-flight lock.
    async fn redeem_and_save(
        &self,
        cred: StoredDelegation,
        skew: chrono::Duration,
    ) -> Result<String, DelegatedError> {
        match self.refresh(&cred).await {
            Err(DelegatedError::RefreshRejected) => {
                // Another node may have rotated the token since we
                // loaded it. Reload once before giving up.
                let latest = self.load_credential().await?;
                if latest.is_fresh(self.clock.now(), skew) {
                    return bearer(&latest);
                }
                if latest.refresh_token.as_deref() != cred.refresh_token.as_deref() {
                    return self.refresh(&latest).await;
                }
                Err(DelegatedError::RefreshRejected)
            }
            other => other,
        }
    }

    /// Redeem `cred`'s refresh token, persist the result, and return
    /// the new access token.
    async fn refresh(&self, cred: &StoredDelegation) -> Result<String, DelegatedError> {
        // Without a refresh_token there's nothing we can do; surface
        // as RefreshRejected so adopter UX routes to the reconnect
        // flow.
        let refresh_token = cred
            .refresh_token
            .as_deref()
            .ok_or(DelegatedError::RefreshRejected)?;

        let refreshed =
            refresh_token_grant(&self.provider, refresh_token, &self.http, &*self.clock).await?;

        // RFC 6749 §6: some IdPs rotate the refresh token (return a
        // new one in the response), others keep the existing one
        // valid (omit it). Preserve the original on omission. The same
        // section says an omitted `scope` means the scope is unchanged, so
        // the stored scopes survive a response that does not restate them.
        let final_credential = StoredDelegation {
            refresh_token: refreshed
                .credential
                .refresh_token
                .or_else(|| cred.refresh_token.clone()),
            scopes: refreshed.scope.unwrap_or_else(|| cred.scopes.clone()),
            ..refreshed.credential
        };
        let access = bearer(&final_credential)?;
        self.store
            .save(&self.tenant, &self.user, final_credential)
            .await
            .map_err(store_err)?;
        Ok(access)
    }
}
