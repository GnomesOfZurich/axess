//! `StoredDelegationSession`: runtime accessor for a user's
//! delegated credential. Loads from the store, refreshes the access
//! token if it's near expiry, and returns a plaintext bearer string
//! to the caller.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use axess_clock::{Clock, SystemClock};
use axess_identity::{TenantId, UserId};

use crate::delegated::error::DelegatedError;

use super::credential::{CredentialSwap, DelegatedCredentialStore, StoredDelegation, store_err};
use super::grant::{GrantRegistration, refresh_token_grant};
use super::provider::DelegatedProvider;

/// Default skew applied to `expires_at` when deciding "refresh now?".
/// Refreshing 60 s before true expiry gives the downstream call
/// headroom for clock drift between axess and the IdP plus normal
/// network latency.
const DEFAULT_REFRESH_SKEW: std::time::Duration = std::time::Duration::from_secs(60);

/// The largest refresh skew [`StoredDelegationSession::with_refresh_skew`]
/// keeps: one day.
const MAX_REFRESH_SKEW: std::time::Duration = std::time::Duration::from_secs(86_400);

/// Idle entries are pruned from the single-flight registry once it
/// holds more than this many keys.
const REFRESH_LOCK_PRUNE_THRESHOLD: usize = 1024;

/// The process-wide default HTTP client: built once, so every session
/// that does not call [`StoredDelegationSession::with_client_settings`]
/// shares one connection pool. A clone is a reference-count bump.
///
/// A build failure (the TLS backend failed to initialise) is returned, not
/// remembered, so the next session tries again. No client stands in for it:
/// the refresh POST carries the client credentials and the refresh token,
/// and a stock `reqwest::Client` would follow a 307 or 308 with them and
/// wait for ever.
fn default_http_client() -> Result<reqwest::Client, DelegatedError> {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    if let Some(client) = CLIENT.get() {
        return Ok(client.clone());
    }
    let built = crate::outbound_http::hardened_client(|settings| settings)?;
    Ok(CLIENT.get_or_init(|| built).clone())
}

/// Say, once per store type, that a refresh fell back to an unconditional
/// save because the store has no compare-and-swap. Without one, a revoke from
/// another process while a refresh is in flight is written back.
fn warn_unsupported_once<S>() {
    static WARNED: OnceLock<Mutex<std::collections::HashSet<&'static str>>> = OnceLock::new();
    let name = std::any::type_name::<S>();
    let first = WARNED
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(name);
    if first {
        tracing::warn!(
            store = name,
            "the delegated credential store does not implement save_if_unchanged; a refresh \
             writes its result unconditionally, so a revoke from another process while it \
             is in flight is overwritten. Implement it atomically (a conditional UPDATE)."
        );
    }
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
/// [`with_client_settings`](Self::with_client_settings), every session uses
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
    refresh_skew: std::time::Duration,
}

impl<S> StoredDelegationSession<S>
where
    S: DelegatedCredentialStore,
{
    /// Build a session. Defaults: [`SystemClock`], the shared default
    /// [`reqwest::Client`], 60-second refresh skew.
    ///
    /// # Errors
    ///
    /// [`DelegatedError::ClientBuild`] when the default HTTP client cannot be
    /// built (the TLS backend failed to initialise). No client with the
    /// protections missing is built in its place.
    pub fn new(
        provider: Arc<DelegatedProvider>,
        store: Arc<S>,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Self, DelegatedError> {
        Ok(Self {
            provider,
            store,
            tenant,
            user,
            http: default_http_client()?,
            clock: Arc::new(SystemClock),
            refresh_skew: DEFAULT_REFRESH_SKEW,
        })
    }

    /// Add settings to the HTTP client of the refresh: a `User-Agent`, a
    /// trusted root certificate, a client certificate for outbound mTLS,
    /// timeouts.
    ///
    /// The client is built again with `configure`'s settings before the
    /// library's own, so it still follows no redirect: a
    /// [`ClientSettings`](axess_factors::egress::ClientSettings) offers
    /// nothing that could change that, and a whole client of the caller's
    /// own is not taken, since a redirect it followed would carry the
    /// credentials to wherever it points. A proxy named in the environment
    /// (`HTTPS_PROXY`) is followed, as before. The endpoint check (HTTPS, or
    /// HTTP to a loopback host) still applies.
    ///
    /// # Errors
    ///
    /// [`DelegatedError::ClientBuild`] when the client cannot be built with the
    /// settings.
    pub fn with_client_settings(
        mut self,
        configure: impl FnOnce(
            axess_factors::egress::ClientSettings,
        ) -> axess_factors::egress::ClientSettings,
    ) -> Result<Self, DelegatedError> {
        self.http = crate::outbound_http::hardened_client(configure)?;
        Ok(self)
    }

    /// Inject a clock for deterministic simulation testing.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Override the refresh-skew (default: 60 s). Refresh triggers
    /// when `now >= expires_at - skew`. A skew longer than one day is held
    /// to one day.
    pub fn with_refresh_skew(mut self, skew: std::time::Duration) -> Self {
        self.refresh_skew = skew.min(MAX_REFRESH_SKEW);
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
    /// Returns [`DelegatedError::RegistrationMismatch`] when the stored
    /// credential was granted through another registration than this
    /// session's provider ([`StoredDelegation::registration`]), one of the
    /// same name included, or through none: nothing is handed out and
    /// nothing is sent, fresh or not, and the user grants again.
    ///
    /// Cancelling the returned future (a request timeout, a client that
    /// hangs up) never loses a rotated refresh token: once the IdP has been
    /// asked to redeem the token, the redeem-and-save step runs to the end in
    /// its own task that holds the single-flight lock, whether or not anyone
    /// is still waiting for the result.
    pub async fn get_access_token(&self) -> Result<String, DelegatedError> {
        let job = self.job();
        let skew = self.refresh_skew;
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
            let redeemed = job.redeem_and_save(cred, skew).await;
            drop(guard);
            redeemed
        })
        .await
        .map_err(|e| DelegatedError::Transport(format!("refresh task failed: {e}")))?
    }

    /// The owned parts of a refresh, for the task that outlives a cancelled
    /// caller.
    fn job(&self) -> RefreshJob<S> {
        RefreshJob {
            registration: GrantRegistration::of(&self.provider),
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
    ///
    /// Takes the same single-flight lock as a refresh, so a refresh in flight
    /// finishes first and the removal comes after it: once this returns, no
    /// later [`get_access_token`](Self::get_access_token) in this process
    /// succeeds. Across processes the refresh writes its result with
    /// [`save_if_unchanged`](DelegatedCredentialStore::save_if_unchanged), so
    /// a row removed meanwhile is not written back; a store without that
    /// compare-and-swap leaves a revoke from another process racing a
    /// refresh.
    pub async fn revoke(&self) -> Result<(), DelegatedError> {
        let lock = refresh_lock((self.tenant, self.user, self.provider.name.clone()));
        let guard = lock.lock().await;
        let revoked = self
            .store
            .revoke(&self.tenant, &self.user, &self.provider.name)
            .await
            .map_err(store_err);
        drop(guard);
        revoked
    }
}

/// Everything a refresh needs, owned, so it can run in a spawned task.
struct RefreshJob<S>
where
    S: DelegatedCredentialStore,
{
    provider: Arc<DelegatedProvider>,
    /// The registration `provider` is: a credential granted through any
    /// other is not used.
    registration: GrantRegistration,
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
    /// The stored credential, when it was granted through this session's
    /// registration. The store's key is the provider's name, which another
    /// registration may share: a credential of any other registration, or of
    /// none, is refused before its access token is handed out or its refresh
    /// token is sent anywhere.
    async fn load_credential(&self) -> Result<StoredDelegation, DelegatedError> {
        let credential = self
            .store
            .load(&self.tenant, &self.user, &self.provider.name)
            .await
            .map_err(store_err)?
            .ok_or(DelegatedError::NotConnected)?;
        if credential.registration.as_ref() != Some(&self.registration) {
            return Err(DelegatedError::RegistrationMismatch {
                provider: self.provider.name.clone(),
            });
        }
        Ok(credential)
    }

    /// Redeem `cred`'s refresh token and persist the result. The caller
    /// holds the single-flight lock.
    async fn redeem_and_save(
        &self,
        cred: StoredDelegation,
        skew: std::time::Duration,
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
        // Saved before the token type is judged: the IdP has already rotated
        // the refresh token and spent the old one, so refusing the answer
        // must not lose the new one.
        let access = bearer(&final_credential);
        // Written only over the row the refresh started from: a row removed
        // (the user disconnected) or replaced (they reconnected) while the
        // IdP was asked is not overwritten.
        let swap = self
            .store
            .save_if_unchanged(&self.tenant, &self.user, cred, final_credential.clone())
            .await
            .map_err(store_err)?;
        match swap {
            CredentialSwap::Saved => access,
            CredentialSwap::Unsupported => {
                // A store without compare-and-swap: the lock in `revoke`
                // still orders a revoke in this process after the refresh,
                // but a revoke from another process can be overwritten.
                warn_unsupported_once::<S>();
                self.store
                    .save(&self.tenant, &self.user, final_credential)
                    .await
                    .map_err(store_err)?;
                access
            }
            CredentialSwap::Changed => {
                // Whatever is stored now is the user's latest word: nothing
                // when they disconnected, a newer credential when they
                // reconnected.
                bearer(&self.load_credential().await?)
            }
        }
    }
}
