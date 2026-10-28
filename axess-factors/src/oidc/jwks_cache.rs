//! JWKS cache with single-flight refresh + min-interval coalescing.
//!
//! Thundering-herd-resistant refresh path reusable by any adopter that
//! verifies JWTs from an OIDC-style issuer (federated IdPs, JWT-SVID
//! workloads, custom token validators) without taking the full OAuth
//! ceremony surface.

use crate::oidc::error::OidcError;
use jsonwebtoken::jwk::JwkSet;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use axess_clock::{Clock, SystemClock};
use tokio::sync::Mutex as AsyncMutex;

/// Lower bound on the gap between consecutive JWKS refreshes per cache.
///
/// Concurrent callers that arrive within this window after a successful
/// refresh are short-circuited without re-hitting the network. 60 s
/// matches OIDC IdP norms: most rotate keys at multi-hour granularity,
/// so a 60-second debounce never delays legitimate rotation pickup by
/// more than the time to verify one re-issued JWT, while still squashing
/// herds on rotation events.
pub const MIN_JWKS_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// How long after a FAILED fetch further refresh calls are refused without
/// touching the network. Without it, N concurrent unknown-`kid` callers
/// against a failing endpoint each wait their turn on the single-flight lock
/// and each issue their own request, which is the herd the success debounce
/// exists to prevent, at the moment the endpoint is least able to take it.
const JWKS_FAILURE_BACKOFF: Duration = Duration::from_secs(5);

/// Default maximum age of a cached key set: 24 hours.
///
/// A key set older than this is refused by [`JwksCache::ensure_fresh`] until a
/// refresh succeeds, so a revoked or rotated-out signing key cannot stay
/// trusted for ever by a process whose refresh loop has stopped or whose IdP
/// is unreachable. Change it with [`JwksCache::with_max_age`].
pub const DEFAULT_JWKS_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Largest JWKS response body read (1 MiB). A key set is a few kilobytes; a
/// larger body is refused while it arrives, not buffered.
pub const MAX_JWKS_BYTES: usize = 1024 * 1024;

/// Refreshable JWKS cache backed by an HTTP `jwks_uri`.
///
/// Owns a cloned [`openidconnect::reqwest::Client`] so [`refresh`](Self::refresh) is callable
/// without the original caller threading the client through every site.
///
/// # Single-flight + min-interval coalescing
///
/// The naive implementation lets N concurrent unknown-`kid` tokens each
/// fire their own HTTPS GET to `jwks_uri`. Most IdPs rate-limit the JWKS
/// endpoint; tripping that limit *blocks legitimate rotation recovery*,
/// exactly the time the cache is stalest. [`refresh`](Self::refresh):
///
/// 1. Serialises concurrent callers via an internal async refresh mutex.
///    Only one HTTPS request is in flight at a time per cache.
/// 2. Inside the lock, checks the timestamp of the most recent refresh.
///    If a peer just refreshed within [`MIN_JWKS_REFRESH_INTERVAL`], the
///    waiter returns `Ok(())` without re-hitting the network; the herd
///    collapses into one fetch + N free returns.
/// 3. After a failed fetch, refuses further refreshes for
///    `JWKS_FAILURE_BACKOFF` without touching the network, and never
///    replaces the cached keys with a failed or empty result: the previous
///    key set keeps serving until a fetch succeeds.
///
/// # Maximum age
///
/// A key set has a maximum age ([`DEFAULT_JWKS_MAX_AGE`], set with
/// [`with_max_age`](Self::with_max_age)), counted from the last successful
/// fetch. [`ensure_fresh`](Self::ensure_fresh) and
/// [`fresh_handle`](Self::fresh_handle) refuse a key set older than that and
/// keep refusing until [`refresh`](Self::refresh) succeeds, so verification
/// fails closed when nothing keeps the keys current. The OAuth provider
/// checks it before every logout-token verification. [`handle`](Self::handle)
/// is the unchecked view for callers that apply their own policy. Keep the
/// keys current with a periodic refresh (the OAuth service can start one);
/// without it the keys expire by `max_age`.
///
/// # Clock
///
/// The debounce and the failure back-off are measured on an injected
/// [`Clock`] ([`SystemClock`] unless [`with_clock`](Self::with_clock) says
/// otherwise), so a `MockClock` steps through both windows without
/// sleeping. A wall clock can step backwards; a stamp that lies in the
/// future is treated as an expired window rather than suppressing refreshes
/// until real time catches up.
pub struct JwksCache {
    jwks_uri: String,
    http_client: openidconnect::reqwest::Client,
    jwks: Arc<RwLock<JwkSet>>,
    refresh_lock: Arc<AsyncMutex<()>>,
    clock: Arc<dyn Clock>,
    /// Unix milliseconds of the last successful refresh.
    last_refresh: Arc<Mutex<Option<i64>>>,
    /// Unix milliseconds of the last failed fetch.
    last_failure: Arc<Mutex<Option<i64>>>,
    /// Unix milliseconds at which the current key set was fetched.
    fetched_at: Arc<Mutex<i64>>,
    max_age: Duration,
}

impl std::fmt::Debug for JwksCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwksCache")
            .field("jwks_uri", &self.jwks_uri)
            .finish_non_exhaustive()
    }
}

/// Whether fewer than `window` has passed between the stamp and `now`.
/// A stamp after `now` (the clock stepped back) is not inside any window.
fn within(stamp_ms: i64, now_ms: i64, window: Duration) -> bool {
    let elapsed = now_ms.saturating_sub(stamp_ms);
    elapsed >= 0 && i128::from(elapsed) < window.as_millis() as i128
}

impl JwksCache {
    /// Fetch a JWKS from `jwks_uri` and return a cache primed with it.
    ///
    /// The supplied `http_client` is cloned and retained for subsequent
    /// [`refresh`](Self::refresh) calls. Callers should configure the
    /// client with redirects disabled (SSRF defense) and a per-operation
    /// timeout before passing it in.
    pub async fn fetch(
        jwks_uri: impl Into<String>,
        http_client: &openidconnect::reqwest::Client,
    ) -> Result<Self, OidcError> {
        let jwks_uri = jwks_uri.into();
        let jwks = fetch_key_set(http_client, &jwks_uri).await?;

        Ok(Self {
            jwks_uri,
            http_client: http_client.clone(),
            jwks: Arc::new(RwLock::new(jwks)),
            refresh_lock: Arc::new(AsyncMutex::new(())),
            clock: Arc::new(SystemClock),
            last_refresh: Arc::new(Mutex::new(None)),
            last_failure: Arc::new(Mutex::new(None)),
            fetched_at: Arc::new(Mutex::new(SystemClock.now().timestamp_millis())),
            max_age: DEFAULT_JWKS_MAX_AGE,
        })
    }

    /// Construct a cache from a pre-parsed [`JwkSet`].
    ///
    /// Useful when discovery and JWKS fetch are interleaved (e.g.
    /// [`crate::oidc::Discovery::fetch`]) so the initial JWKS bytes don't
    /// have to be fetched twice.
    pub fn from_parts(
        jwks_uri: impl Into<String>,
        http_client: &openidconnect::reqwest::Client,
        jwks: JwkSet,
    ) -> Self {
        Self {
            jwks_uri: jwks_uri.into(),
            http_client: http_client.clone(),
            jwks: Arc::new(RwLock::new(jwks)),
            refresh_lock: Arc::new(AsyncMutex::new(())),
            clock: Arc::new(SystemClock),
            last_refresh: Arc::new(Mutex::new(None)),
            last_failure: Arc::new(Mutex::new(None)),
            fetched_at: Arc::new(Mutex::new(SystemClock.now().timestamp_millis())),
            max_age: DEFAULT_JWKS_MAX_AGE,
        }
    }

    /// Measure the refresh debounce, the failure back-off and the key set's
    /// age on `clock`. The key set held at this moment counts as fetched now:
    /// install the clock right after construction.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        *self
            .fetched_at
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = clock.now().timestamp_millis();
        self.clock = clock;
        self
    }

    /// Set the maximum age of the key set (default [`DEFAULT_JWKS_MAX_AGE`]).
    /// Keep it well above the refresh interval, or a single failed refresh
    /// stops verification.
    #[must_use]
    pub fn with_max_age(mut self, max_age: Duration) -> Self {
        self.max_age = max_age;
        self
    }

    /// The configured maximum age of the key set.
    pub fn max_age(&self) -> Duration {
        self.max_age
    }

    /// Refuse a key set older than the maximum age.
    ///
    /// Returns [`OidcError::JwksExpired`] until a [`refresh`](Self::refresh)
    /// succeeds. A fetch time in the future (the clock stepped back) counts
    /// as fresh.
    pub fn ensure_fresh(&self) -> Result<(), OidcError> {
        let fetched = *self
            .fetched_at
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let age_ms = self.clock.now().timestamp_millis().saturating_sub(fetched);
        if age_ms > 0 && u128::from(age_ms.unsigned_abs()) > self.max_age.as_millis() {
            return Err(OidcError::JwksExpired {
                age_secs: age_ms.unsigned_abs() / 1000,
                max_age_secs: self.max_age.as_secs(),
            });
        }
        Ok(())
    }

    /// [`handle`](Self::handle), but only while the key set is within its
    /// maximum age.
    pub fn fresh_handle(&self) -> Result<Arc<RwLock<JwkSet>>, OidcError> {
        self.ensure_fresh()?;
        Ok(self.jwks.clone())
    }

    /// JWKS endpoint URL the cache fetches from.
    pub fn jwks_uri(&self) -> &str {
        &self.jwks_uri
    }

    /// Shared handle to the cached `JwkSet`. Verifiers should clone this
    /// and take a read lock per verification to avoid holding the lock
    /// across `.await`.
    pub fn handle(&self) -> Arc<RwLock<JwkSet>> {
        self.jwks.clone()
    }

    /// Re-fetch the JWKS from `jwks_uri` and replace the cached set.
    ///
    /// Coalesces concurrent callers via single-flight + min-interval
    /// debounce. Safe to call from a `kid`-miss code path or a
    /// background scheduler.
    pub async fn refresh(&self) -> Result<(), OidcError> {
        let refresh_guard = self.refresh_lock.lock().await;

        let now_ms = self.clock.now().timestamp_millis();
        let last = self
            .last_refresh
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .copied();
        if let Some(prev) = last
            && within(prev, now_ms, MIN_JWKS_REFRESH_INTERVAL)
        {
            tracing::debug!(
                jwks_uri = %self.jwks_uri,
                age_secs = now_ms.saturating_sub(prev) / 1000,
                "JWKS refresh coalesced; peer refreshed within debounce window",
            );
            return Ok(());
        }

        let last_failure = self
            .last_failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .copied();
        if let Some(prev) = last_failure
            && within(prev, now_ms, JWKS_FAILURE_BACKOFF)
        {
            return Err(OidcError::JwksFetch(
                "refresh suppressed: the previous fetch failed moments ago".to_string(),
            ));
        }

        let fetched = match fetch_key_set(&self.http_client, &self.jwks_uri).await {
            // A key set with no keys can verify nothing; installing it would
            // evict the last good keys and fail every login until the next
            // successful fetch. Keep serving what we have.
            Ok(set) if set.keys.is_empty() => Err(OidcError::JwksParse(
                "the endpoint returned a key set with no keys".to_string(),
            )),
            other => other,
        };
        let new_jwks = match fetched {
            Ok(set) => set,
            Err(e) => {
                *self
                    .last_failure
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                    Some(self.clock.now().timestamp_millis());
                return Err(e);
            }
        };

        let mut guard = self.jwks.write().unwrap_or_else(|poisoned| {
            tracing::warn!("JWKS RwLock was poisoned; recovering with fresh data");
            poisoned.into_inner()
        });
        *guard = new_jwks;
        *self
            .fetched_at
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = self.clock.now().timestamp_millis();
        *self
            .last_refresh
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some(self.clock.now().timestamp_millis());
        *self
            .last_failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        tracing::info!(jwks_uri = %self.jwks_uri, "JWKS refreshed successfully");
        drop(refresh_guard);
        Ok(())
    }
}

/// GET `jwks_uri` and parse the body as a key set.
///
/// Refuses a non-HTTPS `jwks_uri` (loopback excepted), a body over
/// [`MAX_JWKS_BYTES`] and any non-2xx response, so an error page that happens to parse as a key set can never
/// replace trusted keys.
async fn fetch_key_set(
    http_client: &openidconnect::reqwest::Client,
    jwks_uri: &str,
) -> Result<JwkSet, OidcError> {
    crate::oidc::discovery::require_https_or_loopback(jwks_uri)?;
    let mut response = http_client
        .get(jwks_uri)
        .send()
        .await
        .map_err(|e| OidcError::JwksFetch(format!("{e}")))?;
    let status = response.status();
    if !status.is_success() {
        return Err(OidcError::JwksFetch(format!("HTTP {status}")));
    }
    let bytes = crate::oidc::body::read_capped(
        &mut response,
        MAX_JWKS_BYTES,
        || OidcError::JwksFetch("JWKS body exceeds limit".to_string()),
        |e| OidcError::JwksFetch(format!("read body: {e}")),
    )
    .await?;
    serde_json::from_slice(&bytes).map_err(|e| OidcError::JwksParse(format!("{e}")))
}

#[cfg(test)]
mod tests;
