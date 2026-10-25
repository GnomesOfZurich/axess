//! Background JWKS refresh task.
//!
//! Spawns a periodic ticker that calls [`OAuthProvider::refresh_jwks`]
//! on every registered provider. Proactive: picks up IdP key rotations
//! without waiting for a back-channel logout to trip on a missing `kid`.
//!
//! Lifetime is owned by the caller via the returned [`JoinHandle`];
//! dropping the handle does NOT cancel the task (see the
//! [`AuthnService::spawn_jwks_refresh`] rustdoc).

use crate::authn::service::AuthnService;
use crate::authn::store::{FactorStore, IdentityStore};

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Refresh the JWKS of every registered OAuth provider once and return
    /// the providers whose refresh failed, with their errors.
    ///
    /// This is the body of every tick of
    /// [`spawn_jwks_refresh`](Self::spawn_jwks_refresh), callable on its
    /// own: deterministic tests and schedulers that already own a timer call
    /// it directly instead of waiting on the spawned loop. Each provider
    /// applies its own refresh debounce on its own clock, so a call inside
    /// the debounce window is a cheap no-op for providers refreshed
    /// moments ago.
    pub async fn refresh_all_jwks(
        &self,
    ) -> Vec<(std::sync::Arc<str>, axess_factors::oauth::OAuthError)> {
        let providers: Vec<_> = self.inner.oauth_providers.values().cloned().collect();
        axess_factors::oauth::refresh_providers_jwks(&providers).await
    }

    /// Spawn a background task that periodically refreshes the JWKS for all
    /// registered OAuth providers.
    ///
    /// This proactively picks up IdP key rotations without waiting for a
    /// back-channel logout to fail on a missing `kid`.
    ///
    /// # Lifetime: call `.abort()` to stop
    ///
    /// **Dropping the returned [`tokio::task::JoinHandle`] does NOT cancel
    /// the task**: the spawned future keeps running and holds a strong
    /// `Arc` to every registered provider. Operators that bind the handle
    /// to `_jwks_task` and let it drop end up leaking the task and the
    /// provider Arcs for the rest of the process lifetime.
    ///
    /// To stop the task, hold the `JoinHandle` and call `.abort()` on
    /// shutdown:
    ///
    /// ```rust,ignore
    /// let jwks_task = authn.spawn_jwks_refresh(std::time::Duration::from_secs(3600));
    /// // …on shutdown:
    /// jwks_task.abort();
    /// ```
    ///
    /// # Runtime boundary
    ///
    /// The ticker is `tokio::time::interval` inside a `tokio::spawn`ed task,
    /// which sits outside the injected `Clock`: advancing a `MockClock`
    /// does not fire it. Code that needs to control when a refresh happens
    /// calls [`refresh_all_jwks`](Self::refresh_all_jwks) itself.
    ///
    /// For a more structured cancellation source, store a
    /// `tokio_util::sync::CancellationToken` alongside the task and have
    /// the loop poll it via `tokio::select!`.
    ///
    /// # Arguments
    ///
    /// * `interval`: how often to refresh (e.g. `Duration::from_secs(3600)` for hourly).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let authn = Arc::new(
    ///     AuthnService::builder(identity, factors)
    ///         .with_oauth_provider("google", google_provider)
    ///         .build(),
    /// );
    ///
    /// // Refresh JWKS every hour. Keep the handle and abort on shutdown
    /// // (or this task lives forever).
    /// let jwks_task = authn.spawn_jwks_refresh(Duration::from_secs(3600));
    /// // …
    /// jwks_task.abort();
    /// ```
    pub fn spawn_jwks_refresh(&self, interval: std::time::Duration) -> tokio::task::JoinHandle<()> {
        let providers: Vec<_> = self.inner.oauth_providers.values().cloned().collect();
        spawn_refresh_loop(providers, interval)
    }
}

/// The refresh loop: one pass over `providers` per `interval`, the first
/// pass one interval after the start. A zero interval falls back to the
/// 60 s debounce window, because a zero period would panic inside the task
/// and end the loop silently.
fn spawn_refresh_loop(
    providers: Vec<std::sync::Arc<dyn axess_factors::oauth::OAuthProvider>>,
    interval: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    let interval = if interval.is_zero() {
        tracing::warn!("spawn_jwks_refresh: zero interval; using 60 s");
        axess_factors::oidc::MIN_JWKS_REFRESH_INTERVAL
    } else {
        interval
    };
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // Skip the immediate first tick.
        loop {
            ticker.tick().await;
            axess_factors::oauth::refresh_providers_jwks(&providers).await;
        }
    })
}

/// A refresh loop owned by a built service: it is aborted when the last
/// clone of the service is dropped, so it never outlives the service that
/// started it.
pub(crate) struct JwksRefreshTask(tokio::task::JoinHandle<()>);

impl JwksRefreshTask {
    /// Start the loop on the current tokio runtime. Without a runtime
    /// nothing is started and a warning says so.
    pub(crate) fn start(
        providers: Vec<std::sync::Arc<dyn axess_factors::oauth::OAuthProvider>>,
        interval: std::time::Duration,
    ) -> Option<Self> {
        if tokio::runtime::Handle::try_current().is_err() {
            tracing::warn!(
                "with_jwks_refresh: no tokio runtime at build time; the JWKS refresh \
                 loop was not started"
            );
            return None;
        }
        Some(Self(spawn_refresh_loop(providers, interval)))
    }
}

impl Drop for JwksRefreshTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
