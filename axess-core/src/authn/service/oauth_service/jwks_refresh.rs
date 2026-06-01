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
    /// let authn = Arc::new(AuthnService::new(identity, factors)
    ///     .with_oauth_provider("google", google_provider));
    ///
    /// // Refresh JWKS every hour. Keep the handle and abort on shutdown
    /// // (or this task lives forever).
    /// let jwks_task = authn.spawn_jwks_refresh(Duration::from_secs(3600));
    /// // …
    /// jwks_task.abort();
    /// ```
    pub fn spawn_jwks_refresh(&self, interval: std::time::Duration) -> tokio::task::JoinHandle<()> {
        let providers: Vec<_> = self.oauth_providers.values().cloned().collect();

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // Skip the immediate first tick.
            loop {
                ticker.tick().await;
                for provider in &providers {
                    if let Err(e) = provider.refresh_jwks().await {
                        tracing::warn!(error = %e, "periodic JWKS refresh failed for a provider");
                    }
                }
            }
        })
    }
}
