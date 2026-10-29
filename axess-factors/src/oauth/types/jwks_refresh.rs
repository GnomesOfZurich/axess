//! Refreshing providers' JWKS: one pass ([`refresh_providers_jwks`]) and a
//! background loop around it ([`spawn_jwks_refresh`]).
//!
//! # Runtime boundary
//!
//! [`refresh_providers_jwks`] has no timer, so under deterministic tests it
//! is the entry point: call it and the clock behind each provider's refresh
//! debounce decides what is fetched. [`spawn_jwks_refresh`] is the one piece
//! that waits on `tokio::time::interval` and `tokio::spawn`; that is runtime
//! plumbing outside the `Clock` seam, and a test advancing a `MockClock`
//! does not wake it.

use std::sync::Arc;

use super::error::OAuthError;
use super::provider::OAuthProvider;

/// Refresh the JWKS of every provider once, in order, and return the
/// providers whose refresh failed with their errors.
///
/// A failure never stops the pass: each provider is attempted. An empty
/// result means every refresh succeeded (or was coalesced by the provider's
/// own debounce). Failures are logged at `warn`.
pub async fn refresh_providers_jwks(
    providers: &[Arc<dyn OAuthProvider>],
) -> Vec<(Arc<str>, OAuthError)> {
    let mut failures = Vec::new();
    for provider in providers {
        match provider.refresh_jwks().await {
            Ok(()) => tracing::debug!(provider = %provider.name(), "JWKS refresh ok"),
            Err(e) => {
                tracing::warn!(
                    provider = %provider.name(),
                    error = %e,
                    "JWKS refresh failed; will retry next tick"
                );
                failures.push((provider.name().clone(), e));
            }
        }
    }
    failures
}

/// The refresh ticker. A stall (a suspended host, a long GC, a busy runtime)
/// makes ticks late; the default `Burst` behaviour then fires every missed
/// tick back to back, which is a burst of requests to an endpoint that
/// rate-limits. `Delay` fires once and resumes the normal spacing.
fn refresh_ticker(interval: std::time::Duration) -> tokio::time::Interval {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker
}

/// Spawn a background task that periodically calls
/// [`OAuthProvider::refresh_jwks`] on `provider`.
///
/// IdPs publish their signing keys at a `jwks_uri`; rotated keys appear
/// there and verifiers must re-fetch to keep validating fresh tokens.
/// In-process JWKS is otherwise refreshed lazily: when a token arrives
/// signed by an unknown `kid` and the cache returns
/// [`OAuthError::UnknownKid`](super::error::OAuthError::UnknownKid), the
/// caller is expected to refresh and retry. That works but adds latency
/// on the *first* request after a key rotation. A scheduled refresh
/// keeps the cache warm so the next rotation is invisible to users.
///
/// # Sizing the interval
///
/// Most IdPs rotate signing keys daily to weekly. A 1-hour interval
/// is the sweet spot: fast enough that key rotations are reflected
/// before any cached old keys would be used to verify new tokens,
/// slow enough that a single transient JWKS fetch failure has many
/// retries before the cache goes stale. **Do not poll faster than
/// every 5 minutes**; most IdPs rate-limit JWKS endpoints.
///
/// # Returned handle
///
/// Dropping the returned [`tokio::task::JoinHandle`] does NOT stop the
/// loop; it keeps running and holds `provider`. Keep the handle for the
/// lifetime of the application and call `abort()` on it at shutdown; see
/// the OPERATIONS.md "Graceful shutdown" section.
///
/// Errors from `refresh_jwks` are logged at `warn` and swallowed;
/// the loop keeps running so a transient IdP outage does not
/// permanently halt refresh. Each tick is one
/// [`refresh_providers_jwks`] pass over `provider`.
///
/// This function is runtime-boundary code: the tick comes from
/// `tokio::time::interval`, not from an injected `Clock`.
///
/// ```rust,ignore
/// let provider = Arc::new(OAuthProviderConfig::discover(...).await?);
/// let _jwks = spawn_jwks_refresh(provider.clone(), Duration::from_secs(3600));
/// ```
pub fn spawn_jwks_refresh(
    provider: Arc<dyn OAuthProvider>,
    interval: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    // `tokio::time::interval` panics on a zero period, which inside the
    // spawned task would kill the refresh loop silently. Fall back to the
    // JWKS debounce window instead.
    let interval = if interval.is_zero() {
        tracing::warn!("spawn_jwks_refresh: zero interval; using the 60 s default");
        crate::oidc::MIN_JWKS_REFRESH_INTERVAL
    } else {
        interval
    };
    tokio::spawn(async move {
        let mut ticker = refresh_ticker(interval);
        // Skip the immediate first tick; discovery just ran, JWKS is fresh.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            refresh_providers_jwks(std::slice::from_ref(&provider)).await;
        }
    })
}

#[cfg(test)]
mod ticker_tests {
    use super::*;
    use tokio::time::MissedTickBehavior;

    /// A late tick must not be followed by a burst of the ticks it missed.
    #[tokio::test]
    async fn the_refresh_ticker_delays_after_a_stall() {
        let ticker = refresh_ticker(std::time::Duration::from_secs(3600));
        assert_eq!(ticker.missed_tick_behavior(), MissedTickBehavior::Delay);
    }
}
