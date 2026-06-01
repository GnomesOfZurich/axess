//! Background helper that periodically refreshes a provider's JWKS.

use std::sync::Arc;

use super::provider::OAuthProvider;

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
/// The returned [`tokio::task::JoinHandle`] aborts the loop when
/// dropped. Store it for the lifetime of the application so it can
/// be drained on graceful shutdown; see the OPERATIONS.md
/// "Graceful shutdown" section for the recommended pattern.
///
/// Errors from `refresh_jwks` are logged at `warn` and swallowed;
/// the loop keeps running so a transient IdP outage does not
/// permanently halt refresh.
///
/// ```rust,ignore
/// let provider = Arc::new(OAuthProviderConfig::discover(...).await?);
/// let _jwks = spawn_jwks_refresh(provider.clone(), Duration::from_secs(3600));
/// ```
pub fn spawn_jwks_refresh(
    provider: Arc<dyn OAuthProvider>,
    interval: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // Skip the immediate first tick; discovery just ran, JWKS is fresh.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match provider.refresh_jwks().await {
                Ok(()) => {
                    tracing::debug!(provider = %provider.name(), "JWKS refresh ok");
                }
                Err(e) => {
                    tracing::warn!(
                        provider = %provider.name(),
                        error = %e,
                        "JWKS refresh failed; will retry next tick"
                    );
                }
            }
        }
    })
}
