//! Valkey-backed [`SessionRegistry`] implementation.
//!
//! See the [module-level docs](super) for the registry data-type
//! rationale (Redis sorted set keyed on `register`-time millis for FIFO
//! eviction ordering) and the pub/sub revocation channel layout.

use super::internal::{
    DEFAULT_PREFIX, ValkeyStoreError, registry_key, revocation_session_channel,
    revocation_user_channel,
};
use crate::session::{id::SessionId, store::SessionRegistry};
use axess_clock::{Clock, SystemClock};
use fred::prelude::*;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

// ── ValkeySessionRegistry ────────────────────────────────────────────────────

/// Valkey-backed session registry using sets.
///
/// Each user has a Valkey set containing their valid session IDs.
/// Forced logout removes the set (or a single member).
/// Clone is cheap: the inner client is `Arc`-based.
///
/// Per-session FIFO ordering uses an injected [`Clock`] for the
/// sorted-set score (defaults to [`SystemClock`]). DST tests inject a
/// `MockClock` via [`with_clock`](Self::with_clock) so the
/// `max_sessions_per_user` eviction order is deterministic instead of
/// depending on wall-clock millis between rapid `register()` calls.
#[derive(Clone)]
pub struct ValkeySessionRegistry {
    pub(super) client: Client,
    prefix: Arc<str>,
    /// TTL for registry entries. Should be >= session TTL to avoid
    /// premature eviction. Default: 24 hours.
    ttl: Duration,
    /// Injected clock for the FIFO ordering score. Defaults to
    /// [`SystemClock`]; tests override via [`with_clock`].
    clock: Arc<dyn Clock>,
}

impl ValkeySessionRegistry {
    /// Create a new registry with the default prefix and 24-hour TTL.
    pub fn new(client: Client) -> Self {
        Self {
            client,
            prefix: DEFAULT_PREFIX.into(),
            ttl: Duration::from_secs(24 * 60 * 60),
            clock: Arc::new(SystemClock),
        }
    }

    /// Create a new registry with custom prefix and TTL.
    pub fn with_options(client: Client, prefix: impl Into<Arc<str>>, ttl: Duration) -> Self {
        Self {
            client,
            prefix: prefix.into(),
            ttl,
            clock: Arc::new(SystemClock),
        }
    }

    /// Inject a [`Clock`] for deterministic-simulation testing.
    /// Defaults to [`SystemClock`]; pass a `MockClock`-backed handle
    /// so the FIFO ordering score is deterministic across `register`
    /// calls.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }
}

impl SessionRegistry for ValkeySessionRegistry {
    type Error = ValkeyStoreError;

    async fn register(
        &self,
        user_id: &crate::authn::ids::UserId,
        session_id: &SessionId,
    ) -> Result<(), Self::Error> {
        let key = registry_key(&self.prefix, user_id.to_string().as_str());
        let sid_str = session_id.to_string();
        let ttl_secs = self.ttl.as_secs().min(i64::MAX as u64) as i64;

        // ZADD with score = epoch ms (from the injected `Clock`).
        // Subsequent ZRANGE 0 -1 returns members oldest-first by
        // score, which the `max_sessions_per_user` eviction loop
        // relies on for FIFO semantics. Pipeline ZADD + EXPIRE in a
        // single round-trip so a crash between the two commands
        // cannot leave the sorted set without a TTL (orphan registry
        // entries). `self.clock.now()` honours an injected
        // `MockClock` for deterministic test ordering.
        let score = self.clock.now().timestamp_millis() as f64;
        let pipeline = self.client.pipeline();
        pipeline
            .zadd::<(), _, _>(&key, None, None, false, false, (score, sid_str))
            .await?;
        pipeline.expire::<(), _>(&key, ttl_secs, None).await?;
        pipeline.all::<()>().await?;

        debug!(
            user_id = %user_id,
            session_id = %session_id,
            "session registered in valkey registry"
        );
        Ok(())
    }

    async fn is_valid(
        &self,
        user_id: &crate::authn::ids::UserId,
        session_id: &SessionId,
    ) -> Result<bool, Self::Error> {
        let key = registry_key(&self.prefix, user_id.to_string().as_str());
        let sid_str = session_id.to_string();
        // ZSCORE returns `Some(score)` for an existing member,
        // `None` if absent: equivalent to the previous SISMEMBER
        // boolean, but reading from the sorted-set storage shape.
        let score: Option<f64> = self.client.zscore(&key, &sid_str).await?;
        Ok(score.is_some())
    }

    async fn invalidate_user(
        &self,
        user_id: &crate::authn::ids::UserId,
    ) -> Result<(), Self::Error> {
        let key = registry_key(&self.prefix, user_id.to_string().as_str());
        self.client.del::<(), _>(&key).await?;

        // Publish on the user-level revocation channel so any watcher
        // subscribed to *any* of this user's sessions wakes up.
        // Pub/sub is fire-and-forget; missed messages are tolerable
        // because request-time `is_valid` catches up on the next
        // request: `watch_revocation` is for proactive WS close, not
        // exclusive enforcement.
        let channel = revocation_user_channel(&self.prefix, user_id.to_string().as_str());
        let _: Result<(), _> = self.client.publish(&channel, "1").await;

        debug!(
            user_id = %user_id,
            "all sessions invalidated for user in valkey registry"
        );
        Ok(())
    }

    async fn invalidate_session(
        &self,
        user_id: &crate::authn::ids::UserId,
        session_id: &SessionId,
    ) -> Result<(), Self::Error> {
        let key = registry_key(&self.prefix, user_id.to_string().as_str());
        let sid_str = session_id.to_string();
        self.client.zrem::<(), _, _>(&key, &sid_str).await?;

        // Publish on the session-level channel for any watcher of this
        // specific session. See note in `invalidate_user` re: tolerance
        // of dropped messages.
        let channel = revocation_session_channel(&self.prefix, &sid_str);
        let _: Result<(), _> = self.client.publish(&channel, "1").await;

        debug!(
            user_id = %user_id,
            session_id = %session_id,
            "session removed from valkey registry"
        );
        Ok(())
    }

    async fn active_sessions(
        &self,
        user_id: &crate::authn::ids::UserId,
    ) -> Result<Vec<SessionId>, Self::Error> {
        // ZRANGE 0 -1 returns all members ordered ascending by
        // score, i.e. oldest registration first: matches the trait
        // contract that `max_sessions_per_user` enforcement at
        // `account/mod.rs::complete_factor_step` relies on for
        // FIFO eviction. Previously this fell through to the trait
        // default `Ok(vec![])`, silently disabling the limit for every
        // Valkey-backed deployment.
        let key = registry_key(&self.prefix, user_id.to_string().as_str());
        let members: Vec<String> = self
            .client
            .zrange(&key, 0i64, -1i64, None, false, None, false)
            .await?;
        Ok(members.into_iter().filter_map(|s| s.parse().ok()).collect())
    }

    async fn watch_revocation(&self, user_id: &crate::authn::ids::UserId, session_id: &SessionId) {
        // Spawns a fresh subscriber connection per call. For deployments
        // with thousands of concurrent long-lived watchers (typically
        // WebSocket or SSE), consider replacing this with a shared
        // subscriber + local fan-out (one Redis subscriber connection
        // serving N waiters via DashMap<channel, broadcast>). The trait
        // contract is unchanged by that optimisation.
        let user_channel = revocation_user_channel(&self.prefix, user_id.to_string().as_str());
        let session_channel = revocation_session_channel(&self.prefix, &session_id.to_string());

        let subscriber = self.client.clone_new();
        if subscriber.init().await.is_err() {
            // Connection failure: degrade to never-resolving future.
            // Caller will fall back to next-request validity check.
            std::future::pending::<()>().await;
            return;
        }

        let mut messages = subscriber.message_rx();

        // Race-free: subscribe BEFORE the post-subscribe is_valid check
        // so a revocation arriving during subscription still wakes us.
        if subscriber
            .subscribe(vec![user_channel.clone(), session_channel.clone()])
            .await
            .is_err()
        {
            let _ = subscriber.quit().await;
            std::future::pending::<()>().await;
            return;
        }

        // Post-subscribe revocation check: the session may have been
        // invalidated between session resolution and our subscribe call.
        // If so, return immediately.
        if let Ok(false) = self.is_valid(user_id, session_id).await {
            let _ = subscriber.quit().await;
            return;
        }

        // Await the first message on either channel.
        let _ = messages.recv().await;
        let _ = subscriber.quit().await;
    }
}

// ── HealthCheck ──────────────────────────────────────────────────────────────

use crate::health::{HealthCheck, HealthStatus};
use std::future::Future;
use std::pin::Pin;

/// Health check timeout for Valkey PING operations.
const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(2);

impl HealthCheck for ValkeySessionRegistry {
    fn check(&self) -> Pin<Box<dyn Future<Output = HealthStatus> + Send + '_>> {
        Box::pin(async {
            match tokio::time::timeout(HEALTH_CHECK_TIMEOUT, self.client.ping::<String>(None)).await
            {
                Ok(Ok(_)) => HealthStatus::Healthy,
                Ok(Err(e)) => HealthStatus::Unhealthy(format!("valkey PING failed: {e}")),
                Err(_) => HealthStatus::Unhealthy("valkey PING timeout (2s)".into()),
            }
        })
    }
}
