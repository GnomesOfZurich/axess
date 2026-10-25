//! Valkey-backed [`SessionRegistry`] implementation.
//!
//! See the [module-level docs](super) for the registry data-type
//! rationale (Redis sorted set keyed on `register`-time millis for FIFO
//! eviction ordering) and the pub/sub revocation channel layout.

use super::internal::{
    DEFAULT_PREFIX, ValkeyStoreError, registry_cutoff_ms, registry_key, registry_key_ttl_secs,
    registry_member_live, registry_member_ttl_ms, revocation_session_channel,
    revocation_user_channel,
};
use super::subscriber::SharedSubscriber;
use crate::session::{id::SessionId, store::SessionRegistry};
use axess_clock::{Clock, SystemClock};
use fred::prelude::*;
use fred::types::sorted_sets::{ZRange, ZRangeBound, ZRangeKind};
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

/// Lower bound of the expired range: every score from the beginning.
fn expired_min() -> ZRange {
    ZRange {
        kind: ZRangeKind::Inclusive,
        range: ZRangeBound::NegInfiniteScore,
    }
}

/// Upper bound of the expired range: scores at or below `cutoff`.
fn expired_max(cutoff: f64) -> ZRange {
    ZRange {
        kind: ZRangeKind::Inclusive,
        range: ZRangeBound::Score(cutoff),
    }
}

/// Lower bound of the live range: scores strictly above `cutoff`.
fn live_min(cutoff: f64) -> ZRange {
    ZRange {
        kind: ZRangeKind::Exclusive,
        range: ZRangeBound::Score(cutoff),
    }
}

/// Upper bound of the live range: no upper limit.
fn live_max() -> ZRange {
    ZRange {
        kind: ZRangeKind::Inclusive,
        range: ZRangeBound::InfiniteScore,
    }
}

// ── ValkeySessionRegistry ────────────────────────────────────────────────────

/// Valkey-backed session registry using sorted sets.
///
/// Each user has a sorted set containing their valid session IDs, scored by
/// registration time in epoch milliseconds. A member lives for the
/// registry's `ttl` after its score: reads treat an older member as absent
/// and prune it, so a session whose own key has long expired neither counts
/// toward `max_sessions_per_user` nor validates. Forced logout removes the
/// set (or a single member).
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
    /// The subscriber connection shared by this registry's revocation
    /// watchers and those of its clones.
    pub(super) subscriber: Arc<SharedSubscriber>,
}

impl ValkeySessionRegistry {
    /// Create a new registry with the default prefix and 24-hour TTL.
    pub fn new(client: Client) -> Self {
        Self {
            client,
            prefix: DEFAULT_PREFIX.into(),
            ttl: Duration::from_secs(24 * 60 * 60),
            clock: Arc::new(SystemClock),
            subscriber: SharedSubscriber::new(),
        }
    }

    /// Create a new registry with custom prefix and TTL.
    pub fn with_options(client: Client, prefix: impl Into<Arc<str>>, ttl: Duration) -> Self {
        Self {
            client,
            prefix: prefix.into(),
            ttl,
            clock: Arc::new(SystemClock),
            subscriber: SharedSubscriber::new(),
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
        let ttl_secs = registry_key_ttl_secs(self.ttl);
        let now_ms = self.clock.now().timestamp_millis();
        let cutoff = registry_cutoff_ms(now_ms, registry_member_ttl_ms(self.ttl));

        // ZADD with score = epoch ms (from the injected `Clock`).
        // Subsequent ZRANGE 0 -1 returns members oldest-first by
        // score, which the `max_sessions_per_user` eviction loop
        // relies on for FIFO semantics. Pipeline ZADD + EXPIRE in a
        // single round-trip so a crash between the two commands
        // cannot leave the sorted set without a TTL (orphan registry
        // entries). `now_ms` comes from the injected clock, so a
        // `MockClock` gives deterministic ordering.
        let score = now_ms as f64;
        let pipeline = self.client.pipeline();
        pipeline
            .zremrangebyscore::<(), _, _, _>(&key, expired_min(), expired_max(cutoff))
            .await?;
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
        let now_ms = self.clock.now().timestamp_millis();
        let live = score.is_some_and(|score| {
            registry_member_live(score, now_ms, registry_member_ttl_ms(self.ttl))
        });
        if score.is_some() && !live {
            // Expired member: drop it so it stops occupying a slot.
            self.client.zrem::<(), _, _>(&key, &sid_str).await?;
        }
        Ok(live)
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
        let now_ms = self.clock.now().timestamp_millis();
        let cutoff = registry_cutoff_ms(now_ms, registry_member_ttl_ms(self.ttl));
        self.client
            .zremrangebyscore::<(), _, _, _>(&key, expired_min(), expired_max(cutoff))
            .await?;
        let members: Vec<String> = self
            .client
            .zrangebyscore(&key, live_min(cutoff), live_max(), false, None)
            .await?;
        Ok(members.into_iter().filter_map(|s| s.parse().ok()).collect())
    }

    async fn watch_revocation(&self, user_id: &crate::authn::ids::UserId, session_id: &SessionId) {
        // Every watcher of this registry (and its clones) shares one
        // subscriber connection, opened by the first and closed with the
        // last; each takes its own receiver from the connection's local
        // broadcast and keeps the messages for its two channels.
        let user_channel = revocation_user_channel(&self.prefix, user_id.to_string().as_str());
        let session_channel = revocation_session_channel(&self.prefix, &session_id.to_string());

        let Some(mut watch) = self.subscriber.join(&self.client, &self.prefix).await else {
            // Connection failure: degrade to never-resolving future.
            // Caller will fall back to next-request validity check.
            std::future::pending::<()>().await;
            return;
        };

        // Race-free: the receiver exists BEFORE the post-subscribe is_valid
        // check, so a revocation arriving after the check still wakes us.
        // The session may also have been invalidated between session
        // resolution and joining; if so, return immediately.
        if let Ok(false) = self.is_valid(user_id, session_id).await {
            return;
        }

        loop {
            match watch.messages.recv().await {
                Ok(message) => {
                    let channel: &str = &message.channel;
                    if channel == user_channel || channel == session_channel {
                        return;
                    }
                }
                // Messages were dropped for a slow receiver: one of them may
                // have been ours, so the registry decides.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    if let Ok(false) = self.is_valid(user_id, session_id).await {
                        return;
                    }
                }
                // The connection is gone: fall back to the next request's
                // validity check.
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    std::future::pending::<()>().await;
                }
            }
        }
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
