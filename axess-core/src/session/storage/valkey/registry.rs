//! Valkey-backed [`SessionRegistry`] implementation.
//!
//! See the [module-level docs](super) for the registry data-type
//! rationale (Redis sorted sets keyed on `register`-time millis for FIFO
//! eviction ordering) and the pub/sub revocation channel layout.

use super::internal::{
    DROP_ORPHANS_SCRIPT, END_ONE_SCRIPT, KEEP_ONE_ABSENT, KEEP_ONE_HELD, KEEP_ONE_MOVED,
    KEEP_ONE_SCRIPT, MOVE_FULL, MOVE_GONE, MOVE_MOVED, MOVE_SCRIPT, UserKeys, ValkeyStoreError,
    oldest_first, registry_cutoff_ms, registry_key_ttl_secs, registry_member_live,
    registry_member_ttl_ms, revocation_session_channel, revocation_user_channel,
    script_unavailable, user_keys,
};
use super::subscriber::SharedSubscriber;
use crate::authn::ids::UserId;
use crate::session::{
    id::SessionKey,
    store::{CutOff, MAX_MOVE_RECORDS_PER_USER, MoveOutcome, SessionRegistry},
};
use axess_clock::Clock;
use axess_rng::SecureRng;
use fred::prelude::*;
use fred::types::sorted_sets::{Ordering, ZRange, ZRangeBound, ZRangeKind};
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

mod build;
mod watch;

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

/// The error of a listing that met a member which is not a session key. It
/// names no member: whatever was written there is not echoed.
fn member_not_a_key() -> ValkeyStoreError {
    ValkeyStoreError::Connection(fred::error::Error::new(
        fred::error::ErrorKind::Protocol,
        "a registry member is not a session key",
    ))
}

/// The members a listing read, as session keys, in their order.
///
/// A member that is not a key fails the whole listing. Leaving it out would
/// answer a shorter list than the registry holds, and the session limit
/// counts this list: one member it cannot read would let a user hold one
/// session more than the limit, with nothing said. An error is what the
/// trait asks for whenever the registry cannot answer.
fn listed_keys(members: Vec<String>) -> Result<Vec<SessionKey>, ValkeyStoreError> {
    members
        .iter()
        .map(|member| member.parse().map_err(|_| member_not_a_key()))
        .collect()
}

/// The keys of the sessions a cut-off ended, from the members its script
/// removed.
///
/// A member that is not a key is logged at `warn` and left out: the script
/// has already removed it, so the cut-off holds, and it names no stored row
/// for the caller to delete. Its text is not logged.
fn ended_keys(members: &[String]) -> Vec<SessionKey> {
    members
        .iter()
        .filter_map(|member| {
            let key = member.parse().ok();
            if key.is_none() {
                tracing::warn!(
                    target: "axess::session::valkey",
                    "a cut-off removed a registry member that is not a session key"
                );
            }
            key
        })
        .collect()
}

/// Milliseconds from a `TIME` reply: seconds, then microseconds within the
/// second.
pub(super) fn parse_server_time_ms(reply: &[String]) -> Option<i64> {
    let [secs, micros] = reply else { return None };
    let secs: i64 = secs.parse().ok()?;
    let micros: i64 = micros.parse().ok()?;
    secs.checked_mul(1000)?.checked_add(micros / 1000)
}

// ── ValkeySessionRegistry ────────────────────────────────────────────────────

/// Valkey-backed session registry using sorted sets.
///
/// Each user has a sorted set containing their valid session IDs, scored by
/// the time the session was registered or last found in use, in epoch
/// milliseconds. A member lives for the registry's `ttl` after its score,
/// which `is_valid` moves forward for a session that is used (so an active
/// session never lapses): reads treat an older member as absent
/// and prune it, so a session whose own key has long expired neither counts
/// toward `max_sessions_per_user` nor validates. Forced logout removes the
/// set (or a single member).
/// Clone is cheap: the inner client is `Arc`-based.
///
/// Scores and expiry cutoffs are read from the Valkey server's clock (one
/// `TIME` per operation), not from each app node's own, so nodes whose clocks
/// disagree still prune and order the same set the same way. DST tests inject
/// a [`Clock`] via [`with_clock`](Self::with_clock), which replaces the server
/// clock, so the `max_sessions_per_user` eviction order is deterministic
/// instead of depending on wall-clock millis between rapid `register()`
/// calls; with one injected, every node sharing the set must use the same one.
#[derive(Clone)]
pub struct ValkeySessionRegistry {
    pub(super) client: Client,
    prefix: Arc<str>,
    /// TTL for registry entries. Should be >= session TTL to avoid
    /// premature eviction. Default: 24 hours.
    ttl: Duration,
    /// Injected clock for the score and the expiry cutoff. `None` reads the
    /// Valkey server's own clock (`TIME`), so app nodes with skewed clocks
    /// agree; tests override via [`with_clock`](Self::with_clock).
    clock: Option<Arc<dyn Clock>>,
    /// Random source for the delay before a watcher's recheck after dropped
    /// messages. Defaults to [`SystemRng`](axess_rng::SystemRng); tests
    /// override via [`with_rng`](Self::with_rng).
    rng: Arc<dyn SecureRng>,
    /// The subscriber connection shared by this registry's revocation
    /// watchers and those of its clones.
    pub(super) subscriber: Arc<SharedSubscriber>,
}

impl ValkeySessionRegistry {
    /// Inject a [`Clock`] for deterministic-simulation testing, in place of
    /// the Valkey server's clock (the default): pass a `MockClock`-backed
    /// handle so the FIFO ordering score is deterministic across `register`
    /// calls. Not for production: it makes every node's own clock the
    /// authority for the shared set.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Inject the [`SecureRng`] that draws the delay each revocation watcher
    /// waits before it rechecks the registry after dropped pub/sub messages.
    /// Defaults to [`SystemRng`](axess_rng::SystemRng).
    pub fn with_rng(mut self, rng: Arc<dyn SecureRng>) -> Self {
        self.rng = rng;
        self
    }

    /// The current time in epoch milliseconds: the injected clock's, or the
    /// Valkey server's.
    async fn now_ms(&self) -> Result<i64, ValkeyStoreError> {
        if let Some(clock) = &self.clock {
            return Ok(clock.now().unix_millis());
        }
        let command =
            fred::types::CustomCommand::new_static("TIME", fred::types::ClusterHash::Random, false);
        let reply: Vec<String> = self.client.custom(command, Vec::<String>::new()).await?;
        parse_server_time_ms(&reply).ok_or_else(|| {
            ValkeyStoreError::Connection(fred::error::Error::new(
                fred::error::ErrorKind::Protocol,
                "malformed TIME reply",
            ))
        })
    }

    /// Tell the watchers of `channel` that their session is revoked. The
    /// entry is already gone from the registry, so a failed publish costs
    /// only the push: it is tried once more, and when it still fails the
    /// error is returned so the caller knows the watchers on other nodes were
    /// not told (they find out on their next recheck or request).
    async fn publish_revocation(&self, channel: &str) -> Result<(), ValkeyStoreError> {
        let mut result = self.client.publish::<(), _, _>(channel, "1").await;
        if result.is_err() {
            result = self.client.publish::<(), _, _>(channel, "1").await;
        }
        result.map_err(|e| {
            tracing::warn!(
                target: "axess::session::valkey",
                error = %e,
                "revocation was not published; watchers on other nodes were not told"
            );
            ValkeyStoreError::from(e)
        })
    }

    /// Remove the registration times of sessions that are no longer in the
    /// registry set, so the registration set does not outgrow it. The two
    /// sets are compared on the server, in one script over the user's keys,
    /// which share a slot, so a session registered meanwhile is in both sets
    /// when the script reads them and keeps its time.
    ///
    /// The sweep is housekeeping: a registration time with no registry entry
    /// costs memory until its key expires, and decides nothing. So on a
    /// server that refuses the script, which ran scripts when the registry
    /// was built, the sweep is skipped with a `warn` line, a fault to see,
    /// and the call it serves goes on. There is no form of it in separate
    /// commands.
    pub(super) async fn drop_orphan_registrations(
        &self,
        keys: &UserKeys,
    ) -> Result<(), ValkeyStoreError> {
        let swept: Result<i64, _> = self
            .client
            .eval(
                DROP_ORPHANS_SCRIPT,
                vec![keys.registry.clone(), keys.registered_at.clone()],
                Vec::<Value>::new(),
            )
            .await;
        match swept {
            Ok(_) => Ok(()),
            Err(e) if script_unavailable(&e) => {
                tracing::warn!(
                    target: "axess::session::valkey",
                    error = %e,
                    "the server refuses scripts, so the registry's orphan sweep was skipped"
                );
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }
}

impl ValkeySessionRegistry {
    /// The plain form of an ending by key, for a server that stopped running
    /// scripts after the registry was built. A revocation that fails leaves
    /// a session signed in, so it is carried out with single commands where
    /// they can carry it: the target is found as
    /// [`current_key`](SessionRegistry::current_key) finds it, then the
    /// member, the registration time and the record under `session` go, and
    /// the target's member and registration time. The records that led to
    /// the target stay until the user's keys expire; their target is gone,
    /// so none is followed. Answers the target.
    async fn end_by_commands(
        &self,
        keys: &UserKeys,
        user_id: &UserId,
        session: &SessionKey,
    ) -> Result<Option<SessionKey>, ValkeyStoreError> {
        let target = self.current_key(user_id, session).await?;
        let member = session.to_string();
        self.client
            .zrem::<(), _, _>(&keys.registry, &member)
            .await?;
        self.client
            .zrem::<(), _, _>(&keys.registered_at, &member)
            .await?;
        self.client.hdel::<(), _, _>(&keys.forward, &member).await?;
        self.client
            .zrem::<(), _, _>(&keys.forward_order, &member)
            .await?;
        if let Some(target) = target.filter(|target| target != session) {
            let target = target.to_string();
            self.client
                .zrem::<(), _, _>(&keys.registry, &target)
                .await?;
            self.client
                .zrem::<(), _, _>(&keys.registered_at, &target)
                .await?;
        }
        Ok(target)
    }
}

impl SessionRegistry for ValkeySessionRegistry {
    type Error = ValkeyStoreError;

    async fn register(&self, user_id: &UserId, session: &SessionKey) -> Result<(), Self::Error> {
        let UserKeys {
            registry: key,
            registered_at: registered_key,
            forward,
            forward_order,
        } = user_keys(&self.prefix, user_id)?;
        // A member is the 64 characters of the session's key, never its id.
        let member = session.to_string();
        let ttl_secs = registry_key_ttl_secs(self.ttl);
        let now_ms = self.now_ms().await?;
        let cutoff = registry_cutoff_ms(now_ms, registry_member_ttl_ms(self.ttl));

        // ZADD with score = epoch ms (from the injected `Clock`).
        // Subsequent ZRANGE 0 -1 returns members oldest-first by
        // score, which the `max_sessions_per_user` eviction loop
        // relies on for FIFO semantics. Pipeline ZADD + EXPIRE in a
        // single round-trip so a crash between the two commands
        // cannot leave the sorted set without a TTL (orphan registry
        // entries). `now_ms` is the server's clock unless one is injected,
        // and a `MockClock` gives deterministic ordering.
        let score = now_ms as f64;
        let pipeline = self.client.pipeline();
        pipeline
            .zremrangebyscore::<(), _, _, _>(&key, expired_min(), expired_max(cutoff))
            .await?;
        pipeline
            .zadd::<(), _, _>(&key, None, None, false, false, (score, member.clone()))
            .await?;
        pipeline.expire::<(), _>(&key, ttl_secs, None).await?;
        // The registration time, which use never moves: the eviction order.
        // `NX`: a session registered again keeps its first time.
        pipeline
            .zadd::<(), _, _>(
                &registered_key,
                Some(SetOptions::NX),
                None,
                false,
                false,
                (score, member.clone()),
            )
            .await?;
        pipeline
            .expire::<(), _>(&registered_key, ttl_secs, None)
            .await?;
        // A registered key is not a former one: a record kept under it goes.
        pipeline.hdel::<(), _, _>(&forward, &member).await?;
        pipeline.zrem::<(), _, _>(&forward_order, &member).await?;
        pipeline.expire::<(), _>(&forward, ttl_secs, None).await?;
        pipeline
            .expire::<(), _>(&forward_order, ttl_secs, None)
            .await?;
        pipeline.all::<()>().await?;

        debug!(
            user_id = %user_id,
            session_id = %session.prefix(),
            "session registered in valkey registry"
        );
        Ok(())
    }

    async fn is_valid(&self, user_id: &UserId, session: &SessionKey) -> Result<bool, Self::Error> {
        let UserKeys {
            registry: key,
            registered_at: registered_key,
            forward,
            forward_order,
        } = user_keys(&self.prefix, user_id)?;
        // The registry set alone decides: a key the session was moved away
        // from has a record and no member, so it is not valid.
        let member = session.to_string();
        // ZSCORE returns `Some(score)` for an existing member,
        // `None` if absent: equivalent to the previous SISMEMBER
        // boolean, but reading from the sorted-set storage shape.
        let score: Option<f64> = self.client.zscore(&key, &member).await?;
        let now_ms = self.now_ms().await?;
        let member_ttl_ms = registry_member_ttl_ms(self.ttl);
        let live = score.is_some_and(|score| registry_member_live(score, now_ms, member_ttl_ms));
        if score.is_some() && !live {
            // Expired member: drop it so it stops occupying a slot. The
            // removal is by score range, the same one `register` and
            // `active_sessions` use, not by member: a `ZREM` of the member
            // would also remove a session that was registered again with a
            // fresh score between the read above and this write.
            let cutoff = registry_cutoff_ms(now_ms, member_ttl_ms);
            self.client
                .zremrangebyscore::<(), _, _, _>(&key, expired_min(), expired_max(cutoff))
                .await?;
        }
        if live && let Some(score) = score {
            // A session that is used keeps its member: a session lives as
            // long as it is active, so a member that lapsed a fixed time
            // after `register` would log an active user out. The score moves
            // forward once half the lifetime has gone, so the check writes
            // at most twice per lifetime. `XX` never creates a member (a
            // concurrent revocation is not undone) and `GT` never moves a
            // score back.
            if now_ms as f64 - score >= member_ttl_ms as f64 / 2.0 {
                let pipeline = self.client.pipeline();
                pipeline
                    .zadd::<(), _, _>(
                        &key,
                        Some(SetOptions::XX),
                        Some(Ordering::GreaterThan),
                        false,
                        false,
                        (now_ms as f64, member),
                    )
                    .await?;
                pipeline
                    .expire::<(), _>(&key, registry_key_ttl_secs(self.ttl), None)
                    .await?;
                // The registration set lives as long as the registry set, so
                // an active session keeps its place in the order.
                pipeline
                    .expire::<(), _>(&registered_key, registry_key_ttl_secs(self.ttl), None)
                    .await?;
                // So do the records of the user's moves: a record lives as
                // long as the entry it leads to.
                for records in [&forward, &forward_order] {
                    pipeline
                        .expire::<(), _>(records, registry_key_ttl_secs(self.ttl), None)
                        .await?;
                }
                pipeline.all::<()>().await?;
            }
        }
        Ok(live)
    }

    async fn invalidate_user(&self, user_id: &UserId) -> Result<(), Self::Error> {
        // The user's four keys share a slot, so one `DEL` removes the
        // sessions, their registration times and the records of their moves.
        let keys = user_keys(&self.prefix, user_id)?;
        self.client.del::<(), _>(keys.all()).await?;

        // Publish on the user-level revocation channel so any watcher
        // subscribed to *any* of this user's sessions wakes up.
        let channel = revocation_user_channel(&self.prefix, user_id.to_string().as_str());
        self.publish_revocation(&channel).await?;

        debug!(
            user_id = %user_id,
            "all sessions invalidated for user in valkey registry"
        );
        Ok(())
    }

    /// One server-side script over the user's four keys: it ends the
    /// session the key names, or the one a move took it to. On a server that
    /// stopped running scripts after the registry was built, the ending is a
    /// revocation that must not fail, so it takes a plain form of separate
    /// commands, which ends the session and leaves the records that led to
    /// it until the user's keys expire.
    async fn invalidate_session(
        &self,
        user_id: &UserId,
        session: &SessionKey,
    ) -> Result<(), Self::Error> {
        let keys = user_keys(&self.prefix, user_id)?;
        let member = session.to_string();
        let now_ms = self.now_ms().await?;
        let cutoff = registry_cutoff_ms(now_ms, registry_member_ttl_ms(self.ttl));
        let scripted: Result<String, _> = self
            .client
            .eval(
                END_ONE_SCRIPT,
                keys.all(),
                vec![
                    Value::from(member.as_str()),
                    Value::from(cutoff.to_string().as_str()),
                ],
            )
            .await;
        let target = match scripted {
            Ok(reply) if reply.is_empty() => None,
            Ok(reply) => Some(
                reply
                    .parse::<SessionKey>()
                    .map_err(|_| member_not_a_key())?,
            ),
            Err(e) if script_unavailable(&e) => {
                tracing::warn!(
                    target: "axess::session::valkey",
                    user_id = %user_id,
                    error = %e,
                    "the server refuses scripts, so a session was ended by separate commands; \
                     the records that led to it stay until the user's keys expire"
                );
                self.end_by_commands(&keys, user_id, session).await?
            }
            Err(e) => return Err(e.into()),
        };

        // Publish on the channel of the key named, as for any ending, and on
        // the channel of the key the session was moved to, whose watchers
        // know it by that one.
        self.publish_revocation(&revocation_session_channel(&self.prefix, &member))
            .await?;
        if let Some(target) = target.filter(|target| target != session) {
            self.publish_revocation(&revocation_session_channel(
                &self.prefix,
                &target.to_string(),
            ))
            .await?;
        }

        debug!(
            user_id = %user_id,
            session_id = %session.prefix(),
            "session removed from valkey registry"
        );
        Ok(())
    }

    /// One server-side script over the user's four keys, which share a
    /// slot, so it runs on a cluster as on a single node. A server that
    /// refuses scripts cannot take the step at all: the call fails with
    /// [`ValkeyStoreError::Unsupported`] and ends nothing, where a sequence
    /// of commands would let a session registered or moved between two of
    /// them outlive the cut-off.
    async fn invalidate_other_sessions(
        &self,
        user_id: &UserId,
        keep: &SessionKey,
    ) -> Result<CutOff, Self::Error> {
        let keys = user_keys(&self.prefix, user_id)?;
        let now_ms = self.now_ms().await?;
        let cutoff = registry_cutoff_ms(now_ms, registry_member_ttl_ms(self.ttl));
        let scripted: Result<Vec<String>, _> = self
            .client
            .eval(
                KEEP_ONE_SCRIPT,
                keys.all(),
                vec![
                    Value::from(keep.to_string().as_str()),
                    Value::from(cutoff.to_string().as_str()),
                ],
            )
            .await;
        let mut reply = match scripted {
            Ok(reply) => reply,
            Err(e) if script_unavailable(&e) => {
                tracing::error!(
                    target: "axess::session::valkey",
                    error = %e,
                    "the server refuses scripts, so a user's other sessions cannot be \
                     ended in one step; nothing was ended"
                );
                return Err(ValkeyStoreError::Unsupported(
                    "ending a user's other sessions needs a server that runs scripts",
                ));
            }
            Err(e) => return Err(e.into()),
        };
        // The first element says whether the session to keep was held, had
        // been moved, or neither; the sessions that were ended follow it.
        // The script removed their registration times and records itself.
        let (ended, kept) = match reply.first().map(String::as_str) {
            Some(KEEP_ONE_HELD) => (reply.split_off(1), true),
            Some(KEEP_ONE_MOVED) => (reply.split_off(1), false),
            Some(KEEP_ONE_ABSENT) => return Ok(CutOff::NotHeld),
            _ => {
                return Err(ValkeyStoreError::Connection(fred::error::Error::new(
                    fred::error::ErrorKind::Protocol,
                    "the keep-one script answered none of held, moved and absent",
                )));
            }
        };

        // Tell the watchers of each ended session, on that session's own
        // channel: the user-level channel would wake the kept session's
        // watchers too. Every channel is tried; the first failure is returned
        // once all of them were.
        let mut unpublished = None;
        for sid in &ended {
            let channel = revocation_session_channel(&self.prefix, sid);
            if let Err(e) = self.publish_revocation(&channel).await
                && unpublished.is_none()
            {
                unpublished = Some(e);
            }
        }
        debug!(
            user_id = %user_id,
            kept = %keep.prefix(),
            ended = ended.len(),
            "every other session of the user removed from valkey registry"
        );
        match unpublished {
            Some(e) => Err(e),
            None if kept => Ok(CutOff::KeptOne(ended_keys(&ended))),
            None => Ok(CutOff::KeptNone(ended_keys(&ended))),
        }
    }

    /// One server-side script over the user's four keys, which share a
    /// slot. A server that refuses scripts cannot take the step: the call
    /// fails with [`ValkeyStoreError::Unsupported`] and changes nothing,
    /// where a sequence of commands would hold both keys, or neither, while
    /// a cut-off or an ending ran between two of them.
    async fn move_session(
        &self,
        user_id: &UserId,
        old: &SessionKey,
        new: &SessionKey,
    ) -> Result<MoveOutcome, Self::Error> {
        let keys = user_keys(&self.prefix, user_id)?;
        let now_ms = self.now_ms().await?;
        let cutoff = registry_cutoff_ms(now_ms, registry_member_ttl_ms(self.ttl));
        let scripted: Result<String, _> = self
            .client
            .eval(
                MOVE_SCRIPT,
                keys.all(),
                vec![
                    Value::from(old.to_string().as_str()),
                    Value::from(new.to_string().as_str()),
                    Value::from(now_ms.to_string().as_str()),
                    Value::from(cutoff.to_string().as_str()),
                    Value::from(registry_key_ttl_secs(self.ttl).to_string().as_str()),
                    Value::from(MAX_MOVE_RECORDS_PER_USER.to_string().as_str()),
                ],
            )
            .await;
        let reply = match scripted {
            Ok(reply) => reply,
            Err(e) if script_unavailable(&e) => {
                return Err(ValkeyStoreError::Unsupported(
                    "moving a session needs a server that runs scripts",
                ));
            }
            Err(e) => return Err(e.into()),
        };
        let outcome = match reply.as_str() {
            MOVE_MOVED => MoveOutcome::Moved,
            MOVE_GONE => MoveOutcome::OldGone,
            MOVE_FULL => MoveOutcome::Full,
            _ => {
                return Err(ValkeyStoreError::Connection(fred::error::Error::new(
                    fred::error::ErrorKind::Protocol,
                    "the move script answered none of moved, gone and full",
                )));
            }
        };
        debug!(
            user_id = %user_id,
            old_session_id = %old.prefix(),
            new_session_id = %new.prefix(),
            outcome = ?outcome,
            "session moved in valkey registry"
        );
        Ok(outcome)
    }

    /// Plain reads, no script: the member's score, the time, the record
    /// under the key and its target's score. Nothing is written.
    async fn current_key(
        &self,
        user_id: &UserId,
        session: &SessionKey,
    ) -> Result<Option<SessionKey>, Self::Error> {
        let keys = user_keys(&self.prefix, user_id)?;
        let member = session.to_string();
        let score: Option<f64> = self.client.zscore(&keys.registry, &member).await?;
        let now_ms = self.now_ms().await?;
        let member_ttl_ms = registry_member_ttl_ms(self.ttl);
        let live = |score: Option<f64>| {
            score.is_some_and(|score| registry_member_live(score, now_ms, member_ttl_ms))
        };
        if live(score) {
            return Ok(Some(*session));
        }
        let Some(target) = self
            .client
            .hget::<Option<String>, _, _>(&keys.forward, &member)
            .await?
        else {
            return Ok(None);
        };
        let score: Option<f64> = self.client.zscore(&keys.registry, &target).await?;
        if !live(score) {
            return Ok(None);
        }
        target.parse().map(Some).map_err(|_| member_not_a_key())
    }

    async fn active_sessions(&self, user_id: &UserId) -> Result<Vec<SessionKey>, Self::Error> {
        // The trait promises oldest registration first, which
        // `max_sessions_per_user` enforcement relies on for FIFO eviction.
        // The live members come from the registry set; their order comes
        // from the registration set, because a used session's score there
        // has moved forward.
        let keys = user_keys(&self.prefix, user_id)?;
        let now_ms = self.now_ms().await?;
        let cutoff = registry_cutoff_ms(now_ms, registry_member_ttl_ms(self.ttl));
        self.client
            .zremrangebyscore::<(), _, _, _>(&keys.registry, expired_min(), expired_max(cutoff))
            .await?;
        let live: Vec<(String, f64)> = self
            .client
            .zrangebyscore(&keys.registry, live_min(cutoff), live_max(), true, None)
            .await?;
        // The score says when a session was last used, so it is not the
        // order: the oldest registration is, read from its own set. A session
        // registered before that set existed has no time in it and is
        // ordered by its score, the best time known for it, until it lapses.
        let registered: Vec<Option<f64>> = if live.is_empty() {
            Vec::new()
        } else {
            let members: Vec<&str> = live.iter().map(|(m, _)| m.as_str()).collect();
            self.client.zmscore(&keys.registered_at, members).await?
        };
        self.drop_orphan_registrations(&keys).await?;
        listed_keys(oldest_first(live, &registered))
    }

    async fn watch_revocation(&self, user_id: &UserId, session: &SessionKey) {
        self.watch(user_id, session).await;
    }
}
