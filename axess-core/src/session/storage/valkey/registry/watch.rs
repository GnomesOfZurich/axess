//! How a [`ValkeySessionRegistry`] tells a long-lived connection that its
//! session was revoked: one shared subscriber connection, a check of the
//! registry that reads and never slides, and the polling a watcher falls
//! back to when it has no connection.

use super::super::internal::{
    ValkeyStoreError, Watch, after_check, after_degraded_poll, degraded_poll_delay,
    registry_member_live, registry_member_ttl_ms, revocation_session_channel,
    revocation_user_channel, user_keys,
};
use super::super::subscriber::Event;
use super::ValkeySessionRegistry;
use crate::authn::ids::UserId;
use crate::session::id::SessionKey;
use fred::prelude::*;
use std::time::Duration;

/// Upper bound of the delay before a watcher's recheck, in milliseconds.
const RECHECK_JITTER_MAX_MS: u64 = 250;

impl ValkeySessionRegistry {
    /// The delay before one watcher's recheck: uniform over
    /// `0..=RECHECK_JITTER_MAX_MS` milliseconds, so the watchers of one burst
    /// spread their registry reads over that window instead of issuing them
    /// together.
    pub(in crate::session::storage::valkey) fn recheck_delay(&self) -> Duration {
        Duration::from_millis(self.draw() % (RECHECK_JITTER_MAX_MS + 1))
    }

    /// The wait before a degraded watcher's next poll of the registry, after
    /// `failed_polls` consecutive polls the registry did not answer: see
    /// [`degraded_poll_delay`].
    pub(in crate::session::storage::valkey) fn degraded_poll_delay(
        &self,
        failed_polls: u32,
    ) -> Duration {
        degraded_poll_delay(failed_polls, self.draw())
    }

    /// One draw from the injected random source.
    fn draw(&self) -> u64 {
        let mut bytes = [0u8; 4];
        self.rng.fill_bytes(&mut bytes);
        u64::from(u32::from_le_bytes(bytes))
    }

    /// Whether the member is held and unexpired, by reading it and nothing
    /// else: no slide of the score, no prune. The revocation watchers use
    /// this, so their own polling never counts as the session's activity and
    /// an idle session still lapses a `ttl` after its last request.
    async fn is_live(
        &self,
        user_id: &UserId,
        session: &SessionKey,
    ) -> Result<bool, ValkeyStoreError> {
        let keys = user_keys(&self.prefix, user_id)?;
        let score: Option<f64> = self
            .client
            .zscore(&keys.registry, session.to_string())
            .await?;
        let now_ms = self.now_ms().await?;
        let member_ttl_ms = registry_member_ttl_ms(self.ttl);
        Ok(score.is_some_and(|score| registry_member_live(score, now_ms, member_ttl_ms)))
    }

    /// The body of [`SessionRegistry::watch_revocation`](crate::session::store::SessionRegistry::watch_revocation).
    pub(super) async fn watch(&self, user_id: &UserId, session: &SessionKey) {
        // A prefix under which this user's keys would lie in different slots
        // fails every read of the registry, so the watch could never learn
        // the session is live: it ends at once, as for a revoked session,
        // rather than wait on answers that cannot come.
        if user_keys(&self.prefix, user_id).is_err() {
            return;
        }
        // Every watcher of this registry (and its clones) shares one
        // subscriber connection, opened by the first and closed with the
        // last; each takes its own receiver from the connection's local
        // broadcast and keeps the messages for its two channels.
        let user_channel = revocation_user_channel(&self.prefix, user_id.to_string().as_str());
        let session_channel = revocation_session_channel(&self.prefix, &session.to_string());

        let Some(watch) = self
            .subscriber
            .join(&self.client, &self.prefix, [user_channel, session_channel])
            .await
        else {
            // No subscriber connection: poll the registry until the session
            // is revoked, rather than waiting on a future that never wakes.
            tracing::warn!(
                target: "axess::session::valkey",
                "revocation subscriber unavailable; polling the registry"
            );
            let mut failed_polls = 0;
            loop {
                tokio::time::sleep(self.degraded_poll_delay(failed_polls)).await;
                let answer = self.is_live(user_id, session).await;
                match after_degraded_poll(answer, failed_polls) {
                    Watch::Polling(next) => failed_polls = next,
                    Watch::Ended | Watch::Waiting => return,
                }
            }
        };

        // Race-free: the watcher's slot exists BEFORE the post-subscribe
        // is_valid check, so a revocation arriving after the check still
        // wakes us. The session may also have been invalidated between
        // session resolution and joining; if so, return immediately.
        // After the connection is lost, or a check the registry did not
        // answer, the watcher polls the registry on a timer until a
        // replacement flags it for a recheck. `state` says which, and holds the
        // count of consecutive polls the registry did not answer, which each
        // wait backs off on.
        let mut state = after_check(self.is_live(user_id, session).await);
        loop {
            let event = match state {
                Watch::Ended => return,
                Watch::Polling(failed_polls) => tokio::select! {
                    event = watch.slot.next() => event,
                    () = tokio::time::sleep(self.degraded_poll_delay(failed_polls)) => {
                        let answer = self.is_live(user_id, session).await;
                        state = after_degraded_poll(answer, failed_polls);
                        continue;
                    }
                },
                Watch::Waiting => watch.slot.next().await,
            };
            match event {
                Event::Revoked => return,
                // Messages were dropped for a slow receiver: one of them may
                // have been ours, so the registry decides, after a delay of
                // its own so a burst does not turn into one instant of
                // checks from every watcher.
                Event::Recheck => {
                    tokio::time::sleep(self.recheck_delay()).await;
                    state = after_check(self.is_live(user_id, session).await);
                }
                // The connection is gone: poll the registry until a
                // replacement connection flags this watcher for a recheck.
                Event::Closed => state = Watch::Polling(0),
            }
        }
    }
}
