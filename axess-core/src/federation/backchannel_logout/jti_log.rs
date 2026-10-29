//! Replay log of the `(issuer, jti)` pairs of recently seen logout tokens.
//!
//! Entries age out of a queue in the order they arrived, so recording a token
//! costs the number of entries that expired, not the number the log holds.
//! Arrival order follows the injected clock, so it can differ from time order
//! only across a backwards clock step; an entry stuck behind a newer one then
//! lingers until the newer one expires, which is a delay bounded by the step
//! and never a premature release.
//!
//! The log never forgets an entry that is still inside the replay window to
//! make room. When it is full of live entries it refuses the new token
//! ([`Recorded::Full`]), and the caller answers with a retryable error: the
//! pair is not recorded, so the same token is accepted once room appears.

use chrono::{DateTime, Utc};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

type JtiKey = (String, String);

#[derive(Default)]
struct Inner {
    seen: HashMap<JtiKey, DateTime<Utc>>,
    /// Arrival order, oldest first; one item per entry in `seen`.
    order: VecDeque<(DateTime<Utc>, JtiKey)>,
}

/// Bounded `(issuer, jti)` replay log. See the [module docs](self).
pub(super) struct JtiLog {
    inner: Mutex<Inner>,
    capacity: usize,
}

/// What recording a pair did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Recorded {
    /// The pair was new and is now held.
    New,
    /// The log still holds the pair: a replay.
    Replay,
    /// The pair is new but the log is full of live entries and has no room.
    /// Nothing was recorded or forgotten.
    Full,
}

impl JtiLog {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            capacity,
        }
    }

    /// Record the pair as seen at `now`.
    ///
    /// Entries seen before `cutoff` are dropped first. Then the replay check
    /// runs, so a token the log holds is a replay however full the log is.
    /// Only a new pair that finds the log still at capacity is refused: every
    /// entry left is inside the replay window, and forgetting one to make room
    /// would let its token replay.
    pub(super) fn record(
        &self,
        issuer: &str,
        jti: &str,
        now: DateTime<Utc>,
        cutoff: DateTime<Utc>,
    ) -> Recorded {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.drop_front_while(|seen_at| seen_at < cutoff, usize::MAX);
        let key = (issuer.to_string(), jti.to_string());
        if inner.seen.contains_key(&key) {
            return Recorded::Replay;
        }
        if inner.seen.len() >= self.capacity {
            return Recorded::Full;
        }
        inner.seen.insert(key.clone(), now);
        inner.order.push_back((now, key));
        Recorded::New
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .seen
            .len()
    }
}

impl Inner {
    /// Pop up to `max` items off the front while `due` holds for their
    /// arrival time, forgetting the pair each one names.
    fn drop_front_while(&mut self, due: impl Fn(DateTime<Utc>) -> bool, max: usize) {
        let mut dropped = 0;
        while dropped < max {
            match self.order.front() {
                Some((seen_at, _)) if due(*seen_at) => {}
                _ => break,
            }
            if let Some((_, key)) = self.order.pop_front() {
                self.seen.remove(&key);
            }
            dropped += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + secs, 0).unwrap()
    }

    #[test]
    fn a_pair_is_a_replay_until_it_ages_past_the_cutoff() {
        let log = JtiLog::new(100);
        assert_eq!(log.record("iss", "j1", at(0), at(-300)), Recorded::New);
        assert_eq!(log.record("iss", "j1", at(10), at(-290)), Recorded::Replay);
        assert_eq!(
            log.record("other", "j1", at(10), at(-290)),
            Recorded::New,
            "issuer is part of the key"
        );
        // Cutoff passes the first sighting: the pair is new again.
        assert_eq!(log.record("iss", "j1", at(400), at(100)), Recorded::New);
    }

    #[test]
    fn expiry_cost_is_the_number_expired_not_the_number_held() {
        let log = JtiLog::new(10_000);
        for n in 0..1_000 {
            assert_eq!(
                log.record("iss", &format!("j{n}"), at(n), at(-300)),
                Recorded::New
            );
        }
        assert_eq!(log.len(), 1_000);
        // Cutoff at t=500 drops exactly the 500 older sightings, once.
        assert_eq!(
            log.record("iss", "fresh", at(1_000), at(500)),
            Recorded::New
        );
        assert_eq!(log.len(), 501);
        assert_eq!(
            log.record("iss", "j999", at(1_001), at(500)),
            Recorded::Replay,
            "newer ones stay"
        );
    }

    /// A log full of live entries refuses a new token and forgets nothing:
    /// the oldest token still replays, and a refused token is accepted once
    /// room appears.
    #[test]
    fn a_full_log_refuses_a_new_token_and_evicts_no_live_entry() {
        let log = JtiLog::new(10);
        for n in 0..10 {
            assert_eq!(
                log.record("iss", &format!("j{n}"), at(n), at(-300)),
                Recorded::New
            );
        }
        assert_eq!(log.record("iss", "new", at(10), at(-300)), Recorded::Full);
        assert_eq!(log.len(), 10, "nothing evicted, nothing added");
        assert_eq!(
            log.record("iss", "j0", at(11), at(-300)),
            Recorded::Replay,
            "the oldest live entry still replays"
        );
        assert_eq!(log.record("iss", "j9", at(11), at(-300)), Recorded::Replay);

        // Once j0..j4 age past the cutoff there is room, and the token that
        // was refused is accepted.
        assert_eq!(log.record("iss", "new", at(20), at(5)), Recorded::New);
    }
}
