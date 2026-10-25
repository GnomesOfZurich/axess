//! Replay log of the `(issuer, jti)` pairs of recently seen logout tokens.
//!
//! Entries age out of a queue in the order they arrived, so recording a token
//! costs the number of entries that expired (or were evicted for room), not
//! the number the log holds. Arrival order follows the injected clock, so
//! it can differ from time order only across a backwards clock step; an entry
//! stuck behind a newer one then lingers until the newer one expires, which
//! is a delay bounded by the step and never a premature release.

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
    evict_batch: usize,
}

impl JtiLog {
    pub(super) fn new(capacity: usize, evict_batch: usize) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            capacity,
            evict_batch,
        }
    }

    /// Record the pair as seen at `now`. `true` when it was new; `false`
    /// when the log still holds it (a replay).
    ///
    /// Entries seen before `cutoff` are dropped first; if the log is then at
    /// capacity the oldest `evict_batch` entries are dropped to make room.
    pub(super) fn record(
        &self,
        issuer: &str,
        jti: &str,
        now: DateTime<Utc>,
        cutoff: DateTime<Utc>,
    ) -> bool {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.drop_front_while(|seen_at| seen_at < cutoff, usize::MAX);
        if inner.seen.len() >= self.capacity {
            inner.drop_front_while(|_| true, self.evict_batch);
        }
        let key = (issuer.to_string(), jti.to_string());
        if inner.seen.contains_key(&key) {
            return false;
        }
        inner.seen.insert(key.clone(), now);
        inner.order.push_back((now, key));
        true
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
        let log = JtiLog::new(100, 10);
        assert!(log.record("iss", "j1", at(0), at(-300)));
        assert!(!log.record("iss", "j1", at(10), at(-290)), "replay");
        assert!(
            log.record("other", "j1", at(10), at(-290)),
            "issuer is part of the key"
        );
        // Cutoff passes the first sighting: the pair is new again.
        assert!(log.record("iss", "j1", at(400), at(100)));
    }

    #[test]
    fn expiry_cost_is_the_number_expired_not_the_number_held() {
        let log = JtiLog::new(10_000, 128);
        for n in 0..1_000 {
            assert!(log.record("iss", &format!("j{n}"), at(n), at(-300)));
        }
        assert_eq!(log.len(), 1_000);
        // Cutoff at t=500 drops exactly the 500 older sightings, once.
        assert!(log.record("iss", "fresh", at(1_000), at(500)));
        assert_eq!(log.len(), 501);
        assert!(
            !log.record("iss", "j999", at(1_001), at(500)),
            "newer ones stay"
        );
    }

    #[test]
    fn at_capacity_the_oldest_batch_is_evicted_and_live_entries_stay_otherwise() {
        let log = JtiLog::new(10, 3);
        for n in 0..10 {
            assert!(log.record("iss", &format!("j{n}"), at(n), at(-300)));
        }
        assert!(log.record("iss", "new", at(10), at(-300)));
        assert_eq!(log.len(), 8, "10 - 3 evicted + 1 inserted");
        assert!(
            log.record("iss", "j0", at(11), at(-300)),
            "oldest were evicted"
        );
        assert!(!log.record("iss", "j9", at(11), at(-300)), "newest kept");
    }
}
