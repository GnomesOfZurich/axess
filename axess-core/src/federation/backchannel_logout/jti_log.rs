//! Replay log of the `jti`s of recently seen logout tokens, one partition
//! per issuer.
//!
//! Entries age out of one queue, over every issuer, in the order they
//! arrived, so recording a token costs the number of entries that expired,
//! not the number the log holds. Arrival order follows the injected clock, so
//! it can differ from time order only across a backwards clock step; an entry
//! stuck behind a newer one then lingers until the newer one expires, which
//! is a delay bounded by the step and never a premature release.
//!
//! The log never forgets an entry that is still inside the replay window to
//! make room. The bound is per issuer: when an issuer's partition is full of
//! live entries it refuses that issuer's new token ([`Recorded::Full`]), and
//! the caller answers with a retryable error; the pair is not recorded, so the
//! same token is accepted once room appears. Another issuer's tokens are
//! unaffected, so one IdP cannot starve the others' logouts.
//!
//! Only a verified token reaches the log, and a partition goes with its last
//! entry, whichever issuer's token the expiry ran for. So the log holds a
//! partition for each issuer that sent a verified token within the replay
//! window, and no more: with tenant providers the set of issuers is not fixed
//! when the handler is built, and an issuer that stops sending leaves nothing
//! behind.

use chrono::{DateTime, Utc};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

/// Bounded `(issuer, jti)` replay log. See the [module docs](self).
pub(super) struct JtiLog {
    state: Mutex<State>,
    /// Live entries one issuer may hold.
    capacity: usize,
}

#[derive(Default)]
struct State {
    /// Issuer -> `jti` -> when it was seen. An issuer with no live entry has
    /// no partition.
    issuers: HashMap<Arc<str>, HashMap<String, DateTime<Utc>>>,
    /// Arrival order over every issuer, oldest first; one item per entry.
    order: VecDeque<(DateTime<Utc>, Arc<str>, String)>,
}

/// What recording a pair did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Recorded {
    /// The pair was new and is now held.
    New,
    /// The log still holds the pair: a replay.
    Replay,
    /// The pair is new but the issuer's partition is full of live entries
    /// and has no room. Nothing was recorded or forgotten.
    Full,
}

impl JtiLog {
    /// A log that holds up to `capacity` live entries per issuer.
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            state: Mutex::new(State::default()),
            capacity,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Record the pair as seen at `now`.
    ///
    /// Every entry seen before `cutoff`, of any issuer, is dropped first.
    /// Then the replay check runs, so a token the log holds is a replay
    /// however full the partition is. Only a new pair that finds the issuer's
    /// partition still at capacity is refused: every entry left is inside the
    /// replay window, and forgetting one to make room would let its token
    /// replay.
    pub(super) fn record(
        &self,
        issuer: &str,
        jti: &str,
        now: DateTime<Utc>,
        cutoff: DateTime<Utc>,
    ) -> Recorded {
        let mut state = self.lock();
        state.expire_before(cutoff);
        let held = state.issuers.get(issuer);
        if held.is_some_and(|seen| seen.contains_key(jti)) {
            return Recorded::Replay;
        }
        if held.is_some_and(|seen| seen.len() >= self.capacity) {
            return Recorded::Full;
        }
        let issuer: Arc<str> = match state.issuers.get_key_value(issuer) {
            Some((held, _)) => held.clone(),
            None => issuer.into(),
        };
        state
            .issuers
            .entry(issuer.clone())
            .or_default()
            .insert(jti.to_string(), now);
        state.order.push_back((now, issuer, jti.to_string()));
        Recorded::New
    }

    /// Forget the pair, so the same token is accepted again: the handler
    /// recorded it before acting and could not carry the logout out, and
    /// the IdP's retry must not be refused as a replay. Returns whether the
    /// pair was held.
    pub(super) fn forget(&self, issuer: &str, jti: &str) -> bool {
        let mut state = self.lock();
        let Some(seen_at) = state.take(issuer, jti) else {
            return false;
        };
        state
            .order
            .retain(|(at, iss, held)| !(*at == seen_at && **iss == *issuer && held == jti));
        true
    }

    /// Live entries over every issuer.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.lock().issuers.values().map(HashMap::len).sum()
    }

    /// Issuers with a partition.
    #[cfg(test)]
    fn partitions(&self) -> usize {
        self.lock().issuers.len()
    }
}

impl State {
    /// Pop the items that arrived before `cutoff` off the front, forgetting
    /// the entry each one names.
    fn expire_before(&mut self, cutoff: DateTime<Utc>) {
        while self.order.front().is_some_and(|(at, _, _)| *at < cutoff) {
            if let Some((_, issuer, jti)) = self.order.pop_front() {
                self.take(&issuer, &jti);
            }
        }
    }

    /// Remove one entry, and its issuer's partition when it was the last;
    /// returns when the entry was seen.
    fn take(&mut self, issuer: &str, jti: &str) -> Option<DateTime<Utc>> {
        let seen = self.issuers.get_mut(issuer)?;
        let seen_at = seen.remove(jti)?;
        if seen.is_empty() {
            self.issuers.remove(issuer);
        }
        Some(seen_at)
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

    /// A forgotten pair is new again at once, and only that pair.
    #[test]
    fn a_forgotten_pair_is_accepted_again_and_nothing_else_moves() {
        let log = JtiLog::new(100);
        assert_eq!(log.record("iss", "j1", at(0), at(-300)), Recorded::New);
        assert_eq!(log.record("iss", "j2", at(1), at(-299)), Recorded::New);
        assert!(log.forget("iss", "j1"));
        assert!(!log.forget("iss", "j1"), "already forgotten");
        assert_eq!(log.len(), 1);
        assert_eq!(log.record("iss", "j1", at(2), at(-298)), Recorded::New);
        assert_eq!(log.record("iss", "j2", at(2), at(-298)), Recorded::Replay);
        assert_eq!(log.len(), 2, "no stale order item doubles an entry");
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

    /// The bound is per issuer: an IdP that fills its own log does not get
    /// every other IdP's logouts refused.
    #[test]
    fn one_issuers_full_log_does_not_refuse_another_issuers_token() {
        let log = JtiLog::new(10);
        for n in 0..10 {
            assert_eq!(
                log.record("https://noisy", &format!("j{n}"), at(n), at(-300)),
                Recorded::New
            );
        }
        assert_eq!(
            log.record("https://noisy", "j10", at(10), at(-300)),
            Recorded::Full,
            "the noisy issuer is at its bound"
        );
        assert_eq!(
            log.record("https://quiet", "j1", at(10), at(-300)),
            Recorded::New,
            "another issuer's logout is not starved by the noisy one"
        );
        assert_eq!(
            log.record("https://quiet", "j1", at(11), at(-300)),
            Recorded::Replay
        );
        assert_eq!(log.len(), 11);
    }

    /// An issuer whose every entry expired leaves no partition behind,
    /// whichever issuer's token ran the expiry: with tenant providers the
    /// issuers are not a set fixed at build time.
    #[test]
    fn an_issuer_whose_entries_all_expired_leaves_no_partition() {
        let log = JtiLog::new(10);
        assert_eq!(
            log.record("https://gone", "j1", at(0), at(-300)),
            Recorded::New
        );
        assert_eq!(log.partitions(), 1, "the case exists");
        assert_eq!(
            log.record("https://live", "j1", at(400), at(100)),
            Recorded::New
        );
        assert_eq!(log.len(), 1, "the old entry expired");
        assert_eq!(log.partitions(), 1, "and its partition went with it");
    }
}
