//! The record behind the password reset cooldown.
//!
//! The record lives in this process: a deployment of several instances
//! applies the cooldown per instance, and a shared rate limit in front of
//! the route is the bound across them.
//!
//! The record is bounded by its own count. When it is full the oldest
//! cooldown is dropped to make room, so a flood of made-up identifiers from an
//! unauthenticated caller cannot refuse a real user's reset: a refusal falls
//! only on an identifier that is itself cooling down. Dropping a cooldown early
//! costs little, because what bounds the mail an account can be sent is the
//! store's limit on live reset tokens per account, not this record.

use axess_clock::{Clock, SignedDuration, Timestamp, Until};
use sha2::Digest as _;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// What the cooldown says about one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Asked {
    /// Not asked within the cooldown; the request is noted and goes ahead.
    Fresh,
    /// This identifier asked within the cooldown.
    Cooling,
}

/// Identifiers that asked for a reset recently, keyed by a digest of tenant
/// and identifier so the record holds no identifier and has a fixed key size.
pub(crate) struct ResetCooldowns {
    /// Also makes the read and the write of one request a single step:
    /// without it two requests arriving together both read "not seen" and
    /// both pass.
    state: Mutex<Cooling>,
    capacity: usize,
    cooldown: Duration,
    clock: Arc<dyn Clock>,
}

/// The cooldowns that have not run out. Every cooldown has the same length,
/// so the order they were started in is the order they end in.
#[derive(Default)]
struct Cooling {
    until: HashMap<[u8; 32], Until>,
    ending: VecDeque<([u8; 32], Until)>,
    /// When the table-full warning last sounded.
    alarmed: Option<Timestamp>,
}

impl ResetCooldowns {
    pub(crate) fn new(capacity: usize, cooldown: Duration, clock: Arc<dyn Clock>) -> Self {
        Self {
            state: Mutex::default(),
            capacity: capacity.max(1),
            cooldown,
            clock,
        }
    }

    /// Whether this tenant and identifier asked within the cooldown. When
    /// they did not, the request is noted (and starts the cooldown) before
    /// returning [`Asked::Fresh`].
    ///
    /// Both parts are keyed in their normalised form
    /// ([`normalise_identifier`](crate::validation::normalise_identifier):
    /// NFKC, lowercase, invisible format characters dropped, trimmed), so
    /// `alice@x.com` and `ALICE@x.com\u{200B}` are one request. A part that
    /// normalises to nothing is keyed as the empty string, as an over-long
    /// one already is by the caller.
    pub(crate) fn ask(&self, tenant_identifier: &str, identifier: &str) -> Asked {
        let mut hasher = sha2::Sha256::new();
        for part in [tenant_identifier, identifier] {
            let part = crate::validation::normalise_identifier(part).unwrap_or_default();
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        let key: [u8; 32] = hasher.finalize().into();
        let now = self.clock.now();
        // A poisoned lock guards no invariant a panic can break half-way.
        let mut cooling = self.state.lock().unwrap_or_else(|e| e.into_inner());
        while let Some((expired, until)) = cooling.ending.front().copied() {
            if until > Until::At(now) {
                break;
            }
            cooling.ending.pop_front();
            cooling.until.remove(&expired);
        }
        if cooling.until.contains_key(&key) {
            return Asked::Cooling;
        }
        if cooling.until.len() >= self.capacity {
            // Drop the oldest cooldowns (the ones that end first) to make
            // room. Sounded at most once a second, so a flood is seen by an
            // operator without the log becoming the flood's second victim.
            while cooling.until.len() >= self.capacity {
                let Some((oldest, _)) = cooling.ending.pop_front() else {
                    break;
                };
                cooling.until.remove(&oldest);
            }
            if cooling
                .alarmed
                .is_none_or(|at| now.since(at) >= SignedDuration::seconds(1))
            {
                cooling.alarmed = Some(now);
                tracing::warn!(
                    capacity = self.capacity,
                    "password reset cooldown is full; dropping the oldest cooldowns to make room"
                );
            }
        }
        let until = Until::after(now, self.cooldown);
        cooling.until.insert(key, until);
        cooling.ending.push_back((key, until));
        Asked::Fresh
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axess_clock::testing::MockClock;

    impl ResetCooldowns {
        /// `true` when the request was refused as already asked.
        fn asked(&self, tenant: &str, identifier: &str) -> bool {
            self.ask(tenant, identifier) != Asked::Fresh
        }
    }

    fn cooldowns(capacity: usize, clock: &MockClock) -> ResetCooldowns {
        ResetCooldowns::new(capacity, Duration::from_secs(60), Arc::new(clock.clone()))
    }

    /// An unauthenticated flood of made-up identifiers fills the table; a real
    /// user's first request must still go ahead, and only an identifier that
    /// is itself cooling down is refused.
    #[test]
    fn a_flood_of_made_up_identifiers_does_not_refuse_a_real_user() {
        let clock = MockClock::at_reference();
        let cooldowns = cooldowns(3, &clock);
        for n in 0..10 {
            let _ = cooldowns.ask("t1", &format!("made-up-{n}@example.com"));
        }

        assert_eq!(
            cooldowns.ask("t1", "real@example.com"),
            Asked::Fresh,
            "a flood of other identifiers refused a real user's reset"
        );
        assert_eq!(
            cooldowns.ask("t1", "real@example.com"),
            Asked::Cooling,
            "and the real user's own repeat is still refused"
        );
    }

    #[test]
    fn a_cooldown_ends_with_its_time() {
        let clock = MockClock::at_reference();
        let cooldowns = cooldowns(3, &clock);
        assert!(!cooldowns.asked("t1", "a@example.com"));
        assert!(cooldowns.asked("t1", "a@example.com"));
        clock.advance(axess_clock::SignedDuration::seconds(59));
        assert!(
            cooldowns.asked("t1", "a@example.com"),
            "a second before its time it still holds"
        );
        clock.advance(axess_clock::SignedDuration::seconds(1));
        assert!(
            !cooldowns.asked("t1", "a@example.com"),
            "at its time it has ended"
        );
    }

    /// Once the cooldowns that ran out are forgotten, there is room again.
    #[test]
    fn expired_cooldowns_make_room() {
        let clock = MockClock::at_reference();
        let cooldowns = cooldowns(2, &clock);
        assert!(!cooldowns.asked("t1", "a@example.com"));
        assert!(!cooldowns.asked("t1", "b@example.com"));
        clock.advance(axess_clock::SignedDuration::seconds(61));
        assert!(!cooldowns.asked("t1", "c@example.com"));
        assert!(cooldowns.asked("t1", "c@example.com"));
    }

    /// A full record drops its oldest cooldown for a new one, so it never
    /// holds more than its capacity.
    #[test]
    fn a_full_record_drops_its_oldest_cooldown_for_a_new_one() {
        let clock = MockClock::at_reference();
        let cooldowns = cooldowns(2, &clock);
        assert!(!cooldowns.asked("t1", "a@example.com"));
        assert!(!cooldowns.asked("t1", "b@example.com"));
        assert!(!cooldowns.asked("t1", "c@example.com"));

        assert_eq!(cooldowns.state.lock().unwrap().until.len(), 2);
        assert!(cooldowns.asked("t1", "b@example.com"), "b still holds");
        assert!(
            !cooldowns.asked("t1", "a@example.com"),
            "the oldest was dropped for c"
        );
    }

    /// A full record says so at warn level, once a second at most.
    #[test]
    fn a_full_record_sounds_a_warning_throttled_to_once_a_second() {
        let buf = axess_testing::mock_tracing::PrintedLines::new();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(buf.clone())
            .finish();
        let clock = MockClock::at_reference();
        let alarms =
            |buf: &axess_testing::mock_tracing::PrintedLines| buf.text().matches("WARN").count();
        tracing::subscriber::with_default(subscriber, || {
            let cooldowns = cooldowns(1, &clock);
            assert!(!cooldowns.asked("t1", "a@example.com"));
            for n in 0..5 {
                assert!(!cooldowns.asked("t1", &format!("b{n}@example.com")));
            }
            assert_eq!(
                alarms(&buf),
                1,
                "five evictions in one instant, one warning"
            );
            clock.advance(axess_clock::SignedDuration::seconds(2));
            assert!(!cooldowns.asked("t1", "c@example.com"));
            assert_eq!(
                alarms(&buf),
                2,
                "a second warning after the second has passed"
            );
        });
    }
}
