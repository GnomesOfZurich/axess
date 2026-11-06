//! The record behind the password reset cooldown.
//!
//! The record lives in this process: a deployment of several instances
//! applies the cooldown per instance, and a shared rate limit in front of
//! the route is the bound across them.
//!
//! The record is bounded by its own count, not by an eviction order: a
//! cooldown that has not run out is never pushed out by other identifiers'
//! requests, since that would let a flood of them clear one person's
//! cooldown. When every slot holds a live cooldown a new identifier is
//! answered as already asked, until a cooldown runs out and frees one.

use axess_clock::Clock;
use chrono::{DateTime, Utc};
use sha2::Digest as _;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Identifiers that asked for a reset recently, keyed by a digest of tenant
/// and identifier so the record holds no identifier and has a fixed key size.
pub(crate) struct ResetCooldowns {
    /// Also makes the read and the write of one request a single step:
    /// without it two requests arriving together both read "not seen" and
    /// both pass.
    state: Mutex<Cooling>,
    capacity: usize,
    cooldown: chrono::Duration,
    clock: Arc<dyn Clock>,
}

/// The cooldowns that have not run out. Every cooldown has the same length,
/// so the order they were started in is the order they end in.
#[derive(Default)]
struct Cooling {
    until: HashMap<[u8; 32], DateTime<Utc>>,
    ending: VecDeque<([u8; 32], DateTime<Utc>)>,
    /// When the full-record alarm last sounded.
    alarmed: Option<DateTime<Utc>>,
}

impl ResetCooldowns {
    pub(crate) fn new(capacity: usize, cooldown: Duration, clock: Arc<dyn Clock>) -> Self {
        Self {
            state: Mutex::default(),
            capacity: capacity.max(1),
            cooldown: chrono::Duration::from_std(cooldown).unwrap_or(chrono::Duration::MAX),
            clock,
        }
    }

    /// Whether this tenant and identifier asked within the cooldown. When
    /// they did not, the request is noted (and starts the cooldown) before
    /// returning `false`.
    ///
    /// Both parts are keyed in their normalised form
    /// ([`normalise_identifier`](crate::validation::normalise_identifier):
    /// NFKC, lowercase, invisible format characters dropped, trimmed), so
    /// `alice@x.com` and `ALICE@x.com\u{200B}` are one request. A part that
    /// normalises to nothing is keyed as the empty string, as an over-long
    /// one already is by the caller.
    pub(crate) fn already_asked(&self, tenant_identifier: &str, identifier: &str) -> bool {
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
            if until > now {
                break;
            }
            cooling.ending.pop_front();
            cooling.until.remove(&expired);
        }
        if cooling.until.contains_key(&key) {
            return true;
        }
        if cooling.until.len() >= self.capacity {
            // Sounded at most once a second, so a flood is seen by an
            // operator without the log becoming the flood's second victim.
            if cooling
                .alarmed
                .is_none_or(|at| now.signed_duration_since(at) >= chrono::Duration::seconds(1))
            {
                cooling.alarmed = Some(now);
                tracing::error!(
                    capacity = self.capacity,
                    "password reset cooldown is full of live cooldowns; answering new identifiers as already asked"
                );
            }
            return true;
        }
        let until = now
            .checked_add_signed(self.cooldown)
            .unwrap_or(DateTime::<Utc>::MAX_UTC);
        cooling.until.insert(key, until);
        cooling.ending.push_back((key, until));
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axess_clock::testing::MockClock;

    fn cooldowns(capacity: usize, clock: &MockClock) -> ResetCooldowns {
        ResetCooldowns::new(capacity, Duration::from_secs(60), Arc::new(clock.clone()))
    }

    /// Other people's requests must not clear one person's cooldown.
    #[test]
    fn a_flood_of_other_identifiers_does_not_clear_a_cooldown() {
        let clock = MockClock::now();
        let cooldowns = cooldowns(3, &clock);
        assert!(!cooldowns.already_asked("t1", "victim@example.com"));

        for n in 0..10 {
            let _ = cooldowns.already_asked("t1", &format!("other{n}@example.com"));
        }

        assert!(
            cooldowns.already_asked("t1", "victim@example.com"),
            "the victim's cooldown was pushed out by other identifiers"
        );
    }

    #[test]
    fn a_cooldown_ends_with_its_time() {
        let clock = MockClock::now();
        let cooldowns = cooldowns(3, &clock);
        assert!(!cooldowns.already_asked("t1", "a@example.com"));
        assert!(cooldowns.already_asked("t1", "a@example.com"));
        clock.advance(chrono::Duration::seconds(61));
        assert!(!cooldowns.already_asked("t1", "a@example.com"));
    }

    /// Once the cooldowns that ran out are forgotten, there is room again.
    #[test]
    fn expired_cooldowns_make_room() {
        let clock = MockClock::now();
        let cooldowns = cooldowns(2, &clock);
        assert!(!cooldowns.already_asked("t1", "a@example.com"));
        assert!(!cooldowns.already_asked("t1", "b@example.com"));
        clock.advance(chrono::Duration::seconds(61));
        assert!(!cooldowns.already_asked("t1", "c@example.com"));
        assert!(cooldowns.already_asked("t1", "c@example.com"));
    }

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
        type Writer = Buf;
        fn make_writer(&'a self) -> Buf {
            self.clone()
        }
    }

    /// A full record says so at error level, once a second at most.
    #[test]
    fn a_full_record_sounds_an_error_throttled_to_once_a_second() {
        let buf = Buf::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(buf.clone())
            .finish();
        let clock = MockClock::now();
        let alarms = |buf: &Buf| {
            String::from_utf8(buf.0.lock().unwrap().clone())
                .unwrap()
                .matches("ERROR")
                .count()
        };
        tracing::subscriber::with_default(subscriber, || {
            let cooldowns = cooldowns(1, &clock);
            assert!(!cooldowns.already_asked("t1", "a@example.com"));
            for n in 0..5 {
                assert!(cooldowns.already_asked("t1", &format!("b{n}@example.com")));
            }
            assert_eq!(alarms(&buf), 1, "five refusals in one instant, one alarm");
            clock.advance(chrono::Duration::seconds(2));
            assert!(cooldowns.already_asked("t1", "c@example.com"));
            assert_eq!(
                alarms(&buf),
                2,
                "a second alarm after the second has passed"
            );
        });
    }
}
