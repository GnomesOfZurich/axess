//! A small deterministic generator for the property-style tests: the same
//! seed gives the same values on every run and every machine.

use crate::duration::SignedDuration;
use crate::timestamp::Timestamp;

/// The SplitMix64 generator: one word of state, a full period, and an
/// output that passes for random in a test.
pub(crate) struct Generator {
    state: u64,
}

impl Generator {
    pub(crate) fn new(seed: u64) -> Generator {
        Generator { state: seed }
    }

    pub(crate) fn word(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = self.state;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }

    /// A value in `low..=high`.
    pub(crate) fn between(&mut self, low: i64, high: i64) -> i64 {
        let width = (i128::from(high) - i128::from(low) + 1) as u128;
        let offset = u128::from(self.word()) % width;
        (i128::from(low) + offset as i128) as i64
    }

    /// A fraction of a second: none, whole milliseconds, whole microseconds
    /// or any count of nanoseconds, each one time in four.
    pub(crate) fn nanos(&mut self) -> u32 {
        match self.word() % 4 {
            0 => 0,
            1 => self.between(0, 999) as u32 * 1_000_000,
            2 => self.between(0, 999_999) as u32 * 1_000,
            _ => self.between(0, 999_999_999) as u32,
        }
    }

    /// A reading: anywhere in the range, in the years people live in, near
    /// the epoch, or near either end of the range.
    pub(crate) fn timestamp(&mut self) -> Timestamp {
        let (first, last) = (Timestamp::MIN.unix_seconds(), Timestamp::MAX.unix_seconds());
        let secs = match self.word() % 10 {
            0..=3 => self.between(first, last),
            4..=6 => self.between(-2_208_988_800, 4_102_444_800),
            7 => self.between(-172_800, 172_800),
            8 => self.between(first, first + 172_800),
            _ => self.between(last - 172_800, last),
        };
        Timestamp::new(secs, self.nanos()).expect("a reading inside the range")
    }

    /// A span of any size and sign, built from its two fields.
    pub(crate) fn span(&mut self) -> SignedDuration {
        let secs = match self.word() % 4 {
            0 => self.between(i64::MIN, i64::MAX),
            1 => self.between(-3, 3),
            2 => self.between(i64::MAX - 3, i64::MAX),
            _ => self.between(i64::MIN, i64::MIN + 3),
        };
        let nanos = self.nanos() as i32;
        SignedDuration::from_mixed(secs, if secs < 0 { -nanos } else { nanos })
    }
}
