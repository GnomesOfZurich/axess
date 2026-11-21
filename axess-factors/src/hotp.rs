//! HOTP: HMAC-Based One-Time Passwords (RFC 4226).
//!
//! Counter-based codes; pair the verifier with an application-side
//! counter store that increments on every successful verification.
//! Variants for SHA-1 (RFC default), SHA-256, and SHA-512 cover the
//! OATH-compliant hardware-token universe.

use crate::factor_secret::FactorSecret;
use crate::otp_algorithm::OtpAlgorithm;
pub use crate::otp_core::HotpAlgorithm;
use crate::otp_core::hotp_value;
use crate::{MAX_HOTP_DIGITS, MIN_OTP_DIGITS, MIN_OTP_SECRET_BYTES};
use axess_clock::{Timestamp, Until};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Default HOTP code length in decimal digits (RFC 4226 §5.3 recommended 6).
pub const HOTP_LENGTH: usize = 6;

/// The widest look-ahead window [`verify_hotp`] accepts: one hundred
/// counter steps. RFC 4226 §7.4 asks for a small window, since every step
/// is one more code a guess can match; a stored `lookahead_window` above
/// this verifies nothing until it is corrected, and a token that has
/// drifted further is resynchronised rather than chased.
pub const MAX_HOTP_LOOKAHEAD: u32 = 100;

// ── HotpConfig ───────────────────────────────────────────────────────────────

/// HOTP factor configuration (RFC 4226).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotpConfig {
    /// Shared secret (raw bytes, base32-encoded for provisioning URIs). Plain
    /// text is zeroized in memory on drop, redacted in `Debug`, and written to
    /// the store as it stands; seal it with a `FactorSecretCipher` to keep it
    /// encrypted at rest. See the OTP secret section of the password and TOTP
    /// guide.
    pub secret: FactorSecret,
    /// Number of digits in the generated code (typically 6).
    pub digits: u8,
    /// HMAC algorithm used for code derivation.
    pub algorithm: OtpAlgorithm,
    /// Server-side counter; advances on every successful verification.
    pub counter: u64,
    /// Number of future counter values accepted to handle hardware-token drift.
    pub lookahead_window: u32,
    /// Number of failed verification attempts made against the current
    /// counter window. Incremented on each failed verify; reset to 0 on a
    /// successful verify and when a lock is set. When it reaches
    /// `max_attempts` the factor is locked for a while (see
    /// [`locked_until`](Self::locked_until)); the counter itself does not
    /// move, so the token stays in sync and its next code verifies once
    /// the lock has run out.
    ///
    /// Required by RFC 4226 §7.4 ("the server MUST set a throttling
    /// parameter T"). Without this counter, an attacker has unlimited
    /// guesses against the lookahead window.
    #[serde(default)]
    pub attempt_count: u8,
    /// Maximum failed attempts before the factor is locked. RFC 4226
    /// §7.4 RECOMMENDS T ≤ 10. Default: 5. A value of 0 is
    /// treated as the default, never as "no limit".
    #[serde(default = "default_max_hotp_attempts")]
    pub max_attempts: u8,
    /// The lock a run of `max_attempts` wrong codes sets, and how many
    /// locks came before it. Set and cleared only by
    /// [`lock_at`](Self::lock_at) and [`clear_lock`](Self::clear_lock), so a
    /// lock always starts the attempt count over; read it with
    /// [`locked_until`](Self::locked_until) and [`lockouts`](Self::lockouts).
    /// Stored as the two top-level fields `locked_until` and `lockouts`.
    #[serde(flatten, default)]
    pub throttle: HotpThrottle,
}

/// The lock state of an HOTP factor (RFC 4226 §7.3's delay scheme): the
/// first lock lasts [`HOTP_LOCK_BASE`], each consecutive lock doubles it up
/// to [`HOTP_LOCK_MAX`], and a successful verification clears it. The
/// counter is never advanced to end a run of guesses; doing so would put the
/// token out of sync, so anyone who knew the password could lock the user
/// out of their own token for good.
///
/// The fields are private: a lock is set only through
/// [`HotpConfig::lock_at`], which also starts the attempt count over.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotpThrottle {
    /// Until when verification is refused; `None` when not locked.
    #[serde(default)]
    locked_until: Option<Until>,
    /// How many locks have been set since the last successful
    /// verification; drives the backoff of the next one.
    #[serde(default)]
    lockouts: u8,
}

fn default_max_hotp_attempts() -> u8 {
    5
}

/// How long the first HOTP lock lasts: one minute.
pub const HOTP_LOCK_BASE: Duration = Duration::from_secs(60);

/// The longest an HOTP lock lasts, however many came before it: one hour.
pub const HOTP_LOCK_MAX: Duration = Duration::from_secs(60 * 60);

impl HotpConfig {
    /// How long the lock set after `lockouts` earlier ones lasts:
    /// [`HOTP_LOCK_BASE`] doubled per earlier lock, capped at
    /// [`HOTP_LOCK_MAX`].
    pub fn lock_duration_after(lockouts: u8) -> Duration {
        let doublings = u32::from(lockouts.min(31));
        HOTP_LOCK_BASE
            .checked_mul(1u32 << doublings)
            .map_or(HOTP_LOCK_MAX, |d| d.min(HOTP_LOCK_MAX))
    }

    /// Whether verification is refused at `now` because of an earlier run
    /// of wrong codes.
    pub fn is_locked_at(&self, now: Timestamp) -> bool {
        self.throttle
            .locked_until
            .is_some_and(|until| Until::At(now) < until)
    }

    /// Until when verification is refused, after `max_attempts` wrong codes
    /// against the current counter; `None` when the factor is not locked. A
    /// lock that would end past the range of the clock's readings never ends
    /// ([`Until::Forever`]).
    pub fn locked_until(&self) -> Option<Until> {
        self.throttle.locked_until
    }

    /// How many locks have been set since the last successful verification.
    pub fn lockouts(&self) -> u8 {
        self.throttle.lockouts
    }

    /// Lock the factor at `now` for the backoff its history earns, start
    /// the attempt count over for the period after it and count the lock.
    /// The counter is left where it is.
    pub fn lock_at(&mut self, now: Timestamp) {
        // The backoff is at most an hour. A lock that would end past the
        // range of the clock's readings never ends, which fails closed.
        self.throttle.locked_until = Some(Until::after(
            now,
            Self::lock_duration_after(self.throttle.lockouts),
        ));
        self.throttle.lockouts = self.throttle.lockouts.saturating_add(1);
        self.attempt_count = 0;
    }

    /// Forget the throttle state after a successful verification.
    pub fn clear_lock(&mut self) {
        self.throttle = HotpThrottle::default();
        self.attempt_count = 0;
    }
}

impl Default for HotpConfig {
    fn default() -> Self {
        Self {
            secret: FactorSecret::Plain(crate::secret::ZeroizedString::new("")),
            digits: 6,
            algorithm: OtpAlgorithm::Sha1,
            counter: 0,
            lookahead_window: 10,
            attempt_count: 0,
            max_attempts: 5,
            throttle: HotpThrottle::default(),
        }
    }
}

// Pins the documented `max_attempts` default of five, and that a stored
// config without the throttle fields reads as unlocked. A default of 0
// would lock the user out at once or never count a failure, depending on
// how the verify path reads it.
#[cfg(test)]
mod hotp_config_defaults {
    use super::{HotpConfig, default_max_hotp_attempts};

    #[test]
    fn hotp_default_max_attempts_is_five() {
        assert_eq!(default_max_hotp_attempts(), 5);
        assert_eq!(HotpConfig::default().max_attempts, 5);
    }

    #[test]
    fn a_stored_config_without_the_throttle_fields_reads_as_unlocked() {
        // A row written before the lock existed has neither field.
        let mut json = serde_json::to_value(HotpConfig::default()).expect("serialises");
        let row = json.as_object_mut().expect("an object");
        assert!(row.remove("locked_until").is_some());
        assert!(row.remove("lockouts").is_some());
        let cfg: HotpConfig = serde_json::from_value(json).expect("older rows still read");
        assert_eq!(cfg.locked_until(), None);
        assert_eq!(cfg.lockouts(), 0);
        assert!(!cfg.is_locked_at(axess_clock::testing::MockClock::reference_time()));
    }
}

#[cfg(test)]
mod hotp_lock_backoff {
    use super::{HOTP_LOCK_BASE, HOTP_LOCK_MAX, HotpConfig};
    use axess_clock::testing::Shift;
    use axess_clock::{SignedDuration, Timestamp, Until};

    #[test]
    fn each_consecutive_lock_doubles_up_to_the_cap() {
        assert_eq!(HotpConfig::lock_duration_after(0), HOTP_LOCK_BASE);
        assert_eq!(HotpConfig::lock_duration_after(1), HOTP_LOCK_BASE * 2);
        assert_eq!(HotpConfig::lock_duration_after(5), HOTP_LOCK_BASE * 32);
        assert_eq!(HotpConfig::lock_duration_after(6), HOTP_LOCK_MAX);
        assert_eq!(HotpConfig::lock_duration_after(u8::MAX), HOTP_LOCK_MAX);
    }

    #[test]
    fn a_lock_holds_until_its_end_and_leaves_the_counter_alone() {
        let t0 = Timestamp::from_utc(2026, 1, 1, 12, 0, 0).unwrap();
        let mut cfg = HotpConfig {
            counter: 41,
            attempt_count: 5,
            ..HotpConfig::default()
        };
        cfg.lock_at(t0);
        assert_eq!(cfg.counter, 41);
        assert_eq!(cfg.attempt_count, 0);
        assert_eq!(cfg.lockouts(), 1);
        assert!(cfg.is_locked_at(t0));
        assert!(cfg.is_locked_at(t0.plus(SignedDuration::seconds(59))));
        assert!(!cfg.is_locked_at(t0.plus(SignedDuration::seconds(60))));
        cfg.lock_at(t0);
        assert!(cfg.is_locked_at(t0.plus(SignedDuration::seconds(119))));
        assert!(!cfg.is_locked_at(t0.plus(SignedDuration::seconds(120))));
        cfg.clear_lock();
        assert_eq!((cfg.locked_until(), cfg.lockouts()), (None, 0));
    }

    #[test]
    fn a_lock_ends_at_the_reading_its_backoff_names() {
        let t0 = Timestamp::from_utc(2026, 1, 1, 12, 0, 0).unwrap();
        let mut cfg = HotpConfig::default();
        cfg.lock_at(t0);
        assert_eq!(
            cfg.locked_until(),
            Some(Until::At(t0.plus(SignedDuration::seconds(60))))
        );
        cfg.lock_at(t0);
        assert_eq!(
            cfg.locked_until(),
            Some(Until::At(t0.plus(SignedDuration::seconds(120))))
        );
    }

    #[test]
    fn a_lock_that_would_end_past_the_range_never_ends() {
        // Half a minute before the last reading: the first lock, of one
        // minute, has no reading to end at.
        let late = Timestamp::MAX.minus(SignedDuration::seconds(30));
        let mut cfg = HotpConfig::default();
        cfg.lock_at(late);
        assert_eq!(cfg.locked_until(), Some(Until::Forever));
        assert!(cfg.is_locked_at(late));
        assert!(cfg.is_locked_at(Timestamp::MAX));
        // It is stored as the latest reading, as earlier releases stored it.
        let stored = serde_json::to_value(&cfg).expect("serialises");
        assert_eq!(stored["locked_until"], "+262142-12-31T23:59:59.999999999Z");
        let read: HotpConfig = serde_json::from_value(stored).expect("reads back");
        assert_eq!(read.locked_until(), Some(Until::Forever));
    }
}

/// Verify an HOTP code with a window of acceptable counter values (RFC 4226).
///
/// # Arguments
/// * `secret` - The shared secret (base32 encoded)
/// * `code` - The HOTP code to verify
/// * `counter` - The expected counter value
/// * `length` - Number of digits in the code
/// * `window` - Number of future counter values to check (0 = exact match only)
/// * `algorithm` - The HMAC algorithm to use (defaults to SHA-1 for backward compatibility)
///
/// # Returns
/// `Some(used_counter)` if verification succeeds (the actual counter that matched),
/// `None` if verification fails
pub fn verify_hotp(
    secret: &str,
    code: &str,
    counter: u64,
    length: usize,
    window: u64,
    algorithm: HotpAlgorithm,
) -> Option<u64> {
    // RFC 4226 §5.3 requires at least six digits; a shorter code is
    // brute-forceable in a handful of attempts, and a length of 0 makes the
    // code "0" match every counter.
    if !(MIN_OTP_DIGITS..=MAX_HOTP_DIGITS).contains(&length) {
        return None;
    }
    // A window past the bound verifies nothing: every step widens what a
    // guess can match, and each costs an HMAC, so an unbounded window is
    // both a weaker check and a way to make one verify run for ever.
    if window > u64::from(MAX_HOTP_LOOKAHEAD) {
        return None;
    }

    // Normalize secret for base32 (uppercase, try with and without padding).
    // Wrap the uppercase copy in Zeroizing so it's cleared on drop.
    let secret_upper = Zeroizing::new(secret.trim().to_ascii_uppercase());
    let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &secret_upper)
        .or_else(|| base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &secret_upper))?;

    // Enforce RFC 4226 §4 R6 minimum (128-bit / 16-byte) secret.
    if decoded.len() < MIN_OTP_SECRET_BYTES {
        return None;
    }

    // Wrap the owned bytes so they get zeroed on drop.
    let secret_bytes = Zeroizing::new(decoded);

    // Try each counter value in the window.
    // Always iterate the full window to avoid leaking the match position via timing.
    // The ct_eq comparison runs every iteration; only the first match is recorded.
    // `checked_add` guards against `counter + window` overflowing near
    // `u64::MAX`: debug builds would panic, release builds would silently
    // wrap to 0 and compare against the counter-0 code, a real
    // authentication bypass under adversarial inputs. On overflow we
    // stop iterating; matched stays whatever it was on prior iterations.
    let mut matched: Option<u64> = None;
    // Compare numbers, not strings: the supplied code is read once, and each
    // window step is a `u64` rather than a freshly allocated padded string.
    // A code is `length` ASCII digits and nothing else (a sign or a space
    // would otherwise parse), so equal values mean equal padded codes.
    let trimmed_code = code.trim();
    let supplied = (trimmed_code.len() == length
        && trimmed_code.bytes().all(|b| b.is_ascii_digit()))
    .then(|| trimmed_code.parse::<u64>().ok())
    .flatten();
    let supplied_value = supplied.unwrap_or(u64::MAX);
    for offset in 0..=window {
        let Some(candidate_counter) = counter.checked_add(offset) else {
            break;
        };
        let expected = hotp_value(&secret_bytes, candidate_counter, length, algorithm);
        let is_match = supplied.is_some() && bool::from(expected.ct_eq(&supplied_value));
        if is_match && matched.is_none() {
            matched = Some(candidate_counter);
        }
    }

    matched
}

/// Generate an HOTP code per RFC 4226 as a zero-padded decimal string.
#[cfg(test)]
pub(crate) fn hotp_generate(
    secret: &[u8],
    counter: u64,
    digits: usize,
    algorithm: HotpAlgorithm,
) -> String {
    format!(
        "{:0>width$}",
        hotp_value(secret, counter, digits, algorithm),
        width = digits,
    )
}

#[cfg(test)]
mod tests;
