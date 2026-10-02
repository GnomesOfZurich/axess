//! Recovery codes: one-time fallback credentials for a second factor.
//!
//! A user who enrols an authenticator app receives a set of codes to keep
//! somewhere safe. Each one can stand in for the second factor exactly once,
//! so losing the phone is not losing the account. The set lives in one
//! [`RecoveryCodesConfig`]: Argon2id hashes, each with the instant it was used.
//! Verification returns the config with the matched code marked used; the
//! orchestrator persists it with compare-and-swap, so two concurrent logins
//! presenting the same code cannot both succeed.
//!
//! The shape of a code: [`RECOVERY_CODE_LENGTH`] characters from a 32-symbol
//! alphabet (50 bits), shown as two groups of five (`ABCDE-FGHJK`). The dash
//! is a reading aid only; what is hashed is the canonical form, and
//! [`normalize_recovery_code`] maps anything a person might type back onto it.

use axess_rng::SecureRng;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::password::{generate_password_hash, verify_password};
use crate::secret::ZeroizedString;

/// How many codes a fresh set holds. Ten is what the large providers issue:
/// enough that one used and one mistyped do not leave a person one bad day
/// from being locked out, few enough to store safely.
pub const RECOVERY_CODE_COUNT: usize = 10;

/// Characters per code, before the display dash. Ten symbols from a 32-symbol
/// alphabet is 50 bits: far beyond what login rate limits let anyone guess,
/// and short enough to type from paper.
pub const RECOVERY_CODE_LENGTH: usize = 10;

/// The alphabet: letters and digits without `0`/`O` and `1`/`I`, the pairs
/// misread on screen and in handwriting. Exactly 32 symbols, so
/// `byte % 32` is uniform over a `u8` with no rejection sampling. Codes are
/// upper-cased before hashing and comparison, so `L` stays.
pub const RECOVERY_CODE_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// One stored recovery code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRecoveryCode {
    /// Argon2id hash of the canonical code (PHC string).
    pub hash: String,
    /// When the code was spent, or `None` while it is still usable.
    pub used_at: Option<DateTime<Utc>>,
}

/// A user's set of recovery codes: the factor config for
/// `FactorKind::RecoveryCode`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RecoveryCodesConfig {
    /// Every code issued in the current set, spent or not.
    pub codes: Vec<StoredRecoveryCode>,
}

impl RecoveryCodesConfig {
    /// Codes not yet spent.
    pub fn remaining(&self) -> usize {
        self.codes.iter().filter(|c| c.used_at.is_none()).count()
    }
}

/// A freshly generated set: the plaintext to show the user once, and the
/// config to store. The plaintext is zeroed on drop.
#[derive(Debug)]
pub struct GeneratedRecoveryCodes {
    /// The codes in display form (`ABCDE-FGHJK`), for one-time display.
    pub display: Vec<ZeroizedString>,
    /// What to persist: hashes only.
    pub config: RecoveryCodesConfig,
}

fn generate_canonical(rng: &impl SecureRng) -> ZeroizedString {
    let mut bytes = [0u8; RECOVERY_CODE_LENGTH];
    rng.fill_bytes(&mut bytes);
    let code: String = bytes
        .iter()
        .map(|b| RECOVERY_CODE_ALPHABET[(*b as usize) % RECOVERY_CODE_ALPHABET.len()] as char)
        .collect();
    bytes.fill(0);
    ZeroizedString::new(code)
}

fn display_form(canonical: &str) -> ZeroizedString {
    let split = RECOVERY_CODE_LENGTH / 2;
    ZeroizedString::new(format!("{}-{}", &canonical[..split], &canonical[split..]))
}

/// Generate a set of `count` codes. Hashing is Argon2id per code and
/// deliberately slow: run this off an async executor's worker threads
/// (e.g. `tokio::task::spawn_blocking`).
pub fn generate_recovery_codes(rng: &impl SecureRng, count: usize) -> GeneratedRecoveryCodes {
    let mut display = Vec::with_capacity(count);
    let mut codes = Vec::with_capacity(count);
    for _ in 0..count {
        let canonical = generate_canonical(rng);
        codes.push(StoredRecoveryCode {
            hash: generate_password_hash(&*canonical),
            used_at: None,
        });
        display.push(display_form(canonical.as_ref()));
    }
    GeneratedRecoveryCodes {
        display,
        config: RecoveryCodesConfig { codes },
    }
}

/// The canonical form of a code as a person typed it: whitespace and the
/// display dash removed, upper-cased; so `abcde fghjk` and `ABCDE-FGHJK`
/// are the same code.
pub fn normalize_recovery_code(raw: &str) -> ZeroizedString {
    ZeroizedString::new(
        raw.chars()
            .filter(char::is_ascii_alphanumeric)
            .map(|c| c.to_ascii_uppercase())
            .collect::<String>(),
    )
}

/// Verify `submitted` against the unspent codes in `config`. On a match,
/// returns the config with that code marked used at `now`; the caller must
/// persist it (compare-and-swap) before treating the login as complete.
///
/// Every unspent hash is checked, matched or not, so the time taken does
/// not reveal which position in the set matched. Hashing is Argon2id: run
/// off an async executor's worker threads.
pub fn verify_recovery_code(
    config: &RecoveryCodesConfig,
    submitted: &str,
    now: DateTime<Utc>,
) -> Option<RecoveryCodesConfig> {
    let normalized = normalize_recovery_code(submitted);
    let candidate: &str = normalized.as_ref();
    if candidate.len() != RECOVERY_CODE_LENGTH
        || !candidate
            .bytes()
            .all(|b| RECOVERY_CODE_ALPHABET.contains(&b))
    {
        return None;
    }
    let mut matched: Option<usize> = None;
    for (i, code) in config.codes.iter().enumerate() {
        if code.used_at.is_none()
            && verify_password(candidate, &code.hash).is_ok()
            && matched.is_none()
        {
            matched = Some(i);
        }
    }
    let index = matched?;
    let mut updated = config.clone();
    updated.codes[index].used_at = Some(now);
    Some(updated)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fills every byte with one value: deterministic shape assertions.
    struct FixedRng(u8);
    impl SecureRng for FixedRng {
        fn fill_bytes(&self, dest: &mut [u8]) {
            dest.fill(self.0);
        }
    }

    /// Fills bytes from a counter: distinct codes in one set.
    struct CountingRng(std::sync::atomic::AtomicU8);
    impl SecureRng for CountingRng {
        fn fill_bytes(&self, dest: &mut [u8]) {
            for b in dest {
                *b = self.0.fetch_add(7, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    #[test]
    fn a_code_shows_as_two_groups_of_five() {
        let set = generate_recovery_codes(&FixedRng(0), 1);
        let shown: &str = set.display[0].as_ref();
        assert_eq!(shown.len(), RECOVERY_CODE_LENGTH + 1);
        assert_eq!(&shown[5..6], "-");
    }

    #[test]
    fn the_alphabet_is_32_symbols_without_easily_confused_ones() {
        // 32 is what makes `byte % len` uniform over a u8; a different length
        // reintroduces modulo bias.
        assert_eq!(RECOVERY_CODE_ALPHABET.len(), 32);
        for excluded in b"0O1I" {
            assert!(!RECOVERY_CODE_ALPHABET.contains(excluded));
        }
    }

    #[test]
    fn normalizing_undoes_display_formatting_and_case() {
        let expected = normalize_recovery_code("ABCDE-FGHJK");
        assert_eq!(&*expected, "ABCDEFGHJK");
        let lower = normalize_recovery_code(" abcde fghjk ");
        assert_eq!(&*lower, "ABCDEFGHJK");
    }

    #[test]
    fn a_set_holds_only_hashes_and_verifies_each_code_once() {
        let rng = CountingRng(std::sync::atomic::AtomicU8::new(1));
        let set = generate_recovery_codes(&rng, 3);
        assert_eq!(set.config.remaining(), 3);
        for (shown, stored) in set.display.iter().zip(&set.config.codes) {
            let shown: &str = shown.as_ref();
            assert!(
                !stored.hash.contains(&shown.replace('-', "")),
                "no plaintext stored"
            );
        }

        let first: &str = set.display[0].as_ref();
        let after = verify_recovery_code(&set.config, &first.to_lowercase(), at(100))
            .expect("the code verifies, typed in lower case");
        assert_eq!(after.remaining(), 2);
        assert_eq!(after.codes[0].used_at, Some(at(100)));
        assert!(
            verify_recovery_code(&after, first, at(200)).is_none(),
            "a spent code does not verify again"
        );
        let second: &str = set.display[1].as_ref();
        assert!(verify_recovery_code(&after, second, at(300)).is_some());
    }

    #[test]
    fn malformed_or_unknown_codes_do_not_verify() {
        let set = generate_recovery_codes(&FixedRng(3), 1);
        assert!(verify_recovery_code(&set.config, "", at(1)).is_none());
        assert!(
            verify_recovery_code(&set.config, "ABCDE", at(1)).is_none(),
            "too short"
        );
        assert!(
            verify_recovery_code(&set.config, "00000-00000", at(1)).is_none(),
            "outside the alphabet"
        );
        assert!(
            verify_recovery_code(&set.config, "ZZZZZ-ZZZZZ", at(1)).is_none(),
            "not in the set"
        );
    }
}
