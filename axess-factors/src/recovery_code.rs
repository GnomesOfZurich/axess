//! Recovery codes: one-time fallback credentials for a second factor.
//!
//! A user who enrols an authenticator app receives a set of codes to keep
//! somewhere safe. Each one can stand in for the second factor exactly once,
//! so losing the phone is not losing the account. The set lives in one
//! [`RecoveryCodesConfig`]: a stored form of each code, with the instant it was
//! used. Verification returns the config with the matched code marked used; the
//! orchestrator persists it with compare-and-swap, so two concurrent logins
//! presenting the same code cannot both succeed.
//!
//! The shape of a code: [`RECOVERY_CODE_LENGTH`] characters from a 32-symbol
//! alphabet (50 bits), shown as two groups of five (`ABCDE-FGHJK`). The dash
//! is a reading aid only; what is stored is derived from the canonical form,
//! and [`normalize_recovery_code`] maps anything a person might type back onto
//! it.
//!
//! # Stored forms
//!
//! [`StoredRecoveryCode::hash`] holds one of two forms, told apart by a prefix:
//!
//! - **Keyed** (`hmac-sha256:` followed by 64 hex digits): the HMAC-SHA256 of
//!   the canonical code under a server-side [`RecoveryCodePepper`], made by
//!   [`generate_recovery_codes_peppered`]. Checking it costs microseconds, so a
//!   whole set is compared on every attempt. A 50-bit code does not survive an
//!   offline search against a fast hash, so this form is only as strong as the
//!   pepper staying out of the database: keep it in the secret store, never
//!   beside the rows.
//! - **Argon2id** (a PHC string, starting `$argon2`): what
//!   [`generate_recovery_codes`] writes, and the only form before keyed codes
//!   existed. It needs no secret and costs tens of milliseconds per code, so
//!   verifying a set is ten Argon2 runs: do it off an async executor.
//!
//! A row with no prefix is the Argon2id form, so a set stored by an earlier
//! release verifies unchanged and sets of either form (or a mix) can live side
//! by side. [`verify_recovery_code`] with no pepper cannot match a keyed row
//! and says so by returning `None`, never by guessing.

use axess_rng::SecureRng;
use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

use crate::password::{generate_password_hash_with_rng, verify_password};
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

/// The prefix that marks a keyed stored form.
pub const KEYED_CODE_PREFIX: &str = "hmac-sha256:";

/// Domain label mixed into every keyed code, so a pepper shared with another
/// HMAC use cannot make the two outputs interchangeable.
const KEYED_CODE_DOMAIN: &[u8] = b"axess/recovery-code/v1\0";

const MAC_LEN: usize = 32;

/// The server-side secret keyed recovery codes are derived under.
///
/// At least [`RecoveryCodePepper::MIN_LEN`] bytes of high-entropy key
/// material, held outside the database that stores the codes. Zeroed on drop;
/// `Debug` prints no bytes.
#[derive(Clone)]
pub struct RecoveryCodePepper(Zeroizing<Vec<u8>>);

/// A pepper shorter than [`RecoveryCodePepper::MIN_LEN`] was supplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PepperTooShort {
    /// How many bytes were supplied.
    pub got: usize,
}

impl std::fmt::Display for PepperTooShort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "recovery-code pepper is {} bytes, shorter than the {} minimum",
            self.got,
            RecoveryCodePepper::MIN_LEN
        )
    }
}

impl std::error::Error for PepperTooShort {}

impl RecoveryCodePepper {
    /// The shortest pepper accepted: the size of the HMAC-SHA256 output.
    pub const MIN_LEN: usize = 32;

    /// Wrap key material, refusing anything shorter than [`Self::MIN_LEN`].
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, PepperTooShort> {
        let bytes = Zeroizing::new(bytes.into());
        if bytes.len() < Self::MIN_LEN {
            return Err(PepperTooShort { got: bytes.len() });
        }
        Ok(Self(bytes))
    }

    /// The keyed stored form of a canonical code.
    fn stored_form(&self, canonical: &str) -> String {
        format!("{KEYED_CODE_PREFIX}{}", hex::encode(self.mac(canonical)))
    }

    fn mac(&self, canonical: &str) -> [u8; MAC_LEN] {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.0)
            .expect("HMAC accepts a key of any length");
        mac.update(KEYED_CODE_DOMAIN);
        mac.update(canonical.as_bytes());
        mac.finalize().into_bytes().into()
    }
}

impl std::fmt::Debug for RecoveryCodePepper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RecoveryCodePepper(***)")
    }
}

/// One stored recovery code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRecoveryCode {
    /// The stored form of the canonical code: keyed (`hmac-sha256:` plus hex)
    /// or an Argon2id PHC string. See the module docs.
    pub hash: String,
    /// When the code was spent, or `None` while it is still usable.
    pub used_at: Option<DateTime<Utc>>,
}

impl StoredRecoveryCode {
    /// The 32 bytes of a keyed form, or `None` for an Argon2id row. A keyed
    /// row whose hex is malformed yields `Some` of zeros, which no real MAC
    /// equals in practice and which is still compared, so a corrupt row costs
    /// the same as a sound one.
    fn keyed_mac(&self) -> Option<[u8; MAC_LEN]> {
        let rest = self.hash.strip_prefix(KEYED_CODE_PREFIX)?;
        let mut out = [0u8; MAC_LEN];
        if hex::decode_to_slice(rest, &mut out).is_err() {
            out = [0u8; MAC_LEN];
        }
        Some(out)
    }
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

    /// Whether checking a submission would run Argon2id: some unspent code is
    /// in the Argon2id form. Callers use this to decide whether verification
    /// belongs on a blocking thread.
    pub fn needs_slow_verification(&self) -> bool {
        self.codes
            .iter()
            .any(|c| c.used_at.is_none() && c.keyed_mac().is_none())
    }
}

/// A freshly generated set: the plaintext to show the user once, and the
/// config to store. The plaintext is zeroed on drop.
#[derive(Debug)]
pub struct GeneratedRecoveryCodes {
    /// The codes in display form (`ABCDE-FGHJK`), for one-time display.
    pub display: Vec<ZeroizedString>,
    /// What to persist: stored forms only.
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

fn generate_with(
    rng: &impl SecureRng,
    count: usize,
    store: impl Fn(&str) -> String,
) -> GeneratedRecoveryCodes {
    let mut display = Vec::with_capacity(count);
    let mut codes = Vec::with_capacity(count);
    for _ in 0..count {
        let canonical = generate_canonical(rng);
        codes.push(StoredRecoveryCode {
            hash: store(&canonical),
            used_at: None,
        });
        display.push(display_form(canonical.as_ref()));
    }
    GeneratedRecoveryCodes {
        display,
        config: RecoveryCodesConfig { codes },
    }
}

/// Generate a set of `count` codes stored as Argon2id hashes, with salts drawn
/// from `rng`. Hashing is deliberately slow: run this off an async executor's
/// worker threads (e.g. `tokio::task::spawn_blocking`). Verifying such a set
/// costs one Argon2id run per unspent code; [`generate_recovery_codes_peppered`]
/// makes verification cheap at the price of a server-side secret.
pub fn generate_recovery_codes(rng: &impl SecureRng, count: usize) -> GeneratedRecoveryCodes {
    generate_with(rng, count, |canonical| {
        generate_password_hash_with_rng(rng, canonical)
    })
}

/// Generate a set of `count` codes stored in the keyed form under `pepper`.
/// No Argon2id runs, here or when the set is verified.
pub fn generate_recovery_codes_peppered(
    rng: &impl SecureRng,
    count: usize,
    pepper: &RecoveryCodePepper,
) -> GeneratedRecoveryCodes {
    generate_with(rng, count, |canonical| pepper.stored_form(canonical))
}

/// The canonical form of a code as a person typed it: whitespace and the
/// display dash removed, ASCII letters upper-cased; so `abcde fghjk` and
/// `ABCDE-FGHJK` are the same code. Any other character is kept, so input
/// with a stray symbol never normalises to a valid code.
pub fn normalize_recovery_code(raw: &str) -> ZeroizedString {
    ZeroizedString::new(
        raw.chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect::<String>(),
    )
}

/// The index of the matching unspent row, and how many rows were examined.
///
/// Every row is examined whatever matched, with no early exit: the keyed
/// comparison is a constant-time byte compare for every row (spent or not),
/// and the chosen index is merged with a branch-free select, so neither the
/// time taken nor the control flow depends on which row matched. An Argon2id
/// row costs one verification when unspent and is skipped when spent.
fn find_match(
    config: &RecoveryCodesConfig,
    candidate: &str,
    candidate_mac: Option<&[u8; MAC_LEN]>,
    previous_mac: Option<&[u8; MAC_LEN]>,
) -> (Option<usize>, usize, bool) {
    let mut found = Choice::from(0);
    let mut via_previous = Choice::from(0);
    let mut index = 0u64;
    let mut examined = 0usize;
    for (i, code) in config.codes.iter().enumerate() {
        examined += 1;
        let unspent = Choice::from(code.used_at.is_none() as u8);
        let mut cur_equal = Choice::from(0);
        let mut prev_equal = Choice::from(0);
        let equal = match code.keyed_mac() {
            Some(stored) => {
                // Both comparisons always run, so a row sealed under the
                // previous pepper costs the same as one under the current.
                if let Some(mac) = candidate_mac {
                    cur_equal = mac.ct_eq(&stored);
                }
                if let Some(mac) = previous_mac {
                    prev_equal = mac.ct_eq(&stored);
                }
                cur_equal | prev_equal
            }
            None if bool::from(unspent) => {
                Choice::from(verify_password(candidate, &code.hash).is_ok() as u8)
            }
            None => Choice::from(0),
        };
        let hit = equal & unspent;
        let take = hit & !found;
        index = u64::conditional_select(&index, &(i as u64), take);
        let only_previous = prev_equal & !cur_equal;
        via_previous = Choice::conditional_select(&via_previous, &only_previous, take);
        found |= hit;
    }
    let matched = bool::from(found).then_some(index as usize);
    (matched, examined, bool::from(via_previous))
}

/// Verify `submitted` against the unspent codes in `config`. On a match,
/// returns the config with that code marked used at `now`; the caller must
/// persist it (compare-and-swap) before treating the login as complete.
///
/// `pepper` is needed to match keyed rows; without it only Argon2id rows can
/// match. Every row is examined, matched or not, so the time taken does not
/// reveal which position in the set matched. A set with unspent Argon2id rows
/// runs Argon2id for each: see
/// [`RecoveryCodesConfig::needs_slow_verification`] and run those off an async
/// executor's worker threads.
///
/// After a pepper rotation use [`verify_recovery_code_rotating`].
pub fn verify_recovery_code(
    config: &RecoveryCodesConfig,
    submitted: &str,
    now: DateTime<Utc>,
    pepper: Option<&RecoveryCodePepper>,
) -> Option<RecoveryCodesConfig> {
    verify_recovery_code_rotating(config, submitted, now, pepper, None).map(|m| m.config)
}

/// A successful verification: the config with the matched code spent, and
/// whether the row was keyed under the previous pepper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryMatch {
    /// The config to persist, with the matched code marked used.
    pub config: RecoveryCodesConfig,
    /// True when the code matched only under the previous pepper. A keyed
    /// row cannot be re-keyed without its plaintext, so the set is still
    /// sealed under the retired secret: prompt the user to generate a new
    /// set, and drop the previous pepper once no stored set uses it.
    pub matched_previous_pepper: bool,
}

/// [`verify_recovery_code`] while a pepper rotation is in flight: a keyed row
/// matches under `pepper` (current) or `previous`. Sets generated before the
/// rotation stay usable until their owners regenerate them; new sets are made
/// under the current pepper with [`generate_recovery_codes_peppered`].
pub fn verify_recovery_code_rotating(
    config: &RecoveryCodesConfig,
    submitted: &str,
    now: DateTime<Utc>,
    pepper: Option<&RecoveryCodePepper>,
    previous: Option<&RecoveryCodePepper>,
) -> Option<RecoveryMatch> {
    let normalized = normalize_recovery_code(submitted);
    let candidate: &str = normalized.as_ref();
    if candidate.len() != RECOVERY_CODE_LENGTH
        || !candidate
            .bytes()
            .all(|b| RECOVERY_CODE_ALPHABET.contains(&b))
    {
        return None;
    }
    let candidate_mac = pepper.map(|p| p.mac(candidate));
    let previous_mac = previous.map(|p| p.mac(candidate));
    let (matched, _, via_previous) = find_match(
        config,
        candidate,
        candidate_mac.as_ref(),
        previous_mac.as_ref(),
    );
    let index = matched?;
    let mut updated = config.clone();
    updated.codes[index].used_at = Some(now);
    Some(RecoveryMatch {
        config: updated,
        matched_previous_pepper: via_previous,
    })
}

#[cfg(test)]
mod tests;
