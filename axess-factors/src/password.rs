//! Password factor: Argon2id hashing/verification plus the typed
//! [`PasswordConfig`] / [`PasswordRules`] data the orchestrator
//! persists per user.
//!
//! Hashing is Argon2id with the explicit parameter set
//! [`ARGON2_M_COST_KIB`] / [`ARGON2_T_COST`] / [`ARGON2_P_COST`], built
//! through `argon2` directly so no dependency release can move the work
//! factors. Verification goes through the same crate's
//! `PasswordVerifier` on the stored PHC string. The salt is [`PASSWORD_SALT_LEN`] bytes from a [`SecureRng`], so a
//! deterministic RNG yields a reproducible hash; [`generate_password_hash`]
//! draws it from the operating system. The parameter set is written into the
//! PHC string, so [`verify_password`] needs no configuration and keeps
//! verifying hashes made under any earlier parameter set.
//!
//! Argon2 is deliberately slow (tens of milliseconds): call these from
//! blocking context. The orchestrator runs them through
//! `axess_core::blocking`.
//!
//! A password a person has just chosen goes through [`hash_new_password`]
//! (the rules) or [`hash_new_password_checked`] (the rules and a
//! [`breached::BreachedPasswordCheck`]); see [`breached`] for the check and
//! the range-protocol helpers.
//!
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};
use axess_rng::SecureRng;
use std::fmt;

/// Argon2id memory cost in KiB (19 MiB).
pub const ARGON2_M_COST_KIB: u32 = 19 * 1024;
/// Argon2id iteration count.
pub const ARGON2_T_COST: u32 = 2;
/// Argon2id parallelism.
pub const ARGON2_P_COST: u32 = 1;
/// Longest password accepted, in bytes.
///
/// Argon2 technically accepts up to 4 GiB, but hashing even a few MB is a CPU
/// DoS. 1024 bytes covers any realistic password (including passphrase
/// generators). A login refuses a longer one before hashing it.
pub const MAX_PASSWORD_BYTES: usize = 1024;
/// Bytes of salt in a new hash.
pub const PASSWORD_SALT_LEN: usize = 16;

fn argon2() -> Argon2<'static> {
    let params = Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, None)
        .expect("the compiled-in Argon2 parameters are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Why [`verify_password`] did not accept a password.
///
/// This is the crate's own type: it does not expose the hashing library's
/// error, so a dependency upgrade cannot change a public signature. Callers
/// must treat both variants as a failed login and must not tell the user
/// which one occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordVerifyError {
    /// The stored value is not a PHC string this crate can verify.
    Malformed,
    /// The stored hash is well formed and the password does not match it.
    Mismatch,
}

impl fmt::Display for PasswordVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "stored password hash is not a valid PHC string",
            Self::Mismatch => "password does not match the stored hash",
        })
    }
}

impl std::error::Error for PasswordVerifyError {}

/// Check `password` against a stored Argon2 PHC string.
///
/// Every parameter (algorithm variant, version, memory, iterations,
/// parallelism, salt, output length) is read from `hash`, so hashes made under
/// any earlier parameter set keep verifying and the pinned constants only
/// govern new hashes. The comparison of the derived tag is constant time.
/// Slow by design: call from blocking context.
pub fn verify_password(password: impl AsRef<[u8]>, hash: &str) -> Result<(), PasswordVerifyError> {
    match argon2().verify_password(password.as_ref(), hash) {
        Ok(()) => Ok(()),
        Err(argon2::password_hash::Error::PasswordInvalid) => Err(PasswordVerifyError::Mismatch),
        Err(_) => Err(PasswordVerifyError::Malformed),
    }
}

/// Whether `hash` was made under parameters other than the pinned ones, so a
/// successful login is the moment to hash the password again.
///
/// True for a well-formed PHC string whose algorithm, version, memory cost,
/// iteration count or parallelism differ from [`ARGON2_M_COST_KIB`],
/// [`ARGON2_T_COST`] and [`ARGON2_P_COST`] under Argon2id version 19. A hash
/// that does not parse answers false: [`verify_password`] refuses it, so no
/// login reaches the point of replacing it.
pub fn password_needs_rehash(hash: &str) -> bool {
    let Ok(parsed) = argon2::PasswordHash::new(hash) else {
        return false;
    };
    let Ok(params) = Params::try_from(&parsed) else {
        return false;
    };
    parsed.algorithm != argon2::ARGON2ID_IDENT
        || parsed.version != Some(u32::from(Version::V0x13))
        || params.m_cost() != ARGON2_M_COST_KIB
        || params.t_cost() != ARGON2_T_COST
        || params.p_cost() != ARGON2_P_COST
}

/// Draw a fresh salt from `rng`.
pub fn generate_password_salt(rng: &(impl SecureRng + ?Sized)) -> [u8; PASSWORD_SALT_LEN] {
    let mut salt = [0u8; PASSWORD_SALT_LEN];
    rng.fill_bytes(&mut salt);
    salt
}

/// Argon2id hash of `password` under `salt`, as a PHC string.
///
/// The slow half of hashing, split from salt generation so a caller can draw
/// the salt on the async side (in deterministic order) and move only owned
/// bytes into a blocking task.
pub fn hash_password_with_salt(
    password: impl AsRef<[u8]>,
    salt: &[u8; PASSWORD_SALT_LEN],
) -> String {
    argon2()
        .hash_password_with_salt(password.as_ref(), salt)
        .expect("Argon2id hashing with fixed valid parameters cannot fail")
        .to_string()
}

/// Hash `password` with a salt drawn from `rng`.
pub fn generate_password_hash_with_rng(
    rng: &(impl SecureRng + ?Sized),
    password: impl AsRef<[u8]>,
) -> String {
    hash_password_with_salt(password, &generate_password_salt(rng))
}

/// Hash `password` with a salt from the operating system's RNG.
///
/// This checks nothing: not the length, not any [`PasswordRules`]. It is for
/// hashing a value that is already accepted (a stored password being hashed
/// again, a generated code, a test fixture). To hash a password a person has
/// just chosen, at signup or enrolment, use [`hash_new_password`].
///
/// Prefer [`generate_password_hash_with_rng`] where the caller holds an
/// injected RNG.
pub fn generate_password_hash(password: impl AsRef<[u8]>) -> String {
    generate_password_hash_with_rng(&axess_rng::SystemRng, password)
}

/// Why [`hash_new_password`] or [`hash_new_password_checked`] refused a
/// password.
///
/// Each variant's `Display` is a sentence fit to show the person choosing
/// the password; none names what the breach check saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewPasswordError {
    /// The password is longer than [`MAX_PASSWORD_BYTES`]; a login would
    /// refuse it before hashing, so its owner could never sign in.
    TooLong,
    /// The password does not satisfy the [`PasswordRules`].
    RulesNotMet,
    /// The password is known from a data breach; only
    /// [`hash_new_password_checked`] (and the flows built on it) answer this.
    Breached,
    /// The breached-password check could not answer and the policy was
    /// [`BreachCheckUnavailable::Refuse`](breached::BreachCheckUnavailable::Refuse).
    BreachCheckUnavailable,
}

impl fmt::Display for NewPasswordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLong => "password is longer than the maximum accepted length",
            Self::RulesNotMet => "password does not meet the password rules",
            Self::Breached => "password is known from a data breach; choose another",
            Self::BreachCheckUnavailable => {
                "the breached-password check is unavailable; try again later"
            }
        })
    }
}

impl std::error::Error for NewPasswordError {}

/// The length and rules admission shared by [`hash_new_password`] and
/// [`hash_new_password_checked`]: the password as text when it is within
/// [`MAX_PASSWORD_BYTES`] and passes [`PasswordRules::accepts`].
fn admit_by_rules<'p>(
    password: &'p [u8],
    rules: &PasswordRules,
) -> Result<&'p str, NewPasswordError> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(NewPasswordError::TooLong);
    }
    let Ok(text) = std::str::from_utf8(password) else {
        return Err(NewPasswordError::RulesNotMet);
    };
    if !rules.accepts(text) {
        return Err(NewPasswordError::RulesNotMet);
    }
    Ok(text)
}

/// Hash a password a person has just chosen, at signup or enrolment,
/// checking the rules only.
///
/// Refuses a password over [`MAX_PASSWORD_BYTES`] and one that fails
/// [`PasswordRules::accepts`] (length in characters and each complexity
/// requirement the rules switch on), then hashes with a salt from the
/// operating system's RNG. History reuse (`history_count`) needs the stored
/// hashes and is not checked here. It does not consult a breach list: a
/// password from a public breach corpus passes when it meets the rules. Where
/// one is configured, use [`hash_new_password_checked`], which is the same
/// admission with the check in front of the hash. Slow by design: call from
/// blocking context.
pub fn hash_new_password(
    password: impl AsRef<[u8]>,
    rules: &PasswordRules,
) -> Result<String, NewPasswordError> {
    let password = password.as_ref();
    admit_by_rules(password, rules)?;
    Ok(generate_password_hash(password))
}

/// Hash a password a person has just chosen, after the rules and the
/// breached-password check.
///
/// The admission of [`hash_new_password`] first (cheap and local, so a
/// password that fails the rules is never sent to a check), then
/// [`check_password_breached`](breached::check_password_breached) with
/// `check` and `policy` under the tenant's `rules`, then the hash with a
/// salt from the operating system's RNG. Refuses with
/// [`NewPasswordError::Breached`] for a password the check knows, and with
/// [`NewPasswordError::BreachCheckUnavailable`] when the check errs and
/// `policy` is [`Refuse`](breached::BreachCheckUnavailable::Refuse). With
/// `check` `None` it is [`hash_new_password`] in async form. The hash is
/// computed on the calling task: call from blocking context, or through an
/// executor as `axess_core` does.
pub async fn hash_new_password_checked(
    password: &str,
    rules: &PasswordRules,
    check: Option<&dyn breached::BreachedPasswordCheck>,
    policy: breached::BreachCheckUnavailable,
) -> Result<String, NewPasswordError> {
    admit_by_rules(password.as_bytes(), rules)?;
    breached::check_password_breached(password, rules, check, policy).await?;
    Ok(generate_password_hash(password))
}

use crate::secret::ZeroizedString;
use serde::{Deserialize, Serialize};

/// Password factor configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordConfig {
    /// Argon2id PHC hash string, zeroized on drop.
    pub hash: ZeroizedString,
    /// Strength rules applied when setting a new password.
    pub rules: PasswordRules,
    /// Which password this is, kept when the same password is hashed again
    /// under newer parameters, so a check that depends on the password (a
    /// half-finished login's credential epoch) sees a rehash as no change
    /// while a new password is one.
    ///
    /// `None` means the password is identified by its hash. A rehash writes
    /// that identity here, so the hash can change and the identity not.
    /// Leave it `None` for a new password; carry the old value over only for
    /// the same password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_id: Option<String>,
}

/// Complexity requirements for passwords.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordRules {
    /// Minimum password length in Unicode scalar values.
    pub min_length: usize,
    /// Require at least one ASCII uppercase character.
    pub require_uppercase: bool,
    /// Require at least one ASCII lowercase character.
    pub require_lowercase: bool,
    /// Require at least one ASCII digit.
    pub require_digit: bool,
    /// Require at least one non-alphanumeric character.
    pub require_special: bool,
    /// Number of previous password hashes to check for reuse.
    ///
    /// `0` disables history checking. The default is
    /// [`DEFAULT_PASSWORD_HISTORY`], so a password cannot be reset to one of
    /// the last five; set to e.g. `12` for SOC2 compliance ("cannot reuse
    /// last 12 passwords").
    #[serde(default = "default_history_count")]
    pub history_count: usize,
    /// Whether a chosen password is screened against the deployment's
    /// [`BreachedPasswordCheck`](breached::BreachedPasswordCheck), when one
    /// is configured. `true` by default, and for a stored row written before
    /// the field existed, so a tenant is exempted only on purpose by setting
    /// `false`. Without a configured check the field changes nothing.
    #[serde(default = "default_breached_check")]
    pub breached_check: bool,
}

impl PasswordRules {
    /// Whether `password` is within [`MAX_PASSWORD_BYTES`] and satisfies the
    /// length and complexity requirements. History reuse is not checked.
    pub fn accepts(&self, password: &str) -> bool {
        if password.len() > MAX_PASSWORD_BYTES {
            return false;
        }
        // Characters, not UTF-8 bytes: a 5-character password of 2-byte
        // letters must not satisfy a minimum of 8.
        password.chars().count() >= self.min_length
            && (!self.require_uppercase || password.chars().any(|c| c.is_ascii_uppercase()))
            && (!self.require_lowercase || password.chars().any(|c| c.is_ascii_lowercase()))
            && (!self.require_digit || password.chars().any(|c| c.is_ascii_digit()))
            && (!self.require_special || password.chars().any(|c| !c.is_alphanumeric()))
    }
}

/// How many previous passwords [`PasswordRules::default`] refuses to reuse.
pub const DEFAULT_PASSWORD_HISTORY: usize = 5;

fn default_history_count() -> usize {
    DEFAULT_PASSWORD_HISTORY
}

fn default_breached_check() -> bool {
    true
}

impl Default for PasswordRules {
    fn default() -> Self {
        Self {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: false,
            history_count: DEFAULT_PASSWORD_HISTORY,
            breached_check: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedRng(u8);
    impl SecureRng for FixedRng {
        fn fill_bytes(&self, dest: &mut [u8]) {
            dest.fill(self.0);
        }
    }

    #[test]
    fn the_phc_string_carries_the_pinned_parameters() {
        let hash = generate_password_hash_with_rng(&FixedRng(1), "Gnomes2+");
        assert!(
            hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "unexpected parameter block: {hash}"
        );
    }

    #[test]
    fn the_salt_comes_from_the_injected_rng() {
        let a = generate_password_hash_with_rng(&FixedRng(7), "pw");
        let b = generate_password_hash_with_rng(&FixedRng(7), "pw");
        let c = generate_password_hash_with_rng(&FixedRng(8), "pw");
        assert_eq!(a, b, "same salt and password give the same hash");
        assert_ne!(a, c, "a different salt gives a different hash");
        // 16 bytes of 0x07 in unpadded standard base64.
        assert!(
            a.contains("$BwcHBwcHBwcHBwcHBwcHBw$"),
            "salt not from rng: {a}"
        );
    }

    #[test]
    fn hashes_verify_and_wrong_passwords_do_not() {
        let hash = generate_password_hash("correct horse");
        assert!(verify_password("correct horse", &hash).is_ok());
        assert!(verify_password("battery staple", &hash).is_err());
    }

    #[test]
    fn a_hash_under_the_pinned_parameters_needs_no_rehash() {
        let hash = generate_password_hash_with_rng(&FixedRng(1), "Gnomes2+");
        assert!(!password_needs_rehash(&hash));
    }

    #[test]
    fn a_hash_under_weaker_parameters_needs_a_rehash() {
        let salt = [3u8; PASSWORD_SALT_LEN];
        for (m, t, p) in [
            (ARGON2_M_COST_KIB / 2, ARGON2_T_COST, ARGON2_P_COST),
            (ARGON2_M_COST_KIB, ARGON2_T_COST - 1, ARGON2_P_COST),
            (ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST + 1),
        ] {
            let params = Params::new(m, t, p, None).unwrap();
            let weaker = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let hash = weaker
                .hash_password_with_salt(b"pw", &salt)
                .unwrap()
                .to_string();
            assert!(password_needs_rehash(&hash), "m={m} t={t} p={p}: {hash}");
            assert!(verify_password("pw", &hash).is_ok(), "still verifies");
        }
    }

    #[test]
    fn another_variant_or_version_needs_a_rehash() {
        let salt = [3u8; PASSWORD_SALT_LEN];
        let params = Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, None).unwrap();
        let argon2i = Argon2::new(Algorithm::Argon2i, Version::V0x13, params.clone());
        let hash = argon2i
            .hash_password_with_salt(b"pw", &salt)
            .unwrap()
            .to_string();
        assert!(password_needs_rehash(&hash), "{hash}");
        let old = Argon2::new(Algorithm::Argon2id, Version::V0x10, params);
        let hash = old
            .hash_password_with_salt(b"pw", &salt)
            .unwrap()
            .to_string();
        assert!(password_needs_rehash(&hash), "{hash}");
    }

    #[test]
    fn a_string_that_is_not_a_hash_is_not_rehashed() {
        assert!(!password_needs_rehash("not a phc string"));
        assert!(!password_needs_rehash(""));
    }

    #[test]
    fn a_new_password_over_the_limit_is_refused() {
        let long = format!("Aa1{}", "x".repeat(MAX_PASSWORD_BYTES - 2));
        assert_eq!(long.len(), MAX_PASSWORD_BYTES + 1);
        assert_eq!(
            hash_new_password(&long, &PasswordRules::default()),
            Err(NewPasswordError::TooLong)
        );
        let at_limit = format!("Aa1{}", "x".repeat(MAX_PASSWORD_BYTES - 3));
        assert!(hash_new_password(&at_limit, &PasswordRules::default()).is_ok());
    }

    #[test]
    fn a_new_password_that_fails_the_rules_is_refused() {
        let rules = PasswordRules::default();
        for weak in [
            "short1A",
            "alllowercase123",
            "ALLUPPERCASE123",
            "NoDigitsHereAtAll",
        ] {
            assert_eq!(
                hash_new_password(weak, &rules),
                Err(NewPasswordError::RulesNotMet),
                "{weak}"
            );
        }
    }

    #[test]
    fn a_good_new_password_hashes_and_verifies() {
        let hash = hash_new_password("Gnomes2+andmore", &PasswordRules::default()).unwrap();
        assert!(verify_password("Gnomes2+andmore", &hash).is_ok());
        assert!(!password_needs_rehash(&hash));
    }

    #[test]
    fn password_rules_default_is_pinned() {
        let r = PasswordRules::default();
        assert_eq!(r.min_length, 12);
        assert!(r.require_uppercase);
        assert!(r.require_lowercase);
        assert!(r.require_digit);
        assert!(!r.require_special);
        assert_eq!(r.history_count, 5);
        assert!(r.breached_check);
    }
}

#[cfg(test)]
mod legacy_hashes;

pub mod breached;
