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
/// Prefer [`generate_password_hash_with_rng`] where the caller holds an
/// injected RNG.
pub fn generate_password_hash(password: impl AsRef<[u8]>) -> String {
    generate_password_hash_with_rng(&axess_rng::SystemRng, password)
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
    /// `0` disables history checking (default). Set to e.g. `12` for SOC2
    /// compliance ("cannot reuse last 12 passwords").
    #[serde(default)]
    pub history_count: usize,
}

impl Default for PasswordRules {
    fn default() -> Self {
        Self {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: false,
            history_count: 0,
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
    fn password_rules_default_is_pinned() {
        let r = PasswordRules::default();
        assert_eq!(r.min_length, 12);
        assert!(r.require_uppercase);
        assert!(r.require_lowercase);
        assert!(r.require_digit);
        assert!(!r.require_special);
        assert_eq!(r.history_count, 0);
    }
}

#[cfg(test)]
mod legacy_hashes;
