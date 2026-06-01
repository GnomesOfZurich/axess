//! Password factor: Argon2id hashing/verification plus the typed
//! [`PasswordConfig`] / [`PasswordRules`] data the orchestrator
//! persists per user.
//!
//! Re-exports the `password_auth` crate's [`generate_hash`] (renamed to
//! [`generate_password_hash`]) and [`verify_password`] functions. The
//! library is a thin Argon2id wrapper that picks recommended parameters,
//! generates a per-hash random salt, and stores the parameter set in the
//! encoded hash so verification works without the application tracking
//! parameters separately.
//!
//! [`generate_hash`]: password_auth::generate_hash
//! [`verify_password`]: password_auth::verify_password
//! [`generate_password_hash`]: crate::generate_password_hash

pub use password_auth::{generate_hash as generate_password_hash, verify_password};

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
