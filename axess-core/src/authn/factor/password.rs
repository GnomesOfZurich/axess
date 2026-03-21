//! Password factor types and the `ZeroizedString` secret wrapper.

use serde::{Deserialize, Serialize};
use std::{fmt, ops::Deref};
use zeroize::Zeroize;

// ── ZeroizedString ───────────────────────────────────────────────────────────

/// A `String` that is zeroed in memory on drop.
///
/// Used for secrets at rest in memory (password hashes, OTP secrets) to reduce
/// the window during which sensitive data is recoverable from a process dump.
#[derive(Clone, Serialize, Deserialize)]
pub struct ZeroizedString(String);

impl ZeroizedString {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl Drop for ZeroizedString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Zeroize for ZeroizedString {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Deref for ZeroizedString {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for ZeroizedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ZeroizedString(***)")
    }
}

impl From<String> for ZeroizedString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for ZeroizedString {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

// ── PasswordConfig ───────────────────────────────────────────────────────────

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
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_special: bool,
}

impl Default for PasswordRules {
    fn default() -> Self {
        Self {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: false,
        }
    }
}
