//! Factor policy utilities for the authentication subsystem.
//!
//! This module groups the reusable pieces that describe how factors should be
//! validated and stored:
//! - [`PasswordRules`] / [`PasswordRulesBuilder`] define password complexity
//!   requirements enforced when capturing credentials.
//! - [`OtpRules`] / [`OtpRulesBuilder`] describe acceptable OTP lengths, charsets,
//!   and window tolerances used during HOTP/TOTP verification.
//! - [`FactorConfig`] wraps the serialized configuration persisted alongside each
//!   factor instance so callers can read fields without touching raw JSON maps.
//! - [`FactorConfigBuilder`] provides ergonomic constructors for common factor
//!   configs (password hashes, HOTP, TOTP) and ad-hoc overrides when provisioning
//!   factors through [`AuthSession`](../session/auth_session.rs) or custom backends.
//!
//! Higher-level components (forms, session flows, examples) should rely on these
//! helpers to keep validation logic and stored configurations aligned.

use std::{collections::HashMap, str::FromStr};

use crate::tracing::debug;

use lazy_regex::regex;
use serde::{Deserialize, Serialize};
use serde_json::{Number, Value};

/// Configuration for password validation rules.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasswordRules {
    min: Option<usize>,
    max: Option<usize>,
    require_uppercase: bool,
    require_lowercase: bool,
    require_number: bool,
    require_special: bool,
}

impl PasswordRules {
    pub fn builder() -> PasswordRulesBuilder {
        PasswordRulesBuilder::default()
    }

    pub fn validate(&self, password: &str) -> bool {
        if let Some(min) = self.min
            && password.len() < min
        {
            debug!(
                "Password validation error: Min password length: {} symbols",
                min
            );
            return false;
        }
        if let Some(max) = self.max
            && password.len() > max
        {
            debug!(
                "Password validation error: Max password length: {} symbols",
                max
            );
            return false;
        }

        let has_uppercase = regex!(r#"\p{Lu}"#);
        let has_lowercase = regex!(r#"\p{Ll}"#);
        let has_number = regex!(r#"\d"#);
        let has_special = regex!(r#"[!@#\$%\^&_\*\.\[\]\{\}\(\)\|\+\-~,:;!?'¤<>€£¥₹$/\\]"#);

        if self.require_uppercase && !has_uppercase.is_match(password) {
            debug!("Invalid Password: At least 1 uppercase letter");
            false
        } else if self.require_lowercase && !has_lowercase.is_match(password) {
            debug!("Invalid Password: At least 1 lowercase letter");
            false
        } else if self.require_number && !has_number.is_match(password) {
            debug!("Invalid Password: At least 1 number");
            false
        } else if self.require_special && !has_special.is_match(password) {
            debug!("Invalid Password: At least 1 special symbol");
            false
        } else {
            true
        }
    }
}

impl Default for PasswordRules {
    fn default() -> Self {
        Self {
            min: Some(3),
            max: Some(512),
            require_uppercase: true,
            require_lowercase: true,
            require_number: true,
            require_special: true,
        }
    }
}

#[derive(Default)]
pub struct PasswordRulesBuilder {
    min: Option<usize>,
    max: Option<usize>,
    require_uppercase: bool,
    require_lowercase: bool,
    require_number: bool,
    require_special: bool,
}

impl PasswordRulesBuilder {
    pub fn with_min(mut self, value: Option<usize>) -> Self {
        self.min = value;
        self
    }

    pub fn with_max(mut self, value: Option<usize>) -> Self {
        self.max = value;
        self
    }

    pub fn require_uppercase(mut self, value: bool) -> Self {
        self.require_uppercase = value;
        self
    }

    pub fn require_lowercase(mut self, value: bool) -> Self {
        self.require_lowercase = value;
        self
    }

    pub fn require_number(mut self, value: bool) -> Self {
        self.require_number = value;
        self
    }

    pub fn require_special(mut self, value: bool) -> Self {
        self.require_special = value;
        self
    }

    pub fn build(self) -> PasswordRules {
        PasswordRules {
            min: self.min,
            max: self.max,
            require_uppercase: self.require_uppercase,
            require_lowercase: self.require_lowercase,
            require_number: self.require_number,
            require_special: self.require_special,
        }
    }
}

/// Configuration for TOTP code validation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OtpCharset {
    Numeric,
    Hex,
    Alphanumeric,
}

impl OtpCharset {
    pub fn as_str(&self) -> &'static str {
        match self {
            OtpCharset::Numeric => "numeric",
            OtpCharset::Hex => "hex",
            OtpCharset::Alphanumeric => "alphanumeric",
        }
    }
}

impl FromStr for OtpCharset {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "numeric" => Ok(OtpCharset::Numeric),
            "hex" => Ok(OtpCharset::Hex),
            "alphanumeric" => Ok(OtpCharset::Alphanumeric),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OtpType {
    Totp,
    Hotp,
    #[serde(untagged)]
    Custom(String),
}

impl OtpType {
    pub fn as_str(&self) -> &str {
        match self {
            OtpType::Totp => "totp",
            OtpType::Hotp => "hotp",
            OtpType::Custom(s) => s.as_str(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OtpRules {
    pub length: usize,
    pub charset: OtpCharset,
    pub past_window: u64,
    pub future_window: u64,
    pub period: u64,
}

impl Default for OtpRules {
    fn default() -> Self {
        Self {
            length: 6,
            charset: OtpCharset::Numeric,
            past_window: 1,
            future_window: 0,
            period: 30,
        }
    }
}

impl OtpRules {
    pub fn builder() -> OtpRulesBuilder {
        OtpRulesBuilder::default()
    }

    pub fn totp_defaults() -> Self {
        Self::default()
    }

    pub fn hotp_defaults() -> Self {
        Self {
            length: 6,
            charset: OtpCharset::Numeric,
            past_window: 0,
            future_window: 10,
            period: 0,
        }
    }

    pub fn validate_code(&self, code: &str) -> bool {
        if code.len() != self.length {
            return false;
        }
        match self.charset {
            OtpCharset::Numeric => code.chars().all(|c| c.is_ascii_digit()),
            OtpCharset::Hex => code.chars().all(|c| c.is_ascii_hexdigit()),
            OtpCharset::Alphanumeric => code.chars().all(|c| c.is_ascii_alphanumeric()),
        }
    }
}

#[derive(Default)]
pub struct OtpRulesBuilder {
    length: Option<usize>,
    charset: Option<OtpCharset>,
    past_window: Option<u64>,
    future_window: Option<u64>,
    period: Option<u64>,
}

impl OtpRulesBuilder {
    pub fn with_length(mut self, value: usize) -> Self {
        self.length = Some(value);
        self
    }

    pub fn with_charset(mut self, value: OtpCharset) -> Self {
        self.charset = Some(value);
        self
    }

    pub fn with_past_window(mut self, value: u64) -> Self {
        self.past_window = Some(value);
        self
    }

    pub fn with_future_window(mut self, value: u64) -> Self {
        self.future_window = Some(value);
        self
    }

    pub fn with_period(mut self, value: u64) -> Self {
        self.period = Some(value);
        self
    }

    pub fn build(self) -> OtpRules {
        OtpRules {
            length: self.length.unwrap_or(6),
            charset: self.charset.unwrap_or(OtpCharset::Numeric),
            past_window: self.past_window.unwrap_or(1),
            future_window: self.future_window.unwrap_or(0),
            period: self.period.unwrap_or(30),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct FactorConfig {
    inner: HashMap<String, Value>,
}

impl FactorConfig {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    pub fn from_map(map: HashMap<String, Value>) -> Self {
        Self { inner: map }
    }

    pub fn into_inner(self) -> HashMap<String, Value> {
        self.inner
    }

    pub fn as_map(&self) -> &HashMap<String, Value> {
        &self.inner
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn get_value(&self, key: &str) -> Option<&Value> {
        self.inner.get(key)
    }

    pub fn get_string(&self, key: &str) -> Option<&str> {
        self.get_value(key).and_then(Value::as_str)
    }

    pub fn get_u64(&self, key: &str) -> Option<u64> {
        self.get_value(key).and_then(Value::as_u64)
    }

    pub fn get_usize(&self, key: &str) -> Option<usize> {
        self.get_u64(key).map(|v| v as usize)
    }

    pub fn to_builder(&self) -> FactorConfigBuilder {
        FactorConfigBuilder::from_map(self.inner.clone())
    }
}

#[derive(Clone, Debug, Default)]
pub struct FactorConfigBuilder {
    inner: HashMap<String, Value>,
}

impl FactorConfigBuilder {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    pub fn from_map(map: HashMap<String, Value>) -> Self {
        Self { inner: map }
    }

    pub fn from_config(config: FactorConfig) -> Self {
        Self {
            inner: config.into_inner(),
        }
    }

    pub fn password(hash: impl Into<String>) -> Self {
        Self::new().with_field("password_hash", Value::String(hash.into()))
    }

    pub fn totp(secret: impl Into<String>) -> Self {
        Self::new()
            .with_field("otp_type", Value::String("totp".into()))
            .with_secret(secret)
            .with_length(6)
            .with_period(30)
            .with_windows(1, 0)
            .with_last_totp_step(0)
    }

    pub fn hotp(secret: impl Into<String>) -> Self {
        Self::new()
            .with_field("otp_type", Value::String("hotp".into()))
            .with_secret(secret)
            .with_length(6)
            .with_field("counter", Value::Number(Number::from(0u64)))
            .with_field("window", Value::Number(Number::from(10u64)))
    }

    pub fn with_field(mut self, key: impl Into<String>, value: Value) -> Self {
        self.inner.insert(key.into(), value);
        self
    }

    pub fn with_secret(self, secret: impl Into<String>) -> Self {
        self.with_field("otp_secret", Value::String(secret.into()))
    }

    pub fn with_length(self, length: usize) -> Self {
        self.with_field("length", Value::Number(Number::from(length as u64)))
    }

    pub fn with_period(self, period: u64) -> Self {
        self.with_field("period", Value::Number(Number::from(period)))
    }

    pub fn with_windows(self, past: u64, future: u64) -> Self {
        self.with_field("past_window", Value::Number(Number::from(past)))
            .with_field("future_window", Value::Number(Number::from(future)))
    }

    pub fn with_last_totp_step(self, step: u64) -> Self {
        self.with_field("last_totp_step", Value::Number(Number::from(step)))
    }

    pub fn build(self) -> FactorConfig {
        FactorConfig::from_map(self.inner)
    }

    pub fn build_map(self) -> HashMap<String, Value> {
        self.build().into_inner()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_rules_validation() {
        let rules = PasswordRules::builder()
            .with_min(Some(8))
            .with_max(Some(64))
            .require_uppercase(true)
            .require_lowercase(true)
            .require_number(true)
            .require_special(true)
            .build();

        assert!(rules.validate("Valid123!"));
        assert!(!rules.validate("short"));
        assert!(!rules.validate("NOLOWERCASE123!"));
        assert!(!rules.validate("nouppercase123!"));
        assert!(!rules.validate("NoNumber!"));
        assert!(!rules.validate("NoSpecialChar1"));
    }

    #[test]
    fn config_builder_totp_defaults() {
        let config = FactorConfigBuilder::totp("SECRET").build();

        assert_eq!(config.get_string("otp_type"), Some("totp"));
        assert_eq!(config.get_string("otp_secret"), Some("SECRET"));
        assert_eq!(config.get_u64("length"), Some(6));
        assert_eq!(config.get_u64("period"), Some(30));
        assert_eq!(config.get_u64("past_window"), Some(1));
        assert_eq!(config.get_u64("future_window"), Some(0));
        assert_eq!(config.get_u64("last_totp_step"), Some(0));
    }

    #[test]
    fn config_builder_hotp_defaults() {
        let config = FactorConfigBuilder::hotp("HOTSECRET")
            .with_field("counter", Value::Number(Number::from(7u64)))
            .with_field("window", Value::Number(Number::from(5u64)))
            .build();

        assert_eq!(config.get_string("otp_type"), Some("hotp"));
        assert_eq!(config.get_string("otp_secret"), Some("HOTSECRET"));
        assert_eq!(config.get_u64("length"), Some(6));
        assert_eq!(config.get_u64("counter"), Some(7));
        assert_eq!(config.get_u64("window"), Some(5));
        assert!(config.get_u64("period").is_none());
    }
}
