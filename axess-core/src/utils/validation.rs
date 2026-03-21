//! Input validation helpers for Axess forms and factor flows.
//!
//! Provides reusable checks for passwords, OTP codes, email/URL formats,
//! tenant names, and locale identifiers.

use lazy_regex::regex;

/// Validate a password against simple complexity rules.
pub fn is_valid_password(
    password: &str,
    min_length: usize,
    require_upper: bool,
    require_lower: bool,
    require_digit: bool,
    require_special: bool,
) -> bool {
    if password.len() < min_length {
        return false;
    }
    if require_upper && !password.chars().any(|c| c.is_ascii_uppercase()) {
        return false;
    }
    if require_lower && !password.chars().any(|c| c.is_ascii_lowercase()) {
        return false;
    }
    if require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
        return false;
    }
    if require_special && !password.chars().any(|c| !c.is_alphanumeric()) {
        return false;
    }
    true
}

/// Basic regex validation of email addresses (not fully RFC 5322 compliant).
pub fn is_valid_email(email: &str) -> bool {
    if email.len() > 254 {
        return false;
    }
    let re = regex!(
        r#"(?i)^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"#
    );
    re.is_match(email)
}

/// ISO 639-1 (2 lowercase letters) or IETF BCP 47 (e.g., `"en-US"`) language code.
pub fn is_valid_language_code(code: &str) -> bool {
    if code.len() != 2 && code.len() != 5 {
        return false;
    }
    let re = regex!(r#"^[a-z]{2}(-[A-Z]{2})?$"#);
    re.is_match(code)
}

/// ISO 3166-1 alpha-2 or alpha-3 country code (e.g., `"US"`, `"CHE"`).
pub fn is_valid_country_code(code: &str) -> bool {
    let len = code.len();
    (len == 2 || len == 3) && code.chars().all(|c| c.is_ascii_uppercase())
}

/// Validate URL format (http/https, domain required, max 2048 chars).
pub fn is_valid_url_format(url: &str) -> bool {
    if url.len() > 2048 {
        return false;
    }
    let re = regex!(
        r#"^(https?://)([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+)(:[0-9]{1,5})?(/[^\s?#]*)?(\?[^\s#]*)?(\#[^\s]*)?$"#
    );
    re.is_match(url.trim())
}

/// Validate entity names: Unicode letters, marks, numbers, spaces, punctuation (2-128 chars).
pub fn is_valid_name(name: &str) -> bool {
    let re = regex!(r#"^[\p{L}\p{M}\p{N} ._''\-]{2,128}$"#);
    re.is_match(name)
}

/// Validate a numeric OTP code string (all digits, exact expected length).
pub fn is_valid_otp_code(code: &str, length: u8) -> bool {
    code.len() == length as usize && code.chars().all(|c| c.is_ascii_digit())
}
