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

// ── Security boundary limits ────────────────────────────────────────────────
//
// Hard limits enforced inside the library to prevent CPU/memory DoS even if the
// application layer omits its own validation. These are safety nets — applications
// should still validate earlier for better UX (meaningful error messages).

/// Maximum password length accepted before Argon2 hashing (bytes).
///
/// Argon2 technically accepts up to 4 GiB, but hashing even a few MB is a CPU DoS.
/// 1024 bytes covers any realistic password (including passphrase generators).
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// Maximum OTP code length accepted before hash verification (bytes).
///
/// Real OTP codes are 4–8 digits. 64 bytes allows some margin for whitespace
/// and alternate formats while preventing Argon2 DoS via multi-MB "codes."
pub const MAX_OTP_CODE_BYTES: usize = 64;

/// Maximum length of a login/signup identifier (bytes).
///
/// Covers email addresses (RFC 5321: 254 chars) and UUIDs. Prevents
/// oversized database queries and log-line inflation.
pub const MAX_IDENTIFIER_BYTES: usize = 256;

/// Maximum length of a user display name (bytes).
pub const MAX_DISPLAY_NAME_BYTES: usize = 256;

/// Maximum length of an OAuth authorization code or state parameter (bytes).
///
/// OAuth 2.0 does not specify a max, but real IdPs return < 2 KiB.
pub const MAX_OAUTH_PARAM_BYTES: usize = 4096;

/// Returns `true` if the string contains only printable characters (no control
/// characters except space). Rejects null bytes, tabs, newlines, etc.
pub fn is_printable(s: &str) -> bool {
    s.chars()
        .all(|c| c == ' ' || (!c.is_control() && c != '\u{FEFF}'))
}
