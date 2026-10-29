//! Input validation helpers for Axess forms and factor flows.
//!
//! Provides reusable checks for passwords, OTP codes, email/URL formats,
//! tenant names, and locale identifiers.

use regex::Regex;
use std::sync::LazyLock;

macro_rules! static_regex {
    ($name:ident, $pattern:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pattern).unwrap());
    };
}

static_regex!(
    EMAIL_RE,
    r#"(?i)^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"#
);
static_regex!(LANG_RE, r#"^[a-z]{2}(-[A-Z]{2})?$"#);
static_regex!(
    URL_RE,
    r#"^(https?://)([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+)(:[0-9]{1,5})?(/[^\s?#]*)?(\?[^\s#]*)?(\#[^\s]*)?$"#
);
static_regex!(NAME_RE, r#"^[\p{L}\p{M}\p{N} ._''\-]{2,128}$"#);

/// Validate a password against simple complexity rules.
pub fn is_valid_password(
    password: &str,
    min_length: usize,
    require_upper: bool,
    require_lower: bool,
    require_digit: bool,
    require_special: bool,
) -> bool {
    // A password login refuses anything over `MAX_PASSWORD_BYTES` before
    // hashing it, so a longer one accepted here (at signup or a reset) would
    // be a password its owner can never log in with.
    if password.len() > MAX_PASSWORD_BYTES {
        return false;
    }
    // Characters, not UTF-8 bytes: a 5-character password of 2-byte
    // letters must not satisfy a minimum of 8.
    if password.chars().count() < min_length {
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

/// Validate a password against a tenant's [`PasswordRules`](crate::authn::factor::PasswordRules):
/// the minimum length and each complexity requirement the rules switch on.
/// History reuse (`history_count`) needs the stored hashes and is checked by
/// the service, not here.
pub fn meets_password_rules(password: &str, rules: &crate::authn::factor::PasswordRules) -> bool {
    is_valid_password(
        password,
        rules.min_length,
        rules.require_uppercase,
        rules.require_lowercase,
        rules.require_digit,
        rules.require_special,
    )
}

/// Basic regex validation of email addresses (not fully RFC 5322 compliant).
pub fn is_valid_email(email: &str) -> bool {
    if email.len() > 254 {
        return false;
    }
    EMAIL_RE.is_match(email)
}

/// ISO 639-1 (2 lowercase letters) or IETF BCP 47 (e.g., `"en-US"`) language code.
pub fn is_valid_language_code(code: &str) -> bool {
    if code.len() != 2 && code.len() != 5 {
        return false;
    }
    LANG_RE.is_match(code)
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
    URL_RE.is_match(url.trim())
}

/// Validate entity names: Unicode letters, marks, numbers, spaces, punctuation (2-128 chars).
pub fn is_valid_name(name: &str) -> bool {
    NAME_RE.is_match(name)
}

/// Validate a numeric OTP code string (all digits, exact expected length).
pub fn is_valid_otp_code(code: &str, length: u8) -> bool {
    code.len() == length as usize && code.chars().all(|c| c.is_ascii_digit())
}

// ── Security boundary limits ────────────────────────────────────────────────
//
// Hard limits enforced inside the library to prevent CPU/memory DoS even if the
// application layer omits its own validation. These are safety nets; applications
// should still validate earlier for better UX (meaningful error messages).

/// Maximum password length accepted before Argon2 hashing (bytes).
///
/// Argon2 technically accepts up to 4 GiB, but hashing even a few MB is a CPU DoS.
/// 1024 bytes covers any realistic password (including passphrase generators).
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// Maximum OTP code length accepted before hash verification (bytes).
///
/// Real OTP codes are 4 to 8 digits. 64 bytes allows some margin for whitespace
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

/// Whether `c` is an invisible format character (Unicode category Cf: zero
/// width space and joiners, bidirectional controls, soft hyphen, word joiner
/// and the like) or a noncharacter. None of them has any business in a
/// login identifier (the zero width non-joiner and joiner, U+200C and U+200D,
/// are spelled into ordinary words in several scripts and are allowed), and each makes two identifiers look the same on screen
/// while comparing different.
fn is_invisible_format_char(c: char) -> bool {
    matches!(c,
        '\u{00AD}'
        | '\u{0600}'..='\u{0605}'
        | '\u{061C}'
        | '\u{06DD}'
        | '\u{070F}'
        | '\u{180E}'
        | '\u{200B}'
        | '\u{200E}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{206F}'
        | '\u{FEFF}'
        | '\u{FFF9}'..='\u{FFFB}'
        | '\u{E0001}'
        | '\u{E0020}'..='\u{E007F}'
        | '\u{FDD0}'..='\u{FDEF}'
    ) || (u32::from(c) & 0xFFFE) == 0xFFFE
}

/// Whether a login identifier is acceptable at signup: printable, free of
/// invisible format characters and noncharacters, and already in Unicode
/// normalisation form C.
///
/// `admin` and `admin\u{200B}` are different strings to a store and the
/// same name to a person; so are a composed `\u{00E9}` and an `e` followed
/// by a combining accent. Rather than rewrite what the caller typed (the
/// stored identifier would then differ from what they will type at login),
/// signup refuses a non-NFC identifier, and the application normalises
/// input to NFC at its edge (browsers send NFC for typed text).
pub fn is_acceptable_identifier(identifier: &str) -> bool {
    is_printable(identifier)
        && !identifier.chars().any(is_invisible_format_char)
        && unicode_normalization::is_nfc(identifier)
}

/// Constant-time comparison of two secret byte slices.
///
/// Use this for all comparisons of secrets (HMAC tags, CSRF tokens, session
/// fingerprints, OTP codes, etc.) to prevent timing side-channels. Returns
/// `true` if both slices have equal length and identical contents.
pub fn compare_secrets(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

#[cfg(test)]
mod validation_tests;
