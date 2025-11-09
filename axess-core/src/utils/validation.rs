//! Input validation helpers underpinning Axess forms and factor flows.
//!
//! These routines provide reusable checks for passwords, OTP codes,
//! email/URL formats, tenant names, and locale identifiers so that both
//! library code and examples can enforce consistent data hygiene.

use crate::authn::methods::policy::{OtpRules, PasswordRules};
use lazy_regex::regex;

pub fn is_valid_password(password: &str, rules: &PasswordRules) -> bool {
    rules.validate(password)
}

/// Basic regex validation of email addresses, allowing common formats, but not fully RFC 5322 compliant:
pub fn is_valid_email(email: &str) -> bool {
    if email.len() > 254 {
        return false;
    }
    let re = regex!(
        r#"(?i)^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"#
    );
    re.is_match(email)
}

/// ISO 639-1 is just two lowercase letters (e.g., "en", "fr"), while IETF BCP 47
/// (e.g., "fr-CA", "en-US"), this regex accepts both formats.
pub fn is_valid_language_code(code: &str) -> bool {
    if code.len() != 2 && code.len() != 5 {
        return false;
    }
    let re = regex!(r#"^[a-z]{2}(-[A-Z]{2})?$"#);
    re.is_match(code)
}

/// Validate ISO country codes (2-letter ISO 3166-1 alpha-2 or 3-letter ISO 3166-1 alpha-3).
/// Returns true only for 2 or 3 uppercase ASCII letters.
/// This function enforces that the code is either exactly 2 or exactly 3 letters.
pub fn is_valid_country_code(code: &str) -> bool {
    // Only accept exactly 2 or 3 uppercase ASCII letters (ISO 3166-1 alpha-2/alpha-3)
    let len = code.len();
    (len == 2 || len == 3) && code.chars().all(|c| c.is_ascii_uppercase())
}

/// Validate URL format using a robust regex.
/// Accepts http/https URLs, requires a valid scheme, domain, and optional port/path/query/fragment.
/// Not fully RFC 3986 compliant, but covers most common web URLs.
/// Returns false for URLs longer than 2048 characters (practical limit).
pub fn is_valid_url_format(url: &str) -> bool {
    if url.len() > 2048 {
        return false;
    }
    // Improved regex: stricter domain, optional port, path, query, fragment.
    let re = regex!(
        r#"^(https?://)                                   # scheme
            ([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])? # domain label
            (\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+) # domain
            (:[0-9]{1,5})?                                # optional port
            (/[^\s?#]*)?                                  # optional path
            (\?[^\s#]*)?                                  # optional query
            (\#[^\s]*)?                                   # optional fragment
        $"#
    );
    re.is_match(url.trim())
}

/// Validation of entity names. Supporting a wide range of global names, allowing for expressing
/// these with Unicode letters, marks, numbers, spaces, apostrophes, hyphens, dots, and underscores.
pub fn is_valid_name(name: &str) -> bool {
    let re = regex!(r#"^[\p{L}\p{M}\p{N} ._'’\-]{2,128}$"#);
    re.is_match(name)
}

pub fn is_valid_otp_code(code: &str, rules: &OtpRules) -> bool {
    rules.validate_code(code)
}
