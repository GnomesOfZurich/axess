use lazy_regex::regex;
use serde::{Deserialize, Serialize};
use tracing::debug;

// #[cfg(feature = "authn")]
// pub fn verify_hotp(secret: &str, code: &str, length: usize, counter: u64) -> bool {
//     match TOTP::new(Algorithm::SHA1, length, 30, 1, secret.as_bytes().to_vec()) {
//         Ok(totp) => {
//             let expected = totp.generate_from_input(counter);
//             expected == code
//         },
//         Err(e) => {
//             error!("HOTP verification failed: {:?}", e);
//             false
//         }
//     }
// }

/// Configuration for password validation rules.
#[derive(Clone, Debug)]
pub struct PasswordConfig {
    min: Option<usize>,
    max: Option<usize>,
    has_upper: bool,
    has_lower: bool,
    has_number: bool,
    has_special: bool,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            min: Some(3),
            max: Some(512),
            has_upper: true,
            has_lower: true,
            has_number: true,
            has_special: true,
        }
    }
}

/// Validate password strength based on the provided configuration.
pub fn is_valid_password(password: &str, config: PasswordConfig) -> bool {
    if let Some(min) = config.min
        && password.len() < min
    {
        debug!(
            "Password validation error: Min password length: {} symbols",
            min
        );
        return false;
    }
    if let Some(max) = config.max
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

    if config.has_upper && !has_uppercase.is_match(password) {
        debug!("Invalid Password: At least 1 uppercase letter");
        false
    } else if config.has_lower && !has_lowercase.is_match(password) {
        debug!("Invalid Password: At least 1 lowercase letter");
        false
    } else if config.has_number && !has_number.is_match(password) {
        debug!("Invalid Password: At least 1 number");
        false
    } else if config.has_special && !has_special.is_match(password) {
        debug!("Invalid Password: At least 1 special symbol");
        false
    } else {
        true
    }
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
pub fn is_valid_country_iso(code: &str) -> bool {
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

/// Configuration for TOTP code validation.
#[derive(Clone, Debug)]
pub enum OtpCharset {
    Numeric,
    Hex,
    Alphanumeric,
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

#[derive(Clone, Debug)]
pub struct OtpConfig {
    pub length: usize,
    pub charset: OtpCharset,
}

impl Default for OtpConfig {
    fn default() -> Self {
        Self {
            length: 6,
            charset: OtpCharset::Numeric,
        }
    }
}

/// Validate a OTP code according to the provided config.
pub fn is_valid_otp_code(code: &str, config: &OtpConfig) -> bool {
    if code.len() != config.length {
        return false;
    }
    match config.charset {
        OtpCharset::Numeric => code.chars().all(|c| c.is_ascii_digit()),
        OtpCharset::Hex => code.chars().all(|c| c.is_ascii_hexdigit()),
        OtpCharset::Alphanumeric => code.chars().all(|c| c.is_ascii_alphanumeric()),
    }
}
