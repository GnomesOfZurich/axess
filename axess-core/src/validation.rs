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
mod validation_tests {
    use super::*;

    // ── is_valid_password ────────────────────────────────────────────────

    /// Pin the length boundary `< min_length`. Discriminates `<`
    /// against `==`, `>`, and `<=`.
    #[test]
    fn password_length_boundary_strict_less_than() {
        // Below minimum: rejected.
        assert!(!is_valid_password("ab", 3, false, false, false, false));
        // Exactly minimum: accepted (kills `<=` mutation).
        assert!(is_valid_password("abc", 3, false, false, false, false));
        // Above minimum: accepted.
        assert!(is_valid_password("abcd", 3, false, false, false, false));
        // Empty with min=1: rejected.
        assert!(!is_valid_password("", 1, false, false, false, false));
    }

    /// A fully-compliant password returns true (kills `-> false`).
    #[test]
    fn password_meeting_all_requirements_returns_true() {
        assert!(is_valid_password("Aa1!aaaa", 8, true, true, true, true));
    }

    /// Missing each individual requirement must reject. Pins
    /// each of the four `&& !...any(...)` conjuncts independently;
    /// kills both `&& → ||` and `delete !` mutations on each line.
    #[test]
    fn password_missing_any_required_class_rejects() {
        // Missing uppercase: reject.
        assert!(!is_valid_password("aaaa1!aa", 4, true, false, false, false));
        // Missing lowercase: reject.
        assert!(!is_valid_password("AAAA1!AA", 4, false, true, false, false));
        // Missing digit: reject.
        assert!(!is_valid_password("Aaaa!aaa", 4, false, false, true, false));
        // Missing special: reject.
        assert!(!is_valid_password("Aaaa1aaa", 4, false, false, false, true));
    }

    /// A single-class password where flags are off returns true
    /// discriminates the `&&` short-circuit branches from the
    /// "always reject if any class is missing" mutant.
    #[test]
    fn password_with_no_requirements_just_length_passes() {
        assert!(is_valid_password(
            "aaaaaaaaaa",
            5,
            false,
            false,
            false,
            false
        ));
    }

    // ── is_valid_email ───────────────────────────────────────────────────

    /// Length cap. RFC 5321 ceiling is 254; 255 must reject.
    /// Pins the `>` against `==`, `>=`, `<`. Constructs candidates with
    /// valid email-shape characters at both `254` (must pass the length
    /// guard) and `255` (must reject) so the boundary discriminates
    /// every operator mutation.
    #[test]
    fn email_length_boundary_at_254() {
        // Sanity: a normal address passes.
        assert!(is_valid_email("alice@example.com"));

        // Exactly 254 bytes. Multi-label domain so each label stays
        // under the DNS 63-char limit. Layout:
        //   "abc@" + 63 + "." + 63 + "." + 63 + "." + 58 = 4+63+1+63+1+63+1+58 = 254.
        let at_254 = format!(
            "abc@{}.{}.{}.{}",
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(63),
            "e".repeat(58)
        );
        assert_eq!(at_254.len(), 254);
        assert!(
            is_valid_email(&at_254),
            "email of exactly 254 bytes must pass the length guard \
             (kills `> with ==` and `> with >=` mutations)"
        );

        // Exactly 255 bytes; one over the cap.
        let at_255 = format!("a@{}.co", "b".repeat(250));
        assert_eq!(at_255.len(), 255);
        assert!(
            !is_valid_email(&at_255),
            "email of 255 bytes must be rejected by the > 254 length guard"
        );
    }

    /// Malformed email rejected (kills `-> true` mutation).
    #[test]
    fn email_obvious_garbage_rejected() {
        assert!(!is_valid_email("not-an-email"));
        assert!(!is_valid_email("missing-at.example.com"));
        assert!(!is_valid_email("@no-local.com"));
    }

    // ── is_valid_language_code ────────────────────────────────────────────

    /// Only lengths 2 (e.g. "en") and 5 (e.g. "en-US") are valid.
    /// Pins both `!= 2` and `!= 5` against `==`, and the `&&` against `||`.
    #[test]
    fn language_code_length_boundaries() {
        // Exactly 2: ok.
        assert!(is_valid_language_code("en"));
        // Exactly 5: ok.
        assert!(is_valid_language_code("en-US"));
        // 3 chars: reject (kills `!= 2 → == 2` because the `&&` then evaluates `len == 2 && len != 5` which is false).
        assert!(!is_valid_language_code("eng"));
        // 4 chars: reject.
        assert!(!is_valid_language_code("enUS"));
        // 6 chars: reject.
        assert!(!is_valid_language_code("en-USA"));
        // 1 char: reject.
        assert!(!is_valid_language_code("e"));
    }

    /// A syntactically-correct length but malformed content is
    /// rejected (kills `-> true` mutation that would bypass the regex).
    #[test]
    fn language_code_wrong_shape_rejected() {
        assert!(!is_valid_language_code("EN")); // upper-case primary
        assert!(!is_valid_language_code("en-us")); // lower-case region
        assert!(!is_valid_language_code("e1"));
    }

    // ── is_valid_country_code ─────────────────────────────────────────────

    /// Only alpha-2 ("US") and alpha-3 ("USA") accepted.
    /// Pins the `||` and both `==` operators against negations.
    #[test]
    fn country_code_length_branches() {
        assert!(is_valid_country_code("US"));
        assert!(is_valid_country_code("CHE"));
        assert!(!is_valid_country_code("U"));
        assert!(!is_valid_country_code("USAA"));
    }

    /// Lowercase rejected; pins the `&&` against `||` (which
    /// would short-circuit and accept anything).
    #[test]
    fn country_code_lowercase_rejected() {
        assert!(!is_valid_country_code("us"));
        assert!(!is_valid_country_code("usa"));
        assert!(!is_valid_country_code("Us"));
    }

    // ── is_valid_url_format ───────────────────────────────────────────────

    /// Length cap at 2048. Pins `>` against `==`, `<`, `>=`.
    /// Build candidates at exactly `2048` (must pass the length guard
    /// and the regex) and `2049` (must reject) so all four `>` mutants
    /// flip an observable outcome.
    #[test]
    fn url_length_boundary_at_2048() {
        // Sanity: a normal URL passes.
        assert!(is_valid_url_format("https://example.com/path?x=1"));

        // Exactly 2048 bytes. The URL regex's path component accepts
        // any non-`?#`/non-whitespace bytes, so we pad the path with
        // `a`s once we have a valid scheme + domain prefix.
        //   "https://a.co/" = 13 bytes; pad with 2035 more = 2048.
        let at_2048 = format!("https://a.co/{}", "a".repeat(2048 - 13));
        assert_eq!(at_2048.len(), 2048);
        assert!(
            is_valid_url_format(&at_2048),
            "URL of exactly 2048 bytes must pass the length guard \
             (kills `> with ==` and `> with >=` mutations)"
        );

        // Exactly 2049 bytes; one over the cap.
        let at_2049 = format!("https://a.co/{}", "a".repeat(2049 - 13));
        assert_eq!(at_2049.len(), 2049);
        assert!(
            !is_valid_url_format(&at_2049),
            "URL of 2049 bytes must be rejected by the > 2048 length guard"
        );
    }

    /// An obviously invalid URL is rejected (kills `-> true`).
    #[test]
    fn url_obvious_garbage_rejected() {
        assert!(!is_valid_url_format("not a url"));
        assert!(!is_valid_url_format("ftp://example.com")); // scheme not http/https
        assert!(!is_valid_url_format("https://"));
    }

    // ── is_valid_name ─────────────────────────────────────────────────────

    /// Positive + negative cases pin both body-replacement
    /// mutations.
    #[test]
    fn name_positive_and_negative_cases() {
        assert!(is_valid_name("Alice Liddell"));
        assert!(is_valid_name("Mc'Donald"));
        assert!(!is_valid_name("a")); // too short (<2)
        assert!(!is_valid_name("A".repeat(129).as_str())); // too long (>128)
        assert!(!is_valid_name("Alice<script>")); // invalid char
    }

    // ── is_valid_otp_code ─────────────────────────────────────────────────

    /// Pin both length match (`==`) and digit-only branches.
    /// Discriminates `==` against `!=` and `&&` against `||`.
    #[test]
    fn otp_length_and_digit_only() {
        // Correct: length 6, all digits.
        assert!(is_valid_otp_code("123456", 6));
        // Wrong length (5): reject.
        assert!(!is_valid_otp_code("12345", 6));
        // Wrong length (7): reject.
        assert!(!is_valid_otp_code("1234567", 6));
        // Right length, contains a letter: reject.
        assert!(!is_valid_otp_code("12345a", 6));
        // Right length, contains whitespace: reject.
        assert!(!is_valid_otp_code("12345 ", 6));
        // Empty with length 0: accepted (degenerate but defined).
        assert!(is_valid_otp_code("", 0));
    }

    // ── compare_secrets ───────────────────────────────────────────────────

    /// Equal slices return true; unequal return false. Pins
    /// both `-> true` and `-> false` mutations.
    #[test]
    fn compare_secrets_equal_and_unequal() {
        let a: &[u8] = b"some-secret-value";
        let b: &[u8] = b"some-secret-value";
        let c: &[u8] = b"other-secret-val!";
        assert!(compare_secrets(a, b));
        assert!(!compare_secrets(a, c));
    }

    /// Length mismatch returns false (the `subtle::ConstantTimeEq`
    /// implementation pads-and-compares, but a `-> true` mutation would
    /// still leak through this test).
    #[test]
    fn compare_secrets_length_mismatch_is_false() {
        assert!(!compare_secrets(b"short", b"shorter"));
        assert!(!compare_secrets(b"", b"non-empty"));
    }

    /// Empty-to-empty comparison is true (true byte-equality).
    #[test]
    fn compare_secrets_empty_pair_is_true() {
        assert!(compare_secrets(b"", b""));
    }

    // ── is_printable ──────────────────────────────────────────────────────

    /// Cover both arms of the `c == ' ' || (!c.is_control() && c != '\u{FEFF}')`
    /// disjunction and every byte category:
    /// - Space passes via the explicit `' '` arm (kills `==` → `!=` on space).
    /// - Printable ASCII / Unicode letters pass via the second conjunct.
    /// - Control characters (`\0`, `\t`, `\n`, DEL) reject via `!c.is_control()`
    ///   (kills `delete !` on `is_control`).
    /// - U+FEFF (BOM) rejects via the `!= '\u{FEFF}'` clause (kills `!=` → `==`).
    /// - Empty string returns true (vacuous `.all`); kills `-> false` body.
    #[test]
    fn is_printable_distinguishes_printable_and_control_chars() {
        assert!(is_printable("hello world"));
        assert!(is_printable("café"));
        assert!(is_printable(" "));
        assert!(is_printable(""));

        assert!(!is_printable("a\0b"));
        assert!(!is_printable("a\tb"));
        assert!(!is_printable("line\n"));
        assert!(!is_printable("\u{7F}"));
        assert!(!is_printable("\u{FEFF}"));
        assert!(
            !is_printable("text\u{FEFF}with-bom"),
            "an embedded BOM must reject (kills `!= → ==` on BOM)"
        );
    }
}
