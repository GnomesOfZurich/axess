//! `validation_tests`: extracted from `validation.rs` per the
//! 200-LoC inline-test rule in AGENTS.md.

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

/// The minimum counts characters, not UTF-8 bytes: five two-byte letters
/// are ten bytes but still only five characters.
#[test]
fn min_length_counts_characters_not_bytes() {
    assert!(!is_valid_password("äöüéè", 8, false, false, false, false));
    assert!(is_valid_password("äöüéèàçñ", 8, false, false, false, false));
}

// ── identifiers: invisible characters and normalisation ──────────

#[test]
fn identifiers_with_invisible_format_characters_are_refused() {
    assert!(is_acceptable_identifier("admin"));
    assert!(
        !is_acceptable_identifier("admin\u{200B}"),
        "zero width space"
    );
    assert!(!is_acceptable_identifier("ad\u{202E}min"), "bidi override");
    assert!(!is_acceptable_identifier("admin\u{FEFF}"));
    assert!(!is_acceptable_identifier("admin\u{FDD0}"), "noncharacter");
    // Spelled-in joiners of ordinary words stay.
    assert!(is_acceptable_identifier(
        "\u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0627}\u{0647}"
    ));
}

#[test]
fn identifiers_must_be_in_nfc() {
    assert!(is_acceptable_identifier("caf\u{00E9}"));
    assert!(!is_acceptable_identifier("cafe\u{0301}"), "decomposed form");
}

#[test]
fn a_password_over_the_hashing_limit_is_refused_by_the_rules() {
    let long = "a".repeat(MAX_PASSWORD_BYTES + 1);
    assert!(!is_valid_password(&long, 3, false, false, false, false));
    let at_limit = "a".repeat(MAX_PASSWORD_BYTES);
    assert!(is_valid_password(&at_limit, 3, false, false, false, false));
}

/// One key for every spelling a person reads as the same identifier, and
/// nothing left of an identifier that was only invisible characters.
#[test]
fn normalise_identifier_folds_case_invisibles_and_whitespace() {
    let key = normalise_identifier("alice@x.com");
    assert_eq!(key.as_deref(), Some("alice@x.com"));
    for variant in [
        "ALICE@x.com\u{200B}",
        " Alice@X.COM ",
        "alice\u{FEFF}@x.com",
        "ali\u{200D}ce@x.com",
        "\u{FF41}lice@x.com",
    ] {
        assert_eq!(normalise_identifier(variant), key, "{variant:?}");
    }
    assert_eq!(normalise_identifier("\u{200B} \u{FEFF}"), None);
    assert_ne!(
        normalise_identifier("alice@x.com"),
        normalise_identifier("alicia@x.com")
    );
}

/// Every code point of Unicode general category Cf (Unicode 16.0, 170 code
/// points), as ranges. The zero width non-joiner and joiner (U+200C, U+200D)
/// are spelled into ordinary words in several scripts and are the one pair
/// the validator lets through.
const UNICODE_CF_RANGES: &[(u32, u32)] = &[
    (0x00AD, 0x00AD),
    (0x0600, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
];

#[test]
fn every_format_character_but_the_joiners_is_refused_in_an_identifier() {
    let mut seen = 0;
    let mut accepted = Vec::new();
    for &(lo, hi) in UNICODE_CF_RANGES {
        for cp in lo..=hi {
            let c = char::from_u32(cp).expect("a scalar value");
            seen += 1;
            if matches!(c, '\u{200C}' | '\u{200D}') {
                assert!(is_acceptable_identifier(&format!("ab{c}cd")), "{cp:04X}");
                continue;
            }
            if is_acceptable_identifier(&format!("ab{c}cd")) {
                accepted.push(format!("U+{cp:04X}"));
            }
        }
    }
    assert_eq!(
        seen, 170,
        "the Cf table above must list all of Unicode 16.0"
    );
    assert!(
        accepted.is_empty(),
        "format characters accepted in an identifier: {}",
        accepted.join(", ")
    );
}
