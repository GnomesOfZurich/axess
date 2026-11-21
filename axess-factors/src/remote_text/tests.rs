//! The bounds of remote text in an error: a parse error keeps its head and
//! its position, and the cut never splits a character.

use super::*;

/// A body of this shape holds numbers only.
type Expects = std::collections::BTreeMap<String, u64>;

#[test]
fn a_parse_error_over_a_long_value_keeps_its_head_and_its_position() {
    let body = format!(
        r#"{{"expires_in": "{}\n\u001b[2J"}}"#,
        "A".repeat(60 * 1024)
    );
    let error = serde_json::from_str::<Expects>(&body).expect_err("a string is not a u64");
    assert!(error.to_string().len() > 60 * 1024, "serde quotes it whole");

    let safe = parse_error(&error);
    assert!(safe.starts_with("invalid type: string"), "{safe}");
    assert!(safe.contains("..."), "the cut is marked: {safe}");
    assert!(
        safe.ends_with(&format!(" at line 1 column {}", error.column())),
        "{safe}"
    );
    assert!(safe.len() <= PARSE_ERROR_LOG_BYTES + 32, "{}", safe.len());
    assert!(!safe.chars().any(char::is_control), "{safe:?}");
}

#[test]
fn a_short_parse_error_is_kept_whole() {
    let error = serde_json::from_str::<Expects>(r#"{"expires_in": "x"}"#).expect_err("not a u64");
    assert_eq!(parse_error(&error), error.to_string());
}

#[test]
fn a_conversion_error_has_no_position_and_is_still_cut() {
    let value = serde_json::json!({ "expires_in": "B".repeat(10_000) });
    let error = serde_json::from_value::<Expects>(value).expect_err("not a u64");
    let safe = parse_error(&error);
    assert!(safe.len() <= PARSE_ERROR_LOG_BYTES, "{}", safe.len());
    assert!(!safe.contains("line"), "{safe}");
}

#[cfg(feature = "jwt")]
#[test]
fn a_jose_error_over_a_token_is_cut() {
    let long = format!("{}{}", "C".repeat(5_000), '\u{2028}');
    let safe = error_text(&long);
    assert!(safe.len() <= PARSE_ERROR_LOG_BYTES, "{}", safe.len());
    assert!(!safe.contains('\u{2028}'));
}
