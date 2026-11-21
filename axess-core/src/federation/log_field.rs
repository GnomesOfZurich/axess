//! Bounding what the unauthenticated logout endpoints write to a log.
//!
//! The logout endpoints take their `iss`, `sid` and `sub` from the network
//! before any check has vouched for them, so a log line that carries one
//! carries whatever a stranger chose to send: any length, any control
//! characters. [`loggable`] cuts a value to a short prefix and escapes it
//! as `axess_factors::log_text::log_safe` escapes every other text bound for
//! a log line, by the same named ranges on every toolchain.

/// Longest prefix of an untrusted value that reaches a log line, in
/// characters.
const LOG_PREFIX_CHARS: usize = 64;

/// `value` cut to [`LOG_PREFIX_CHARS`] characters, with every character
/// `axess_factors::log_text::escapes` names (a control character, a line
/// separator, a bidirectional control, a zero-width character, the byte
/// order mark, a Hangul filler) written as an escape, and a marker with the
/// full length when it was cut.
pub(super) fn loggable(value: &str) -> String {
    let end = value
        .char_indices()
        .nth(LOG_PREFIX_CHARS)
        .map_or(value.len(), |(at, _)| at);
    // The prefix is already bounded, so the escape is the only growth.
    let mut shown = axess_factors::log_text::log_safe(&value[..end], usize::MAX);
    if end < value.len() {
        shown.push_str(&format!("...({} bytes)", value.len()));
    }
    shown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_value_is_cut_and_a_control_character_is_escaped() {
        let long = "x".repeat(10_000);
        let shown = loggable(&long);
        assert!(shown.len() < 100, "{}", shown.len());
        assert!(shown.ends_with("(10000 bytes)"), "{shown}");
        assert_eq!(loggable("a\nb\u{1b}[31m"), "a\\nb\\u{1b}[31m");
        assert_eq!(loggable("short"), "short");
    }

    /// The characters that reorder or hide text are escaped here as the
    /// other log paths escape them, whatever the compiler's Unicode tables
    /// hold: the Hangul filler is a letter to them, and a blank to a reader.
    #[test]
    fn a_value_is_escaped_as_every_other_log_text_is() {
        for c in [
            '\u{202E}', '\u{2066}', '\u{200F}', '\u{061C}', '\u{200B}', '\u{2060}', '\u{FEFF}',
            '\u{3164}', '\u{115F}', '\u{FFA0}',
        ] {
            let value = format!("issuer{c}x");
            assert_eq!(
                loggable(&value),
                axess_factors::log_text::log_safe(&value, usize::MAX)
            );
            assert_eq!(loggable(&value), format!("issuer{}x", c.escape_default()));
        }
        assert_eq!(loggable("caf\u{e9}"), "caf\u{e9}");
        // A quote and a backslash are text to every log path alike.
        let quoted = r#"say "a\b""#;
        assert_eq!(
            loggable(quoted),
            axess_factors::log_text::log_safe(quoted, usize::MAX)
        );
    }
}
