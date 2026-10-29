//! Bounding what the unauthenticated logout endpoints write to a log.
//!
//! The logout endpoints take their `iss`, `sid` and `sub` from the network
//! before any check has vouched for them, so a log line that carries one
//! carries whatever a stranger chose to send: any length, any control
//! characters. [`loggable`] cuts a value to a short prefix and escapes it.

/// Longest prefix of an untrusted value that reaches a log line, in
/// characters.
const LOG_PREFIX_CHARS: usize = 64;

/// `value` cut to [`LOG_PREFIX_CHARS`] characters with control characters
/// escaped, and a marker with the full length when it was cut.
pub(super) fn loggable(value: &str) -> String {
    let mut shown: String = value
        .chars()
        .take(LOG_PREFIX_CHARS)
        .flat_map(char::escape_debug)
        .collect();
    if value.chars().nth(LOG_PREFIX_CHARS).is_some() {
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
}
