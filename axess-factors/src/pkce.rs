//! PKCE utilities exposed for application-side validation.
//!
//! The library validates `code_verifier`s internally before sending
//! them to the authorization server (see `AuthnService::finish_oauth_login`),
//! but applications occasionally want the same predicate at their own
//! boundary, for instance to reject a malformed verifier early in a
//! custom callback handler before any session work happens.
//!
//! Always-on (no feature gate): PKCE is a pure-spec predicate
//! (RFC 7636 §4.1) with no OAuth-protocol dependencies.

/// Check whether a string satisfies the RFC 7636 §4.1
/// `code_verifier` grammar:
///
/// > code-verifier = 43*128unreserved
/// > unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
///
/// Returns `true` for any string of length 43–128 inclusive whose
/// every byte is alphanumeric, `-`, `.`, `_`, or `~`. Anything
/// else returns `false`. The check is byte-by-byte and fixed-time
/// in the length dimension; it does not allocate.
///
/// ```
/// use axess_factors::pkce::is_valid_verifier;
///
/// // 43-byte minimum, all in-alphabet
/// assert!(is_valid_verifier(&"a".repeat(43)));
///
/// // Too short
/// assert!(!is_valid_verifier(&"a".repeat(42)));
///
/// // Out-of-alphabet byte
/// assert!(!is_valid_verifier(&format!("{}!", "a".repeat(42))));
/// ```
pub fn is_valid_verifier(verifier: &str) -> bool {
    let len = verifier.len();
    if !(43..=128).contains(&len) {
        return false;
    }
    verifier
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_' || b == b'~')
}

#[cfg(test)]
mod pkce_tests {
    use super::*;

    /// Length boundaries are inclusive at both ends per
    /// RFC 7636 §4.1 (43..=128). Pins `delete !` (which would invert
    /// the range check) and pins the body replacements `-> true /
    /// -> false` jointly with the alphabet tests below.
    #[test]
    fn is_valid_verifier_length_boundaries_are_inclusive() {
        // Inside the inclusive range; all-alphanumeric, must accept.
        assert!(
            is_valid_verifier(&"a".repeat(43)),
            "length 43 (lower bound) must be accepted"
        );
        assert!(
            is_valid_verifier(&"a".repeat(128)),
            "length 128 (upper bound) must be accepted"
        );

        // Outside the range; must reject.
        assert!(
            !is_valid_verifier(&"a".repeat(42)),
            "length 42 (one below lower bound) must reject"
        );
        assert!(
            !is_valid_verifier(&"a".repeat(129)),
            "length 129 (one above upper bound) must reject"
        );
        assert!(!is_valid_verifier(""), "empty must reject");
    }

    /// Each of the four unreserved punctuation bytes
    /// (`-`, `.`, `_`, `~`) is accepted on its own merits in the
    /// alphabet predicate.
    #[test]
    fn is_valid_verifier_accepts_each_unreserved_punctuation() {
        for ch in &['-', '.', '_', '~'] {
            let s = format!("{}{}", "a".repeat(42), ch);
            assert!(
                is_valid_verifier(&s),
                "'{ch}' must be accepted as an unreserved verifier byte"
            );
        }
    }

    /// Bytes outside the unreserved set are rejected. Pins
    /// the `-> true` body replacement (would accept anything) and
    /// confirms the alphabet predicate fails closed for common URL
    /// metacharacters.
    #[test]
    fn is_valid_verifier_rejects_bytes_outside_unreserved_set() {
        for bad in &['!', '*', '+', '/', '=', ' ', '\n', '@', '#'] {
            let s = format!("{}{}", "a".repeat(42), bad);
            assert!(
                !is_valid_verifier(&s),
                "'{bad}' must NOT be accepted as a verifier byte"
            );
        }
    }
}
