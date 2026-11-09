// Fuzz the real RFC 7636 section 4.1 `code_verifier` predicate,
// `axess_factors::pkce::is_valid_verifier`, which the OAuth login path calls
// on the value it stashed before sending it to the authorisation server.
//
// The reference below is the RFC's grammar written out independently:
//   code-verifier = 43*128unreserved
//   unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
// The predicate and the reference must agree on every input, so a change that
// loosens the alphabet or the length window, or that adds work to the hot
// path, is caught here and not by a copy that drifted with it.

#![no_main]

use axess_factors::pkce::is_valid_verifier;
use libfuzzer_sys::fuzz_target;

fn rfc7636(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

fuzz_target!(|data: &[u8]| {
    if let Ok(verifier) = std::str::from_utf8(data) {
        assert_eq!(
            is_valid_verifier(verifier),
            rfc7636(verifier),
            "{verifier:?}"
        );
    }
});
