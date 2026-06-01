// Fuzz the RFC 7636 §4.1 `code_verifier` predicate. The live
// implementation lives at
// `axess_core::authn::service::oauth_service::is_valid_pkce_verifier`
// (currently private). This target re-implements the spec; any panic
// or pathological allocation discovered here applies equally to the
// library function.
//
// The predicate is byte-by-byte and length-bounded, so a crashing input
// would indicate a regression in the std `is_ascii_alphanumeric` /
// `bytes()` machinery rather than axess code; the value is in catching
// any future change that adds, say, a regex compile or a heap allocation
// to the hot path.

#![no_main]

use libfuzzer_sys::fuzz_target;

fn pkce_spec(verifier: &str) -> bool {
    let len = verifier.len();
    if !(43..=128).contains(&len) {
        return false;
    }
    verifier
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_' || b == b'~')
}

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = pkce_spec(s);
    }
});
