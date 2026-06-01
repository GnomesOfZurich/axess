// Fuzz the back-channel-logout JWT splitter. The pre-validation
// path splits the compact-serialised JWT on `.`, base64url-decodes the
// payload, and feeds the result to `serde_json`. None of those steps
// have intrinsic bounds beyond what the compact-serialisation grammar
// implies, so any malformed input has to be rejected without panicking.
//
// `decode_jwt_payload` itself is `pub(super)`, so the fuzz target
// re-implements the same shape against the public crates the function
// composes (`base64`, `serde_json`). A divergence between this target
// and the live function would surface as a missed bug; treat both
// the live fn and this target as the contract under test.

#![no_main]

use base64::Engine as _;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    // Compact JWT: header.payload.signature; split on the first two
    // `.` and decode the payload exactly as `decode_jwt_payload` does.
    let mut parts = s.splitn(3, '.');
    let _header = parts.next();
    let Some(payload) = parts.next() else {
        return;
    };
    let _signature = parts.next();

    let Ok(decoded) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload) else {
        return;
    };
    let _ = serde_json::from_slice::<serde_json::Value>(&decoded);
});
