// Fuzz the JSON-fallback decode path. The SQL codec attempts MessagePack
// first and falls back to JSON for legacy rows; the fallback must
// survive arbitrary corrupt inputs without panicking. Same threat
// surface as the MessagePack target, different codec, different
// failure modes.

#![no_main]

use axess_core::session::data::SessionData;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<SessionData>(data);
});
