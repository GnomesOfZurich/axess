// Fuzz the MessagePack decode path used by the SQL and Valkey session
// stores. `SessionData` round-trips via `rmp_serde::from_slice`,
// including a deeply nested `serde_json::Value` in the `custom` bag
//; exactly the shape MessagePack's recursive decoder is most likely
// to misbehave on. Any crash here is a denial-of-service vector
// against the session-load path.

#![no_main]

use axess_core::session::data::SessionData;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Discard errors on purpose; the fuzzer is hunting panics, OOMs,
    // and stack overflows, not invalid-input rejections.
    let _ = rmp_serde::from_slice::<SessionData>(data);
});
