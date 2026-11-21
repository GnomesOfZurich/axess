// Fuzz the MessagePack decode path used by the SQL and Valkey session
// stores. `SessionData` round-trips via `rmp_serde::from_slice`,
// including a deeply nested `serde_json::Value` in the `custom` bag
//; exactly the shape MessagePack's recursive decoder is most likely
// to misbehave on. Any crash here is a denial-of-service vector
// against the session-load path.
//
// A decode that succeeds is held to a round trip through the encoder the
// stores use (`rmp_serde::to_vec_named`): the value it produced, encoded
// again and decoded again, encodes to the same bytes. A decoder that
// accepts an input it cannot reproduce has read it as something the stores
// would never have written, which a panic-only target cannot see.

#![no_main]

use axess_core::session::data::SessionData;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Errors on invalid input are the expected outcome; the oracle applies
    // to what the decoder accepts.
    let Ok(decoded) = rmp_serde::from_slice::<SessionData>(data) else {
        return;
    };
    let encoded = rmp_serde::to_vec_named(&decoded).expect("a decoded session encodes");
    let again = rmp_serde::from_slice::<SessionData>(&encoded)
        .expect("what the stores' encoder wrote decodes");
    assert_eq!(
        rmp_serde::to_vec_named(&again).expect("a decoded session encodes"),
        encoded,
        "the MessagePack round trip is a fixed point"
    );
});
