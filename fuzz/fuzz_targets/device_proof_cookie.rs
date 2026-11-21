// Fuzz the reader of the device-key proof cookie, a value any client can
// put in its `Cookie` header and the session layer reads on every request
// before a store is touched.
//
// The contract, held for two kinds of input: arbitrary text proves nothing,
// and a genuine cookie proves its key exactly when it is whole and has not
// ended; with one byte of it changed it proves nothing. The reader is
// private to axess-core and is reached through the entry points the crate
// keeps for this target.

#![no_main]

use axess_core::testing::device_key_parsers::{
    GRACE, mint_proof_cookie, proven_key, read_proof_cookie,
};
use libfuzzer_sys::fuzz_target;

const EXPIRES: i64 = 2_000_000_000;

/// A number from the input.
fn number(data: &[u8], at: usize) -> i64 {
    let mut bytes = [0u8; 8];
    for (slot, byte) in bytes.iter_mut().zip(data.iter().skip(at)) {
        *slot = *byte;
    }
    i64::from_le_bytes(bytes)
}

fuzz_target!(|data: &[u8]| {
    let genuine = mint_proof_cookie(EXPIRES).expect("a date");
    let now = number(data, 0);

    // Arbitrary text: it must return, and prove nothing unless it is the
    // genuine value.
    if let Ok(text) = std::str::from_utf8(data) {
        let proven = read_proof_cookie(text, EXPIRES - 1);
        assert!(proven.is_none() || text == genuine, "{text:?}");
    }

    // The genuine value at a time from the input: proven until its expiry
    // plus the grace, and not from then on.
    let grace = i64::try_from(GRACE.as_secs()).unwrap_or(i64::MAX);
    let live = now < EXPIRES.saturating_add(grace);
    let read = read_proof_cookie(&genuine, now);
    if axess_clock::Timestamp::from_unix_seconds(now).is_some() {
        assert_eq!(read, live.then(proven_key), "now {now}");
    } else {
        assert_eq!(read, None);
    }

    // The genuine value with one byte changed, where the input says.
    let mut edited = genuine.clone().into_bytes();
    let index = usize::from(*data.get(8).unwrap_or(&0)) % edited.len();
    let replacement = *data.get(9).unwrap_or(&b'A');
    if edited[index] != replacement {
        edited[index] = replacement;
        if let Ok(edited) = String::from_utf8(edited) {
            assert_eq!(
                read_proof_cookie(&edited, EXPIRES - 1),
                None,
                "byte {index} changed: {edited:?}"
            );
        }
    }
});
