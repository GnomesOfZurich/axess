// Fuzz the check of a device-key registration offer, the challenge a
// registration proof answers, which arrives inside a proof any client can
// post.
//
// The contract: arbitrary text is no offer; the genuine offer holds exactly
// until it expires; with one byte changed it does not hold. The check is
// private to axess-core and is reached through the entry points the crate
// keeps for this target.

#![no_main]

use axess_core::testing::device_key_parsers::{mint_offer, offer_holds};
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
    let genuine = mint_offer(EXPIRES).expect("a date");
    let now = number(data, 0);

    if let Ok(text) = std::str::from_utf8(data) {
        assert!(
            !offer_holds(text, EXPIRES - 1) || text == genuine,
            "{text:?}"
        );
    }

    let in_time = axess_clock::Timestamp::from_unix_seconds(now).is_some() && now < EXPIRES;
    assert_eq!(offer_holds(&genuine, now), in_time, "now {now}");

    let mut edited = genuine.clone().into_bytes();
    let index = usize::from(*data.get(8).unwrap_or(&0)) % edited.len();
    let replacement = *data.get(9).unwrap_or(&b'A');
    if edited[index] != replacement {
        edited[index] = replacement;
        if let Ok(edited) = String::from_utf8(edited) {
            assert!(
                !offer_holds(&edited, EXPIRES - 1),
                "byte {index} changed: {edited:?}"
            );
        }
    }
});
