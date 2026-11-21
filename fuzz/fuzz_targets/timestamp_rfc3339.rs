// Fuzz the reader of RFC 3339 text, `axess_clock::Timestamp::parse_rfc3339`,
// which reads every stored and sent timestamp: a session row, a stored
// lockout, a token's lifetime.
//
// The reader must refuse or read any text without a panic. What it reads is
// a reading inside the range, and that reading must survive its own text:
// written in the `Z` form or with the numeric offset and read again, it is
// the same reading, and the text it is written as does not change on the
// way. `FromStr` is the same reader and `Display` the same writer.
//
// The input is used twice, so the second half does not wait for the fuzzer
// to find a text that reads: once as text, and once as a count of seconds
// and nanoseconds folded into the range, which is written and read back the
// same way.

#![no_main]

use axess_clock::Timestamp;
use libfuzzer_sys::fuzz_target;

/// A reading is the reading both of its written forms name, and writing it
/// twice gives one text.
fn reads_back_as_itself(at: Timestamp) {
    assert!(Timestamp::MIN <= at && at <= Timestamp::MAX, "{at:?}");
    assert_eq!(
        Timestamp::new(at.unix_seconds(), at.subsec_nanos()),
        Some(at)
    );

    let written = at.to_rfc3339();
    assert_eq!(at.to_string(), written);
    let read = Timestamp::parse_rfc3339(&written);
    assert_eq!(read, Ok(at), "{written:?}");
    assert_eq!(written.parse::<Timestamp>(), read, "{written:?}");

    let numeric = at.to_rfc3339_numeric_offset();
    assert_eq!(Timestamp::parse_rfc3339(&numeric), Ok(at), "{numeric:?}");
    assert_eq!(
        numeric.strip_suffix("+00:00"),
        written.strip_suffix('Z'),
        "{numeric:?} and {written:?}"
    );
}

/// The bytes as a reading: the first eight as seconds, counted from the
/// first second of the range and wrapped at its last, and the next four as
/// nanoseconds, wrapped at one second.
fn folded(data: &[u8]) -> Option<Timestamp> {
    let seconds = u64::from_le_bytes(data.get(..8)?.try_into().ok()?);
    let nanos = u32::from_le_bytes(data.get(8..12)?.try_into().ok()?);
    let first = Timestamp::MIN.unix_seconds();
    let width = Timestamp::MAX.unix_seconds().abs_diff(first) + 1;
    let offset = i64::try_from(seconds % width).ok()?;
    Timestamp::new(first + offset, nanos % 1_000_000_000)
}

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let read = Timestamp::parse_rfc3339(text);
        assert_eq!(text.parse::<Timestamp>(), read, "{text:?}");
        if let Ok(at) = read {
            reads_back_as_itself(at);
        }
    }
    if let Some(at) = folded(data) {
        reads_back_as_itself(at);
    }
});
