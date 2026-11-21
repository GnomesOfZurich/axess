//! The shortest subkeyed blob that opens is the one an empty plaintext seals
//! to: the marker, a salt and a tag. A body one byte shorter was never sealed
//! and is refused before a key is tried.

use super::*;
use axess_testing::mock_tracing::TracingCapture;

const ROW: &[u8] = b"row-1";

/// What `open_subkeyed` logs when no configured key opened a body.
const NO_KEY_OPENED: &str = "failed with the configured keys";

fn rotated() -> SessionCrypto {
    SessionCrypto::new(crate::testing::test_key(9)).with_previous_key(crate::testing::test_key(7))
}

#[test]
fn the_subkeyed_blob_of_an_empty_plaintext_opens() {
    let crypto = rotated();
    let sealed = crypto.seal_bound(BoundFormat::SESSION, ROW, b"").unwrap();
    assert_eq!(sealed.len(), 4 + subkey::SALT_LEN + 16);
    let opened = crypto
        .open_bound(BoundFormat::SESSION, ROW, &[], &sealed)
        .unwrap();
    assert!(opened.plaintext.is_empty());
}

#[test]
fn a_subkeyed_body_one_byte_short_is_refused_before_a_key_is_tried() {
    let capture = TracingCapture::install();
    let crypto = rotated();
    let tried = || {
        capture
            .events()
            .iter()
            .filter(|event| event.message.contains(NO_KEY_OPENED))
            .count()
    };

    // The control: a full-length body that no configured key opens is tried
    // under both keys, and that is logged.
    let stranger = SessionCrypto::new(crate::testing::test_key(3))
        .seal_bound(BoundFormat::SESSION, ROW, b"")
        .unwrap();
    assert!(
        crypto
            .open_bound(BoundFormat::SESSION, ROW, &[], &stranger)
            .is_err()
    );
    assert_eq!(tried(), 1, "the control reaches the keys");

    let sealed = crypto.seal_bound(BoundFormat::SESSION, ROW, b"").unwrap();
    let marker = 4;
    for body in [
        subkey::SALT_LEN + 15,
        subkey::SALT_LEN + 1,
        subkey::SALT_LEN,
        subkey::SALT_LEN - 1,
        0,
    ] {
        let short = &sealed[..marker + body];
        assert!(
            crypto
                .open_bound(BoundFormat::SESSION, ROW, &[], short)
                .is_err(),
            "a body of {body} bytes"
        );
    }
    assert_eq!(
        tried(),
        1,
        "a body shorter than a salt and a tag reaches no key: {:?}",
        capture.events()
    );
}
