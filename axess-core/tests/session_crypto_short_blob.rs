#![cfg(all(
    feature = "testing",
    any(
        feature = "sqlite",
        feature = "sqlite-unbundled",
        feature = "postgres",
        feature = "mysql",
        feature = "valkey",
        feature = "delegated-stored-encrypted"
    )
))]
//! The shortest blob `SessionCrypto` opens is the one an empty plaintext
//! seals to: a nonce and a tag. A blob one byte shorter was never sealed and
//! is refused before a key is tried. Its own test binary: the second test
//! reads a thread-scoped tracing capture.

use axess_clock::testing::MockClock;
use axess_core::session::SessionCrypto;
use axess_core::testing::test_key;
use axess_testing::mock_tracing::TracingCapture;
use std::sync::Arc;

/// A 96-bit nonce and a 128-bit tag.
const SHORTEST_BLOB: usize = 12 + 16;

/// What `decrypt_with_aad` logs when the current key did not open a blob
/// and it goes on to the previous one.
const FALLBACK: &str = "trying previous key";

/// A cipher under the key of `seed`, on the test's clock.
fn cipher(clock: &MockClock, seed: u8) -> SessionCrypto {
    SessionCrypto::new(test_key(seed)).with_clock(Arc::new(clock.clone()))
}

/// A cipher that has rotated from one key to another.
fn rotated(clock: &MockClock) -> SessionCrypto {
    cipher(clock, 9).with_previous_key(test_key(7))
}

#[test]
fn the_ciphertext_of_an_empty_plaintext_decrypts() {
    let clock = MockClock::at_reference();
    let crypto = rotated(&clock);
    let sealed = crypto.encrypt_with_aad(b"row", b"").unwrap();
    assert_eq!(sealed.len(), SHORTEST_BLOB);
    assert_eq!(crypto.decrypt_with_aad(b"row", &sealed).unwrap(), b"");
}

#[test]
fn a_blob_one_byte_short_is_refused_before_a_key_is_tried() {
    let capture = TracingCapture::install();
    let clock = MockClock::at_reference();
    let crypto = rotated(&clock);

    // The control: a full-length blob that no configured key opens is tried
    // under the current key and then the previous one, and that is logged.
    let stranger = cipher(&clock, 3).encrypt_with_aad(b"row", b"").unwrap();
    assert_eq!(stranger.len(), SHORTEST_BLOB);
    assert!(crypto.decrypt_with_aad(b"row", &stranger).is_err());
    let fallbacks = || {
        capture
            .events()
            .iter()
            .filter(|event| event.message.contains(FALLBACK))
            .count()
    };
    assert_eq!(fallbacks(), 1, "the control reaches the keys");

    let sealed = crypto.encrypt_with_aad(b"row", b"").unwrap();
    for short in [
        &sealed[..SHORTEST_BLOB - 1],
        &sealed[..12],
        &sealed[..11],
        &sealed[..0],
    ] {
        assert!(
            crypto.decrypt_with_aad(b"row", short).is_err(),
            "{} bytes",
            short.len()
        );
    }
    assert_eq!(
        fallbacks(),
        1,
        "a blob shorter than a nonce and a tag reaches no key: {:?}",
        capture.events()
    );
}
