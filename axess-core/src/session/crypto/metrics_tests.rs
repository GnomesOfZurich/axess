//! The use of the previous encryption key is reported to the rotation sink.

use super::*;
use crate::testing::RecordingMetrics;

/// A blob that opens only under the previous encryption key is counted; one
/// that opens under the current key is not.
#[test]
fn a_blob_opened_under_the_previous_encryption_key_is_counted() {
    let rotation = Arc::new(RecordingMetrics::default());
    let old = crate::testing::test_key(7);
    let new = crate::testing::test_key(9);
    let sealed_old = SessionCrypto::new(old)
        .encrypt_with_aad(b"row", b"payload")
        .unwrap();
    let rotated = SessionCrypto::new(new)
        .with_previous_key(old)
        .with_metrics(rotation.clone());
    let sealed_new = rotated.encrypt_with_aad(b"row", b"payload").unwrap();

    assert_eq!(
        rotated.decrypt_with_aad(b"row", &sealed_new).unwrap(),
        b"payload"
    );
    assert_eq!(rotation.count("encryption_key_fallback"), 0);
    assert_eq!(
        rotated.decrypt_with_aad(b"row", &sealed_old).unwrap(),
        b"payload"
    );
    assert_eq!(rotation.count("encryption_key_fallback"), 1);
}

/// A blob that opens under neither key is not a fallback.
#[test]
fn a_blob_that_opens_under_no_key_is_not_counted() {
    let rotation = Arc::new(RecordingMetrics::default());
    let stranger = SessionCrypto::new(crate::testing::test_key(3))
        .encrypt_with_aad(b"row", b"payload")
        .unwrap();
    let rotated = SessionCrypto::new(crate::testing::test_key(9))
        .with_previous_key(crate::testing::test_key(7))
        .with_metrics(rotation.clone());
    assert!(rotated.decrypt_with_aad(b"row", &stranger).is_err());
    assert_eq!(rotation.count("encryption_key_fallback"), 0);
}
