//! Row-bound encryption: a blob only opens for the row id it was sealed for.

use super::*;

const KEY: [u8; 32] = [5u8; 32];
const A: &[u8] = b"session-a";
const B: &[u8] = b"session-b";

#[test]
fn blob_sealed_for_one_row_does_not_open_under_another() {
    let crypto = SessionCrypto::new(KEY);
    let sealed = crypto
        .seal_bound(BoundFormat::SESSION, A, b"admin data")
        .unwrap();
    assert!(crypto.open_bound(BoundFormat::SESSION, B, &sealed).is_err());
    let opened = crypto.open_bound(BoundFormat::SESSION, A, &sealed).unwrap();
    assert_eq!(opened.plaintext, b"admin data");
    assert!(!opened.legacy);
}

#[test]
fn a_different_domain_label_does_not_open() {
    let crypto = SessionCrypto::new(KEY);
    let sealed = crypto.seal_bound(BoundFormat::SESSION, A, b"data").unwrap();
    // Same marker, different label: the AAD differs, so authentication fails.
    let forged = BoundFormat {
        magic: BoundFormat::SESSION.magic,
        label: BoundFormat::DEVICE_BINDINGS.label,
    };
    assert!(crypto.open_bound(forged, A, &sealed).is_err());
}

#[test]
fn tampered_aad_bytes_fail_authentication() {
    let crypto = SessionCrypto::new(KEY);
    let body = crypto
        .encrypt_with_aad(&BoundFormat::SESSION.aad(A), b"data")
        .unwrap();
    assert!(
        crypto
            .decrypt_with_aad(&BoundFormat::SESSION.aad(A), &body)
            .is_ok()
    );
    let mut aad = BoundFormat::SESSION.aad(A);
    *aad.last_mut().unwrap() ^= 1;
    assert!(crypto.decrypt_with_aad(&aad, &body).is_err());
    assert!(
        crypto.decrypt_unbound(&body).is_err(),
        "empty AAD must not open it"
    );
}

#[test]
fn legacy_blob_opens_and_is_flagged() {
    let crypto = SessionCrypto::new(KEY);
    let legacy = crypto.encrypt_unbound(b"old row").unwrap();
    assert!(!BoundFormat::SESSION.marks(&legacy));
    let opened = crypto.open_bound(BoundFormat::SESSION, A, &legacy).unwrap();
    assert_eq!(opened.plaintext, b"old row");
    assert!(opened.legacy);
    // Legacy blobs carry no id, so they open under any id: the fallback the
    // next save removes.
    assert!(crypto.open_bound(BoundFormat::SESSION, B, &legacy).is_ok());
}

#[test]
fn marked_blob_never_falls_back_to_empty_aad() {
    let crypto = SessionCrypto::new(KEY);
    // An attacker-built blob: the marker in front of a body that is valid
    // under the EMPTY AAD. It must be refused, not accepted via the legacy
    // path.
    let body = crypto.encrypt_unbound(b"smuggled").unwrap();
    let mut blob = BoundFormat::SESSION.magic.to_vec();
    blob.extend_from_slice(&body);
    assert!(crypto.open_bound(BoundFormat::SESSION, A, &blob).is_err());
}

#[test]
fn key_rotation_still_opens_bound_blobs() {
    let old = SessionCrypto::new([1u8; 32]);
    let sealed = old.seal_bound(BoundFormat::SESSION, A, b"rotated").unwrap();
    let rotated = SessionCrypto::new([2u8; 32]).with_previous_key([1u8; 32]);
    let opened = rotated
        .open_bound(BoundFormat::SESSION, A, &sealed)
        .unwrap();
    assert_eq!(opened.plaintext, b"rotated");
    assert!(
        rotated
            .open_bound(BoundFormat::SESSION, B, &sealed)
            .is_err()
    );
}
