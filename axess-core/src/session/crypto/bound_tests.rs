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
    assert!(
        crypto
            .open_bound(BoundFormat::SESSION, B, &[], &sealed)
            .is_err()
    );
    let opened = crypto
        .open_bound(BoundFormat::SESSION, A, &[], &sealed)
        .unwrap();
    assert_eq!(opened.plaintext, b"admin data");
    assert!(!opened.stale);
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
    assert!(crypto.open_bound(forged, A, &[], &sealed).is_err());
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
    let opened = crypto
        .open_bound(BoundFormat::SESSION, A, &[], &legacy)
        .unwrap();
    assert_eq!(opened.plaintext, b"old row");
    assert!(opened.stale);
    // Legacy blobs carry no id, so they open under any id: the fallback the
    // next save removes.
    assert!(
        crypto
            .open_bound(BoundFormat::SESSION, B, &[], &legacy)
            .is_ok()
    );
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
    assert!(
        crypto
            .open_bound(BoundFormat::SESSION, A, &[], &blob)
            .is_err()
    );
}

#[test]
fn key_rotation_still_opens_bound_blobs() {
    let old = SessionCrypto::new([1u8; 32]);
    let sealed = old.seal_bound(BoundFormat::SESSION, A, b"rotated").unwrap();
    let rotated = SessionCrypto::new([2u8; 32]).with_previous_key([1u8; 32]);
    let opened = rotated
        .open_bound(BoundFormat::SESSION, A, &[], &sealed)
        .unwrap();
    assert_eq!(opened.plaintext, b"rotated");
    assert!(
        rotated
            .open_bound(BoundFormat::SESSION, B, &[], &sealed)
            .is_err()
    );
}

fn v1_device_blob(crypto: &SessionCrypto, tenant: &str, device: &str, plaintext: &[u8]) -> Vec<u8> {
    let body = crypto
        .encrypt_with_aad(
            &BoundFormat::DEVICE_BINDINGS_V1.aad(&device_row_id_v1(tenant, device)),
            plaintext,
        )
        .unwrap();
    let mut blob = BoundFormat::DEVICE_BINDINGS_V1.magic.to_vec();
    blob.extend_from_slice(&body);
    blob
}

fn open_device(
    crypto: &SessionCrypto,
    tenant: &str,
    device: &str,
    blob: &[u8],
) -> Result<Opened, CryptoError> {
    crypto.open_bound(
        BoundFormat::DEVICE_BINDINGS,
        &device_row_id(tenant, device),
        &[(
            BoundFormat::DEVICE_BINDINGS_V1,
            device_row_id_v1(tenant, device),
        )],
        blob,
    )
}

/// Ids that differ only in where a zero byte falls joined to the same bytes
/// under the 0.11.0 row id, so a blob sealed for one pair opened for the
/// other. The length-prefixed id keeps them apart.
#[test]
fn length_prefixed_row_ids_do_not_collide_where_zero_joined_ones_did() {
    assert_eq!(device_row_id_v1("a\0b", "c"), device_row_id_v1("a", "b\0c"));
    assert_ne!(device_row_id("a\0b", "c"), device_row_id("a", "b\0c"));

    let crypto = SessionCrypto::new(KEY);
    let sealed = crypto
        .seal_bound(
            BoundFormat::DEVICE_BINDINGS,
            &device_row_id("a\0b", "c"),
            b"x",
        )
        .unwrap();
    assert!(open_device(&crypto, "a\0b", "c", &sealed).is_ok());
    assert!(open_device(&crypto, "a", "b\0c", &sealed).is_err());
}

/// A blob written by 0.11.0 still opens, is flagged stale, and is sealed
/// afresh in the current format.
#[test]
fn a_device_blob_of_the_previous_format_opens_and_is_stale() {
    let crypto = SessionCrypto::new(KEY);
    let old = v1_device_blob(&crypto, "t", "d", b"bindings");
    let opened = open_device(&crypto, "t", "d", &old).unwrap();
    assert_eq!(opened.plaintext, b"bindings");
    assert!(opened.stale);
    assert!(open_device(&crypto, "t", "other", &old).is_err());

    let fresh = crypto
        .seal_bound(
            BoundFormat::DEVICE_BINDINGS,
            &device_row_id("t", "d"),
            b"bindings",
        )
        .unwrap();
    assert!(!open_device(&crypto, "t", "d", &fresh).unwrap().stale);
}

/// With legacy blobs rejected, a blob without a marker is refused (it opens
/// under any row id, so it cannot be told from a moved one), while bound
/// blobs of every format still open.
#[test]
fn rejecting_legacy_blobs_refuses_unmarked_blobs_only() {
    let open = SessionCrypto::new(KEY);
    let strict = SessionCrypto::new(KEY).with_legacy_blobs(LegacyBlobs::Reject);
    let legacy = open.encrypt_unbound(b"old row").unwrap();

    assert!(
        open.open_bound(BoundFormat::SESSION, A, &[], &legacy)
            .is_ok()
    );
    assert!(
        strict
            .open_bound(BoundFormat::SESSION, A, &[], &legacy)
            .is_err()
    );
    assert!(
        strict
            .open_bound(BoundFormat::SESSION, B, &[], &legacy)
            .is_err()
    );

    let bound = strict
        .seal_bound(BoundFormat::SESSION, A, b"new row")
        .unwrap();
    assert!(
        strict
            .open_bound(BoundFormat::SESSION, A, &[], &bound)
            .is_ok()
    );
    let old_device = v1_device_blob(&strict, "t", "d", b"bindings");
    assert!(open_device(&strict, "t", "d", &old_device).is_ok());
}
