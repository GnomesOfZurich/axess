//! Row-bound encryption: a blob only opens for the row id it was sealed for.

use super::*;

const KEY: [u8; 32] = [5u8; 32];
const A: &[u8] = b"session-a";
const B: &[u8] = b"session-b";

fn accepting() -> SessionCrypto {
    SessionCrypto::new(KEY).with_legacy_blobs(LegacyBlobs::Accept)
}

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
    let crypto = accepting();
    let legacy = crypto.encrypt_unbound(b"old row").unwrap();
    assert!(!BoundFormat::SESSION.marks(&legacy));
    let opened = crypto
        .open_bound(BoundFormat::SESSION, A, &[], &legacy)
        .unwrap();
    assert_eq!(opened.plaintext, b"old row");
    assert!(opened.stale && opened.legacy);
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
    let crypto = accepting();
    let old = v1_device_blob(&crypto, "t", "d", b"bindings");
    let opened = open_device(&crypto, "t", "d", &old).unwrap();
    assert_eq!(opened.plaintext, b"bindings");
    assert!(opened.stale && opened.legacy);
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
    let open = accepting();
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
    // The 0.11.0 marked format is refused too; only the policy that reads
    // legacy blobs opens it.
    let old_device = v1_device_blob(&strict, "t", "d", b"bindings");
    assert!(open_device(&strict, "t", "d", &old_device).is_err());
    assert!(open_device(&open, "t", "d", &old_device).is_ok());
}

/// Reject is the default: a deployment must opt in to reading blobs that are
/// not bound to their row.
#[test]
fn legacy_blobs_are_refused_by_default() {
    let crypto = SessionCrypto::new(KEY);
    let legacy = crypto.encrypt_unbound(b"old row").unwrap();
    assert!(
        crypto
            .open_bound(BoundFormat::SESSION, A, &[], &legacy)
            .is_err()
    );
    let v1 = v1_device_blob(&crypto, "t", "d", b"bindings");
    assert!(open_device(&crypto, "t", "d", &v1).is_err());
}

/// Acceptance ends at the cutoff, read from the injected clock.
#[test]
fn legacy_blobs_are_accepted_only_until_the_cutoff() {
    use axess_clock::testing::MockClock;
    let t0 = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    let clock = Arc::new(MockClock::at(t0));
    let crypto = SessionCrypto::new(KEY)
        .with_legacy_blobs(LegacyBlobs::AcceptUntil(t0 + chrono::Duration::hours(1)))
        .with_clock(clock.clone());
    let legacy = crypto.encrypt_unbound(b"old row").unwrap();
    let v1 = v1_device_blob(&crypto, "t", "d", b"bindings");

    assert!(
        crypto
            .open_bound(BoundFormat::SESSION, A, &[], &legacy)
            .is_ok()
    );
    assert!(open_device(&crypto, "t", "d", &v1).is_ok());
    clock.set(t0 + chrono::Duration::hours(1));
    assert!(
        crypto
            .open_bound(BoundFormat::SESSION, A, &[], &legacy)
            .is_err()
    );
    assert!(open_device(&crypto, "t", "d", &v1).is_err());
    // Blobs in the current format are unaffected by the cutoff.
    let bound = crypto.seal_bound(BoundFormat::SESSION, A, b"new").unwrap();
    assert!(
        crypto
            .open_bound(BoundFormat::SESSION, A, &[], &bound)
            .is_ok()
    );
}

/// A pre-binding nonce is random, so about one legacy blob in 2^32 starts
/// with the four marker bytes. It used to fail to open under every policy;
/// now a policy that reads legacy blobs opens it, and the default refuses it.
#[test]
fn a_legacy_blob_whose_nonce_starts_with_the_marker_still_opens() {
    struct MarkerNonce;
    impl axess_rng::SecureRng for MarkerNonce {
        fn fill_bytes(&self, dest: &mut [u8]) {
            for (i, byte) in dest.iter_mut().enumerate() {
                *byte = BoundFormat::SESSION.magic.get(i).copied().unwrap_or(0x5a);
            }
        }
    }
    let sealer = SessionCrypto::new(KEY).with_rng(Arc::new(MarkerNonce));
    let legacy = sealer.encrypt_unbound(b"old row").unwrap();
    assert!(
        BoundFormat::SESSION.marks(&legacy),
        "the nonce reads as a marker"
    );

    let opened = accepting()
        .open_bound(BoundFormat::SESSION, A, &[], &legacy)
        .unwrap();
    assert_eq!(opened.plaintext, b"old row");
    assert!(opened.legacy);
    assert!(
        SessionCrypto::new(KEY)
            .open_bound(BoundFormat::SESSION, A, &[], &legacy)
            .is_err()
    );
}

/// A blob in the current format that only the previous key opens is
/// reported stale, so the caller re-seals it; once re-sealed it opens with
/// the new key alone.
#[test]
fn a_blob_opened_with_the_previous_key_is_stale() {
    let old = SessionCrypto::new([1u8; 32]);
    let sealed = old
        .seal_bound(
            BoundFormat::DEVICE_BINDINGS,
            &device_row_id("t", "d"),
            b"bindings",
        )
        .unwrap();

    let rotated = SessionCrypto::new([2u8; 32]).with_previous_key([1u8; 32]);
    let opened = open_device(&rotated, "t", "d", &sealed).unwrap();
    assert_eq!(opened.plaintext, b"bindings");
    assert!(opened.stale, "the previous key opened it");

    let resealed = rotated
        .seal_bound(
            BoundFormat::DEVICE_BINDINGS,
            &device_row_id("t", "d"),
            &opened.plaintext,
        )
        .unwrap();
    let new_only = SessionCrypto::new([2u8; 32]);
    let again = open_device(&new_only, "t", "d", &resealed).unwrap();
    assert!(!again.stale);
    assert!(open_device(&new_only, "t", "d", &sealed).is_err());
}
