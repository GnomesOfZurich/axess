//! Row binding of the encrypted bindings blob, and the miss rule of guarded
//! trust changes.

use super::*;
use crate::device::types::{DeviceBinding, FingerprintHash};
use chrono::{TimeZone, Utc};

fn bindings() -> Vec<DeviceBinding> {
    let now = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    vec![DeviceBinding::Cookie {
        token_hash: FingerprintHash::from_bytes([0xAB; 32]),
        issued_at: now,
        last_used_at: now,
    }]
}

fn codec() -> BindingsCodec {
    BindingsCodec::encrypted(SessionCrypto::new([6u8; 32]))
}

#[test]
fn blob_from_one_device_does_not_decode_under_another() {
    let blob = codec().encode("t1", "device-a", &bindings()).unwrap();
    assert!(codec().decode("t1", "device-b", &blob).is_err());
    assert!(codec().decode("t2", "device-a", &blob).is_err());
    assert_eq!(codec().decode("t1", "device-a", &blob).unwrap(), bindings());
}

#[test]
fn tenant_and_device_ids_cannot_be_shifted_across_the_separator() {
    let blob = codec().encode("ab", "c", &bindings()).unwrap();
    assert!(codec().decode("a", "bc", &blob).is_err());
}

#[test]
fn legacy_blob_decodes_and_the_next_encode_is_bound() {
    let legacy = BASE64.encode(
        SessionCrypto::new([6u8; 32])
            .encrypt_unbound(&rmp_serde::to_vec_named(&bindings()).unwrap())
            .unwrap(),
    );
    assert_eq!(codec().decode("t1", "d", &legacy).unwrap(), bindings());

    let resealed = codec().encode("t1", "d", &bindings()).unwrap();
    assert_ne!(resealed, legacy);
    assert!(codec().decode("t1", "other", &resealed).is_err());
}

#[test]
fn marked_blob_with_empty_aad_body_is_refused() {
    let body = SessionCrypto::new([6u8; 32])
        .encrypt_unbound(&rmp_serde::to_vec_named(&bindings()).unwrap())
        .unwrap();
    let mut blob = b"AXD\x01".to_vec();
    blob.extend_from_slice(&body);
    assert!(codec().decode("t1", "d", &BASE64.encode(blob)).is_err());
}

/// A guarded trust change that matched no row and finds the row at the
/// level it expected has not been applied: the caller writes again rather
/// than being told the transition happened.
#[test]
fn a_miss_that_finds_the_expected_level_is_retried_not_reported_applied() {
    use crate::device::store::TrustTransition;
    use crate::device::types::DeviceTrustLevel::{Revoked, Seen, Trusted};
    assert_eq!(super::transition_after_miss(Some(Trusted), Trusted), None);
    assert_eq!(
        super::transition_after_miss(Some(Revoked), Trusted),
        Some(TrustTransition::Refused { current: Revoked })
    );
    assert_eq!(
        super::transition_after_miss(None, Seen),
        Some(TrustTransition::Missing)
    );
}

/// A bindings blob sealed by 0.11.0 (`AXD 0x01`, ids joined by a zero byte)
/// still decodes under its own ids and not under another pair, and the next
/// encode writes the current format.
#[test]
fn a_blob_of_the_previous_format_decodes_and_is_replaced_on_encode() {
    use crate::session::crypto::{BoundFormat, device_row_id_v1};
    let crypto = SessionCrypto::new([6u8; 32]);
    let body = crypto
        .encrypt_with_aad(
            &BoundFormat::DEVICE_BINDINGS_V1.aad(&device_row_id_v1("t1", "d")),
            &rmp_serde::to_vec_named(&bindings()).unwrap(),
        )
        .unwrap();
    let mut blob = b"AXD\x01".to_vec();
    blob.extend_from_slice(&body);
    let stored = BASE64.encode(blob);

    assert_eq!(codec().decode("t1", "d", &stored).unwrap(), bindings());
    assert!(codec().decode("t1", "other", &stored).is_err());
    let current = BASE64
        .decode(codec().encode("t1", "d", &bindings()).unwrap())
        .unwrap();
    assert!(current.starts_with(b"AXD\x02"));
}

/// Ids that differ only in where a zero byte falls do not share a blob.
#[test]
fn ids_that_differ_only_by_a_zero_byte_split_do_not_share_a_blob() {
    let blob = codec().encode("a\0b", "c", &bindings()).unwrap();
    assert!(codec().decode("a", "b\0c", &blob).is_err());
    assert_eq!(codec().decode("a\0b", "c", &blob).unwrap(), bindings());
}

/// With legacy blobs rejected, an unmarked blob is refused.
#[test]
fn rejecting_legacy_blobs_refuses_an_unmarked_bindings_blob() {
    use crate::session::crypto::LegacyBlobs;
    let strict = BindingsCodec::encrypted(
        SessionCrypto::new([6u8; 32]).with_legacy_blobs(LegacyBlobs::Reject),
    );
    let legacy = BASE64.encode(
        SessionCrypto::new([6u8; 32])
            .encrypt_unbound(&rmp_serde::to_vec_named(&bindings()).unwrap())
            .unwrap(),
    );
    assert!(strict.decode("t1", "d", &legacy).is_err());
    let bound = strict.encode("t1", "d", &bindings()).unwrap();
    assert_eq!(strict.decode("t1", "d", &bound).unwrap(), bindings());
}
