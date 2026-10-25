//! Row binding of the encrypted bindings blob.

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
