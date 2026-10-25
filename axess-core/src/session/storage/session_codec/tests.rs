//! Id binding of the encrypted session codec.

use super::*;
use crate::session::crypto::BoundFormat;

fn id(n: u8) -> SessionId {
    format!("00000000-0000-4000-8000-0000000000{n:02x}")
        .parse()
        .expect("fixed test id")
}

fn sample() -> SessionData {
    SessionData {
        custom: serde_json::json!({"role": "admin"}),
        ..SessionData::default()
    }
}

fn codec() -> SessionCodec {
    SessionCodec::encrypted(SessionCrypto::new([8u8; 32]))
}

#[test]
fn blob_encrypted_under_one_id_fails_under_another() {
    let blob = codec().encode_bytes(&id(1), &sample()).unwrap();
    assert!(codec().decode_bytes(&id(2), &blob).is_err());
    let back = codec().decode_bytes(&id(1), &blob).unwrap();
    assert_eq!(back.custom, sample().custom);
}

#[test]
fn new_blobs_carry_the_marker() {
    let blob = codec().encode_bytes(&id(1), &sample()).unwrap();
    assert!(BoundFormat::SESSION.marks(&blob));
}

#[test]
fn legacy_blob_reads_and_is_resealed_by_the_next_encode() {
    let crypto = SessionCrypto::new([8u8; 32]);
    let legacy = crypto
        .encrypt_unbound(&rmp_serde::to_vec_named(&sample()).unwrap())
        .unwrap();
    assert!(!BoundFormat::SESSION.marks(&legacy));

    let loaded = codec().decode_bytes(&id(1), &legacy).unwrap();
    assert_eq!(loaded.custom, sample().custom);

    let resealed = codec().encode_bytes(&id(1), &loaded).unwrap();
    assert!(BoundFormat::SESSION.marks(&resealed));
    assert!(codec().decode_bytes(&id(2), &resealed).is_err());
}

#[test]
fn marked_blob_with_empty_aad_body_is_refused() {
    let crypto = SessionCrypto::new([8u8; 32]);
    let body = crypto
        .encrypt_unbound(&rmp_serde::to_vec_named(&sample()).unwrap())
        .unwrap();
    let mut blob = b"AXS\x01".to_vec();
    blob.extend_from_slice(&body);
    assert!(codec().decode_bytes(&id(1), &blob).is_err());
}

#[test]
fn plaintext_codec_is_unchanged() {
    let plain = SessionCodec::plaintext();
    let blob = plain.encode_bytes(&id(1), &sample()).unwrap();
    assert_eq!(
        plain.decode_bytes(&id(2), &blob).unwrap().custom,
        sample().custom
    );
}
