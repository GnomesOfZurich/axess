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
    SessionCodec::encrypted(SessionCrypto::new(crate::testing::test_key(8)))
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

fn accepting_codec() -> SessionCodec {
    SessionCodec::encrypted(
        SessionCrypto::new(crate::testing::test_key(8))
            .with_legacy_blobs(crate::session::crypto::LegacyBlobs::Accept),
    )
}

#[test]
fn a_legacy_blob_is_refused_by_default() {
    let legacy = SessionCrypto::new(crate::testing::test_key(8))
        .encrypt_unbound(&rmp_serde::to_vec_named(&sample()).unwrap())
        .unwrap();
    assert!(codec().decode_bytes(&id(1), &legacy).is_err());
    assert!(accepting_codec().decode_bytes(&id(1), &legacy).is_ok());
}

#[test]
fn legacy_blob_reads_and_is_resealed_by_the_next_encode() {
    let crypto = SessionCrypto::new(crate::testing::test_key(8));
    let legacy = crypto
        .encrypt_unbound(&rmp_serde::to_vec_named(&sample()).unwrap())
        .unwrap();
    assert!(!BoundFormat::SESSION.marks(&legacy));

    let loaded = accepting_codec().decode_bytes(&id(1), &legacy).unwrap();
    assert_eq!(loaded.custom, sample().custom);

    let resealed = codec().encode_bytes(&id(1), &loaded).unwrap();
    assert!(BoundFormat::SESSION.marks(&resealed));
    assert!(codec().decode_bytes(&id(2), &resealed).is_err());
}

/// A blob without any binding is read under the legacy window but is not
/// marked for a re-seal: a re-seal would bind a blob moved between rows to the
/// row it was found under. It is sealed afresh by the next save.
#[test]
fn an_unbound_blob_is_read_but_not_marked_for_reseal() {
    let legacy = SessionCrypto::new(crate::testing::test_key(8))
        .encrypt_unbound(&rmp_serde::to_vec_named(&sample()).unwrap())
        .unwrap();
    let Decoded {
        data: loaded,
        reseal,
    } = accepting_codec()
        .decode_bytes_checked(&id(1), &legacy)
        .unwrap();
    assert_eq!(loaded.custom, sample().custom);
    assert!(!reseal, "a read does not bind an unbound blob to a row");
}

/// A bound blob that only the previous key opens is marked for a re-seal
/// under the current key.
#[test]
fn a_blob_under_the_previous_key_is_marked_for_reseal() {
    let blob = codec().encode_bytes(&id(1), &sample()).unwrap();
    let rotated = SessionCodec::encrypted(
        SessionCrypto::new(crate::testing::test_key(9))
            .with_previous_key(crate::testing::test_key(8)),
    );
    let Decoded {
        data: loaded,
        reseal,
    } = rotated.decode_bytes_checked(&id(1), &blob).unwrap();
    assert_eq!(loaded.custom, sample().custom);
    assert!(reseal);
}

#[test]
fn marked_blob_with_empty_aad_body_is_refused() {
    let crypto = SessionCrypto::new(crate::testing::test_key(8));
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
