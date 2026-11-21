//! Id binding of the encrypted session codec.

use super::*;
use crate::session::crypto::{BoundFormat, LegacyBlobs};
use crate::session::id::{SessionId, SessionKey};

/// The key of the fixed session id that ends in `n`.
fn id(n: u8) -> SessionKey {
    let id: SessionId = format!("00000000-0000-4000-8000-0000000000{n:02x}")
        .parse()
        .expect("fixed test id");
    SessionKey::of(&id)
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

/// A sealed session starts with the marker of the second session format,
/// in its per-record-subkey layout.
#[test]
fn a_sealed_session_starts_with_the_second_format_marker() {
    let blob = codec().encode_bytes(&id(1), &sample()).unwrap();
    assert!(BoundFormat::SESSION.marks(&blob));
    assert_eq!(blob[..4], [0x41, 0x58, 0x53, 0x82]);
}

/// Every legacy policy a `SessionCrypto` can carry.
fn policies() -> [LegacyBlobs; 3] {
    let far = axess_clock::Timestamp::from_unix_seconds(4_000_000_000).expect("a valid instant");
    [
        LegacyBlobs::Reject,
        LegacyBlobs::AcceptUntil(far),
        LegacyBlobs::Accept,
    ]
}

fn codec_under(policy: LegacyBlobs) -> SessionCodec {
    SessionCodec::encrypted(
        SessionCrypto::new(crate::testing::test_key(8)).with_legacy_blobs(policy),
    )
}

/// The session id whose key is `id(n)`.
fn session_id(n: u8) -> SessionId {
    format!("00000000-0000-4000-8000-0000000000{n:02x}")
        .parse()
        .expect("fixed test id")
}

/// What an earlier release could have left in a session's row, each a
/// sealed, readable session: none of it is the current sealed form.
fn earlier_blobs(n: u8) -> Vec<(&'static str, Vec<u8>)> {
    let crypto = SessionCrypto::new(crate::testing::test_key(8));
    let plain = rmp_serde::to_vec_named(&sample()).unwrap();
    let (key, session) = (id(n), session_id(n));
    let unbound = crypto.encrypt_unbound(&plain).unwrap();
    let mut marked = b"AXS\x82".to_vec();
    marked.extend_from_slice(&unbound);
    let mut marked_as_first = b"AXS\x81".to_vec();
    marked_as_first.extend_from_slice(&unbound);
    vec![
        ("a blob with no binding", unbound),
        (
            "the first session format, bound to the session id",
            crypto
                .seal_bound(BoundFormat::SESSION_V1, session.as_bytes(), &plain)
                .unwrap(),
        ),
        (
            "the first session format, bound to the key",
            crypto
                .seal_bound(BoundFormat::SESSION_V1, key.as_bytes(), &plain)
                .unwrap(),
        ),
        (
            "the direct layout of the first format",
            crypto
                .seal_direct_layout(BoundFormat::SESSION_V1, session.as_bytes(), &plain)
                .unwrap(),
        ),
        (
            "the direct layout of the current format",
            crypto
                .seal_direct_layout(BoundFormat::SESSION, key.as_bytes(), &plain)
                .unwrap(),
        ),
        ("the current marker before an unbound body", marked),
        ("the first marker before an unbound body", marked_as_first),
    ]
}

/// A session is read from the current sealed form only: under `Reject`,
/// `AcceptUntil` and `Accept` alike, a blob with no binding, in the first
/// session format or in a direct layout is refused, and a blob in the
/// current form loads.
#[test]
fn no_legacy_blob_is_a_session_under_any_policy() {
    for policy in policies() {
        for (what, blob) in earlier_blobs(1) {
            let refused = codec_under(policy).decode_bytes_checked(&id(1), &blob);
            assert!(
                matches!(refused, Err(SqlStoreError::Crypto(_))),
                "{what} was read as a session under {policy:?}"
            );
        }
        let current = codec().encode_bytes(&id(1), &sample()).unwrap();
        let Decoded { data, reseal } = codec_under(policy)
            .decode_bytes_checked(&id(1), &current)
            .expect("the current form loads under every policy");
        assert_eq!(data.custom, sample().custom);
        assert!(!reseal);
    }
}

/// A blob of the first session format carries the marker `81` and is not a
/// session, whichever name of the session it was bound to: the id, as an
/// earlier release bound it, or the key.
#[test]
fn the_first_session_format_is_marked_81_and_refused() {
    let plain = rmp_serde::to_vec_named(&sample()).unwrap();
    for row_id in [session_id(1).as_bytes().as_slice(), id(1).as_bytes()] {
        let blob = SessionCrypto::new(crate::testing::test_key(8))
            .seal_bound(BoundFormat::SESSION_V1, row_id, &plain)
            .unwrap();
        assert_eq!(blob[..4], [0x41, 0x58, 0x53, 0x81]);
        for policy in policies() {
            assert!(
                codec_under(policy).decode_bytes(&id(1), &blob).is_err(),
                "a blob of the first session format was read under {policy:?}"
            );
        }
    }
}

/// A session whose row holds a legacy blob is written afresh by its next
/// save: the encode seals the current form whatever the row held.
#[test]
fn an_encode_seals_the_current_form_over_a_legacy_blob() {
    let crypto = SessionCrypto::new(crate::testing::test_key(8));
    let legacy = crypto
        .encrypt_unbound(&rmp_serde::to_vec_named(&sample()).unwrap())
        .unwrap();
    assert!(!BoundFormat::SESSION.marks(&legacy));
    assert!(
        codec_under(LegacyBlobs::Accept)
            .decode_bytes(&id(1), &legacy)
            .is_err()
    );

    let sealed = codec().encode_bytes(&id(1), &sample()).unwrap();
    assert!(BoundFormat::SESSION.marks(&sealed));
    assert!(codec().decode_bytes(&id(2), &sealed).is_err());
    assert!(codec().decode_bytes(&id(1), &sealed).is_ok());
}

/// A SQL row with no value in its binary column is not a session, whatever
/// its text column holds: the text is not read.
#[cfg(any(
    feature = "sqlite",
    feature = "sqlite-unbundled",
    feature = "postgres",
    feature = "mysql"
))]
#[test]
fn a_row_without_a_binary_value_is_not_a_session() {
    assert!(matches!(
        SessionCodec::binary_column(None),
        Err(SqlStoreError::Decode(_))
    ));
    let blob = codec().encode_bytes(&id(1), &sample()).unwrap();
    assert_eq!(
        SessionCodec::binary_column(Some(blob.clone())).unwrap(),
        blob
    );
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
fn a_marked_blob_with_an_unbound_body_is_refused() {
    let crypto = SessionCrypto::new(crate::testing::test_key(8));
    let body = crypto
        .encrypt_unbound(&rmp_serde::to_vec_named(&sample()).unwrap())
        .unwrap();
    for marker in [b"AXS\x01", b"AXS\x02", b"AXS\x81", b"AXS\x82"] {
        let mut blob = marker.to_vec();
        blob.extend_from_slice(&body);
        assert!(codec().decode_bytes(&id(1), &blob).is_err());
        assert!(
            codec_under(LegacyBlobs::Accept)
                .decode_bytes(&id(1), &blob)
                .is_err()
        );
    }
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

#[test]
fn an_encrypted_session_carrying_assurance_round_trips() {
    let data = crate::session::data::assured_fixture::assured_session();
    let blob = codec().encode_bytes(&id(3), &data).unwrap();
    let back = codec().decode_bytes(&id(3), &blob).unwrap();
    assert_eq!(back.auth_state, data.auth_state);
}

/// The session as JSON, the encoding of the 0.1.x line: the bytes a
/// pre-MessagePack row held.
fn json_session() -> Vec<u8> {
    serde_json::to_vec(&sample()).expect("a session encodes as JSON")
}

#[test]
fn a_json_blob_is_refused_by_the_plaintext_codec() {
    let refused = SessionCodec::plaintext().decode_bytes(&id(1), &json_session());
    assert!(
        matches!(refused, Err(SqlStoreError::Decode(_))),
        "a JSON session is not read: {refused:?}"
    );
}

#[test]
fn a_sealed_json_blob_is_refused_by_the_encrypted_codec() {
    let crypto = SessionCrypto::new(crate::testing::test_key(8));
    let sealed = crypto
        .seal_bound(BoundFormat::SESSION, id(1).as_bytes(), &json_session())
        .unwrap();
    let refused = codec().decode_bytes(&id(1), &sealed);
    assert!(
        matches!(refused, Err(SqlStoreError::Decode(_))),
        "a sealed JSON session opens but is not read: {refused:?}"
    );
}

#[test]
fn a_messagepack_session_round_trips_under_each_codec() {
    for codec in [SessionCodec::plaintext(), codec()] {
        let blob = codec.encode_bytes(&id(4), &sample()).unwrap();
        let Decoded { data, reseal } = codec.decode_bytes_checked(&id(4), &blob).unwrap();
        assert_eq!(data.custom, sample().custom);
        assert!(!reseal, "a blob in the current form needs no re-seal");
    }
}
