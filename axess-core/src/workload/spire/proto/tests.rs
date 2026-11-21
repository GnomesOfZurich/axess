//! The Workload API messages: that each field lands where it belongs, that
//! an unknown field is skipped, and that no bytes make a decoder panic.

use proptest::prelude::*;
use serde_json::json;

use super::*;
use crate::workload::spire::wire::put_varint;

fn message(fields: &[(u32, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (number, value) in fields {
        put_bytes(&mut out, *number, value);
    }
    out
}

fn varint_field(number: u32, value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    put_varint(&mut out, u64::from(number) << 3);
    put_varint(&mut out, value);
    out
}

fn double_field(number: u32, value: f64) -> Vec<u8> {
    let mut out = Vec::new();
    put_varint(&mut out, (u64::from(number) << 3) | 1);
    out.extend_from_slice(&value.to_bits().to_le_bytes());
    out
}

/// A `Struct` with one field `key` whose `Value` is `value`.
fn struct_of(key: &str, value: &[u8]) -> Vec<u8> {
    message(&[(1, &message(&[(1, key.as_bytes()), (2, value)]))])
}

/// Run every decoder over `bytes`; whatever one of them accepts is within
/// the limits the module states.
fn within_limits(bytes: &[u8]) -> bool {
    let x509 = decode_x509_svid_response(bytes).is_ok_and(|response| {
        response.svids.len() > MAX_SVIDS
            || response.crls.len() > MAX_CRLS
            || response.federated_bundles.len() > MAX_BUNDLES
    });
    let x509_bundles = decode_x509_bundles_response(bytes).is_ok_and(|response| {
        response.crls.len() > MAX_CRLS || response.bundles.len() > MAX_BUNDLES
    });
    let jwt_bundles = decode_jwt_bundles_response(bytes)
        .is_ok_and(|response| response.bundles.len() > MAX_BUNDLES);
    let jwt = decode_jwt_svid_response(bytes).is_ok_and(|svids| svids.len() > MAX_SVIDS);
    let validated = decode_validate_jwt_svid_response(bytes)
        .is_ok_and(|validation| validation.spiffe_id.len() > bytes.len());
    !(x509 || x509_bundles || jwt_bundles || jwt || validated)
}

#[test]
fn an_x509_svid_response_reads_every_field() {
    let svid = message(&[
        (1, b"spiffe://example.org/billing/acme"),
        (2, b"chain"),
        (3, b"key"),
        (4, b"bundle"),
        (5, b"internal"),
    ]);
    let federated = message(&[(1, b"spiffe://partner.test"), (2, b"partner bundle")]);
    let response = message(&[
        (1, &svid),
        (2, b"crl one"),
        (3, &federated),
        (2, b"crl two"),
    ]);

    let decoded = decode_x509_svid_response(&response).expect("a well-formed response");
    assert_eq!(decoded.svids.len(), 1);
    assert_eq!(
        decoded.svids[0].spiffe_id,
        "spiffe://example.org/billing/acme"
    );
    assert_eq!(decoded.svids[0].cert_chain, b"chain");
    assert_eq!(decoded.svids[0].private_key.as_slice(), b"key");
    assert_eq!(decoded.svids[0].bundle, b"bundle");
    assert_eq!(decoded.svids[0].hint, "internal");
    assert_eq!(decoded.crls, [b"crl one".to_vec(), b"crl two".to_vec()]);
    assert_eq!(
        decoded.federated_bundles,
        [(
            "spiffe://partner.test".to_owned(),
            b"partner bundle".to_vec()
        )]
    );
}

#[test]
fn an_unknown_field_is_skipped() {
    let mut svid = message(&[(1, b"spiffe://example.org/a/b"), (9, b"from a newer agent")]);
    svid.extend(varint_field(12, 7));
    let mut response = message(&[(1, &svid), (15, b"also new")]);
    response.extend(double_field(14, 1.5));
    let decoded = decode_x509_svid_response(&response).expect("unknown fields are skipped");
    assert_eq!(decoded.svids[0].spiffe_id, "spiffe://example.org/a/b");
}

#[test]
fn a_known_field_of_the_wrong_wire_type_is_refused() {
    // `svids` (field 1) as a varint.
    assert_eq!(
        decode_x509_svid_response(&varint_field(1, 1)).err(),
        Some(ProtoError::WrongType("svids"))
    );
    // `spiffe_id` of a JWT SVID as a varint.
    let response = message(&[(1, &varint_field(1, 1))]);
    assert_eq!(
        decode_jwt_svid_response(&response).err(),
        Some(ProtoError::WrongType("spiffe_id"))
    );
}

#[test]
fn a_string_that_is_not_utf8_is_refused() {
    let svid = message(&[(1, &[0xFF, 0xFE])]);
    assert_eq!(
        decode_x509_svid_response(&message(&[(1, &svid)])).err(),
        Some(ProtoError::NotUtf8("spiffe_id"))
    );
}

#[test]
fn x509_bundles_carry_revocation_lists_in_field_one_and_bundles_in_field_two() {
    let entry = message(&[(1, b"example.org"), (2, b"authorities")]);
    let response = message(&[(1, b"crl"), (2, &entry)]);
    let decoded = decode_x509_bundles_response(&response).expect("a well-formed response");
    assert_eq!(decoded.crls, [b"crl".to_vec()]);
    assert_eq!(
        decoded.bundles,
        [("example.org".to_owned(), b"authorities".to_vec())]
    );
}

#[test]
fn jwt_bundles_carry_bundles_in_field_one() {
    let entry = message(&[(1, b"example.org"), (2, br#"{"keys":[]}"#)]);
    let decoded =
        decode_jwt_bundles_response(&message(&[(1, &entry)])).expect("a well-formed response");
    assert!(decoded.crls.is_empty());
    assert_eq!(
        decoded.bundles,
        [("example.org".to_owned(), br#"{"keys":[]}"#.to_vec())]
    );
}

#[test]
fn a_jwt_svid_response_reads_every_svid() {
    let first = message(&[(1, b"spiffe://example.org/a/b"), (2, b"h.p.s"), (3, b"one")]);
    let second = message(&[(1, b"spiffe://example.org/c/d"), (2, b"h2.p2.s2")]);
    let decoded = decode_jwt_svid_response(&message(&[(1, &first), (1, &second)]))
        .expect("a well-formed response");
    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[0].spiffe_id, "spiffe://example.org/a/b");
    assert_eq!(decoded[0].token.as_str(), "h.p.s");
    assert_eq!(decoded[0].hint, "one");
    assert_eq!(decoded[1].token.as_str(), "h2.p2.s2");
    assert_eq!(decoded[1].hint, "");
}

#[test]
fn more_svids_than_the_limit_are_refused() {
    let svid = message(&[(1, b"spiffe://example.org/a/b")]);
    let fields: Vec<(u32, &[u8])> = (0..=MAX_SVIDS).map(|_| (1, svid.as_slice())).collect();
    assert_eq!(
        decode_x509_svid_response(&message(&fields)).err(),
        Some(ProtoError::TooMany {
            field: "svids",
            max: MAX_SVIDS
        })
    );
}

#[test]
fn the_requests_are_written_as_the_agent_reads_them() {
    let audiences = ["https://api.example.org".to_owned(), "second".to_owned()];
    assert_eq!(
        encode_jwt_svid_request(&audiences, Some("spiffe://example.org/a/b")),
        message(&[
            (1, b"https://api.example.org"),
            (1, b"second"),
            (2, b"spiffe://example.org/a/b"),
        ])
    );
    assert_eq!(
        encode_jwt_svid_request(&audiences[..1], None),
        message(&[(1, b"https://api.example.org")])
    );
    assert_eq!(
        encode_validate_jwt_svid_request("aud", "h.p.s").to_vec(),
        message(&[(1, b"aud"), (2, b"h.p.s")])
    );
}

#[test]
fn validated_claims_read_as_json() {
    let mut claims = Vec::new();
    claims.extend(struct_of(
        "sub",
        &message(&[(3, b"spiffe://example.org/a/b")]),
    ));
    claims.extend(struct_of("exp", &double_field(2, 1_767_229_200.0)));
    claims.extend(struct_of("ratio", &double_field(2, 0.25)));
    claims.extend(struct_of("admin", &varint_field(4, 1)));
    claims.extend(struct_of("nothing", &varint_field(1, 0)));
    let list = message(&[(1, &message(&[(3, b"one")])), (1, &message(&[(3, b"two")]))]);
    claims.extend(struct_of("aud", &message(&[(6, &list)])));
    let nested = struct_of("tid", &message(&[(3, b"t-1")]));
    claims.extend(struct_of("ctx", &message(&[(5, &nested)])));
    let response = message(&[(1, b"spiffe://example.org/a/b"), (2, &claims)]);

    let decoded = decode_validate_jwt_svid_response(&response).expect("a well-formed response");
    assert_eq!(decoded.spiffe_id, "spiffe://example.org/a/b");
    assert_eq!(
        serde_json::Value::Object(decoded.claims),
        json!({
            "sub": "spiffe://example.org/a/b",
            "exp": 1_767_229_200,
            "ratio": 0.25,
            "admin": true,
            "nothing": null,
            "aud": ["one", "two"],
            "ctx": { "tid": "t-1" },
        })
    );
}

#[test]
fn claims_that_nest_too_deep_are_refused() {
    let mut value = message(&[(3, b"bottom")]);
    for _ in 0..MAX_CLAIM_DEPTH {
        value = message(&[(5, &struct_of("k", &value))]);
    }
    let response = message(&[(2, &struct_of("top", &value))]);
    assert_eq!(
        decode_validate_jwt_svid_response(&response).err(),
        Some(ProtoError::TooDeep(MAX_CLAIM_DEPTH))
    );
}

#[test]
fn a_claim_that_is_not_a_finite_number_is_refused() {
    for number in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let response = message(&[(2, &struct_of("exp", &double_field(2, number)))]);
        assert_eq!(
            decode_validate_jwt_svid_response(&response).err(),
            Some(ProtoError::NotFinite)
        );
    }
}

proptest! {
    /// No bytes make a decoder panic; each ends in a value or an error.
    #[test]
    fn every_decoder_ends_on_any_input(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        prop_assert!(within_limits(&bytes));
    }

    /// Bytes that are a well-formed message at the top level, with anything
    /// inside the nested fields.
    #[test]
    fn every_decoder_ends_on_any_nested_input(
        fields in proptest::collection::vec(
            (1u32..8, proptest::collection::vec(any::<u8>(), 0..64)),
            0..12,
        ),
    ) {
        let mut bytes = Vec::new();
        for (number, value) in &fields {
            put_bytes(&mut bytes, *number, value);
        }
        prop_assert!(within_limits(&bytes));
    }

    /// A bundle map written field by field reads back entry by entry.
    #[test]
    fn a_bundle_map_round_trips(
        entries in proptest::collection::vec(
            ("[a-z0-9.-]{1,24}", proptest::collection::vec(any::<u8>(), 0..48)),
            0..8,
        ),
    ) {
        let mut response = Vec::new();
        for (trust_domain, bundle) in &entries {
            put_bytes(&mut response, 1, &message(&[(1, trust_domain.as_bytes()), (2, bundle)]));
        }
        let decoded = decode_jwt_bundles_response(&response).expect("a well-formed response");
        prop_assert_eq!(decoded.bundles, entries);
    }

    /// A whole number a double holds exactly comes back as that integer.
    #[test]
    fn whole_numbers_come_back_as_integers(seconds in -9_007_199_254_740_991i64..9_007_199_254_740_992) {
        let response = message(&[(2, &struct_of("n", &double_field(2, seconds as f64)))]);
        let decoded = decode_validate_jwt_svid_response(&response).expect("a finite number");
        prop_assert_eq!(decoded.claims.get("n").and_then(serde_json::Value::as_i64), Some(seconds));
    }
}
