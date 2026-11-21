//! The fake agent writes what the client reads: its encoders against the
//! client's decoders, without a socket.

use proptest::prelude::*;
use serde_json::{Map, Value, json};

use super::*;
use crate::workload::spire::proto;
use crate::workload::spire::transport::{SECURITY_HEADER, percent_decoded};

/// The client's reading of a `ValidateJWTSVIDResponse` the fake wrote.
fn claims_read_back(spiffe_id: &str, claims: &Map<String, Value>) -> Map<String, Value> {
    let mut message = Vec::new();
    put_bytes(&mut message, 1, spiffe_id.as_bytes());
    put_bytes(&mut message, 2, &encode_struct(claims));
    let decoded = proto::decode_validate_jwt_svid_response(&message).expect("the client reads it");
    assert_eq!(decoded.spiffe_id, spiffe_id);
    decoded.claims
}

/// The names the standards give, written out. The service and its methods
/// are those of `workloadapi.proto`, the definition section 3 of the SPIFFE
/// Workload API standard points to: `service SpiffeWorkloadAPI`, in no
/// package, with the X.509-SVID profile's `FetchX509SVID` and
/// `FetchX509Bundles` (section 5.2) and the JWT-SVID profile's
/// `FetchJWTSVID`, `FetchJWTBundles` and `ValidateJWTSVID` (section 6.2).
/// The metadata key is the one section 3 of the SPIFFE Workload Endpoint
/// standard requires on every request: `workload.spiffe.io`, with the value
/// `true`. The client and the fake each carry their own copy; both are held
/// to these, and neither to the other.
#[test]
fn the_client_and_the_fake_use_the_names_the_workload_api_defines() {
    let methods = [
        (
            WorkloadApiMethod::FetchX509Svid,
            proto::FETCH_X509_SVID,
            "FetchX509SVID",
            "/SpiffeWorkloadAPI/FetchX509SVID",
        ),
        (
            WorkloadApiMethod::FetchX509Bundles,
            proto::FETCH_X509_BUNDLES,
            "FetchX509Bundles",
            "/SpiffeWorkloadAPI/FetchX509Bundles",
        ),
        (
            WorkloadApiMethod::FetchJwtSvid,
            proto::FETCH_JWT_SVID,
            "FetchJWTSVID",
            "/SpiffeWorkloadAPI/FetchJWTSVID",
        ),
        (
            WorkloadApiMethod::FetchJwtBundles,
            proto::FETCH_JWT_BUNDLES,
            "FetchJWTBundles",
            "/SpiffeWorkloadAPI/FetchJWTBundles",
        ),
        (
            WorkloadApiMethod::ValidateJwtSvid,
            proto::VALIDATE_JWT_SVID,
            "ValidateJWTSVID",
            "/SpiffeWorkloadAPI/ValidateJWTSVID",
        ),
    ];
    assert_eq!(methods.len(), WorkloadApiMethod::ALL.len());
    for (method, client_name, name, path) in methods {
        assert_eq!(client_name, name);
        assert_eq!(method.path(), path);
        assert_eq!(WorkloadApiMethod::of_path(path), Some(method));
    }
    assert_eq!(SECURITY_HEADER, "workload.spiffe.io");
    assert_eq!(SECURITY_METADATA, "workload.spiffe.io");
}

#[test]
fn a_path_that_is_no_method_of_the_workload_api_is_not_found() {
    assert_eq!(WorkloadApiMethod::of_path("/SpiffeWorkloadAPI/Other"), None);
    assert_eq!(WorkloadApiMethod::of_path("FetchX509SVID"), None);
    assert_eq!(
        WorkloadApiMethod::of_path("/spiffe.workload.SpiffeWorkloadAPI/FetchX509SVID"),
        None
    );
    assert_eq!(WorkloadApiMethod::of_path("/Other/FetchX509SVID"), None);
    assert!(WorkloadApiMethod::FetchX509Svid.streams());
    assert!(!WorkloadApiMethod::FetchJwtSvid.streams());
    assert!(!WorkloadApiMethod::ValidateJwtSvid.streams());
}

#[test]
fn claims_of_every_json_type_survive_the_round_trip() {
    let claims = json!({
        "sub": "spiffe://example.org/billing/acme",
        "aud": ["one", "two"],
        "exp": 1_767_229_200,
        "ratio": 0.5,
        "admin": false,
        "nothing": null,
        "ctx": { "tid": "t-1", "levels": [1, 2] },
    });
    let claims = claims.as_object().expect("an object");
    assert_eq!(
        &claims_read_back("spiffe://example.org/billing/acme", claims),
        claims
    );
}

#[test]
fn a_status_message_is_escaped_as_grpc_writes_it() {
    assert_eq!(percent_encoded("no identity issued"), "no identity issued");
    assert_eq!(percent_encoded("100%"), "100%25");
    assert_eq!(percent_encoded("a\nb"), "a%0Ab");
    assert_eq!(percent_encoded("caf\u{e9}"), "caf%C3%A9");
}

#[test]
fn the_strings_of_a_field_are_read_in_order() {
    let mut message = Vec::new();
    put_bytes(&mut message, 1, b"first");
    put_bytes(&mut message, 2, b"other");
    put_bytes(&mut message, 1, b"second");
    assert_eq!(strings_of_field(&message, 1), ["first", "second"]);
    assert_eq!(strings_of_field(&message, 2), ["other"]);
    assert!(strings_of_field(&message, 3).is_empty());
}

#[test]
fn a_map_entry_is_a_key_and_a_value() {
    let entry = map_entry("example.org", b"bundle");
    assert_eq!(strings_of_field(&entry, 1), ["example.org"]);
    assert_eq!(strings_of_field(&entry, 2), ["bundle"]);
}

/// JSON a claim may hold: what a `google.protobuf.Value` carries. Numbers
/// are whole numbers a double holds exactly, or halves, so that the round
/// trip through a double is exact.
fn claim_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        (-1_000_000_000i64..1_000_000_000).prop_map(|n| json!(n)),
        (-1000i32..1000).prop_map(|n| json!(f64::from(n) + 0.5)),
        "\\PC{0,16}".prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 24, 4, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            proptest::collection::btree_map("[a-z]{1,8}", inner, 0..4)
                .prop_map(|fields| Value::Object(fields.into_iter().collect())),
        ]
    })
}

proptest! {
    /// Whatever the claims, the client reads back what the fake wrote.
    #[test]
    fn claims_round_trip(
        fields in proptest::collection::btree_map("[a-z]{1,8}", claim_value(), 0..6),
    ) {
        let claims: Map<String, Value> = fields.into_iter().collect();
        prop_assert_eq!(claims_read_back("spiffe://example.org/a/b", &claims), claims);
    }

    /// Whatever the status message, the client reads back what the fake
    /// wrote, and the header value is one HTTP accepts.
    #[test]
    fn status_messages_round_trip(message in "\\PC{0,64}") {
        let encoded = percent_encoded(&message);
        prop_assert!(HeaderValue::from_str(&encoded).is_ok());
        prop_assert_eq!(percent_decoded(encoded.as_bytes()), message);
    }
}
