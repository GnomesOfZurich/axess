//! `tests`: the unit tests of `dpop.rs`, kept beside it per the
//! 200-line inline-test rule in AGENTS.md.

use super::*;

/// DPoP counts as advertised only when the list names the algorithm the
/// proofs are signed with; an absent member, an empty list and a list of
/// other algorithms leave it off.
#[test]
fn dpop_is_advertised_only_with_the_proofs_algorithm() {
    let doc = |v: serde_json::Value| serde_json::json!({ "dpop_signing_alg_values_supported": v });
    assert!(advertised_in(&doc(serde_json::json!(["ES256"]))));
    assert!(advertised_in(&doc(serde_json::json!(["PS256", "ES256"]))));
    assert!(!advertised_in(&serde_json::json!({})));
    assert!(!advertised_in(&doc(serde_json::json!([]))));
    assert!(!advertised_in(&doc(serde_json::json!([
        "PS256", "EdDSA", "es256"
    ]))));
    assert!(!advertised_in(&doc(serde_json::json!("ES256"))));
}

const IAT: i64 = 1_767_225_600;
const JTI: [u8; 16] = [0xab; 16];

fn key(seed: u8) -> DpopKey {
    DpopKey::from_seed([seed; 32])
}

/// Confirm `BTreeMap`-driven canonical JWK matches the lex-ordered JSON
/// RFC 7638 requires. Pure-data check: exercises the canonicalisation
/// independently of P-256 key generation.
#[test]
fn canonical_jwk_lex_ordering() {
    use std::collections::BTreeMap;
    let mut members: BTreeMap<&'static str, &str> = BTreeMap::new();
    // Insert intentionally out of order; `BTreeMap` must reorder.
    members.insert("kty", "EC");
    members.insert("crv", "P-256");
    members.insert("x", "ax");
    members.insert("y", "ay");
    let canonical = serde_json::to_string(&members).unwrap();
    // RFC 7638 §3.2: required EC members in lex order are
    // crv, kty, x, y.
    assert_eq!(canonical, r#"{"crv":"P-256","kty":"EC","x":"ax","y":"ay"}"#);
}

/// Identical seed gives an identical thumbprint (the DST contract: a
/// seeded `SecureRng` driving key generation gives reproducible
/// `cnf.jkt` across runs); different seeds give different ones.
#[test]
fn deterministic_thumbprint_from_seed() {
    let proof_a1 = generate_dpop_proof(
        &key(0x11),
        "POST",
        "https://api.example.com/x",
        None,
        IAT,
        JTI,
    )
    .unwrap();
    let proof_a2 = generate_dpop_proof(
        &key(0x11),
        "POST",
        "https://api.example.com/x",
        None,
        IAT,
        JTI,
    )
    .unwrap();
    let proof_b = generate_dpop_proof(
        &key(0x22),
        "POST",
        "https://api.example.com/x",
        None,
        IAT,
        JTI,
    )
    .unwrap();

    assert_eq!(proof_a1.thumbprint, proof_a2.thumbprint);
    assert_ne!(proof_a1.thumbprint, proof_b.thumbprint);
    // base64url-no-pad of a 32-byte SHA-256 is 43 chars.
    assert_eq!(proof_a1.thumbprint.len(), 43);
}

/// Regression test for the lex-ordering rail. Hardcodes the SHA-256
/// thumbprint expected for a known seed, so any future regression that
/// reorders JWK members (or accidentally adds a field) flips the digest.
#[test]
fn known_seed_yields_known_thumbprint() {
    let seed = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let proof = generate_dpop_proof(
        &DpopKey::from_seed(seed),
        "GET",
        "https://rs.example.com/",
        None,
        IAT,
        JTI,
    )
    .unwrap();
    let expected = "6UoWwDCkLjV0J-pQG8c0THxbVhBcpR0AZDift1Yl5DM";
    assert_eq!(
        proof.thumbprint, expected,
        "pinned thumbprint changed; JWK canonicalisation may have regressed"
    );
}

fn decode_part(jwt: &str, index: usize) -> serde_json::Value {
    use base64::Engine as _;
    let part = jwt.split('.').nth(index).expect("jwt part");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .expect("base64url");
    serde_json::from_slice(&bytes).expect("json")
}

/// `iat` and `jti` are the caller's values, not a clock read and a
/// fresh UUID, and the whole proof (header and payload) repeats.
#[test]
fn iat_and_jti_are_exactly_what_the_caller_supplied() {
    let k = key(0x33);
    let proof = generate_dpop_proof(&k, "POST", "https://a.example/t", None, IAT, JTI).unwrap();
    let payload = decode_part(&proof.proof_jwt, 1);
    assert_eq!(payload["iat"], IAT);
    assert_eq!(payload["jti"], "abababab-abab-4bab-abab-abababababab");
    assert_eq!(payload["htm"], "POST");
    assert_eq!(payload["htu"], "https://a.example/t");

    let again = generate_dpop_proof(&k, "POST", "https://a.example/t", None, IAT, JTI).unwrap();
    assert_eq!(
        decode_part(&again.proof_jwt, 0),
        decode_part(&proof.proof_jwt, 0)
    );
    assert_eq!(decode_part(&again.proof_jwt, 1), payload);

    let later =
        generate_dpop_proof(&k, "POST", "https://a.example/t", None, IAT + 1, [1; 16]).unwrap();
    let later_payload = decode_part(&later.proof_jwt, 1);
    assert_eq!(later_payload["iat"], IAT + 1);
    assert_ne!(later_payload["jti"], payload["jti"]);
}

/// Two proofs from one key for different URLs, one of them bound to an
/// access token, report one thumbprint and it is the key's own; a proof
/// from another key reports another. This is what a `cnf.jkt` binding
/// needs and what a key drawn per proof could never give.
#[test]
fn one_key_gives_one_thumbprint_across_proofs() {
    let k = key(0x44);
    let first =
        generate_dpop_proof(&k, "POST", "https://as.example/token", None, IAT, JTI).unwrap();
    let second = generate_dpop_proof(
        &k,
        "GET",
        "https://rs.example/accounts",
        Some("access-token"),
        IAT + 5,
        [2; 16],
    )
    .unwrap();
    assert_eq!(first.thumbprint, second.thumbprint);
    assert_eq!(first.thumbprint, k.thumbprint().unwrap());

    let other = generate_dpop_proof(
        &key(0x55),
        "GET",
        "https://rs.example/accounts",
        None,
        IAT,
        JTI,
    )
    .unwrap();
    assert_ne!(other.thumbprint, first.thumbprint);
}

/// The proof verifies under the verifier a resource server runs, and the
/// thumbprint it reports is the key's.
#[test]
fn a_generated_proof_verifies_and_reports_the_keys_thumbprint() {
    use crate::oauth::provider::dpop_verify::{
        DpopVerifyRequest, MemoryJtiCache, verify_dpop_proof,
    };
    let k = key(0x66);
    let proof = generate_dpop_proof(
        &k,
        "POST",
        "https://as.example/token",
        Some("tok"),
        IAT,
        JTI,
    )
    .unwrap();
    let now = chrono::DateTime::from_timestamp(IAT, 0).unwrap();
    let verified = verify_dpop_proof(
        DpopVerifyRequest {
            proof_jwt: &proof.proof_jwt,
            htm: "POST",
            htu: "https://as.example/token",
            access_token: Some("tok"),
            max_iat_skew_secs: 60,
            jti_cache: &MemoryJtiCache::new(),
        },
        now,
    )
    .expect("verifies");
    assert_eq!(verified.thumbprint, k.thumbprint().unwrap());
}

/// RFC 9449 section 4.2: `htu` is the request URL without its query and
/// fragment, whichever caller made the proof, including a caller of the
/// public trait method who hands over the URL it is about to request.
#[test]
fn htu_drops_the_query_and_the_fragment() {
    let k = key(0x34);
    let proof = generate_dpop_proof(
        &k,
        "GET",
        "https://rs.example.com/resource?page=2&token=abc#top",
        None,
        IAT,
        JTI,
    )
    .unwrap();
    assert_eq!(
        decode_part(&proof.proof_jwt, 1)["htu"],
        "https://rs.example.com/resource"
    );
}
