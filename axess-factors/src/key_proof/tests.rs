use super::testing::SoftwareKey;
use super::*;
use serde_json::json;

const TARGET: ProofTarget<'static> = ProofTarget {
    method: "POST",
    url: "https://app.example/axess/device-key",
};
const CHALLENGE: &str = "challenge-0001";
const SHAPES: [KeyProofShape; 2] = [KeyProofShape::Browser, KeyProofShape::App];

fn key() -> SoftwareKey {
    SoftwareKey::from_seed([7; 32])
}

fn other_key() -> SoftwareKey {
    SoftwareKey::from_seed([8; 32])
}

fn request<'a>(jws: &'a str, shape: KeyProofShape, key: ProofKey<'a>) -> KeyProofRequest<'a> {
    KeyProofRequest {
        jws,
        shape,
        target: TARGET,
        challenge: CHALLENGE,
        key,
    }
}

/// A proof built from edited parts, verified as a registration.
fn verify_edited(
    shape: KeyProofShape,
    edit: impl FnOnce(&mut serde_json::Value, &mut serde_json::Value),
) -> Result<VerifiedKeyProof, KeyProofError> {
    let (mut header, mut claims) = key().proof_parts(shape, TARGET, CHALLENGE, true);
    edit(&mut header, &mut claims);
    let jws = key().sign_parts(&header, &claims);
    verify_key_proof(request(&jws, shape, ProofKey::Embedded))
}

#[test]
fn a_registration_proof_verifies_under_the_key_it_carries() {
    for shape in SHAPES {
        let jws = key().sign(shape, TARGET, CHALLENGE, true);
        let verified = verify_key_proof(request(&jws, shape, ProofKey::Embedded)).unwrap();
        assert_eq!(verified.key, key().public(), "{shape:?}");
        assert_eq!(verified.thumbprint, key().public().thumbprint());
    }
}

#[test]
fn a_later_proof_verifies_under_the_stored_key_and_needs_none_of_its_own() {
    let stored = key().public();
    for shape in SHAPES {
        let jws = key().sign(shape, TARGET, CHALLENGE, false);
        let verified = verify_key_proof(request(&jws, shape, ProofKey::Stored(&stored))).unwrap();
        assert_eq!(verified.key, stored);
        // Without a key of its own it cannot stand as a registration.
        assert_eq!(
            verify_key_proof(request(&jws, shape, ProofKey::Embedded)),
            Err(KeyProofError::Key)
        );
    }
}

/// The stored key decides. A proof signed by another key, and carrying that
/// key, is refused: the key in the proof is not read.
#[test]
fn the_stored_key_is_used_when_the_proof_carries_another() {
    let stored = key().public();
    for shape in SHAPES {
        let by_another = other_key().sign(shape, TARGET, CHALLENGE, true);
        assert_eq!(
            verify_key_proof(request(&by_another, shape, ProofKey::Embedded))
                .map(|verified| verified.key),
            Ok(other_key().public()),
            "the proof is a sound one for its own key"
        );
        assert_eq!(
            verify_key_proof(request(&by_another, shape, ProofKey::Stored(&stored))),
            Err(KeyProofError::Signature),
            "{shape:?}"
        );
    }
}

#[test]
fn each_structural_fault_is_refused_by_name() {
    for shape in SHAPES {
        let good = key().sign(shape, TARGET, CHALLENGE, true);
        let oversize = format!("{good}{}", "A".repeat(MAX_KEY_PROOF_BYTES));
        let cases: [(&str, String, KeyProofError); 6] = [
            ("oversize", oversize, KeyProofError::TooLarge),
            ("two segments", "a.b".to_string(), KeyProofError::Malformed),
            (
                "four segments",
                format!("{good}.x"),
                KeyProofError::Malformed,
            ),
            (
                "not base64url",
                "***.***.***".to_string(),
                KeyProofError::Malformed,
            ),
            (
                "a header that is not an object",
                format!("{}.e30.sig", URL_SAFE_NO_PAD.encode("[1]")),
                KeyProofError::Malformed,
            ),
            (
                "claims that are not JSON",
                format!(
                    "{}.{}.sig",
                    URL_SAFE_NO_PAD.encode("{}"),
                    URL_SAFE_NO_PAD.encode("x")
                ),
                KeyProofError::Malformed,
            ),
        ];
        for (what, jws, expected) in cases {
            assert_eq!(
                verify_key_proof(request(&jws, shape, ProofKey::Embedded)),
                Err(expected),
                "{shape:?}: {what}"
            );
        }
    }
}

/// The bounds are the documented ones: 8 KiB of proof, 256 bytes of `jti`.
#[test]
fn the_size_bounds_are_the_documented_ones() {
    assert_eq!(MAX_KEY_PROOF_BYTES, 8192);
    assert_eq!(MAX_REQUEST_JTI_BYTES, 256);
}

/// A proof of exactly the size bound is read; one byte more is not.
#[test]
fn the_size_bound_is_inclusive() {
    let at_bound = "a".repeat(MAX_KEY_PROOF_BYTES);
    assert_eq!(
        parse_key_proof(&at_bound, KeyProofShape::App).err(),
        Some(KeyProofError::Malformed)
    );
    let over = "a".repeat(MAX_KEY_PROOF_BYTES + 1);
    assert_eq!(
        parse_key_proof(&over, KeyProofShape::App).err(),
        Some(KeyProofError::TooLarge)
    );
}

#[test]
fn every_algorithm_but_es256_is_refused() {
    for shape in SHAPES {
        for alg in ["ES384", "EdDSA", "RS256", "PS256", "HS256", "none", "es256"] {
            assert_eq!(
                verify_edited(shape, |header, _| header["alg"] = json!(alg)),
                Err(KeyProofError::Algorithm),
                "{shape:?} {alg}"
            );
        }
        assert_eq!(
            verify_edited(shape, |header, _| {
                header.as_object_mut().unwrap().remove("alg");
            }),
            Err(KeyProofError::Algorithm)
        );
    }
}

/// Each shape has its own `typ`, so a proof made for one front-end is not a
/// proof for the other.
#[test]
fn the_typ_must_be_the_shapes_own() {
    for shape in SHAPES {
        for typ in ["JWT", "at+jwt", "DPOP+JWT", ""] {
            assert_eq!(
                verify_edited(shape, |header, _| header["typ"] = json!(typ)),
                Err(KeyProofError::Type),
                "{shape:?} {typ}"
            );
        }
    }
    let browser = key().sign(KeyProofShape::Browser, TARGET, CHALLENGE, true);
    assert_eq!(
        verify_key_proof(request(&browser, KeyProofShape::App, ProofKey::Embedded)),
        Err(KeyProofError::Type)
    );
    let app = key().sign(KeyProofShape::App, TARGET, CHALLENGE, true);
    assert_eq!(
        verify_key_proof(request(&app, KeyProofShape::Browser, ProofKey::Embedded)),
        Err(KeyProofError::Type)
    );
}

/// Where a registration's key sits in the header, as it does in the app
/// shape and, per the constants, in the browser shape.
fn key_member(shape: KeyProofShape) -> Option<&'static str> {
    match shape {
        KeyProofShape::App => Some("jwk"),
        KeyProofShape::Browser => match browser_draft::PROOF_KEY_PLACE {
            browser_draft::KeyPlace::Header => Some(browser_draft::PROOF_KEY_MEMBER),
            browser_draft::KeyPlace::Claims => None,
        },
    }
}

#[test]
fn a_key_that_is_not_a_p256_public_key_is_refused() {
    for shape in SHAPES {
        let Some(member) = key_member(shape) else {
            continue;
        };
        let edits: [(&str, serde_json::Value); 6] = [
            ("kty", json!("RSA")),
            ("crv", json!("P-384")),
            ("x", json!(URL_SAFE_NO_PAD.encode([1u8; 31]))),
            ("y", json!(7)),
            ("d", json!(URL_SAFE_NO_PAD.encode([1u8; 32]))),
            ("k", json!("AA")),
        ];
        for (field, value) in edits {
            assert_eq!(
                verify_edited(shape, |header, _| header[member][field] = value.clone()),
                Err(KeyProofError::Key),
                "{shape:?} {field}"
            );
        }
        assert_eq!(
            verify_edited(shape, |header, _| header[member] = json!("a string")),
            Err(KeyProofError::Key)
        );
    }
}

/// Two coordinates that are not a point of the curve are no key: a proof
/// that carries them is refused as a key fault where the key enters, and a
/// stored pair of that kind is refused as a key fault before any signature
/// is checked, under a challenge proof and under a request proof alike.
#[test]
fn a_point_off_the_curve_is_refused() {
    let off_curve = P256Key {
        x: [1; 32],
        y: [1; 32],
    };
    assert_eq!(
        P256Key::from_jwk(&off_curve.to_jwk()),
        Err(KeyProofError::Key)
    );
    assert_eq!(
        P256Key::from_jwk(&key().public().to_jwk()),
        Ok(key().public())
    );
    for shape in SHAPES {
        if let Some(member) = key_member(shape) {
            assert_eq!(
                verify_edited(shape, |header, _| header[member] = off_curve.to_jwk()),
                Err(KeyProofError::Key),
                "{shape:?}: embedded"
            );
        }
        let jws = key().sign(shape, TARGET, CHALLENGE, false);
        assert_eq!(
            verify_key_proof(request(&jws, shape, ProofKey::Stored(&off_curve))),
            Err(KeyProofError::Key),
            "{shape:?}: stored"
        );
    }
    let jws = key().sign_request(TARGET, 1_000, "j");
    assert_eq!(
        parse_key_proof(&jws, KeyProofShape::App)
            .unwrap()
            .verify_request(check(&off_curve, 1_000)),
        Err(KeyProofError::Key),
        "request proof: stored"
    );
}

/// A header that marks an extension critical is refused: none is understood.
#[test]
fn a_header_with_crit_is_refused() {
    for shape in SHAPES {
        for crit in [json!(["b64"]), json!([]), json!("exp")] {
            assert_eq!(
                verify_edited(shape, |header, _| header["crit"] = crit.clone()),
                Err(KeyProofError::Malformed),
                "{shape:?} {crit}"
            );
        }
    }
}

/// A revision of the draft that carries the endpoint in an audience claim
/// holds a browser proof to it; the constants name none today.
#[test]
fn an_audience_claim_must_name_the_endpoint_when_the_draft_has_one() {
    let claims = json!({ "aud": TARGET.url });
    let claim = |name: &str| claims.get(name).and_then(|v| v.as_str());
    assert!(audience_holds(Some("aud"), claim, TARGET.url));
    assert!(!audience_holds(
        Some("aud"),
        claim,
        "https://app.example/axess/device-key/refresh"
    ));
    assert!(!audience_holds(Some("endpoint"), claim, TARGET.url));
    assert!(audience_holds(None, claim, "https://elsewhere.example"));
}

#[test]
fn a_proof_for_another_request_is_refused() {
    let app = |edit: fn(&mut serde_json::Value)| {
        verify_edited(KeyProofShape::App, |_, claims| edit(claims))
    };
    assert_eq!(
        app(|claims| claims["htm"] = json!("GET")),
        Err(KeyProofError::Target)
    );
    assert_eq!(
        app(|claims| claims["htm"] = json!("post")),
        Err(KeyProofError::Target),
        "methods are compared exactly"
    );
    assert_eq!(
        app(|claims| claims["htu"] = json!("https://app.example/axess/device-key/refresh")),
        Err(KeyProofError::Target)
    );
    assert_eq!(
        app(|claims| {
            claims.as_object_mut().unwrap().remove("htu");
        }),
        Err(KeyProofError::Target)
    );
    if let Some(audience) = browser_draft::PROOF_AUDIENCE_CLAIM {
        assert_eq!(
            verify_edited(KeyProofShape::Browser, |_, claims| {
                claims[audience] = json!("https://other.example/")
            }),
            Err(KeyProofError::Target)
        );
    }
}

#[test]
fn a_proof_for_another_challenge_or_none_is_refused_before_its_signature() {
    for shape in SHAPES {
        let stale = key().sign(shape, TARGET, "challenge-0000", true);
        assert_eq!(
            verify_key_proof(request(&stale, shape, ProofKey::Embedded)),
            Err(KeyProofError::Challenge),
            "{shape:?}"
        );
        // The challenge is judged first: a proof for a stale challenge whose
        // signature is also wrong is still a challenge refusal.
        let damaged = format!("{}AAAA", &stale[..stale.len() - 4]);
        assert_eq!(
            verify_key_proof(request(&damaged, shape, ProofKey::Embedded)),
            Err(KeyProofError::Challenge)
        );
        let claim = match shape {
            KeyProofShape::Browser => browser_draft::PROOF_CHALLENGE_CLAIM,
            KeyProofShape::App => "nonce",
        };
        assert_eq!(
            verify_edited(shape, |_, claims| {
                claims.as_object_mut().unwrap().remove(claim);
            }),
            Err(KeyProofError::Challenge)
        );
        assert_eq!(
            verify_edited(shape, |_, claims| claims[claim] = json!(1)),
            Err(KeyProofError::Challenge)
        );
    }
}

#[test]
fn an_altered_payload_or_signature_fails_the_signature_check() {
    for shape in SHAPES {
        let good = key().sign(shape, TARGET, CHALLENGE, true);
        let parts: Vec<&str> = good.split('.').collect();

        // The claims re-encoded with one more member, the signature kept.
        let mut claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        claims["extra"] = json!(true);
        let altered = format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(claims.to_string()),
            parts[2]
        );
        assert_eq!(
            verify_key_proof(request(&altered, shape, ProofKey::Embedded)),
            Err(KeyProofError::Signature),
            "{shape:?}"
        );

        // A signature by another key over the same input.
        let forged = format!(
            "{}.{}.{}",
            parts[0],
            parts[1],
            other_key().sign_bytes(format!("{}.{}", parts[0], parts[1]).as_bytes())
        );
        assert_eq!(
            verify_key_proof(request(&forged, shape, ProofKey::Embedded)),
            Err(KeyProofError::Signature)
        );

        // A signature that is not base64url at all.
        let garbage = format!("{}.{}.***", parts[0], parts[1]);
        assert_eq!(
            verify_key_proof(request(&garbage, shape, ProofKey::Embedded)),
            Err(KeyProofError::Signature)
        );
    }
}

/// The two-step form lets a caller verify the signature first and judge the
/// challenge afterwards, which is the order a refresh token's proof needs.
#[test]
fn the_two_steps_report_the_challenge_and_the_signature_apart() {
    let stored = key().public();
    for shape in SHAPES {
        let jws = key().sign(shape, TARGET, "challenge-0000", false);
        let parsed = parse_key_proof(&jws, shape).unwrap();
        assert_eq!(parsed.challenge(), Some("challenge-0000"));
        assert!(parsed.answers("challenge-0000"));
        assert!(!parsed.answers(CHALLENGE));
        assert!(!parsed.answers(""));
        assert!(parsed.verify(TARGET, ProofKey::Stored(&stored)).is_ok());
        assert_eq!(
            parsed.verify(TARGET, ProofKey::Stored(&other_key().public())),
            Err(KeyProofError::Signature)
        );
    }
}

#[test]
fn a_seed_names_one_key_and_the_public_key_round_trips_as_a_jwk() {
    assert_eq!(key().public(), key().public());
    assert_ne!(key().public(), other_key().public());
    let public = key().public();
    assert_eq!(P256Key::from_jwk(&public.to_jwk()), Ok(public));
    // A seed that is no valid scalar still yields a key.
    assert_ne!(SoftwareKey::from_seed([0; 32]).public(), public);
    assert_ne!(SoftwareKey::from_seed([0xff; 32]).public(), public);
}

/// The thumbprint is the one the DPoP verifier reports for the same key, so
/// a key has one name whichever verifier saw it.
#[test]
fn the_thumbprint_is_the_rfc_7638_one() {
    let public = key().public();
    let canonical = format!(
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
        URL_SAFE_NO_PAD.encode(public.x),
        URL_SAFE_NO_PAD.encode(public.y)
    );
    let expected: [u8; 32] = {
        use sha2::Digest as _;
        sha2::Sha256::digest(canonical.as_bytes()).into()
    };
    assert_eq!(public.thumbprint(), expected);
}

/// No sender text reaches a refusal: the errors are fixed strings.
#[test]
fn no_refusal_carries_the_senders_text() {
    let all = [
        KeyProofError::TooLarge,
        KeyProofError::Malformed,
        KeyProofError::Algorithm,
        KeyProofError::Type,
        KeyProofError::Key,
        KeyProofError::Target,
        KeyProofError::Challenge,
        KeyProofError::Signature,
        KeyProofError::Time,
        KeyProofError::Identifier,
    ];
    let texts: std::collections::HashSet<String> = all.iter().map(ToString::to_string).collect();
    assert_eq!(texts.len(), all.len(), "each refusal reads differently");
}

fn check<'a>(key: &'a P256Key, now_unix: i64) -> RequestProofCheck<'a> {
    RequestProofCheck {
        target: TARGET,
        now_unix,
        max_age: std::time::Duration::from_secs(60),
        max_ahead: std::time::Duration::from_secs(5),
        key: ProofKey::Stored(key),
    }
}

fn verify_request(jws: &str, now_unix: i64) -> Result<VerifiedRequestProof, KeyProofError> {
    let stored = key().public();
    parse_key_proof(jws, KeyProofShape::App)?.verify_request(check(&stored, now_unix))
}

#[test]
fn a_request_proof_verifies_and_hands_back_its_jti() {
    let jws = key().sign_request(TARGET, 1_000, "jti-1");
    let verified = verify_request(&jws, 1_000).unwrap();
    assert_eq!(verified.jti, "jti-1");
    assert_eq!(verified.iat, 1_000);
    assert_eq!(verified.thumbprint, key().public().thumbprint());
}

/// The `iat` may lie its lifetime before now and the clock allowance after
/// it, both bounds included, and no further either way.
#[test]
fn a_request_proofs_iat_window_is_inclusive() {
    let jws = key().sign_request(TARGET, 1_000, "jti-1");
    for now in [995, 1_000, 1_060] {
        assert!(verify_request(&jws, now).is_ok(), "{now}");
    }
    for now in [994, 1_061, i64::MIN, i64::MAX] {
        assert_eq!(verify_request(&jws, now), Err(KeyProofError::Time), "{now}");
    }
}

#[test]
fn a_request_proof_is_refused_for_each_fault() {
    let other = ProofTarget {
        method: "GET",
        url: TARGET.url,
    };
    assert_eq!(
        verify_request(&key().sign_request(other, 1_000, "j"), 1_000),
        Err(KeyProofError::Target)
    );
    assert_eq!(
        verify_request(&key().sign_request(TARGET, 1_000, ""), 1_000),
        Err(KeyProofError::Identifier)
    );
    let long = "j".repeat(MAX_REQUEST_JTI_BYTES + 1);
    assert_eq!(
        verify_request(&key().sign_request(TARGET, 1_000, &long), 1_000),
        Err(KeyProofError::Identifier)
    );
    let at_bound = "j".repeat(MAX_REQUEST_JTI_BYTES);
    assert!(verify_request(&key().sign_request(TARGET, 1_000, &at_bound), 1_000).is_ok());
    assert_eq!(
        verify_request(&other_key().sign_request(TARGET, 1_000, "j"), 1_000),
        Err(KeyProofError::Signature)
    );
    // No `iat`: a challenge proof is no request proof.
    let challenge_proof = key().sign(KeyProofShape::App, TARGET, CHALLENGE, false);
    assert_eq!(
        verify_request(&challenge_proof, 1_000),
        Err(KeyProofError::Time)
    );
    // The browser shape never rides on a request.
    let browser = key().sign(KeyProofShape::Browser, TARGET, CHALLENGE, false);
    let stored = key().public();
    assert_eq!(
        parse_key_proof(&browser, KeyProofShape::Browser)
            .unwrap()
            .verify_request(check(&stored, 1_000)),
        Err(KeyProofError::Type)
    );
}

/// Under the key it carries, a request proof shows that its sender holds
/// that key and nothing about whose key it is: the answer names the key, for
/// the caller to compare with the one it holds for the device. A proof that
/// carries no key, or one that is no key, is a key fault, and a signature
/// that is not the carried key's is refused.
#[test]
fn a_request_proof_verifies_under_the_key_it_carries_and_names_it() {
    let embedded = RequestProofCheck {
        target: TARGET,
        now_unix: 1_000,
        max_age: std::time::Duration::from_secs(60),
        max_ahead: std::time::Duration::from_secs(5),
        key: ProofKey::Embedded,
    };
    let verify = |jws: &str| {
        parse_key_proof(jws, KeyProofShape::App)
            .unwrap()
            .verify_request(embedded)
    };
    for signer in [key(), other_key()] {
        let verified = verify(&signer.sign_request(TARGET, 1_000, "j")).unwrap();
        assert_eq!(verified.key, signer.public());
        assert_eq!(verified.thumbprint, signer.public().thumbprint());
    }
    // No key in the header: the challenge shape's proof without one.
    let (mut header, mut claims) = key().proof_parts(KeyProofShape::App, TARGET, CHALLENGE, false);
    claims["iat"] = json!(1_000);
    claims["jti"] = json!("j");
    assert_eq!(
        verify(&key().sign_parts(&header, &claims)).map(|v| v.jti),
        Err(KeyProofError::Key)
    );
    // Another key's public half over this key's signature.
    header["jwk"] = other_key().public().to_jwk();
    assert_eq!(
        verify(&key().sign_parts(&header, &claims)).map(|v| v.jti),
        Err(KeyProofError::Signature)
    );
}
