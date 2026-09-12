//! `jwt_validation_tests`: extracted from `validation.rs` per the
//! 200-LoC inline-test rule in AGENTS.md.

use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{EncodingKey, Header, encode};
use rsa::RsaPrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;

/// Generate an RSA-2048 key pair and return (private DER, JwkSet with one key, kid).
fn rsa_keypair() -> (Vec<u8>, JwkSet, String) {
    let mut rng = rsa::rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("key generation");
    let public_key = private_key.to_public_key();
    let kid = "test-key-1".to_string();

    let private_der = private_key
        .to_pkcs1_der()
        .expect("PKCS1 DER encode")
        .as_bytes()
        .to_vec();

    let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

    let jwk_json = serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": n,
            "e": e,
        }]
    });
    let jwks: JwkSet = serde_json::from_value(jwk_json).expect("JwkSet parse");

    (private_der, jwks, kid)
}

/// Sign a JWT with the given claims, kid, and algorithm.
fn sign_jwt(claims: &serde_json::Value, kid: &str, private_der: &[u8]) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let key = EncodingKey::from_rsa_der(private_der);
    encode(&header, claims, &key).expect("JWT encode")
}

fn sample_claims() -> serde_json::Value {
    let now = chrono::Utc::now().timestamp();
    serde_json::json!({
        "iss": "https://idp.example.com",
        "sub": "user-42",
        "aud": "my-client",
        "exp": now + 3600,
        "iat": now,
    })
}

// ── Happy path ─────────────────────────────────────────────────────

/// Valid RS256 JWT against its own JWKS verifies successfully.
#[test]
fn valid_rs256_jwt_verifies() {
    let (der, jwks, kid) = rsa_keypair();
    let token = sign_jwt(&sample_claims(), &kid, &der);

    let result = verify_jwt_signature(&token, &jwks, Some("my-client"), ALLOWED_ALGORITHMS);
    assert!(result.is_ok(), "valid JWT must verify: {result:?}");

    let claims = result.unwrap();
    assert_eq!(claims["sub"], "user-42");
}

/// Pin the strict-greater boundary `now > exp + leeway` on line
/// 285. At `now == exp + leeway` (the inclusive expiry boundary)
/// the token must STILL be accepted. Kills `> → >=` which would
/// reject tokens at the boundary and cut every token's usable
/// lifetime short by `1` second.
#[test]
fn verify_jwt_accepts_at_exact_exp_plus_leeway_boundary() {
    use axess_clock::testing::MockClock;
    use chrono::{TimeZone, Utc};
    let (der, jwks, kid) = rsa_keypair();
    // Token expires at t=1_000_000_100; leeway = 60; clock at
    // exp + leeway = 1_000_000_160.
    let exp = 1_000_000_100i64;
    let leeway: u64 = 60;
    let now = exp + leeway as i64;
    let claims = serde_json::json!({ "iss": "x", "sub": "u", "exp": exp });
    let token = sign_jwt(&claims, &kid, &der);
    let clock = MockClock::at(Utc.timestamp_opt(now, 0).single().unwrap());
    let cfg = ValidationConfig {
        audience: None,
        leeway_secs: leeway,
        ..ValidationConfig::default()
    };
    let result = verify_jwt(&token, &jwks, &cfg, ALLOWED_ALGORITHMS, &clock);
    assert!(
        result.is_ok(),
        "token at exact exp+leeway boundary must verify (kills `> → >=` on line 285): {result:?}"
    );

    // And one second past must reject; confirms the boundary is at
    // the right value, not shifted.
    let clock_after = MockClock::at(Utc.timestamp_opt(now + 1, 0).single().unwrap());
    let result_after = verify_jwt(&token, &jwks, &cfg, ALLOWED_ALGORITHMS, &clock_after);
    assert!(
        matches!(result_after, Err(JwtError::VerificationFailed(_))),
        "token one second past exp+leeway must reject: {result_after:?}"
    );
}

/// Pin the strict-less boundary `now < nbf - leeway` on line 291
/// at `now == nbf - leeway` the token must STILL be accepted
/// (it just became valid). Kills `< → <=` which would reject
/// tokens at the boundary, opening a 1-second blackout right at
/// validity start.
#[test]
fn verify_jwt_accepts_at_exact_nbf_minus_leeway_boundary() {
    use axess_clock::testing::MockClock;
    use chrono::{TimeZone, Utc};
    let (der, jwks, kid) = rsa_keypair();
    // Token nbf = 1_000_000_500; leeway = 60; clock at
    // nbf - leeway = 1_000_000_440 (exactly the boundary).
    let nbf = 1_000_000_500i64;
    let leeway: u64 = 60;
    let now = nbf - leeway as i64;
    // Add a far-future exp so the exp check passes unconditionally.
    let claims = serde_json::json!({
        "iss": "x",
        "sub": "u",
        "nbf": nbf,
        "exp": nbf + 3600,
    });
    let token = sign_jwt(&claims, &kid, &der);
    let clock = MockClock::at(Utc.timestamp_opt(now, 0).single().unwrap());
    let cfg = ValidationConfig {
        audience: None,
        leeway_secs: leeway,
        ..ValidationConfig::default()
    };
    let result = verify_jwt(&token, &jwks, &cfg, ALLOWED_ALGORITHMS, &clock);
    assert!(
        result.is_ok(),
        "token at exact nbf-leeway boundary must verify (kills `< → <=` on line 291): {result:?}"
    );

    // And one second before must reject.
    let clock_before = MockClock::at(Utc.timestamp_opt(now - 1, 0).single().unwrap());
    let result_before = verify_jwt(&token, &jwks, &cfg, ALLOWED_ALGORITHMS, &clock_before);
    assert!(
        matches!(result_before, Err(JwtError::VerificationFailed(_))),
        "token one second before nbf-leeway must reject: {result_before:?}"
    );
}

/// Audience validation disabled when `expected_audience` is None.
#[test]
fn audience_none_skips_aud_check() {
    let (der, jwks, kid) = rsa_keypair();
    let token = sign_jwt(&sample_claims(), &kid, &der);

    let result = verify_jwt_signature(&token, &jwks, None, ALLOWED_ALGORITHMS);
    assert!(
        result.is_ok(),
        "audience=None must skip aud check: {result:?}"
    );
}

// ── Algorithm allowlist ────────────────────────────────────────────

/// HS256 (symmetric) is rejected even if the token is otherwise valid.
/// Pins the allowlist check against removal; without it a crafted HS256
/// token could bypass asymmetric verification.
#[test]
fn disallowed_algorithm_rejected() {
    let (der, jwks, kid) = rsa_keypair();
    // Sign with RS256 but restrict allowlist to ES256 only
    let token = sign_jwt(&sample_claims(), &kid, &der);

    let result = verify_jwt_signature(&token, &jwks, None, &[Algorithm::ES256]);
    assert!(
        matches!(result, Err(JwtError::DisallowedAlgorithm(Algorithm::RS256))),
        "RS256 not in allowlist must be rejected: {result:?}"
    );
}

/// `ALLOWED_ALGORITHMS` contains exactly the expected asymmetric set.
/// Pins against accidental inclusion of HS* or `none`.
#[test]
fn allowed_algorithms_are_asymmetric_only() {
    for alg in ALLOWED_ALGORITHMS {
        let name = format!("{alg:?}");
        assert!(
            !name.starts_with("HS"),
            "symmetric algorithm {name} must not be in ALLOWED_ALGORITHMS"
        );
    }
    assert!(
        ALLOWED_ALGORITHMS.contains(&Algorithm::RS256),
        "RS256 must be allowed"
    );
    assert!(
        ALLOWED_ALGORITHMS.contains(&Algorithm::ES256),
        "ES256 must be allowed"
    );
}

// ── KID handling ───────────────────────────────────────────────────

/// JWT with no `kid` header is rejected. Pins the MissingKid branch.
#[test]
fn missing_kid_rejected() {
    let (der, jwks, _) = rsa_keypair();
    // Sign without kid
    let mut header = Header::new(Algorithm::RS256);
    header.kid = None;
    let key = EncodingKey::from_rsa_der(&der);
    let token = encode(&header, &sample_claims(), &key).expect("encode");

    let result = verify_jwt_signature(&token, &jwks, None, ALLOWED_ALGORITHMS);
    assert!(
        matches!(result, Err(JwtError::MissingKid)),
        "missing kid must be rejected: {result:?}"
    );
}

/// JWT with unknown `kid` is rejected. Pins the UnknownKid branch.
#[test]
fn unknown_kid_rejected() {
    let (der, jwks, _) = rsa_keypair();
    let token = sign_jwt(&sample_claims(), "nonexistent-kid", &der);

    let result = verify_jwt_signature(&token, &jwks, None, ALLOWED_ALGORITHMS);
    assert!(
        matches!(result, Err(JwtError::UnknownKid(ref k)) if k == "nonexistent-kid"),
        "unknown kid must be rejected: {result:?}"
    );
}

// ── Algorithm mismatch ─────────────────────────────────────────────

/// JWK declares `alg: RS256` but JWT header says RS384 → rejected.
/// Prevents key confusion attacks across a rotating JWKS with mixed key types.
#[test]
fn algorithm_mismatch_rejected() {
    let (der, jwks, kid) = rsa_keypair();
    // Sign with RS384 but JWK declares RS256
    let mut header = Header::new(Algorithm::RS384);
    header.kid = Some(kid);
    let key = EncodingKey::from_rsa_der(&der);
    let token = encode(&header, &sample_claims(), &key).expect("encode");

    let result = verify_jwt_signature(&token, &jwks, None, ALLOWED_ALGORITHMS);
    assert!(
        matches!(result, Err(JwtError::AlgorithmMismatch { .. })),
        "alg mismatch must be rejected: {result:?}"
    );
}

// ── Audience mismatch ──────────────────────────────────────────────

/// Wrong audience is rejected by jsonwebtoken's aud validation.
#[test]
fn wrong_audience_rejected() {
    let (der, jwks, kid) = rsa_keypair();
    let token = sign_jwt(&sample_claims(), &kid, &der);

    let result = verify_jwt_signature(&token, &jwks, Some("wrong-client"), ALLOWED_ALGORITHMS);
    assert!(
        matches!(result, Err(JwtError::VerificationFailed(_))),
        "wrong audience must be rejected: {result:?}"
    );
}

// ── Malformed input ────────────────────────────────────────────────

/// Completely garbage input is rejected at the header decode stage.
#[test]
fn garbage_input_rejected() {
    let jwks = JwkSet { keys: vec![] };
    let result = verify_jwt_signature("not-a-jwt", &jwks, None, ALLOWED_ALGORITHMS);
    assert!(
        matches!(result, Err(JwtError::InvalidHeader(_))),
        "garbage input must fail at header decode: {result:?}"
    );
}

/// Expired JWT is rejected (jsonwebtoken validates `exp` by default).
#[test]
fn expired_jwt_rejected() {
    let (der, jwks, kid) = rsa_keypair();
    let mut claims = sample_claims();
    claims["exp"] = serde_json::json!(0); // epoch = long expired
    let token = sign_jwt(&claims, &kid, &der);

    let result = verify_jwt_signature(&token, &jwks, None, ALLOWED_ALGORITHMS);
    assert!(
        matches!(result, Err(JwtError::VerificationFailed(_))),
        "expired JWT must be rejected: {result:?}"
    );
}

// ── Signature tampering ────────────────────────────────────────────

/// Tampered signature is rejected. Flips a byte in the signature
/// segment to simulate an attacker modifying claims after signing.
#[test]
fn tampered_signature_rejected() {
    let (der, jwks, kid) = rsa_keypair();
    let token = sign_jwt(&sample_claims(), &kid, &der);

    // Flip a byte in the signature (last segment)
    let parts: Vec<&str> = token.split('.').collect();
    let mut sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).expect("b64 decode sig");
    sig_bytes[0] ^= 0xFF;
    let tampered_sig = URL_SAFE_NO_PAD.encode(&sig_bytes);
    let tampered = format!("{}.{}.{}", parts[0], parts[1], tampered_sig);

    let result = verify_jwt_signature(&tampered, &jwks, None, ALLOWED_ALGORITHMS);
    assert!(
        matches!(result, Err(JwtError::VerificationFailed(_))),
        "tampered signature must be rejected: {result:?}"
    );
}
