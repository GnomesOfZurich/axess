use super::*;
use axess_factors::jwt::verifier::JwtVerifier;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CustomClaims {}

fn one_hour_from_now() -> DateTime<Utc> {
    Utc::now() + Duration::hours(1)
}

// ── ES256 (P-256) key support ────────────────────────────────────────

fn fresh_es256_pkcs8_pem() -> String {
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::pkcs8::EncodePrivateKey;
    let secret = p256::SecretKey::random(&mut OsRng);
    secret
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .expect("PKCS#8 PEM encode")
        .to_string()
}

#[tokio::test]
async fn es256_mint_roundtrips_through_jwt_verifier() {
    let key = LocalIdpSigningKey::generate_es256();
    let idp = LocalIdpFixture::with_signing_key("https://test.idp.local", key);
    let claims = MintClaims::new("alice", one_hour_from_now())
        .with_audience("https://api.example.com")
        .with_issued_at(Utc::now());

    let token = idp.mint(&claims);
    let verifier = JwtVerifier::new(idp.jwks_handle())
        .with_issuer("https://test.idp.local")
        .with_audience("https://api.example.com")
        .with_algorithms([Algorithm::ES256]);
    let verified = verifier
        .verify::<CustomClaims>(&token)
        .await
        .expect("ES256 mint must verify");
    assert_eq!(verified.sub.as_deref(), Some("alice"));
    assert_eq!(verified.iss.as_deref(), Some("https://test.idp.local"));
}

#[test]
fn es256_jwk_shape_is_ec_p256() {
    let key = LocalIdpSigningKey::generate_es256();
    let jwk_json = serde_json::to_value(key.jwk()).expect("JWK serialise");
    assert_eq!(jwk_json["kty"], "EC");
    assert_eq!(jwk_json["crv"], "P-256");
    assert_eq!(jwk_json["alg"], "ES256");
    assert!(jwk_json["x"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(jwk_json["y"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(jwk_json.get("n").is_none(), "EC JWK must not carry n");
}

#[tokio::test]
async fn es256_from_pem_roundtrips() {
    let pem = fresh_es256_pkcs8_pem();
    let key1 =
        LocalIdpSigningKey::from_ec_pem(&pem, "stable", Algorithm::ES256).expect("PEM parses");
    let key2 =
        LocalIdpSigningKey::from_ec_pem(&pem, "stable", Algorithm::ES256).expect("PEM parses");
    assert_eq!(
        key1.jwk().common.key_id,
        key2.jwk().common.key_id,
        "same PEM yields same kid"
    );
    let idp = LocalIdpFixture::with_signing_key("https://idp", key1);
    let claims = MintClaims::new("alice", one_hour_from_now())
        .with_audience("https://api")
        .with_issued_at(Utc::now());
    let token = idp.mint(&claims);
    let verifier = JwtVerifier::new(idp.jwks_handle())
        .with_audience("https://api")
        .with_algorithms([Algorithm::ES256]);
    verifier
        .verify::<CustomClaims>(&token)
        .await
        .expect("PEM-loaded ES256 mint must verify");
}

#[test]
fn es256_from_pkcs8_der_roundtrip() {
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::pkcs8::EncodePrivateKey;
    let secret = p256::SecretKey::random(&mut OsRng);
    let der = secret.to_pkcs8_der().expect("PKCS#8 DER");
    let key = LocalIdpSigningKey::from_ec_pkcs8_der(der.as_bytes(), "der-kid", Algorithm::ES256)
        .expect("PKCS#8 DER parses");
    assert_eq!(key.key_id(), "der-kid");
    assert_eq!(key.algorithm(), Algorithm::ES256);
}

#[test]
fn es256_from_sec1_der_roundtrip() {
    use p256::SecretKey;
    use p256::elliptic_curve::rand_core::OsRng;
    let secret = SecretKey::random(&mut OsRng);
    let der = secret.to_sec1_der().expect("SEC1 DER");
    let key = LocalIdpSigningKey::from_ec_sec1_der(&der, "sec1-kid", Algorithm::ES256)
        .expect("SEC1 DER parses");
    assert_eq!(key.key_id(), "sec1-kid");
}

#[tokio::test]
async fn es256_from_sec1_pem_roundtrips() {
    use p256::SecretKey;
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::pkcs8::LineEnding;
    let secret = SecretKey::random(&mut OsRng);
    let pem = secret
        .to_sec1_pem(LineEnding::LF)
        .expect("SEC1 PEM encode")
        .to_string();
    assert!(
        pem.starts_with("-----BEGIN EC PRIVATE KEY-----"),
        "SEC1 header is what `from_ec_pem` auto-detects"
    );
    let key = LocalIdpSigningKey::from_ec_pem(&pem, "sec1-pem-kid", Algorithm::ES256)
        .expect("SEC1 PEM parses");
    assert_eq!(key.key_id(), "sec1-pem-kid");

    let idp = LocalIdpFixture::with_signing_key("https://idp", key);
    let claims = MintClaims::new("alice", one_hour_from_now())
        .with_audience("https://api")
        .with_issued_at(Utc::now());
    let token = idp.mint(&claims);
    let verifier = JwtVerifier::new(idp.jwks_handle())
        .with_audience("https://api")
        .with_algorithms([Algorithm::ES256]);
    verifier
        .verify::<CustomClaims>(&token)
        .await
        .expect("SEC1-PEM-loaded ES256 mint must verify");
}

#[test]
#[should_panic(expected = "EC constructors only support")]
fn signing_key_rejects_non_es256_algorithm_at_ec_pem_load() {
    let pem = fresh_es256_pkcs8_pem();
    let _ = LocalIdpSigningKey::from_ec_pem(&pem, "kid", Algorithm::RS256);
}

#[test]
fn es256_debug_redacts_private_material() {
    let key = LocalIdpSigningKey::generate_es256();
    let debug = format!("{key:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("BEGIN"));
}

#[tokio::test]
async fn rsa_and_es256_keys_coexist_in_same_jwks() {
    let rsa_key = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-kid");
    let ec_key = LocalIdpSigningKey::generate_es256().with_key_id("ec-kid");
    let idp = LocalIdpFixture::with_signing_key("https://idp", rsa_key)
        .with_extra_public_jwk(ec_key.jwk().clone());

    let jwks = idp.jwks();
    assert_eq!(jwks.keys.len(), 2);
    let kids: Vec<_> = jwks
        .keys
        .iter()
        .filter_map(|k| k.common.key_id.as_deref())
        .collect();
    assert!(kids.contains(&"rsa-kid"));
    assert!(kids.contains(&"ec-kid"));
}

#[tokio::test]
async fn es256_rotate_to_es256_preserves_grace_window() {
    let now = Utc::now();
    let k1 = LocalIdpSigningKey::generate_es256().with_key_id("ec-1");
    let k2 = LocalIdpSigningKey::generate_es256().with_key_id("ec-2");

    let idp = LocalIdpFixture::with_signing_key("https://idp", k1);
    let token_pre = idp.mint(
        &MintClaims::new("alice", now + Duration::hours(1))
            .with_audience("https://api")
            .with_issued_at(now),
    );

    let rotated = idp.rotate_signing_key(k2);
    let token_post = rotated.mint(
        &MintClaims::new("alice", now + Duration::hours(1))
            .with_audience("https://api")
            .with_issued_at(now),
    );

    let verifier = JwtVerifier::new(rotated.jwks_handle())
        .with_audience("https://api")
        .with_algorithms([Algorithm::ES256]);
    verifier
        .verify::<CustomClaims>(&token_pre)
        .await
        .expect("pre-rotation ES256 still verifies");
    verifier
        .verify::<CustomClaims>(&token_post)
        .await
        .expect("post-rotation ES256 verifies");
}

#[tokio::test]
async fn es256_rotate_from_rsa_to_ec() {
    let now = Utc::now();
    let rsa = LocalIdpSigningKey::generate_rsa().with_key_id("rsa");
    let ec = LocalIdpSigningKey::generate_es256().with_key_id("ec");

    let idp = LocalIdpFixture::with_signing_key("https://idp", rsa);
    let token_rsa = idp.mint(
        &MintClaims::new("alice", now + Duration::hours(1))
            .with_audience("https://api")
            .with_issued_at(now),
    );

    let rotated = idp.rotate_signing_key(ec);
    let token_ec = rotated.mint(
        &MintClaims::new("alice", now + Duration::hours(1))
            .with_audience("https://api")
            .with_issued_at(now),
    );

    let verifier = JwtVerifier::new(rotated.jwks_handle())
        .with_audience("https://api")
        .with_algorithms([Algorithm::RS256, Algorithm::ES256]);
    verifier
        .verify::<CustomClaims>(&token_rsa)
        .await
        .expect("pre-rotation RSA still verifies");
    verifier
        .verify::<CustomClaims>(&token_ec)
        .await
        .expect("post-rotation ES256 verifies");
}

#[test]
fn es256_with_key_id_updates_jwk_kid() {
    let key = LocalIdpSigningKey::generate_es256().with_key_id("renamed-ec");
    assert_eq!(key.key_id(), "renamed-ec");
    assert_eq!(key.jwk().common.key_id.as_deref(), Some("renamed-ec"));
}

#[test]
fn with_algorithm_dispatches_es256_to_ec_keygen() {
    let idp = LocalIdpFixture::with_algorithm("https://idp", Algorithm::ES256);
    assert_eq!(idp.algorithm(), Algorithm::ES256);
    let jwk_json = serde_json::to_value(idp.signing_key().jwk()).expect("JWK serialise");
    assert_eq!(jwk_json["kty"], "EC");
    assert_eq!(jwk_json["crv"], "P-256");
}

#[test]
fn with_algorithm_dispatches_rsa_family_to_rsa_keygen() {
    for alg in [Algorithm::RS256, Algorithm::RS384, Algorithm::RS512] {
        let idp = LocalIdpFixture::with_algorithm("https://idp", alg);
        assert_eq!(idp.algorithm(), alg);
        let jwk_json = serde_json::to_value(idp.signing_key().jwk()).expect("JWK serialise");
        assert_eq!(jwk_json["kty"], "RSA");
    }
}
