use super::*;
use axess_factors::jwt::verifier::JwtVerifier;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CustomClaims {}

fn one_hour_from_now() -> DateTime<Utc> {
    Utc::now() + Duration::hours(1)
}

/// Helper to PEM-encode a fresh RSA private key for the
/// adopter-supplied-PEM tests.
fn fresh_rsa_pkcs1_pem() -> String {
    use rsa::pkcs1::EncodeRsaPrivateKey;
    let mut rng = rsa::rand_core::OsRng;
    let key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA gen");
    key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
        .expect("PKCS#1 PEM encode")
        .to_string()
}

fn fresh_rsa_pkcs8_pem() -> String {
    use rsa::pkcs8::EncodePrivateKey;
    let mut rng = rsa::rand_core::OsRng;
    let key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA gen");
    key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .expect("PKCS#8 PEM encode")
        .to_string()
}

#[tokio::test]
async fn from_rsa_pem_pkcs1_round_trips_through_verifier() {
    let pem = fresh_rsa_pkcs1_pem();
    let signing_key = LocalIdpSigningKey::from_rsa_pem(&pem, "stable-kid", Algorithm::RS256)
        .expect("PKCS#1 PEM parse");
    let idp = LocalIdpFixture::with_signing_key("https://test.idp.local", signing_key);
    let token = idp.mint(
        &MintClaims::new("alice", one_hour_from_now())
            .with_audience("https://api.example.com")
            .with_issued_at(Utc::now()),
    );
    let verifier = JwtVerifier::new(idp.jwks_handle()).with_audience("https://api.example.com");
    verifier
        .verify::<CustomClaims>(&token)
        .await
        .expect("verify with adopter-supplied PKCS#1 PEM");
    assert_eq!(idp.key_id(), "stable-kid");
}

#[tokio::test]
async fn from_rsa_pem_pkcs8_round_trips_through_verifier() {
    let pem = fresh_rsa_pkcs8_pem();
    let signing_key = LocalIdpSigningKey::from_rsa_pem(&pem, "pkcs8-kid", Algorithm::RS256)
        .expect("PKCS#8 PEM parse");
    let idp = LocalIdpFixture::with_signing_key("https://test.idp.local", signing_key);
    let token = idp.mint(
        &MintClaims::new("alice", one_hour_from_now())
            .with_audience("https://api.example.com")
            .with_issued_at(Utc::now()),
    );
    let verifier = JwtVerifier::new(idp.jwks_handle()).with_audience("https://api.example.com");
    verifier
        .verify::<CustomClaims>(&token)
        .await
        .expect("verify with adopter-supplied PKCS#8 PEM");
    assert_eq!(idp.key_id(), "pkcs8-kid");
}

#[test]
fn from_rsa_pem_malformed_returns_error() {
    let err = LocalIdpSigningKey::from_rsa_pem("not a pem", "kid", Algorithm::RS256).unwrap_err();
    assert!(
        matches!(err, LocalIdpKeyError::PemParse(_)),
        "expected PemParse, got {err:?}"
    );
}

#[tokio::test]
async fn from_rsa_pkcs1_der_round_trips() {
    use rsa::pkcs1::EncodeRsaPrivateKey;
    let mut rng = rsa::rand_core::OsRng;
    let key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("gen");
    let der = key.to_pkcs1_der().expect("DER").as_bytes().to_vec();
    let signing_key = LocalIdpSigningKey::from_rsa_pkcs1_der(&der, "der-kid", Algorithm::RS256)
        .expect("DER parse");
    let idp = LocalIdpFixture::with_signing_key("https://test.idp.local", signing_key);
    let token = idp.mint(
        &MintClaims::new("alice", one_hour_from_now())
            .with_audience("https://api.example.com")
            .with_issued_at(Utc::now()),
    );
    let verifier = JwtVerifier::new(idp.jwks_handle()).with_audience("https://api.example.com");
    verifier
        .verify::<CustomClaims>(&token)
        .await
        .expect("verify with PKCS#1 DER key");
}

#[test]
fn from_rsa_pkcs1_der_malformed_returns_error() {
    let err =
        LocalIdpSigningKey::from_rsa_pkcs1_der(&[0u8; 32], "kid", Algorithm::RS256).unwrap_err();
    assert!(matches!(err, LocalIdpKeyError::DerParse(_)));
}

/// Same PEM loaded twice produces fixtures that can verify each
/// other's tokens; confirms PEM parsing is deterministic and the
/// key really is shared.
#[tokio::test]
async fn same_pem_loaded_twice_produces_interchangeable_fixtures() {
    let pem = fresh_rsa_pkcs1_pem();
    let key1 = LocalIdpSigningKey::from_rsa_pem(&pem, "kid", Algorithm::RS256).unwrap();
    let key2 = LocalIdpSigningKey::from_rsa_pem(&pem, "kid", Algorithm::RS256).unwrap();
    let idp1 = LocalIdpFixture::with_signing_key("https://test.idp.local", key1);
    let idp2 = LocalIdpFixture::with_signing_key("https://test.idp.local", key2);

    let token = idp1.mint(
        &MintClaims::new("alice", one_hour_from_now())
            .with_audience("https://api.example.com")
            .with_issued_at(Utc::now()),
    );
    // Verify using idp2's JWKS handle; they should be interchangeable.
    let verifier = JwtVerifier::new(idp2.jwks_handle()).with_audience("https://api.example.com");
    verifier
        .verify::<CustomClaims>(&token)
        .await
        .expect("interchangeable fixtures");
}

#[test]
fn signing_key_with_key_id_updates_jwk_kid() {
    let key = LocalIdpSigningKey::generate_rsa().with_key_id("renamed");
    assert_eq!(key.key_id(), "renamed");
    assert_eq!(key.jwk().common.key_id.as_deref(), Some("renamed"));
}

#[test]
fn signing_key_debug_redacts_private_material() {
    let key = LocalIdpSigningKey::generate_rsa();
    let debug = format!("{key:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("BEGIN"));
}

#[test]
#[should_panic(expected = "RSA constructors only support")]
fn signing_key_rejects_non_rsa_algorithm_at_pem_load() {
    let pem = fresh_rsa_pkcs1_pem();
    let _ = LocalIdpSigningKey::from_rsa_pem(&pem, "kid", Algorithm::ES256);
}
