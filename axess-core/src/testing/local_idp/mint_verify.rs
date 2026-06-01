use std::sync::Arc;

use super::*;
use crate::testing::MockClock;
use axess_factors::jwt::verifier::JwtVerifier;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CustomClaims {
    #[serde(default)]
    department: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
}

fn one_hour_from_now() -> DateTime<Utc> {
    Utc::now() + Duration::hours(1)
}

#[tokio::test]
async fn mint_roundtrips_through_jwt_verifier() {
    let idp = LocalIdpFixture::new("https://test.idp.local");
    // Pin the `issuer()` accessor against `-> ""` / `-> "xyzzy"`.
    assert_eq!(
        idp.issuer(),
        "https://test.idp.local",
        "issuer() must borrow the configured issuer string"
    );
    let claims = MintClaims::new("alice", one_hour_from_now())
        .with_audience("https://api.example.com")
        .with_issued_at(Utc::now());

    let token = idp.mint(&claims);
    let verifier = JwtVerifier::new(idp.jwks_handle())
        .with_issuer("https://test.idp.local")
        .with_audience("https://api.example.com");
    let verified = verifier
        .verify::<CustomClaims>(&token)
        .await
        .expect("happy-path verify");
    assert_eq!(verified.iss.as_deref(), Some("https://test.idp.local"));
    assert_eq!(verified.sub.as_deref(), Some("alice"));
}

#[tokio::test]
async fn mint_propagates_custom_claims() {
    let idp = LocalIdpFixture::new("https://test.idp.local");
    let claims = MintClaims::new("bob", one_hour_from_now())
        .with_audience("https://api.example.com")
        .with_issued_at(Utc::now())
        .with_custom_claim("department", serde_json::json!("research"))
        .with_custom_claim("roles", serde_json::json!(["admin", "auditor"]));

    let token = idp.mint(&claims);
    let verifier = JwtVerifier::new(idp.jwks_handle()).with_audience("https://api.example.com");
    let verified = verifier
        .verify::<CustomClaims>(&token)
        .await
        .expect("verify with custom claims");
    assert_eq!(verified.custom.department.as_deref(), Some("research"));
    assert_eq!(verified.custom.roles, vec!["admin", "auditor"]);
}

#[tokio::test]
async fn audience_mismatch_rejected_by_verifier() {
    let idp = LocalIdpFixture::new("https://test.idp.local");
    let claims = MintClaims::new("alice", one_hour_from_now())
        .with_audience("https://other.example.com")
        .with_issued_at(Utc::now());
    let token = idp.mint(&claims);

    let verifier = JwtVerifier::new(idp.jwks_handle()).with_audience("https://api.example.com");
    let result = verifier.verify::<CustomClaims>(&token).await;
    assert!(
        result.is_err(),
        "audience mismatch must be rejected by the verifier"
    );
}

#[tokio::test]
async fn expired_token_rejected_against_advanced_clock() {
    let idp = LocalIdpFixture::new("https://test.idp.local");
    let now = Utc::now();
    let claims = MintClaims::new("alice", now + Duration::seconds(60))
        .with_audience("https://api.example.com")
        .with_issued_at(now);
    let token = idp.mint(&claims);

    // Mock clock past the token's exp + jsonwebtoken default leeway (60s).
    let clock = Arc::new(MockClock::at(now + Duration::seconds(200)));
    let verifier = JwtVerifier::new(idp.jwks_handle())
        .with_audience("https://api.example.com")
        .with_clock(clock);
    let result = verifier.verify::<CustomClaims>(&token).await;
    assert!(
        result.is_err(),
        "expired token must be rejected when clock advances past exp"
    );
}

#[tokio::test]
async fn not_yet_valid_token_rejected_against_pre_nbf_clock() {
    let idp = LocalIdpFixture::new("https://test.idp.local");
    let now = Utc::now();
    let nbf = now + Duration::seconds(600);
    let claims = MintClaims::new("alice", now + Duration::hours(1))
        .with_audience("https://api.example.com")
        .with_not_before(nbf)
        .with_issued_at(now);
    let token = idp.mint(&claims);

    let clock = Arc::new(MockClock::at(now));
    let verifier = JwtVerifier::new(idp.jwks_handle())
        .with_audience("https://api.example.com")
        .with_clock(clock);
    let result = verifier.verify::<CustomClaims>(&token).await;
    assert!(result.is_err(), "pre-nbf clock must reject token");
}

#[tokio::test]
async fn mint_jwt_svid_produces_spiffe_subject() {
    let idp = LocalIdpFixture::new("https://test.idp.local");
    let token = idp.mint_jwt_svid(
        "test.gnomes",
        "compute-worker",
        "acme",
        "https://api.gnomes",
        Duration::minutes(5),
    );
    let verifier = JwtVerifier::new(idp.jwks_handle()).with_audience("https://api.gnomes");
    let verified = verifier
        .verify::<CustomClaims>(&token)
        .await
        .expect("SVID verify");
    assert_eq!(
        verified.sub.as_deref(),
        Some("spiffe://test.gnomes/compute-worker/acme")
    );
}

#[test]
fn jwks_json_serializes_to_well_formed_jwks() {
    let idp = LocalIdpFixture::new("https://test.idp.local");
    let json = idp.jwks_json();
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON parse");
    let keys = parsed
        .get("keys")
        .and_then(|k| k.as_array())
        .expect("keys[]");
    assert_eq!(keys.len(), 1);
    let key = &keys[0];
    assert_eq!(key["kty"], "RSA");
    assert_eq!(key["alg"], "RS256");
    assert_eq!(key["use"], "sig");
    assert!(key.get("n").is_some());
    assert!(key.get("e").is_some());
    assert!(key.get("d").is_none(), "private exponent must not leak");
}

#[test]
fn with_key_id_overrides_both_jwk_and_signing_header() {
    let idp = LocalIdpFixture::new("https://test.idp.local").with_key_id("custom-kid");
    assert_eq!(idp.key_id(), "custom-kid");
    let token = idp.mint(&MintClaims::new("alice", one_hour_from_now()));
    let header = jsonwebtoken::decode_header(&token).expect("decode header");
    assert_eq!(header.kid.as_deref(), Some("custom-kid"));

    let json = idp.jwks_json();
    assert!(json.contains("\"kid\":\"custom-kid\""));
}

#[tokio::test]
async fn iss_claim_cannot_be_overridden_via_custom_claims() {
    let idp = LocalIdpFixture::new("https://test.idp.local");
    let claims = MintClaims::new("alice", one_hour_from_now())
        .with_audience("https://api.example.com")
        .with_issued_at(Utc::now())
        .with_custom_claim("iss", serde_json::json!("https://evil.idp"));
    let token = idp.mint(&claims);

    let verifier = JwtVerifier::new(idp.jwks_handle())
        .with_issuer("https://test.idp.local")
        .with_audience("https://api.example.com");
    let verified = verifier
        .verify::<CustomClaims>(&token)
        .await
        .expect("verify");
    assert_eq!(
        verified.iss.as_deref(),
        Some("https://test.idp.local"),
        "fixture iss must not be overridable via custom claims"
    );
}

#[tokio::test]
async fn multi_audience_validates_against_either() {
    let idp = LocalIdpFixture::new("https://test.idp.local");
    let claims = MintClaims::new("alice", one_hour_from_now())
        .with_audiences(["https://api.example.com", "https://other.example.com"])
        .with_issued_at(Utc::now());
    let token = idp.mint(&claims);

    let v1 = JwtVerifier::new(idp.jwks_handle()).with_audience("https://api.example.com");
    let v2 = JwtVerifier::new(idp.jwks_handle()).with_audience("https://other.example.com");
    assert!(v1.verify::<CustomClaims>(&token).await.is_ok());
    assert!(v2.verify::<CustomClaims>(&token).await.is_ok());
}

#[test]
fn clone_shares_keypair() {
    let idp = LocalIdpFixture::new("https://test.idp.local");
    let clone = idp.clone();
    let token1 = idp.mint(&MintClaims::new("alice", one_hour_from_now()));
    let token2 = clone.mint(&MintClaims::new("alice", one_hour_from_now()));

    let header1 = jsonwebtoken::decode_header(&token1).unwrap();
    let header2 = jsonwebtoken::decode_header(&token2).unwrap();
    assert_eq!(header1.kid, header2.kid);
    assert_eq!(idp.key_id(), clone.key_id());
}

#[test]
fn algorithm_accessor_returns_configured_alg() {
    let idp = LocalIdpFixture::new("https://test.idp.local");
    assert_eq!(idp.algorithm(), Algorithm::RS256);

    let idp384 = LocalIdpFixture::with_algorithm("https://test.idp.local", Algorithm::RS384);
    assert_eq!(idp384.algorithm(), Algorithm::RS384);
}

#[test]
#[should_panic(expected = "LocalIdpFixture::with_algorithm supports")]
fn unsupported_algorithm_panics() {
    let _ = LocalIdpFixture::with_algorithm("https://test", Algorithm::HS256);
}

#[tokio::test]
async fn jti_claim_propagates_to_verified_claims() {
    let idp = LocalIdpFixture::new("https://test.idp.local");
    let claims = MintClaims::new("alice", one_hour_from_now())
        .with_audience("https://api.example.com")
        .with_issued_at(Utc::now())
        .with_jwt_id("test-jti-1234");
    let token = idp.mint(&claims);

    let verifier = JwtVerifier::new(idp.jwks_handle()).with_audience("https://api.example.com");
    let verified = verifier
        .verify::<CustomClaims>(&token)
        .await
        .expect("verify with jti");
    assert_eq!(verified.jti.as_deref(), Some("test-jti-1234"));
}

// ── verifier_algorithms() accessor ──────────────────────────────────

#[test]
fn verifier_algorithms_default_rsa_only() {
    let idp = LocalIdpFixture::new("https://idp");
    assert_eq!(idp.verifier_algorithms(), vec![Algorithm::RS256]);
}

#[test]
fn verifier_algorithms_es256_only() {
    let idp =
        LocalIdpFixture::with_signing_key("https://idp", LocalIdpSigningKey::generate_es256());
    assert_eq!(idp.verifier_algorithms(), vec![Algorithm::ES256]);
}

#[test]
fn verifier_algorithms_rotation_carries_historical_alg() {
    let rsa = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let ec = LocalIdpSigningKey::generate_es256().with_key_id("ec-1");
    let idp = LocalIdpFixture::with_signing_key("https://idp", rsa).rotate_signing_key(ec);
    let algs = idp.verifier_algorithms();
    assert!(algs.contains(&Algorithm::ES256), "current alg in set");
    assert!(algs.contains(&Algorithm::RS256), "historical alg in set");
    assert_eq!(algs.len(), 2, "no duplicates");
}

#[test]
fn verifier_algorithms_extra_public_jwk_with_alg_included() {
    let foreign = LocalIdpSigningKey::generate_es256().with_key_id("foreign-ec");
    let idp = LocalIdpFixture::new("https://idp").with_extra_public_jwk(foreign.jwk().clone());
    let algs = idp.verifier_algorithms();
    assert!(algs.contains(&Algorithm::RS256));
    assert!(algs.contains(&Algorithm::ES256));
}

#[test]
fn verifier_algorithms_extra_public_jwk_without_alg_skipped() {
    let foreign = LocalIdpSigningKey::generate_es256().with_key_id("foreign-ec");
    let mut jwk_no_alg = foreign.jwk().clone();
    jwk_no_alg.common.key_algorithm = None;
    let idp = LocalIdpFixture::new("https://idp").with_extra_public_jwk(jwk_no_alg);
    let algs = idp.verifier_algorithms();
    assert_eq!(algs, vec![Algorithm::RS256], "alg-less extra JWK skipped");
}

#[test]
fn verifier_algorithms_dedupes_when_historical_matches_current() {
    let k1 = LocalIdpSigningKey::generate_rsa().with_key_id("k1");
    let k2 = LocalIdpSigningKey::generate_rsa().with_key_id("k2");
    let idp = LocalIdpFixture::with_signing_key("https://idp", k1).rotate_signing_key(k2);
    let algs = idp.verifier_algorithms();
    assert_eq!(
        algs,
        vec![Algorithm::RS256],
        "same alg dedupes to single entry"
    );
}

#[tokio::test]
async fn verifier_algorithms_drives_with_algorithms_for_es256() {
    let idp =
        LocalIdpFixture::with_signing_key("https://idp", LocalIdpSigningKey::generate_es256());
    let now = Utc::now();
    let token = idp.mint(
        &MintClaims::new("alice", now + Duration::hours(1))
            .with_audience("https://api")
            .with_issued_at(now),
    );
    // Wire the accessor straight into the verifier; no need for the
    // adopter to know which algorithms the fixture happens to use.
    let verifier = JwtVerifier::new(idp.jwks_handle())
        .with_audience("https://api")
        .with_algorithms(idp.verifier_algorithms());
    verifier
        .verify::<CustomClaims>(&token)
        .await
        .expect("ES256 mint verifies under accessor-driven allowlist");
}
