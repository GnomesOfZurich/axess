//! Shared test fixtures: RSA keypair, JWKS, JWT signer, verifier
//! builder. Used by both recipe integration tests.

use std::sync::{Arc, RwLock};

use axess_clock::testing::MockClock;
use axess_factors::jwt::verifier::JwtVerifier;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::DateTime;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rsa::RsaPrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;

/// Mint a fresh RSA-2048 keypair, return `(private_der, jwks, kid)`.
///
/// The DER bytes feed `jsonwebtoken::EncodingKey::from_rsa_der`; the
/// `JwkSet` is what `JwtVerifier` consults to verify signatures.
pub fn rsa_keypair(kid: &str) -> (Vec<u8>, JwkSet) {
    let mut rng = rsa::rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("RSA key generation");
    let public_key = private_key.to_public_key();
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
    (private_der, jwks)
}

/// Sign `claims` as an RS256 JWT under `kid`.
pub fn sign(claims: &serde_json::Value, kid: &str, der: &[u8]) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let key = EncodingKey::from_rsa_der(der);
    encode(&header, claims, &key).expect("JWT encode")
}

/// Pinned UTC epoch for all recipe-test timestamps: 2026-01-01T00:00:00Z.
/// Same instant the rest of the workspace's DST primitives pin to.
const PINNED_EPOCH_SECS: i64 = 1_767_225_600;

/// Build a `JwtVerifier` pinning `iss` + `aud` against the supplied
/// JWKS, with its `iat`/`exp`/`nbf` clock pinned to `PINNED_EPOCH_SECS`
/// via [`MockClock`] so the test runs deterministically regardless of
/// wall-clock time (e.g. on a build agent in a year where the
/// hardcoded `now`/`exp` would otherwise be expired).
pub fn build_verifier(jwks: JwkSet, issuer: &str, audience: &str) -> Arc<JwtVerifier> {
    let clock = Arc::new(MockClock::at(pinned_now()));
    Arc::new(
        JwtVerifier::new(Arc::new(RwLock::new(jwks)))
            .with_issuer(issuer)
            .with_audience(audience)
            .with_clock(clock),
    )
}

/// Pinned `DateTime<Utc>` matching [`PINNED_EPOCH_SECS`].
pub fn pinned_now() -> DateTime<chrono::Utc> {
    DateTime::from_timestamp(PINNED_EPOCH_SECS, 0).expect("PINNED_EPOCH_SECS is valid")
}

/// Pinned claim timestamps for "now + 1h expiry"; matches the
/// `MockClock` the verifier consults, so JWTs `iat`-stamped here and
/// `exp`-stamped here + 1h validate cleanly.
pub fn now_and_exp() -> (i64, i64) {
    (PINNED_EPOCH_SECS, PINNED_EPOCH_SECS + 3600)
}
