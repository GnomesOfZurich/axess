//! A throwaway RSA key, its JWKS, and tokens signed with it at the pinned
//! instant: what a recipe test and the fixture generator build a token
//! from. Every user of this module uses all of it.

use axess::jwt::encode;
use axess_clock::testing::MockClock;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rsa::RsaPrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;

/// Mint a fresh RSA-2048 keypair, return `(private_der, jwks)`.
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
///
/// The example takes `jwt-rust-crypto`, but a workspace build with
/// `--all-features` compiles both backends in, and `jsonwebtoken` cannot
/// derive a provider from two. `axess::jwt::encode` settles one before it
/// signs, as every signature and verification of axess does.
pub fn sign(claims: &serde_json::Value, kid: &str, der: &[u8]) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let key = EncodingKey::from_rsa_der(der);
    encode(&header, claims, &key).expect("JWT encode")
}

/// Pinned claim timestamps for "now + 1h expiry", at the reference instant
/// ([`MockClock::reference_time`], 2026-01-01T00:00:00Z): the instant the
/// `MockClock` a test's verifier consults stands at, so JWTs `iat`-stamped
/// here and `exp`-stamped here + 1h validate cleanly whatever the day.
pub fn now_and_exp() -> (i64, i64) {
    let now = MockClock::reference_time().unix_seconds();
    (now, now + 3600)
}
