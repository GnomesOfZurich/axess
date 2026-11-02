//! DPoP (RFC 9449) on the client side: the proofs a request carries, and
//! whether a discovery document advertises DPoP with the algorithm the
//! proofs are signed with.
//!
//! Whether a provider binds its tokens to a DPoP key is one switch, the
//! `dpop` field of [`OAuthProviderConfig`](super::OAuthProviderConfig),
//! resolved once by [`OAuthProviderBuilder::build`](super::OAuthProviderBuilder::build):
//! on by default when the discovery document advertises DPoP, required by
//! [`with_dpop`](super::OAuthProviderBuilder::with_dpop), off by
//! [`without_dpop`](super::OAuthProviderBuilder::without_dpop), on under the
//! FAPI profile with [`SenderConstraint::DPoP`](crate::oauth::SenderConstraint::DPoP).
//! The requests that honour it live in
//! [`sender_constrained`](super::sender_constrained).

use super::super::types::{DpopKey, OAuthError};

/// The JWS algorithm every proof is signed with: `ES256`, over the P-256
/// key a [`DpopKey`] holds.
pub(super) const DPOP_SIGNING_ALG: &str = "ES256";

/// Whether a discovery document advertises DPoP in a form these proofs can
/// meet: its `dpop_signing_alg_values_supported` (RFC 9449 section 5.1)
/// lists [`DPOP_SIGNING_ALG`]. A document without the member, with an empty
/// list, or with a list of other algorithms does not.
pub(super) fn advertised_in(document: &serde_json::Value) -> bool {
    crate::oauth::extract_string_array(document, "dpop_signing_alg_values_supported")
        .iter()
        .any(|alg| alg == DPOP_SIGNING_ALG)
}

/// Generate a DPoP proof JWT (RFC 9449) with `key`.
///
/// Signs the `htm`/`htu`/`iat`/`jti` claims plus optional `ath` (access token
/// hash) when binding to a resource-server request, and returns the JWT
/// together with the RFC 7638 thumbprint of `key` (the value the
/// authorization server echoes back in `cnf.jkt`).
///
/// RFC 9449 requires every proof presented with a bound token to be signed by
/// the key the token is bound to, so the key is the caller's to create once
/// per session ([`DpopKey::generate`]) and keep for the token's life. Two
/// proofs from one key for different URLs report the same thumbprint.
///
/// # Caller-supplied entropy and time
///
/// Nothing here reads a clock or a random source. The caller passes the
/// 16 bytes that become the `jti` (as a version-4 UUID) and the `iat` Unix
/// second, so the same inputs give the same header and payload and a seeded
/// [`SecureRng`](axess_rng::SecureRng) with a mock clock reproduces the whole
/// proof.
pub(super) fn generate_dpop_proof(
    key: &DpopKey,
    http_method: &str,
    http_url: &str,
    access_token: Option<&str>,
    iat: i64,
    jti_bytes: [u8; 16],
) -> Result<super::super::types::DpopProof, OAuthError> {
    generate_dpop_proof_with_nonce(
        key,
        http_method,
        http_url,
        access_token,
        None,
        iat,
        jti_bytes,
    )
}

/// [`generate_dpop_proof`] carrying the `nonce` an authorization or resource
/// server demanded (RFC 9449 §8, §9): the server answers a proof without one
/// with `use_dpop_nonce` and a `DPoP-Nonce` header, and the request is sent
/// again with a proof that echoes it.
pub(super) fn generate_dpop_proof_with_nonce(
    key: &DpopKey,
    http_method: &str,
    http_url: &str,
    access_token: Option<&str>,
    server_nonce: Option<&str>,
    iat: i64,
    jti_bytes: [u8; 16],
) -> Result<super::super::types::DpopProof, OAuthError> {
    use jsonwebtoken::{Algorithm, EncodingKey};
    use p256::pkcs8::EncodePrivateKey;
    use sha2::Digest;

    let ec_key = key.secret_key()?;
    // jsonwebtoken's `EncodingKey::from_ec_der` expects PKCS#8
    // PrivateKeyInfo, not raw SEC1 ECPrivateKey.
    let ec_key_der = ec_key
        .to_pkcs8_der()
        .map_err(|e| OAuthError::Config(format!("DPoP key generation failed: {e}")))?;
    let encoding_key = EncodingKey::from_ec_der(ec_key_der.as_bytes());

    let (x_b64, y_b64) = key.public_coordinates()?;
    let thumbprint = key.thumbprint()?;

    use base64::Engine as _;
    let b64 = &base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let jwk_value = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x_b64,
        "y": y_b64,
    });

    let jti = uuid::Builder::from_random_bytes(jti_bytes)
        .into_uuid()
        .to_string();

    let mut payload = serde_json::json!({
        "htm": http_method,
        "htu": http_url,
        "iat": iat,
        "jti": jti,
    });

    if let Some(nonce) = server_nonce {
        payload["nonce"] = serde_json::Value::String(nonce.to_string());
    }

    // If binding to an access token, include `ath` (access token hash).
    if let Some(at) = access_token {
        let ath_bytes = sha2::Sha256::digest(at.as_bytes());
        payload["ath"] = serde_json::Value::String(b64.encode(ath_bytes));
    }

    // Build JWT manually because jsonwebtoken doesn't support `jwk` in header.
    let header_json = serde_json::json!({
        "alg": DPOP_SIGNING_ALG,
        "typ": "dpop+jwt",
        "jwk": jwk_value,
    });
    let header_b64 = b64.encode(header_json.to_string().as_bytes());
    let payload_b64 = b64.encode(payload.to_string().as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");

    // The first jsonwebtoken sign or verify in a process fixes its crypto
    // provider; under feature unification that first call must be ours,
    // or the crate's own fallback panics on every later use.
    crate::jwt::ensure_crypto_provider();
    let signature =
        jsonwebtoken::crypto::sign(signing_input.as_bytes(), &encoding_key, Algorithm::ES256)
            .map_err(|e| OAuthError::Config(format!("DPoP signing failed: {e}")))?;

    let proof_jwt = format!("{signing_input}.{signature}");

    Ok(super::super::types::DpopProof {
        proof_jwt,
        thumbprint,
    })
}

#[cfg(test)]
mod tests;
