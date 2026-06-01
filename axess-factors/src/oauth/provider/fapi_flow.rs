//! FAPI 2.0 Baseline Profile helpers: PAR (RFC 9126) and DPoP (RFC 9449).
//!
//! These free functions carry the actual protocol logic for the FAPI-specific
//! extensions. The corresponding [`OAuthProvider`](super::super::OAuthProvider)
//! trait methods on [`OAuthProviderConfig`](super::OAuthProviderConfig) are
//! thin wrappers that delegate here.

use super::super::types::{AuthUrlResult, OAuthError, OAuthLoginOptions, ParResponse};
use super::OAuthProviderConfig;

/// Build an authorization URL using the Pushed Authorization Request (PAR)
/// endpoint (RFC 9126). Unlike the standard flow, the request parameters
/// are first POSTed to the PAR endpoint; the returned `request_uri` is then
/// used as the sole parameter on the browser redirect.
pub(super) async fn build_auth_url_par(
    cfg: &OAuthProviderConfig,
    options: &OAuthLoginOptions,
) -> Result<AuthUrlResult, OAuthError> {
    use openidconnect::{CsrfToken, Nonce, PkceCodeChallenge};

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let csrf_state = CsrfToken::new_random();
    let nonce = Nonce::new_random();

    // Collect all scopes.
    let mut all_scopes: Vec<String> = cfg.scopes.clone();
    all_scopes.extend(options.extra_scopes.iter().cloned());
    let scope_str = all_scopes.join(" ");

    // Build PAR form parameters.
    let nonce_str = nonce.secret().clone();
    let state_str = csrf_state.secret().clone();
    let redirect_str = cfg.redirect_url.to_string();
    let challenge_str = pkce_challenge.as_str().to_string();
    let mut params: Vec<(&str, &str)> = vec![
        ("response_type", "code"),
        ("redirect_uri", &redirect_str),
        ("scope", &scope_str),
        ("state", &state_str),
        ("nonce", &nonce_str),
        ("code_challenge", &challenge_str),
        ("code_challenge_method", "S256"),
    ];

    let response_mode_str;
    if let Some(ref mode) = options.response_mode {
        response_mode_str = mode.as_str().to_string();
        params.push(("response_mode", &response_mode_str));
    }
    let prompt_str;
    if let Some(ref prompt) = options.prompt {
        prompt_str = prompt.clone();
        params.push(("prompt", &prompt_str));
    }
    let hint_str;
    if let Some(ref hint) = options.login_hint {
        hint_str = hint.clone();
        params.push(("login_hint", &hint_str));
    }

    // Push to PAR endpoint.
    let par_response = push_authorization_request(cfg, &params).await?;

    // Build minimal authorization URL with request_uri.
    let auth_endpoint = cfg.metadata.authorization_endpoint().url().clone();

    let mut auth_url = auth_endpoint;
    auth_url
        .query_pairs_mut()
        .append_pair("client_id", cfg.client_id.as_str())
        .append_pair("request_uri", &par_response.request_uri);

    Ok((
        auth_url,
        state_str,
        nonce_str,
        pkce_verifier.secret().to_string(),
    ))
}

/// POST the authorization request parameters to the IdP's PAR endpoint.
/// Called by [`build_auth_url_par`] as part of the FAPI flow, and also
/// re-exposed on the trait so downstream code can push requests directly
/// when building non-standard flows.
pub(super) async fn push_authorization_request(
    cfg: &OAuthProviderConfig,
    params: &[(&str, &str)],
) -> Result<ParResponse, OAuthError> {
    let par_url = cfg.par_endpoint.as_deref().ok_or_else(|| {
        OAuthError::Config(
            "provider metadata does not include pushed_authorization_request_endpoint".to_string(),
        )
    })?;

    let mut form: Vec<(&str, &str)> = Vec::with_capacity(params.len() + 2);
    form.push(("client_id", cfg.client_id.as_str()));
    if let Some(ref secret) = cfg.client_secret {
        form.push(("client_secret", secret.secret()));
    }
    form.extend_from_slice(params);

    let response = cfg
        .http_client
        .post(par_url)
        .form(&form)
        .send()
        .await
        .map_err(|e| OAuthError::TokenExchange(format!("PAR request failed: {e}")))?;

    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|e| OAuthError::TokenExchange(format!("PAR response read failed: {e}")))?;

    if !status.is_success() {
        let error_body = String::from_utf8_lossy(&body);
        return Err(OAuthError::TokenExchange(format!(
            "PAR endpoint returned HTTP {status}: {error_body}"
        )));
    }

    serde_json::from_slice(&body)
        .map_err(|e| OAuthError::TokenExchange(format!("PAR response parse failed: {e}")))
}

/// Generate a fresh DPoP proof JWT (RFC 9449) for sender-constrained tokens.
///
/// Creates a per-proof ephemeral ES256 key pair, signs the `htm`/`htu`/`iat`
/// claims plus optional `ath` (access token hash) when binding to a
/// resource-server request, and returns the JWT together with the RFC 7638
/// JWK thumbprint (which the IdP echoes back in `cnf.jkt`).
///
/// # Caller-supplied entropy
///
/// The 32 random bytes used to derive the ephemeral key are passed in by
/// the caller rather than read from `OsRng` directly, so deterministic
/// simulation tests get reproducible DPoP keys via a seeded
/// [`SecureRng`](axess_rng::SecureRng). The bytes are
/// interpreted as a P-256 scalar (big-endian); on the cosmically unlikely
/// chance that they fall outside the curve order, the input is hashed
/// once and retried.
#[cfg(feature = "fapi")]
pub(super) fn generate_dpop_proof(
    http_method: &str,
    http_url: &str,
    access_token: Option<&str>,
    mut key_seed: [u8; 32],
) -> Result<super::super::types::DpopProof, OAuthError> {
    use jsonwebtoken::{Algorithm, EncodingKey};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use sha2::Digest;

    // DPoP uses an ephemeral ES256 key pair per proof. Build it from the
    // injected seed bytes so DST tests are reproducible.
    let ec_key = loop {
        let bytes_ref: &[u8; 32] = &key_seed;
        match p256::SecretKey::from_slice(bytes_ref) {
            Ok(k) => break k,
            Err(_) => {
                // Re-hash and retry: ~2^-128 probability per iteration.
                key_seed = sha2::Sha256::digest(key_seed).into();
            }
        }
    };
    // jsonwebtoken's `EncodingKey::from_ec_der` expects PKCS#8
    // PrivateKeyInfo, NOT raw SEC1 ECPrivateKey. The previous
    // implementation passed `to_sec1_der()`, which silently produced
    // a `Config("DPoP signing failed: InvalidEcdsaKey")` at sign
    // time. The bug was masked by zero DPoP test coverage; the
    // determinism tests surfaced it. Use
    // `to_pkcs8_der()` for the format jsonwebtoken actually accepts.
    use p256::pkcs8::EncodePrivateKey;
    let ec_key_der = ec_key
        .to_pkcs8_der()
        .map_err(|e| OAuthError::Config(format!("DPoP key generation failed: {e}")))?;
    let encoding_key = EncodingKey::from_ec_der(ec_key_der.as_bytes());

    let public_key = ec_key.public_key();
    let ec_point = public_key.to_encoded_point(false);
    let x_bytes = ec_point
        .x()
        .ok_or_else(|| OAuthError::Config("DPoP: failed to extract EC x coordinate".to_string()))?;
    let y_bytes = ec_point
        .y()
        .ok_or_else(|| OAuthError::Config("DPoP: failed to extract EC y coordinate".to_string()))?;

    use base64::Engine as _;
    let b64 = &base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let x_b64 = b64.encode(x_bytes.as_slice());
    let y_b64 = b64.encode(y_bytes.as_slice());

    // Build the JWK in a `BTreeMap<&str, &str>` and serialise via
    // `serde_json::to_string`. `BTreeMap`'s ordered iteration produces the
    // RFC 7638 canonical lex-ordered JSON without ad-hoc string templating
    //; so adding a new public-key field can never silently break the
    // thumbprint by ordering it incorrectly.
    let mut canonical_members: std::collections::BTreeMap<&'static str, &str> =
        std::collections::BTreeMap::new();
    canonical_members.insert("crv", "P-256");
    canonical_members.insert("kty", "EC");
    canonical_members.insert("x", &x_b64);
    canonical_members.insert("y", &y_b64);
    let canonical = serde_json::to_string(&canonical_members)
        .map_err(|e| OAuthError::Config(format!("DPoP JWK canonicalisation failed: {e}")))?;
    let thumbprint_bytes = sha2::Sha256::digest(canonical.as_bytes());
    let thumbprint = b64.encode(thumbprint_bytes);

    let jwk_value = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x_b64,
        "y": y_b64,
    });

    let now = chrono::Utc::now().timestamp();
    let jti = uuid::Uuid::new_v4().to_string();

    let mut payload = serde_json::json!({
        "htm": http_method,
        "htu": http_url,
        "iat": now,
        "jti": jti,
    });

    // If binding to an access token, include `ath` (access token hash).
    if let Some(at) = access_token {
        let ath_bytes = sha2::Sha256::digest(at.as_bytes());
        payload["ath"] = serde_json::Value::String(b64.encode(ath_bytes));
    }

    // Build JWT manually because jsonwebtoken doesn't support `jwk` in header.
    let header_json = serde_json::json!({
        "alg": "ES256",
        "typ": "dpop+jwt",
        "jwk": jwk_value,
    });
    let header_b64 = b64.encode(header_json.to_string().as_bytes());
    let payload_b64 = b64.encode(payload.to_string().as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");

    let signature =
        jsonwebtoken::crypto::sign(signing_input.as_bytes(), &encoding_key, Algorithm::ES256)
            .map_err(|e| OAuthError::Config(format!("DPoP signing failed: {e}")))?;

    let proof_jwt = format!("{signing_input}.{signature}");

    Ok(super::super::types::DpopProof {
        proof_jwt,
        thumbprint,
    })
}

#[cfg(all(test, feature = "fapi"))]
mod fapi_tests {
    use super::*;

    /// Confirm `BTreeMap`-driven canonical JWK matches the
    /// hand-crafted lex-ordered JSON the previous implementation used.
    /// Pure-data check: exercises the canonicalisation independently
    /// of P-256 key generation.
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

    /// Identical seed → identical thumbprint. Proves
    /// the DST contract: a seeded `SecureRng` driving DPoP key
    /// generation gives reproducible `cnf.jkt` across test runs.
    /// Different seeds → different thumbprints.
    #[test]
    fn deterministic_thumbprint_from_seed() {
        let seed_a = [0x11u8; 32];
        let seed_b = [0x22u8; 32];

        let proof_a1 =
            generate_dpop_proof("POST", "https://api.example.com/x", None, seed_a).unwrap();
        let proof_a2 =
            generate_dpop_proof("POST", "https://api.example.com/x", None, seed_a).unwrap();
        let proof_b =
            generate_dpop_proof("POST", "https://api.example.com/x", None, seed_b).unwrap();

        assert_eq!(
            proof_a1.thumbprint, proof_a2.thumbprint,
            "same seed must produce the same JWK thumbprint"
        );
        assert_ne!(
            proof_a1.thumbprint, proof_b.thumbprint,
            "different seeds must produce different thumbprints"
        );
        // Sanity: thumbprint is base64url-no-pad of a 32-byte SHA-256 →
        // expected length 43 chars.
        assert_eq!(proof_a1.thumbprint.len(), 43);
    }

    /// Regression test for the lex-ordering rail. Hardcodes
    /// the SHA-256 thumbprint expected for a known seed, so any future
    /// regression that reorders JWK members (or accidentally adds a
    /// field) will flip the digest and fail loudly.
    #[test]
    fn known_seed_yields_known_thumbprint() {
        // Seed picked once and pinned. If you change this test, change
        // the expected thumbprint below in lockstep.
        let seed = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let proof = generate_dpop_proof("GET", "https://rs.example.com/", None, seed).unwrap();
        // Pin the digest. If this string ever changes, the canonical
        // JWK form changed; review carefully before updating.
        let expected = "6UoWwDCkLjV0J-pQG8c0THxbVhBcpR0AZDift1Yl5DM";
        assert_eq!(
            proof.thumbprint, expected,
            "pinned thumbprint changed; JWK canonicalisation may have regressed"
        );
    }
}
