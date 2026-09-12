//! `tests`: extracted from `bearer.rs` per the
//! 200-LoC inline-test rule in AGENTS.md.

use super::*;

// ── extract_bearer_token ────────────────────────────────────────���────

#[test]
fn extract_bearer_token_valid() {
    assert_eq!(
        extract_bearer_token(Some("Bearer eyJhbGciOiJSUzI1NiJ9.abc.def")),
        Some("eyJhbGciOiJSUzI1NiJ9.abc.def")
    );
}

#[test]
fn extract_bearer_token_missing_header() {
    assert_eq!(extract_bearer_token(None), None);
}

#[test]
fn extract_bearer_token_wrong_scheme() {
    assert_eq!(extract_bearer_token(Some("Basic dXNlcjpwYXNz")), None);
}

#[test]
fn extract_bearer_token_empty_after_bearer() {
    assert_eq!(extract_bearer_token(Some("Bearer ")), None);
}

#[test]
fn extract_bearer_token_no_space_after_bearer() {
    assert_eq!(extract_bearer_token(Some("Bearertoken")), None);
}

// ── validate_bearer_token ────────────────────────────────────────────

fn rsa_keypair() -> (Vec<u8>, JwkSet, String) {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use rsa::RsaPrivateKey;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::traits::PublicKeyParts;

    let mut rng = rsa::rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("key generation");
    let public_key = private_key.to_public_key();
    let kid = "test-kid-bearer".to_string();

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

fn sign_jwt(private_der: &[u8], kid: &str, claims: &serde_json::Value) -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};
    let key = EncodingKey::from_rsa_der(private_der);
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(kid.to_string());
    encode(&header, claims, &key).expect("JWT encode")
}

fn make_config(jwks: JwkSet) -> BearerConfig {
    BearerConfig {
        issuers: vec![BearerIssuerConfig {
            issuer: "https://accounts.example.com".to_string(),
            audience: Some("my-service".to_string()),
            jwks: Arc::new(jwks),
            extra_claims: vec!["namespace".to_string()],
        }],
    }
}

fn valid_claims() -> serde_json::Value {
    let now = chrono::Utc::now().timestamp();
    serde_json::json!({
        "iss": "https://accounts.example.com",
        "sub": "spiffe://cluster.local/ns/default/sa/worker",
        "aud": "my-service",
        "exp": now + 300,
        "iat": now,
        "namespace": "production"
    })
}

#[test]
fn valid_bearer_token_produces_workload_identity() {
    let (private_der, jwks, kid) = rsa_keypair();
    let config = make_config(jwks);
    let claims = valid_claims();
    let token = sign_jwt(&private_der, &kid, &claims);

    let header = format!("Bearer {token}");
    let result = validate_bearer_token(Some(&header), &config).unwrap();
    let identity = result.expect("should produce identity");

    assert_eq!(
        identity.subject,
        "spiffe://cluster.local/ns/default/sa/worker"
    );
    assert_eq!(identity.issuer, "https://accounts.example.com");
    assert_eq!(identity.audiences, vec!["my-service"]);
    assert_eq!(
        identity.claims.get("namespace"),
        Some(&"production".to_string())
    );
}

#[test]
fn no_authorization_header_returns_none() {
    let config = make_config(JwkSet { keys: vec![] });
    let result = validate_bearer_token(None, &config).unwrap();
    assert!(result.is_none());
}

#[test]
fn untrusted_issuer_returns_error() {
    let (private_der, jwks, kid) = rsa_keypair();
    let config = make_config(jwks);
    let mut claims = valid_claims();
    claims["iss"] = serde_json::json!("https://evil.example.com");
    let token = sign_jwt(&private_der, &kid, &claims);

    let header = format!("Bearer {token}");
    let result = validate_bearer_token(Some(&header), &config);
    assert!(matches!(result, Err(BearerError::UntrustedIssuer(_))));
}

#[test]
fn missing_sub_claim_returns_error() {
    let (private_der, jwks, kid) = rsa_keypair();
    let config = make_config(jwks);
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": "https://accounts.example.com",
        "aud": "my-service",
        "exp": now + 300,
        "iat": now,
    });
    let token = sign_jwt(&private_der, &kid, &claims);

    let header = format!("Bearer {token}");
    let result = validate_bearer_token(Some(&header), &config);
    assert!(matches!(result, Err(BearerError::MissingSubject)));
}

#[test]
fn array_aud_claim_populates_all_audiences() {
    let (private_der, jwks, kid) = rsa_keypair();
    let config = make_config(jwks);
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": "https://accounts.example.com",
        "sub": "worker",
        "aud": ["my-service", "other-service"],
        "exp": now + 300,
        "iat": now,
    });
    let token = sign_jwt(&private_der, &kid, &claims);

    let header = format!("Bearer {token}");
    let identity = validate_bearer_token(Some(&header), &config)
        .expect("array aud should validate")
        .expect("identity must be produced");
    assert_eq!(
        identity.audiences,
        vec!["my-service".to_string(), "other-service".to_string()],
        "array aud claim must populate audiences in order"
    );
}

#[test]
fn wrong_audience_returns_jwt_error() {
    let (private_der, jwks, kid) = rsa_keypair();
    let config = make_config(jwks);
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": "https://accounts.example.com",
        "sub": "worker",
        "aud": "wrong-service",
        "exp": now + 300,
        "iat": now,
    });
    let token = sign_jwt(&private_der, &kid, &claims);

    let header = format!("Bearer {token}");
    let result = validate_bearer_token(Some(&header), &config);
    assert!(matches!(result, Err(BearerError::Jwt(_))));
}

#[test]
fn expired_token_returns_jwt_error() {
    let (private_der, jwks, kid) = rsa_keypair();
    let config = make_config(jwks);
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": "https://accounts.example.com",
        "sub": "worker",
        "aud": "my-service",
        "exp": now - 300,
        "iat": now - 600,
    });
    let token = sign_jwt(&private_der, &kid, &claims);

    let header = format!("Bearer {token}");
    let result = validate_bearer_token(Some(&header), &config);
    assert!(matches!(result, Err(BearerError::Jwt(_))));
}

#[test]
fn garbage_token_returns_invalid_token() {
    let config = make_config(JwkSet { keys: vec![] });
    let result = validate_bearer_token(Some("Bearer not.a.jwt!"), &config);
    assert!(matches!(result, Err(BearerError::InvalidToken(_))));
}

#[test]
fn missing_iss_claim_returns_error() {
    let (private_der, jwks, kid) = rsa_keypair();
    let config = make_config(jwks);
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "sub": "worker",
        "aud": "my-service",
        "exp": now + 300,
        "iat": now,
    });
    let token = sign_jwt(&private_der, &kid, &claims);

    let header = format!("Bearer {token}");
    let result = validate_bearer_token(Some(&header), &config);
    assert!(matches!(result, Err(BearerError::MissingIssuer)));
}

#[test]
fn extra_claims_only_captures_configured_keys() {
    let (private_der, jwks, kid) = rsa_keypair();
    let config = make_config(jwks);
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": "https://accounts.example.com",
        "sub": "worker",
        "aud": "my-service",
        "exp": now + 300,
        "iat": now,
        "namespace": "staging",
        "secret_field": "should-not-appear"
    });
    let token = sign_jwt(&private_der, &kid, &claims);

    let header = format!("Bearer {token}");
    let identity = validate_bearer_token(Some(&header), &config)
        .unwrap()
        .unwrap();
    assert_eq!(
        identity.claims.get("namespace"),
        Some(&"staging".to_string())
    );
    assert!(!identity.claims.contains_key("secret_field"));
}
