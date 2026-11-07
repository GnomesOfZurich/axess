//! `tests`: extracted from `bearer.rs` per the
//! 200-LoC inline-test rule in AGENTS.md.

use super::*;

// ── extract_bearer_token ────────────────────────────────────────���────

#[test]
fn extract_bearer_token_valid() {
    assert_eq!(
        extract_bearer_token(Some("Bearer eyJhbGciOiJSUzI1NiJ9.abc.def")).unwrap(),
        Some("eyJhbGciOiJSUzI1NiJ9.abc.def")
    );
}

#[test]
fn extract_bearer_token_missing_header() {
    assert_eq!(extract_bearer_token(None).unwrap(), None);
}

#[test]
fn extract_bearer_token_wrong_scheme() {
    assert_eq!(
        extract_bearer_token(Some("Basic dXNlcjpwYXNz")).unwrap(),
        None
    );
}

/// A header that names the scheme and carries no token is malformed, not
/// absent: it is refused rather than served as anonymous.
#[test]
fn a_bearer_header_without_a_token_is_refused() {
    let config = BearerConfig::new(Vec::new());
    for header in ["Bearer", "Bearer ", "Bearer   ", "bearer\t", "Bearer\t\t "] {
        assert!(
            matches!(
                validate_bearer_token(Some(header), &config),
                Err(BearerError::InvalidToken(_))
            ),
            "{header:?}"
        );
    }
}

/// A tab between the scheme and the token is whitespace, not part of the
/// scheme, so the token is read (and judged) rather than the header ignored.
#[test]
fn a_tab_after_the_scheme_separates_the_token() {
    let config = BearerConfig::new(Vec::new());
    assert!(matches!(
        validate_bearer_token(Some("Bearer\tnot.a.jwt!"), &config),
        Err(BearerError::InvalidToken(_))
    ));
}

#[tokio::test]
async fn the_layer_answers_401_for_a_bearer_header_without_a_token() {
    for header in ["Bearer", "Bearer ", "Bearer   "] {
        let res = through_layer(header, BearerConfig::new(Vec::new())).await;
        assert_eq!(
            res.status(),
            axum::http::StatusCode::UNAUTHORIZED,
            "{header:?}"
        );
    }
}

#[test]
fn extract_bearer_token_no_space_after_bearer() {
    assert_eq!(extract_bearer_token(Some("Bearertoken")).unwrap(), None);
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
    // Signing needs a provider as much as verifying does, and under
    // `--all-features` jsonwebtoken has no default. Verification installs one
    // itself; a signer asks.
    crate::jwt::ensure_crypto_provider();
    let key = EncodingKey::from_rsa_der(private_der);
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(kid.to_string());
    encode(&header, claims, &key).expect("JWT encode")
}

fn make_config(jwks: JwkSet) -> BearerConfig {
    BearerConfig::new(vec![BearerIssuerConfig {
        issuer: "https://accounts.example.com".to_string(),
        audience: Audience::Exact("my-service".to_string()),
        jwks: Arc::new(jwks),
        extra_claims: vec!["namespace".to_string()],
    }])
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

// ── injected clock ───────────────────────────────────────────────────

/// 2020-09-13T12:26:40Z, years before any real wall clock this suite runs on.
const MOCK_EPOCH: i64 = 1_600_000_000;

fn mock_clock() -> Arc<axess_clock::testing::MockClock> {
    use chrono::TimeZone;
    Arc::new(axess_clock::testing::MockClock::at(
        chrono::Utc.timestamp_opt(MOCK_EPOCH, 0).unwrap(),
    ))
}

fn claims_expiring_at(exp: i64) -> serde_json::Value {
    serde_json::json!({
        "iss": "https://accounts.example.com",
        "sub": "worker",
        "aud": "my-service",
        "exp": exp,
        "nbf": exp - 300,
    })
}

#[test]
fn token_is_judged_against_the_injected_clock_not_the_wall_clock() {
    let (private_der, jwks, kid) = rsa_keypair();
    let clock = mock_clock();
    let config = make_config(jwks).with_clock(clock.clone());
    // `exp` is years in the real past: the wall clock would call it expired.
    let token = sign_jwt(&private_der, &kid, &claims_expiring_at(MOCK_EPOCH + 300));
    let header = format!("Bearer {token}");

    let identity = validate_bearer_token(Some(&header), &config)
        .expect("a token inside its life on the injected clock is accepted")
        .expect("identity");
    assert_eq!(identity.subject, "worker");

    // Past `exp` plus the 60 s default leeway.
    clock.advance_secs(300 + 61);
    let result = validate_bearer_token(Some(&header), &config);
    assert!(
        matches!(&result, Err(BearerError::Jwt(e)) if e.to_string().contains("token expired")),
        "advancing the injected clock past exp must expire the token: {result:?}"
    );
}

#[test]
fn nbf_is_judged_against_the_injected_clock() {
    let (private_der, jwks, kid) = rsa_keypair();
    let clock = mock_clock();
    let config = make_config(jwks).with_clock(clock.clone());
    let mut claims = claims_expiring_at(MOCK_EPOCH + 3600);
    claims["nbf"] = serde_json::json!(MOCK_EPOCH + 600);
    let header = format!("Bearer {}", sign_jwt(&private_der, &kid, &claims));

    let early = validate_bearer_token(Some(&header), &config);
    assert!(
        matches!(&early, Err(BearerError::Jwt(e)) if e.to_string().contains("not yet valid")),
        "nbf in the injected future must be refused: {early:?}"
    );

    clock.advance_secs(600);
    assert!(
        validate_bearer_token(Some(&header), &config)
            .unwrap()
            .is_some()
    );
}

#[test]
fn layer_clock_replaces_the_configured_clock() {
    let (private_der, jwks, kid) = rsa_keypair();
    let config = make_config(jwks);
    let token = sign_jwt(&private_der, &kid, &claims_expiring_at(MOCK_EPOCH + 300));
    let header = format!("Bearer {token}");

    assert!(
        validate_bearer_token(Some(&header), &config).is_err(),
        "the default system clock sees this token as long expired"
    );
    let layer = BearerTokenLayer::new(config).with_clock(mock_clock());
    assert!(
        validate_bearer_token(Some(&header), &layer.config)
            .unwrap()
            .is_some()
    );
}

// ── layer response ───────────────────────────────────────────────────

async fn through_layer(authorization: &str, config: BearerConfig) -> axum::response::Response {
    use tower::{Layer, ServiceExt};
    let inner = tower::service_fn(|_req: axum::http::Request<axum::body::Body>| async {
        Ok::<_, std::convert::Infallible>(axum::response::Response::new(axum::body::Body::empty()))
    });
    let service = BearerTokenLayer::new(config).layer(inner);
    let req = axum::http::Request::builder()
        .header(axum::http::header::AUTHORIZATION, authorization)
        .body(axum::body::Body::empty())
        .unwrap();
    service.oneshot(req).await.unwrap()
}

/// Whatever check failed, the client sees the same fixed body and challenge,
/// so the response is no probe for which of kid, audience or lifetime was
/// wrong; the reason is only in the log.
#[tokio::test]
async fn every_rejection_answers_with_the_same_fixed_body() {
    let (der, jwks, kid) = rsa_keypair();
    let mut wrong_aud = valid_claims();
    wrong_aud["aud"] = serde_json::json!("another-service");
    let mut expired = valid_claims();
    expired["exp"] = serde_json::json!(chrono::Utc::now().timestamp() - 3600);

    let mut bodies = Vec::new();
    for token in [
        sign_jwt(&der, &kid, &wrong_aud),
        sign_jwt(&der, &kid, &expired),
        sign_jwt(&der, "unknown-kid", &valid_claims()),
        "not.a.jwt".to_owned(),
    ] {
        let res = through_layer(&format!("Bearer {token}"), make_config(jwks.clone())).await;
        assert_eq!(res.status(), axum::http::StatusCode::UNAUTHORIZED);
        assert_eq!(
            res.headers()[axum::http::header::WWW_AUTHENTICATE],
            r#"Bearer error="invalid_token""#
        );
        let body = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
        bodies.push(String::from_utf8(body.to_vec()).unwrap());
    }
    assert!(
        bodies.iter().all(|b| b == r#"{"error":"invalid_token"}"#),
        "{bodies:?}"
    );
}

/// The constructor requires an audience and the token must carry it.
#[test]
fn the_issuer_constructor_pins_an_audience() {
    let (der, jwks, kid) = rsa_keypair();
    let config = BearerConfig::new(vec![
        BearerIssuerConfig::new("https://accounts.example.com", "my-service", Arc::new(jwks))
            .with_extra_claims(["namespace"]),
    ]);
    let header = format!("Bearer {}", sign_jwt(&der, &kid, &valid_claims()));
    let identity = validate_bearer_token(Some(&header), &config)
        .unwrap()
        .unwrap();
    assert_eq!(
        identity.claims.get("namespace").map(String::as_str),
        Some("production")
    );
    let mut other = valid_claims();
    other["aud"] = serde_json::json!("elsewhere");
    let header = format!("Bearer {}", sign_jwt(&der, &kid, &other));
    assert!(validate_bearer_token(Some(&header), &config).is_err());
}

/// Skipping the audience check is an explicit, loudly named choice. A
/// token for another audience is refused unless the issuer was configured
/// with `Audience::AnyDangerous`.
#[test]
fn any_audience_is_an_explicit_dangerous_choice() {
    let (private_der, jwks, kid) = rsa_keypair();
    let jwks = Arc::new(jwks);
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": "https://accounts.example.com",
        "sub": "worker",
        "aud": "some-other-service",
        "exp": now + 300,
        "iat": now,
    });
    let header = format!("Bearer {}", sign_jwt(&private_der, &kid, &claims));

    let pinned = BearerConfig::new(vec![BearerIssuerConfig::new(
        "https://accounts.example.com",
        "my-service",
        jwks.clone(),
    )]);
    assert!(
        matches!(
            validate_bearer_token(Some(&header), &pinned),
            Err(BearerError::Jwt(_))
        ),
        "a token for another audience is refused by default"
    );

    let any = BearerConfig::new(vec![BearerIssuerConfig {
        issuer: "https://accounts.example.com".to_string(),
        audience: Audience::AnyDangerous,
        jwks,
        extra_claims: Vec::new(),
    }]);
    let identity = validate_bearer_token(Some(&header), &any)
        .expect("validates")
        .expect("a bearer token is present");
    assert_eq!(identity.audiences, vec!["some-other-service"]);
}

// ── several configs for one issuer ───────────────────────────────────

/// Two configs may name the same issuer (an old and a new key set, or one
/// per audience). A token the first one cannot verify is tried against the
/// next.
#[test]
fn a_token_is_tried_against_every_config_for_its_issuer() {
    let (_other_der, other_jwks, _) = rsa_keypair();
    let (der, jwks, kid) = rsa_keypair();
    let issuer = |jwks: JwkSet| BearerIssuerConfig {
        issuer: "https://accounts.example.com".to_string(),
        audience: Audience::Exact("my-service".to_string()),
        jwks: Arc::new(jwks),
        extra_claims: Vec::new(),
    };
    // The key that signed the token is the second config's.
    let config = BearerConfig::new(vec![issuer(other_jwks), issuer(jwks)]);
    let token = sign_jwt(&der, &kid, &valid_claims());
    let identity = validate_bearer_token(Some(&format!("Bearer {token}")), &config)
        .expect("the second config verifies it")
        .expect("an identity");
    assert_eq!(identity.issuer, "https://accounts.example.com");
}

/// When no config for the issuer verifies the token, it is refused.
#[test]
fn a_token_no_config_for_its_issuer_verifies_is_refused() {
    let (_o1, jwks_a, _) = rsa_keypair();
    let (_o2, jwks_b, _) = rsa_keypair();
    let (der, _jwks, kid) = rsa_keypair();
    let issuer = |jwks: JwkSet| BearerIssuerConfig {
        issuer: "https://accounts.example.com".to_string(),
        audience: Audience::Exact("my-service".to_string()),
        jwks: Arc::new(jwks),
        extra_claims: Vec::new(),
    };
    let config = BearerConfig::new(vec![issuer(jwks_a), issuer(jwks_b)]);
    let token = sign_jwt(&der, &kid, &valid_claims());
    assert!(matches!(
        validate_bearer_token(Some(&format!("Bearer {token}")), &config),
        Err(BearerError::Jwt(_))
    ));
}

// ── the Authorization header ─────────────────────────────────────────

/// Send `value` through the layer with a handler that reports whether a
/// workload identity arrived; the status is the layer's own.
async fn through_layer_raw(
    value: axum::http::HeaderValue,
    config: BearerConfig,
) -> (axum::http::StatusCode, bool) {
    use tower::{Layer, ServiceExt};
    let inner = tower::service_fn(|req: axum::http::Request<axum::body::Body>| async move {
        let has = req.extensions().get::<WorkloadIdentity>().is_some();
        let mut res = axum::response::Response::new(axum::body::Body::empty());
        res.extensions_mut().insert(has);
        Ok::<_, std::convert::Infallible>(res)
    });
    let service = BearerTokenLayer::new(config).layer(inner);
    let req = axum::http::Request::builder()
        .header(axum::http::header::AUTHORIZATION, value)
        .body(axum::body::Body::empty())
        .unwrap();
    let res = service.oneshot(req).await.unwrap();
    let has = res.extensions().get::<bool>().copied().unwrap_or(false);
    (res.status(), has)
}

/// A header that is not valid text carries a credential nobody can read,
/// so it is refused; passing the request on unauthenticated would let a
/// mangled token read as no token.
#[tokio::test]
async fn an_authorization_header_that_is_not_text_is_refused() {
    let (_der, jwks, _kid) = rsa_keypair();
    let value = axum::http::HeaderValue::from_bytes(b"Bearer \xff\xfe").unwrap();
    let (status, _) = through_layer_raw(value, make_config(jwks)).await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
}

/// RFC 7235 section 2.1: the scheme is case-insensitive, and RFC 7230
/// allows more than one space after it.
#[tokio::test]
async fn the_bearer_scheme_is_case_insensitive_and_spaces_are_trimmed() {
    let (der, jwks, kid) = rsa_keypair();
    let token = sign_jwt(&der, &kid, &valid_claims());
    for header in [
        format!("bearer {token}"),
        format!("BEARER {token}"),
        format!("Bearer   {token}"),
        format!("Bearer {token} "),
    ] {
        let value = axum::http::HeaderValue::from_str(&header).unwrap();
        let (status, has) = through_layer_raw(value, make_config(jwks.clone())).await;
        assert_eq!(status, axum::http::StatusCode::OK, "{header}");
        assert!(has, "{header} reads as the token it carries");
    }
}

/// The issuer of a token nobody has verified is the attacker's text: the
/// error carries a bounded, escaped copy, not the whole of it.
#[test]
fn an_untrusted_issuer_is_echoed_bounded_and_escaped() {
    let (private_der, jwks, kid) = rsa_keypair();
    let config = make_config(jwks);
    let mut claims = valid_claims();
    // Far past the echo cap, and inside the token size limit so the issuer
    // check, not the size check, is what refuses it.
    let forged = format!("evil\nWARN forged line\r\u{1b}[31m{}", "x".repeat(4 * 1024));
    claims["iss"] = serde_json::json!(forged);
    let token = sign_jwt(&private_der, &kid, &claims);

    let header = format!("Bearer {token}");
    let err = validate_bearer_token(Some(&header), &config).unwrap_err();

    let text = err.to_string();
    assert!(matches!(err, BearerError::UntrustedIssuer(_)), "{text}");
    assert!(
        text.len() <= "untrusted issuer: ".len() + MAX_ISSUER_ECHO_BYTES + 64,
        "the error carries {} bytes",
        text.len()
    );
    assert!(!text.chars().any(char::is_control), "{text:?}");
    assert!(text.ends_with("..."), "the cut is marked: {text}");
}

#[test]
fn a_short_issuer_is_echoed_whole_and_a_cut_keeps_characters_whole() {
    assert_eq!(
        echo_issuer("https://evil.example.com"),
        "https://evil.example.com"
    );
    let multibyte = "é".repeat(MAX_ISSUER_ECHO_BYTES);
    let echoed = echo_issuer(&multibyte);
    assert!(echoed.ends_with("..."));
    assert!(echoed.trim_end_matches("...").chars().all(|c| c == 'é'));
}
