//!  Phase 3: tests for the outbound OAuth client.
//!
//! Token endpoint is stood up via `wiremock`. Caching + refresh
//! behaviour is exercised against an injected [`MockClock`] so the
//! tests are deterministic.

use super::*;
use axess_clock::testing::MockClock;
use chrono::{DateTime, Utc};
use serde_json::json;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn t0() -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000, 0).expect("fixed t0")
}

async fn token_server_returning(body: serde_json::Value) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;
    server
}

fn token_url(server: &MockServer) -> Url {
    Url::parse(&format!("{}/oauth2/token", server.uri())).expect("token URL")
}

#[tokio::test]
async fn first_call_fetches_and_caches() {
    let server = token_server_returning(json!({
        "access_token": "tok-alpha",
        "token_type": "Bearer",
        "expires_in": 3600,
    }))
    .await;

    let clock = Arc::new(MockClock::at(t0()));
    let client = OutboundOAuthClient::new(
        token_url(&server),
        ClientAuthMethod::ClientSecretBasic {
            client_id: "axess-feed-worker".into(),
            client_secret: "shh".into(),
        },
    )
    .with_clock(clock.clone());

    let token = client.get_access_token().await.expect("must fetch token");
    assert_eq!(token, "tok-alpha");

    // Second call; should hit cache, not the server. wiremock would
    // panic on .verify() if an unexpected request landed.
    let token2 = client.get_access_token().await.expect("cache hit");
    assert_eq!(token2, "tok-alpha");

    // Exactly one POST to /oauth2/token.
    let received = server.received_requests().await.expect("requests");
    assert_eq!(received.len(), 1, "cache hit must not re-fetch");
}

#[tokio::test]
async fn cached_token_refreshes_when_clock_advances_past_threshold() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok-first",
            "token_type": "Bearer",
            "expires_in": 100,
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok-second",
            "token_type": "Bearer",
            "expires_in": 100,
        })))
        .mount(&server)
        .await;

    let clock = Arc::new(MockClock::at(t0()));
    let client = OutboundOAuthClient::new(
        token_url(&server),
        ClientAuthMethod::ClientSecretBasic {
            client_id: "axess".into(),
            client_secret: "shh".into(),
        },
    )
    .with_clock(clock.clone())
    .with_refresh_threshold(Duration::from_secs(30));

    let t1 = client.get_access_token().await.expect("first fetch");
    assert_eq!(t1, "tok-first");

    // Token has expires_in=100, refresh_threshold=30 → refresh due at
    // t0 + 70. Advancing 60s should NOT trigger refresh.
    clock.advance_secs(60);
    let t2 = client.get_access_token().await.expect("still cached");
    assert_eq!(t2, "tok-first", "60s in is still inside the cache window");

    // Advancing another 15s puts us at t0 + 75, past the refresh-due
    // mark. Now we expect a fresh fetch.
    clock.advance_secs(15);
    let t3 = client.get_access_token().await.expect("refresh");
    assert_eq!(t3, "tok-second", "past refresh threshold must refresh");
}

#[tokio::test]
async fn force_refresh_bypasses_cache() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok-a",
            "expires_in": 3600,
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok-b",
            "expires_in": 3600,
        })))
        .mount(&server)
        .await;

    let clock = Arc::new(MockClock::at(t0()));
    let client = OutboundOAuthClient::new(
        token_url(&server),
        ClientAuthMethod::ClientSecretBasic {
            client_id: "axess".into(),
            client_secret: "shh".into(),
        },
    )
    .with_clock(clock.clone());

    let first = client.get_access_token().await.expect("first");
    assert_eq!(first, "tok-a");

    // Cache is still valid (3600s lifetime), but force_refresh must
    // ignore that.
    let second = client.force_refresh().await.expect("force refresh");
    assert_eq!(second, "tok-b");

    // Subsequent get_access_token returns the refreshed (cached) value.
    let third = client.get_access_token().await.expect("now cached");
    assert_eq!(third, "tok-b");
}

#[tokio::test]
async fn client_secret_basic_sends_authorization_header() {
    let server = MockServer::start().await;
    // Match on the exact Authorization header value.
    // base64("axess-id:Gnomes2+") = "YXhlc3MtaWQ6R25vbWVzMis=".
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .and(header("authorization", "Basic YXhlc3MtaWQ6R25vbWVzMis="))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok",
            "expires_in": 3600,
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = OutboundOAuthClient::new(
        token_url(&server),
        ClientAuthMethod::ClientSecretBasic {
            client_id: "axess-id".into(),
            client_secret: "Gnomes2+".into(),
        },
    );
    let _ = client.get_access_token().await.expect("auth header sent");
    // MockServer drop-time check enforces the .expect(1).
}

#[tokio::test]
async fn client_secret_post_sends_secret_in_form_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .and(body_string_contains("client_id=axess-id"))
        // `+` in a form value URL-encodes to `%2B` on the wire.
        .and(body_string_contains("client_secret=Gnomes2%2B"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok",
            "expires_in": 3600,
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = OutboundOAuthClient::new(
        token_url(&server),
        ClientAuthMethod::ClientSecretPost {
            client_id: "axess-id".into(),
            client_secret: "Gnomes2+".into(),
        },
    );
    let _ = client
        .get_access_token()
        .await
        .expect("secret-in-body sent");
}

#[tokio::test]
async fn token_endpoint_error_status_propagates() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "invalid_client",
            "error_description": "rotated secret",
        })))
        .mount(&server)
        .await;

    let client = OutboundOAuthClient::new(
        token_url(&server),
        ClientAuthMethod::ClientSecretBasic {
            client_id: "axess".into(),
            client_secret: "wrong".into(),
        },
    );
    let err = client
        .get_access_token()
        .await
        .expect_err("401 must propagate");
    match err {
        OAuthClientError::TokenEndpoint { status, body } => {
            assert_eq!(status, 401);
            assert!(body.contains("invalid_client"));
        }
        other => panic!("expected TokenEndpoint, got {other:?}"),
    }
}

#[tokio::test]
async fn malformed_token_response_rejected() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(
            // 200 but no `access_token` field.
            ResponseTemplate::new(200).set_body_json(json!({
                "expires_in": 3600,
            })),
        )
        .mount(&server)
        .await;
    let client = OutboundOAuthClient::new(
        token_url(&server),
        ClientAuthMethod::ClientSecretBasic {
            client_id: "axess".into(),
            client_secret: "shh".into(),
        },
    );
    let err = client
        .get_access_token()
        .await
        .expect_err("missing access_token must reject");
    assert!(
        matches!(err, OAuthClientError::MalformedResponse(_)),
        "expected MalformedResponse, got {err:?}"
    );
}

#[tokio::test]
async fn missing_expires_in_defaults_to_one_hour() {
    let server = token_server_returning(json!({
        "access_token": "tok-no-exp",
    }))
    .await;

    let clock = Arc::new(MockClock::at(t0()));
    let client = OutboundOAuthClient::new(
        token_url(&server),
        ClientAuthMethod::ClientSecretBasic {
            client_id: "axess".into(),
            client_secret: "shh".into(),
        },
    )
    .with_clock(clock.clone());

    let t1 = client.get_access_token().await.expect("first");
    assert_eq!(t1, "tok-no-exp");

    // 30 minutes in; well inside the 1-hour default.
    clock.advance_secs(30 * 60);
    let t2 = client.get_access_token().await.expect("cached");
    assert_eq!(t2, "tok-no-exp");
    let received = server.received_requests().await.expect("rcv");
    assert_eq!(received.len(), 1, "default 1h lifetime must hold");
}

#[tokio::test]
async fn private_key_jwt_sends_signed_client_assertion() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rsa::RsaPrivateKey;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::EncodePublicKey;

    let mut rng = rsa::rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
    let public_key = private_key.to_public_key();
    let der = private_key
        .to_pkcs1_der()
        .expect("pkcs1 der")
        .as_bytes()
        .to_vec();

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .and(body_string_contains(
            "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer",
        ))
        .and(body_string_contains("client_assertion="))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "tok-jwt",
                "expires_in": 3600,
            })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = OutboundOAuthClient::new(
        token_url(&server),
        ClientAuthMethod::PrivateKeyJwt {
            client_id: "axess-fapi".into(),
            signing_key: jsonwebtoken::EncodingKey::from_rsa_der(&der),
            algorithm: jsonwebtoken::Algorithm::RS256,
            key_id: Some("kid-1".into()),
            audience: format!("{}/oauth2/token", server.uri()),
            assertion_ttl: Duration::from_secs(60),
        },
    );
    let token = client.get_access_token().await.expect("jwt assertion sent");
    assert_eq!(token, "tok-jwt");

    // Sanity-pluck the assertion JWT from the recorded request body.
    let req = &server
        .received_requests()
        .await
        .expect("rcv")
        .first()
        .expect("at least one request")
        .body
        .clone();
    let body = String::from_utf8(req.clone()).expect("utf8 body");
    let assertion_param = body
        .split('&')
        .find(|p| p.starts_with("client_assertion="))
        .expect("client_assertion in body");
    let assertion = assertion_param
        .strip_prefix("client_assertion=")
        .expect("strip prefix");

    // Header + payload should decode and roundtrip the claims.
    let parts: Vec<&str> = assertion.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT must have three dot-separated parts");
    let header_json = URL_SAFE_NO_PAD.decode(parts[0]).expect("base64 header");
    let header_val: serde_json::Value = serde_json::from_slice(&header_json).expect("json header");
    assert_eq!(header_val["alg"], "RS256");
    assert_eq!(header_val["kid"], "kid-1");

    let payload_json = URL_SAFE_NO_PAD.decode(parts[1]).expect("base64 payload");
    let payload: serde_json::Value = serde_json::from_slice(&payload_json).expect("json payload");
    assert_eq!(payload["iss"], "axess-fapi");
    assert_eq!(payload["sub"], "axess-fapi");
    assert_eq!(
        payload["aud"].as_str().unwrap(),
        format!("{}/oauth2/token", server.uri())
    );
    assert!(payload["jti"].is_string());
    assert!(payload["exp"].is_number());
    assert!(payload["iat"].is_number());

    // Sanity: the assertion is verifiable against the actual public
    // key. Confirms axess didn't accidentally sign with a different
    // key or send a malformed signature.
    let pem = public_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .expect("public key pem");
    let decoding_key =
        jsonwebtoken::DecodingKey::from_rsa_pem(pem.as_bytes()).expect("decoding key");
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[format!("{}/oauth2/token", server.uri())]);
    let _ = jsonwebtoken::decode::<serde_json::Value>(assertion, &decoding_key, &validation)
        .expect("signature verifies");
}

#[tokio::test]
async fn scopes_are_sent_in_form_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .and(body_string_contains("scope=read+write"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok",
            "expires_in": 3600,
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = OutboundOAuthClient::new(
        token_url(&server),
        ClientAuthMethod::ClientSecretBasic {
            client_id: "axess".into(),
            client_secret: "shh".into(),
        },
    )
    .with_scopes(["read", "write"]);
    let _ = client.get_access_token().await.expect("scope sent");
}
