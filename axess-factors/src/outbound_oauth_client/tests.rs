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
    .expect("an HTTPS or loopback token URL")
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
    .expect("an HTTPS or loopback token URL")
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
    .expect("an HTTPS or loopback token URL")
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
    // Match on the exact Authorization header value. RFC 6749 §2.3.1
    // form-urlencodes id and secret before the Basic encoding, so the `+`
    // travels as `%2B`: base64("axess-id:Gnomes2%2B").
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .and(header(
            "authorization",
            "Basic YXhlc3MtaWQ6R25vbWVzMiUyQg==",
        ))
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
    )
    .expect("an HTTPS or loopback token URL");
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
    )
    .expect("an HTTPS or loopback token URL");
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
    )
    .expect("an HTTPS or loopback token URL");
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
    )
    .expect("an HTTPS or loopback token URL");
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
    .expect("an HTTPS or loopback token URL")
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
    )
    .expect("an HTTPS or loopback token URL");
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
    // Raw components rather than PEM: `DecodingKey::from_rsa_pem` sits
    // behind `jsonwebtoken`'s `use_pem` feature, which this workspace
    // does not enable because no production path parses a PEM through
    // `jsonwebtoken` (`LocalIdpSigningKey` uses the `rsa` / `p256`
    // crates directly). Taking it here would put `pem` + `simple_asn1`
    // in every adopter's build for one assertion.
    use rsa::traits::PublicKeyParts;
    let decoding_key = jsonwebtoken::DecodingKey::from_rsa_raw_components(
        &public_key.n().to_bytes_be(),
        &public_key.e().to_bytes_be(),
    );
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
    .expect("an HTTPS or loopback token URL")
    .with_scopes(["read", "write"]);
    let _ = client.get_access_token().await.expect("scope sent");
}

#[tokio::test]
async fn out_of_range_expires_in_is_refused() {
    for body in [
        r#"{"access_token":"t","expires_in":10000000000000000}"#,
        r#"{"access_token":"t","expires_in":18446744073709551615}"#,
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .mount(&server)
            .await;
        let client = OutboundOAuthClient::new(
            token_url(&server),
            ClientAuthMethod::ClientSecretBasic {
                client_id: "axess".into(),
                client_secret: "shh".into(),
            },
        )
        .expect("an HTTPS or loopback token URL");
        let err = client.get_access_token().await.expect_err("refused");
        assert!(
            matches!(err, OAuthClientError::MalformedResponse(_)),
            "got {err:?}"
        );
    }
}

// ── transport rail, timeouts and single flight ───────────────────────────────

fn basic() -> ClientAuthMethod {
    ClientAuthMethod::ClientSecretBasic {
        client_id: "axess".into(),
        client_secret: "shh".into(),
    }
}

/// A token URL that is not HTTPS, other than loopback, is refused before the
/// client secret can be sent anywhere.
#[test]
fn a_plain_http_token_url_to_a_remote_host_is_refused() {
    for url in [
        "http://idp.example.net/token",
        "http://localhost.evil.example/token",
        "http://localhost@evil.example/token",
        "ftp://idp.example.net/token",
    ] {
        let refused = OutboundOAuthClient::new(Url::parse(url).unwrap(), basic());
        assert!(
            matches!(refused, Err(OAuthClientError::InsecureEndpoint)),
            "{url} must be refused"
        );
    }
    for url in [
        "https://idp.example.net/token",
        "http://localhost:8080/token",
        "http://127.0.0.1/token",
        "http://[::1]:9/token",
    ] {
        assert!(
            OutboundOAuthClient::new(Url::parse(url).unwrap(), basic()).is_ok(),
            "{url} must be accepted"
        );
    }
}

/// The default client follows no redirect: a 307 from the token endpoint is
/// an error response, and the credentials are not sent to its `Location`.
#[tokio::test]
async fn a_redirecting_token_endpoint_is_an_error_and_the_target_is_never_called() {
    let target = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "stolen", "expires_in": 60
        })))
        .mount(&target)
        .await;
    let origin = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("location", format!("{}/capture", target.uri())),
        )
        .mount(&origin)
        .await;

    let client = OutboundOAuthClient::new(token_url(&origin), basic()).unwrap();
    let err = client
        .get_access_token()
        .await
        .expect_err("a redirect is an error");
    assert!(
        matches!(err, OAuthClientError::TokenEndpoint { status: 307, .. }),
        "got {err:?}"
    );
    assert!(
        target.received_requests().await.unwrap().is_empty(),
        "the redirect target must never be called"
    );
}

/// A token endpoint that never answers fails the fetch at the request
/// timeout and releases the gate, instead of holding every caller forever.
#[tokio::test]
async fn a_hung_token_endpoint_times_out_and_releases_the_gate() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "access_token": "late", "expires_in": 60 }))
                .set_delay(Duration::from_secs(5)),
        )
        .mount(&server)
        .await;
    let client = OutboundOAuthClient::new(token_url(&server), basic())
        .unwrap()
        .with_request_timeout(Duration::from_millis(100));

    let started = std::time::Instant::now();
    let err = client.get_access_token().await.expect_err("times out");
    assert!(matches!(err, OAuthClientError::Transport(_)), "got {err:?}");
    assert!(started.elapsed() < Duration::from_secs(3));

    // The gate is free: the next caller is not stuck behind the first.
    let again = tokio::time::timeout(Duration::from_secs(3), client.get_access_token()).await;
    assert!(again.expect("the second call must not hang").is_err());
}

/// A token whose lifetime is at or under the refresh threshold is cached for
/// half its life, instead of being fetched anew on every call.
#[tokio::test]
async fn a_short_lived_token_is_cached_for_half_its_life() {
    let server = token_server_returning(json!({
        "access_token": "short", "token_type": "Bearer", "expires_in": 20
    }))
    .await;
    let clock = Arc::new(MockClock::at(t0()));
    // Threshold 30 s against a 20 s token: previously due at once.
    let client = OutboundOAuthClient::new(token_url(&server), basic())
        .unwrap()
        .with_clock(clock.clone())
        .with_refresh_threshold(Duration::from_secs(30));

    assert_eq!(client.get_access_token().await.unwrap(), "short");
    clock.advance_secs(5);
    assert_eq!(client.get_access_token().await.unwrap(), "short");
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "five seconds into a twenty-second token is still cached"
    );

    clock.advance_secs(6);
    client.get_access_token().await.unwrap();
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        2,
        "past half its life the refresh is due"
    );
}

/// Callers that arrive together after a `401` share one fetch.
#[tokio::test]
async fn concurrent_force_refreshes_share_one_fetch() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "access_token": "fresh", "expires_in": 3600 }))
                .set_delay(Duration::from_millis(150)),
        )
        .mount(&server)
        .await;
    let client = Arc::new(OutboundOAuthClient::new(token_url(&server), basic()).unwrap());

    let calls: Vec<_> = (0..8)
        .map(|_| {
            let client = Arc::clone(&client);
            tokio::spawn(async move { client.force_refresh().await })
        })
        .collect();
    for call in calls {
        assert_eq!(call.await.unwrap().unwrap(), "fresh");
    }
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "eight simultaneous force_refresh calls are one fetch"
    );
}

/// While one caller refreshes a token that is due but not expired, the others
/// are served the cached token without waiting for the fetch.
#[tokio::test]
async fn callers_are_served_the_unexpired_token_while_a_refresh_is_in_flight() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "access_token": "first", "expires_in": 100 })),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "access_token": "second", "expires_in": 100 }))
                .set_delay(Duration::from_millis(400)),
        )
        .mount(&server)
        .await;
    let clock = Arc::new(MockClock::at(t0()));
    let client = Arc::new(
        OutboundOAuthClient::new(token_url(&server), basic())
            .unwrap()
            .with_clock(clock.clone())
            .with_refresh_threshold(Duration::from_secs(30)),
    );
    assert_eq!(client.get_access_token().await.unwrap(), "first");

    // Due (t0 + 75 > refresh_at 70) but not expired (< 100).
    clock.advance_secs(75);
    let refresher = {
        let client = Arc::clone(&client);
        tokio::spawn(async move { client.get_access_token().await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;

    let started = std::time::Instant::now();
    let served = client.get_access_token().await.unwrap();
    assert_eq!(served, "first", "served from the cache");
    assert!(
        started.elapsed() < Duration::from_millis(250),
        "must not wait for the fetch in flight ({:?})",
        started.elapsed()
    );
    assert_eq!(refresher.await.unwrap().unwrap(), "second");
}
