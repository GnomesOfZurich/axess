//! What the client takes from the token endpoint's answer: refusals, a body
//! that does not parse, the token's lifetime and its type.

use super::*;

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

    let client = loopback_new(
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

/// The body of a token endpoint's refusal reaches the error with control
/// characters and the Unicode line separators escaped.
#[tokio::test]
async fn a_token_endpoint_error_body_is_log_safe() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(503).set_body_raw(
            "unavailable\r\nINFO forged line\x1b[2J\u{2028}",
            "text/plain",
        ))
        .mount(&server)
        .await;

    let client = loopback_new(
        token_url(&server),
        ClientAuthMethod::ClientSecretBasic {
            client_id: "axess".into(),
            client_secret: "secret".into(),
        },
    )
    .expect("an HTTPS or loopback token URL");
    let err = client
        .get_access_token()
        .await
        .expect_err("503 must propagate");
    let OAuthClientError::TokenEndpoint { body, .. } = &err else {
        panic!("expected TokenEndpoint, got {err:?}");
    };
    assert!(!body.chars().any(char::is_control), "{body:?}");
    assert!(!body.contains('\u{2028}'), "{body:?}");
    assert!(
        body.contains("unavailable") && body.contains("forged line"),
        "{body}"
    );
}

/// A huge error body reaches the error cut at the reader's cap with its
/// truncation suffix, which the sanitiser does not cut off.
#[tokio::test]
async fn a_huge_token_endpoint_error_body_keeps_its_truncation_suffix() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(
            ResponseTemplate::new(503).set_body_raw(vec![b'x'; 10 * 1024 * 1024], "text/plain"),
        )
        .mount(&server)
        .await;

    let client = loopback_new(
        token_url(&server),
        ClientAuthMethod::ClientSecretBasic {
            client_id: "axess".into(),
            client_secret: "secret".into(),
        },
    )
    .expect("an HTTPS or loopback token URL");
    let err = client
        .get_access_token()
        .await
        .expect_err("503 must propagate");
    let OAuthClientError::TokenEndpoint { body, .. } = &err else {
        panic!("expected TokenEndpoint, got {err:?}");
    };
    assert!(
        body.ends_with(crate::http_body::TRUNCATED_SUFFIX),
        "{} bytes ending {:?}",
        body.len(),
        &body[body.len().saturating_sub(20)..]
    );
    assert_eq!(
        body.len(),
        crate::http_body::ERROR_BODY_BYTES + crate::http_body::TRUNCATED_SUFFIX.len()
    );
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
    let client = loopback_new(
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
        "token_type": "Bearer",
    }))
    .await;

    let clock = Arc::new(MockClock::at(t0()));
    let client = loopback_new(
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
async fn out_of_range_expires_in_is_refused() {
    for body in [
        r#"{"access_token":"t","token_type":"Bearer","expires_in":10000000000000000}"#,
        r#"{"access_token":"t","token_type":"Bearer","expires_in":18446744073709551615}"#,
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .mount(&server)
            .await;
        let client = loopback_new(
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

#[tokio::test]
async fn a_token_that_is_not_a_bearer_token_is_refused() {
    let server = token_server_returning(json!({
        "access_token": "tok-dpop",
        "token_type": "DPoP",
        "expires_in": 3600,
    }))
    .await;
    let client = loopback_new(
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
        .expect_err("a DPoP-bound token must not be used as a bearer token");
    assert!(
        matches!(err, OAuthClientError::MalformedResponse(_)),
        "{err:?}"
    );
}

#[tokio::test]
async fn bearer_is_accepted_in_any_case() {
    let server = token_server_returning(json!({
        "access_token": "tok-alpha",
        "token_type": "bearer",
        "expires_in": 3600,
    }))
    .await;
    let client = loopback_new(
        token_url(&server),
        ClientAuthMethod::ClientSecretBasic {
            client_id: "axess".into(),
            client_secret: "shh".into(),
        },
    )
    .expect("an HTTPS or loopback token URL");
    assert_eq!(client.get_access_token().await.unwrap(), "tok-alpha");
}

#[tokio::test]
async fn a_response_without_token_type_is_refused() {
    let server = token_server_returning(json!({
        "access_token": "tok-untyped",
        "expires_in": 3600,
    }))
    .await;
    let client = loopback_new(
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
        .expect_err("RFC 6749 section 5.1 requires token_type");
    assert!(
        matches!(err, OAuthClientError::MalformedResponse(_)),
        "{err:?}"
    );
}
