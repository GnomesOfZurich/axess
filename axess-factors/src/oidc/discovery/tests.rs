//! `tests`: extracted from `discovery.rs` per the
//! 200-LoC inline-test rule in AGENTS.md.

use super::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn sample_jwks_json() -> serde_json::Value {
    serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "k1",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
        }],
    })
}

fn discovery_json(issuer: &str, jwks_uri: &str) -> serde_json::Value {
    serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": jwks_uri,
        "end_session_endpoint": format!("{issuer}/logout"),
        "scopes_supported": ["openid", "email", "profile"],
    })
}

#[tokio::test]
async fn document_fetch_parses_well_known() {
    let server = MockServer::start().await;
    let jwks_uri = format!("{}/jwks", server.uri());
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(discovery_json(&server.uri(), &jwks_uri)),
        )
        .mount(&server)
        .await;

    let client = openidconnect::reqwest::Client::new();
    let doc = DiscoveryDocument::fetch(&server.uri(), &client)
        .await
        .expect("fetch ok");

    assert_eq!(doc.issuer, server.uri());
    assert_eq!(doc.jwks_uri, jwks_uri);
    assert!(doc.authorization_endpoint.is_some());
    assert!(doc.end_session_endpoint.is_some());
    assert!(doc.revocation_endpoint.is_none());
    // Raw JSON preserves extension fields.
    assert!(doc.raw.get("scopes_supported").is_some());
}

#[tokio::test]
async fn document_fetch_rejects_missing_jwks_uri() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": server.uri(),
            // jwks_uri intentionally omitted
        })))
        .mount(&server)
        .await;

    let client = openidconnect::reqwest::Client::new();
    let err = DiscoveryDocument::fetch(&server.uri(), &client)
        .await
        .expect_err("missing jwks_uri must reject");
    assert!(
        matches!(err, OidcError::MissingField("jwks_uri")),
        "expected MissingField(jwks_uri), got {err:?}",
    );
}

/// The loopback exception is decided by the parsed HOST, never by a
/// prefix of the string: these three all start like loopback and are not.
#[test]
fn loopback_is_the_host_not_a_prefix() {
    for url in [
        "http://localhost.attacker.com",
        "http://127.0.0.1.nip.io",
        "http://localhost@evil.com",
        "http://[::1]@evil.com/",
        "http://idp.example.com",
        "not a url",
    ] {
        assert!(
            matches!(
                require_https_or_loopback(url),
                Err(OidcError::NonHttpsIssuer(_))
            ),
            "{url} must be refused"
        );
    }
    for url in [
        "http://localhost",
        "http://localhost:8080/realms/dev",
        "http://127.0.0.1:8080",
        "http://[::1]:8443",
        "https://idp.example.com",
    ] {
        assert!(
            require_https_or_loopback(url).is_ok(),
            "{url} must be accepted"
        );
    }
    // Userinfo on an https URL is refused as well: a pin that reads as one host and resolves to another.
    assert!(require_https_or_loopback("https://localhost@evil.com").is_err());
}

#[tokio::test]
async fn document_fetch_rejects_non_https_non_loopback() {
    let client = openidconnect::reqwest::Client::new();
    let err = DiscoveryDocument::fetch("http://idp.example.com", &client)
        .await
        .expect_err("plain http must reject");
    assert!(
        matches!(err, OidcError::NonHttpsIssuer(_)),
        "expected NonHttpsIssuer, got {err:?}",
    );
}

/// A document whose `issuer` is not the URL it was fetched from is a
/// mix-up, refused as such.
#[tokio::test]
async fn document_fetch_rejects_issuer_mismatch() {
    let server = MockServer::start().await;
    let jwks_uri = format!("{}/jwks", server.uri());
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(discovery_json("https://other-idp.example", &jwks_uri)),
        )
        .mount(&server)
        .await;
    let client = openidconnect::reqwest::Client::new();
    let err = DiscoveryDocument::fetch(&server.uri(), &client)
        .await
        .expect_err("mismatched issuer must reject");
    assert!(
        matches!(err, OidcError::InvalidIssuer(_)),
        "expected InvalidIssuer, got {err:?}"
    );
}

/// A `jwks_uri` over plain http to a remote host is refused: the keys
/// would travel on a rail an on-path attacker can rewrite.
#[tokio::test]
async fn document_fetch_rejects_plain_http_jwks_uri() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery_json(
            &server.uri(),
            "http://keys.attacker.example/jwks",
        )))
        .mount(&server)
        .await;
    let client = openidconnect::reqwest::Client::new();
    let err = DiscoveryDocument::fetch(&server.uri(), &client)
        .await
        .expect_err("http jwks_uri must reject");
    assert!(
        matches!(err, OidcError::NonHttpsIssuer(_)),
        "expected NonHttpsIssuer, got {err:?}"
    );
}

/// An error status with a JSON body is not a discovery document.
#[tokio::test]
async fn document_fetch_rejects_error_status() {
    let server = MockServer::start().await;
    let jwks_uri = format!("{}/jwks", server.uri());
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(discovery_json(&server.uri(), &jwks_uri)),
        )
        .mount(&server)
        .await;
    let client = openidconnect::reqwest::Client::new();
    let err = DiscoveryDocument::fetch(&server.uri(), &client)
        .await
        .expect_err("a 500 must reject");
    assert!(
        matches!(err, OidcError::DiscoveryFetch(_)),
        "expected DiscoveryFetch, got {err:?}"
    );
}

#[tokio::test]
async fn discovery_fetch_chains_jwks() {
    let server = MockServer::start().await;
    let jwks_uri = format!("{}/jwks", server.uri());
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(discovery_json(&server.uri(), &jwks_uri)),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_jwks_json()))
        .mount(&server)
        .await;

    let client = openidconnect::reqwest::Client::new();
    let discovery = Discovery::fetch(&server.uri(), &client)
        .await
        .expect("discovery ok");

    assert_eq!(discovery.document().issuer, server.uri());
    let handle = discovery.jwks();
    assert_eq!(handle.read().unwrap().keys.len(), 1);
}

/// A discovery body over the cap is refused, not buffered.
#[tokio::test]
async fn a_discovery_body_over_the_cap_is_refused() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(vec![b'a'; MAX_DISCOVERY_BYTES + 1], "application/json"),
        )
        .mount(&server)
        .await;
    let client = openidconnect::reqwest::Client::new();

    let err = DiscoveryDocument::fetch(&server.uri(), &client)
        .await
        .expect_err("oversized body");

    assert!(
        matches!(&err, OidcError::DiscoveryFetch(m) if m == "discovery body exceeds limit"),
        "got {err:?}"
    );
}
