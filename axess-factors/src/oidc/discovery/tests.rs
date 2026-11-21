//! `tests`: the unit tests of `discovery.rs`, kept beside it per the
//! 200-line inline-test rule in AGENTS.md.

use super::*;
use crate::egress::{EgressPolicy, ScreenedClient};
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

    let doc = DiscoveryDocument::fetch(&server.uri(), &unscreened_client())
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

    let err = DiscoveryDocument::fetch(&server.uri(), &unscreened_client())
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
    let err = DiscoveryDocument::fetch("http://idp.example.com", &screened_client())
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
    let err = DiscoveryDocument::fetch(&server.uri(), &unscreened_client())
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
    let err = DiscoveryDocument::fetch(&server.uri(), &unscreened_client())
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
    let err = DiscoveryDocument::fetch(&server.uri(), &unscreened_client())
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

    let discovery = Discovery::fetch(&server.uri(), &unscreened_client())
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

    let err = DiscoveryDocument::fetch(&server.uri(), &unscreened_client())
        .await
        .expect_err("oversized body");

    assert!(
        matches!(&err, OidcError::DiscoveryFetch(m) if m == "discovery body exceeds limit"),
        "got {err:?}"
    );
}

/// The issuer in the document must equal the one fetched from, character
/// for character (OIDC Discovery section 4.3): a trailing slash names a
/// different issuer, and the `iss` of every token is compared the same way.
#[tokio::test]
async fn document_fetch_compares_the_issuer_exactly() {
    let server = MockServer::start().await;
    let jwks_uri = format!("{}/jwks", server.uri());
    // The document names the issuer with a slash the caller did not give.
    let with_slash = format!("{}/", server.uri());
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(discovery_json(&with_slash, &jwks_uri)),
        )
        .mount(&server)
        .await;
    let err = DiscoveryDocument::fetch(&server.uri(), &unscreened_client())
        .await
        .expect_err("a different issuer string must reject");
    assert!(
        matches!(err, OidcError::InvalidIssuer(_)),
        "expected InvalidIssuer, got {err:?}"
    );
}

/// A client built under `policy`, with a short timeout.
fn client_under(policy: EgressPolicy) -> ScreenedClient {
    policy
        .build_client(|settings| settings.timeout(std::time::Duration::from_secs(2)))
        .expect("client")
}

/// A client under the default policy.
fn screened_client() -> ScreenedClient {
    client_under(EgressPolicy::screened())
}

/// A client under the named opt-out, which reaches the mock on loopback.
fn unscreened_client() -> ScreenedClient {
    client_under(EgressPolicy::unscreened())
}

fn refused_as(err: &OidcError, setting: &str, range: &str) -> bool {
    matches!(err, OidcError::EgressRefused { setting: s, range: r } if s == setting && r == range)
}

/// Under the default policy a private issuer is refused by name, with no
/// connection made.
#[tokio::test]
async fn document_fetch_refuses_a_private_issuer_by_default() {
    let err = DiscoveryDocument::fetch("https://10.0.0.5", &screened_client())
        .await
        .expect_err("a private issuer is refused");

    assert!(refused_as(&err, "issuer URL", "private"), "{err:?}");
}

#[tokio::test]
async fn discovery_fetch_refuses_a_metadata_issuer_by_default() {
    let err = Discovery::fetch("https://169.254.169.254", &screened_client())
        .await
        .err()
        .expect("a metadata issuer is refused");

    assert!(refused_as(&err, "issuer URL", "metadata"), "{err:?}");
}

/// The key set's address is screened before it is fetched, under the policy
/// the client carries.
#[tokio::test]
async fn discovery_fetch_refuses_a_private_jwks_uri() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(discovery_json(&server.uri(), "https://10.0.0.5/jwks")),
        )
        .mount(&server)
        .await;
    let client = client_under(EgressPolicy::screened_allowing_loopback_http());

    let err = Discovery::fetch(&server.uri(), &client)
        .await
        .err()
        .expect("a private jwks_uri is refused");

    assert!(refused_as(&err, "jwks_uri", "private"), "{err:?}");
}

/// A server on loopback whose discovery path answers `302` to `target`.
async fn redirecting_issuer(target: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", target))
        .mount(&server)
        .await;
    server
}

/// A client the policy built follows no redirect, so a redirecting issuer
/// answers `302` and the fetch refuses it by name: the document behind the
/// redirect is never read.
#[tokio::test]
async fn a_redirected_document_is_refused() {
    let hidden_document = MockServer::start().await;
    let issuer = redirecting_issuer(&format!(
        "{}/.well-known/openid-configuration",
        hidden_document.uri()
    ))
    .await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery_json(
            &issuer.uri(),
            &format!("{}/jwks", hidden_document.uri()),
        )))
        .expect(0)
        .mount(&hidden_document)
        .await;
    let client = client_under(EgressPolicy::screened_allowing_loopback_http());

    let refused = DiscoveryDocument::fetch(&issuer.uri(), &client).await;

    match refused {
        Ok(doc) => panic!(
            "the redirected document was accepted: issuer {}",
            doc.issuer
        ),
        Err(OidcError::DiscoveryFetch(m)) => assert!(m.contains("redirect"), "{m}"),
        Err(other) => panic!("refused, but not by name: {other:?}"),
    }
}

/// The fetch takes no answer that did not come from the URL it asked for,
/// whatever client made the request: a client that follows redirects, which
/// no public entry point accepts, is refused here too, so the guard does not
/// rest on the client's settings alone.
#[tokio::test]
async fn the_fetch_refuses_an_answer_from_another_url() {
    let hidden_document = MockServer::start().await;
    let issuer = redirecting_issuer(&format!(
        "{}/.well-known/openid-configuration",
        hidden_document.uri()
    ))
    .await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery_json(
            &issuer.uri(),
            &format!("{}/jwks", hidden_document.uri()),
        )))
        .mount(&hidden_document)
        .await;
    let following = openidconnect::reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(1))
        .build()
        .expect("client");

    let refused = DiscoveryDocument::fetch_inner(
        &issuer.uri(),
        &following,
        EgressPolicy::screened_allowing_loopback_http(),
    )
    .await;

    match refused {
        Ok(doc) => panic!(
            "the redirected document was accepted: issuer {}",
            doc.issuer
        ),
        Err(OidcError::DiscoveryFetch(m)) => assert!(m.contains("another URL"), "{m}"),
        Err(other) => panic!("refused, but not by name: {other:?}"),
    }
}

/// The client the fetch takes carries the policy: a loopback identity
/// provider is reached through a client built under the loopback opt-in, and
/// the document and the key set both arrive.
#[tokio::test]
async fn a_screened_client_fetches_the_document_and_the_key_set() {
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
    let client = client_under(EgressPolicy::screened_allowing_loopback_http());

    let discovery = Discovery::fetch(&server.uri(), &client)
        .await
        .expect("document and key set");

    assert_eq!(discovery.document().issuer, server.uri());
    assert_eq!(discovery.jwks().read().unwrap().keys.len(), 1);
}

/// Under the default policy the same client refuses the loopback issuer by
/// name, before any request.
#[tokio::test]
async fn a_screened_client_refuses_a_loopback_issuer_by_name() {
    let err = DiscoveryDocument::fetch("https://127.0.0.1:9/", &screened_client())
        .await
        .unwrap_err();

    assert!(refused_as(&err, "issuer URL", "loopback"), "{err:?}");
}

/// What a discovery document says is the remote party's text: an `issuer`
/// or a `jwks_uri` that is refused reaches the error escaped and cut, so a
/// document can neither forge a log line nor fill one.
#[tokio::test]
async fn a_refused_document_value_is_quoted_cut_and_escaped() {
    let forged = format!(
        "http://keys.attacker.example/\nWARN forged line\u{2028}{}",
        "A".repeat(3000)
    );
    for forge_issuer in [true, false] {
        let server = MockServer::start().await;
        let good_jwks = format!("{}/jwks", server.uri());
        let document = if forge_issuer {
            discovery_json(&forged, &good_jwks)
        } else {
            discovery_json(&server.uri(), &forged)
        };
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(document))
            .mount(&server)
            .await;
        let client = EgressPolicy::unscreened()
            .build_client(|settings| settings.timeout(std::time::Duration::from_secs(2)))
            .expect("client");
        let err = DiscoveryDocument::fetch(&server.uri(), &client)
            .await
            .expect_err("the document is refused");
        match (&err, forge_issuer) {
            (OidcError::InvalidIssuer(_), true) | (OidcError::NonHttpsIssuer(_), false) => {}
            other => panic!("unexpected refusal: {other:?}"),
        }
        let text = err.to_string();
        assert!(text.len() <= 512, "{} bytes in one error", text.len());
        assert!(!text.contains(&"A".repeat(300)), "quoted whole");
        assert!(
            !text
                .chars()
                .any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}')),
            "{text:?}"
        );
        assert!(text.contains("\\nWARN forged line"), "{text}");
    }
}
