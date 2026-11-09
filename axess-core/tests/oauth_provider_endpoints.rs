//! What `OAuthProviderConfig` does with the endpoints it is given: the ones
//! discovery advertises, the ones configuration supplies, the post-logout
//! redirect allowlist.
//!
//! Run with: `cargo test -p axess-core --features testing,oauth --test oauth_provider_endpoints`

#![cfg(all(feature = "testing", feature = "oauth"))]

use axess_factors::oauth::{OAuthError, OAuthProvider, OAuthProviderBuilder, OAuthProviderConfig};
use axess_testing::oauth_wiremock::{oauth_discovery_document, oauth_generate_rsa_keypair};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

/// A wiremock IdP whose discovery document carries `extra` members.
async fn idp_with(extra: serde_json::Value) -> MockServer {
    let server = MockServer::start().await;
    let (_, jwk, _) = oauth_generate_rsa_keypair();
    let mut doc = oauth_discovery_document(&server.uri());
    doc.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(doc))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
        .mount(&server)
        .await;
    server
}

async fn discover(server: &MockServer) -> Result<OAuthProviderBuilder, OAuthError> {
    OAuthProviderConfig::discover(
        "test",
        &server.uri(),
        "test-client-id",
        "test-secret",
        "http://localhost:3000/callback",
    )
    .await
}

/// Discovery reads the endpoints outside the standard metadata set. The typed
/// metadata drops them (its additional-metadata type is empty), so without a
/// read of the raw document `build_end_session_url` always answered `None`
/// and PAR and revocation were never configured by discovery.
#[tokio::test]
async fn discovery_reads_the_optional_endpoints_from_the_raw_document() {
    let server = idp_with(json!({
        "end_session_endpoint": format!("{}/logout", "http://localhost:9"),
        "revocation_endpoint": "http://localhost:9/revoke",
        "pushed_authorization_request_endpoint": "http://localhost:9/par",
        "authorization_response_iss_parameter_supported": true,
    }))
    .await;
    let provider = discover(&server)
        .await
        .unwrap()
        .with_allowed_post_logout_redirect_uris(["https://app.example/after"])
        .build()
        .unwrap();

    let url = provider
        .build_end_session_url(Some("hint"), Some("https://app.example/after"), None)
        .expect("end_session_endpoint was discovered");
    assert_eq!(url.path(), "/logout");
    assert!(provider.authorization_response_iss_required());
}

/// An IdP that advertises no `iss` parameter support does not make callers
/// pass one.
#[tokio::test]
async fn iss_parameter_is_required_only_when_advertised() {
    let server = idp_with(json!({})).await;
    let provider = discover(&server).await.unwrap().build().unwrap();
    assert!(!provider.authorization_response_iss_required());
}

/// An empty `post_logout_redirect_uri` allowlist forwards nothing; a listed
/// destination is forwarded, an unlisted one dropped.
#[tokio::test]
async fn an_empty_post_logout_allowlist_forwards_no_redirect() {
    let server = idp_with(json!({ "end_session_endpoint": "http://localhost:9/logout" })).await;
    let bare = discover(&server).await.unwrap().build().unwrap();

    let url = bare
        .build_end_session_url(None, Some("https://evil.example"), None)
        .expect("endpoint discovered");
    assert!(
        !url.query_pairs()
            .any(|(k, _)| k == "post_logout_redirect_uri"),
        "no allowlist configured, so nothing is forwarded: {url}"
    );

    let listed = discover(&server)
        .await
        .unwrap()
        .with_allowed_post_logout_redirect_uris(["https://app/after"])
        .build()
        .unwrap();
    let forwarded = |redirect: &str| {
        listed
            .build_end_session_url(None, Some(redirect), None)
            .unwrap()
            .query_pairs()
            .any(|(k, v)| k == "post_logout_redirect_uri" && v == redirect)
    };
    assert!(forwarded("https://app/after"));
    assert!(!forwarded("https://app/after/../other"));
    assert!(!forwarded("https://evil.example"));
}

/// An endpoint that receives a secret or a token is HTTPS, or loopback HTTP.
/// Discovery refuses a remote plain-HTTP endpoint it is told about, and
/// `build` refuses one a setter named, naming the setting, before the
/// provider exists to send anything.
#[tokio::test]
async fn plain_http_endpoints_to_remote_hosts_are_refused() {
    // Discovery: a plain-HTTP token endpoint on a remote host.
    let server = idp_with(json!({ "token_endpoint": "http://idp.example.net/token" })).await;
    let err = match discover(&server).await {
        Err(e) => e,
        Ok(_) => panic!("a plain-HTTP remote token endpoint must be refused"),
    };
    assert!(
        matches!(&err, OAuthError::Config(m) if m.contains("token_endpoint")),
        "got {err:?}"
    );

    // Setters: `build` refuses each, naming it.
    let server = idp_with(json!({})).await;
    type Setter = fn(OAuthProviderBuilder) -> OAuthProviderBuilder;
    let cases: [(Setter, &str); 4] = [
        (
            |b| b.with_revocation_endpoint("http://idp.example.net/revoke"),
            "revocation_endpoint",
        ),
        (
            |b| b.with_par_endpoint("http://idp.example.net/par"),
            "pushed_authorization_request_endpoint",
        ),
        (
            |b| b.with_device_authorization_endpoint("http://idp.example.net/device"),
            "device_authorization_endpoint",
        ),
        (
            |b| b.with_end_session_endpoint("http://idp.example.net/logout"),
            "end_session_endpoint",
        ),
    ];
    for (set, what) in cases {
        let insecure = set(discover(&server).await.unwrap());
        let err = insecure.build().err().expect(what);
        assert!(
            matches!(&err, OAuthError::Config(m) if m.contains(what)),
            "{what}: {err:?}"
        );
    }
    // The same settings over loopback HTTP build.
    assert!(
        discover(&server)
            .await
            .unwrap()
            .with_revocation_endpoint("http://localhost:9/revoke")
            .with_par_endpoint("http://127.0.0.1:9/par")
            .with_device_authorization_endpoint("http://localhost:9/device")
            .with_end_session_endpoint("http://localhost:9/logout")
            .build()
            .is_ok()
    );
}
