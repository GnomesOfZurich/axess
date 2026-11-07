#![cfg(feature = "testing-oauth")]
//! A tenant writes the issuer URL of its identity provider, and the document
//! behind it names more URLs. The directory fetches them, so it refuses the
//! ones that reach the loopback interface, the private network or a cloud
//! metadata service, and makes no connection to find out.

use axess_core::authn::ids::TenantId;
use axess_core::federation::oauth_tenant::{
    MemoryTenantOAuthProviderStore, StoredTenantOAuthProviders, TenantClientCredential, TenantDpop,
    TenantOAuthProviderRecord, TenantOAuthProviderStore, TenantOAuthProviders,
};
use axess_core::testing::oauth_wiremock::{oauth_discovery_document, oauth_generate_rsa_keypair};
use axess_factors::FactorSecret;
use axess_factors::egress::EgressPolicy;
use axess_factors::oauth::OAuthError;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn tenant() -> TenantId {
    axess_core::authn::ids::testing::tenant("acme")
}

fn record(issuer: &str) -> TenantOAuthProviderRecord {
    TenantOAuthProviderRecord {
        tenant_id: tenant(),
        name: "sso".into(),
        issuer: issuer.to_string(),
        client_id: "client".into(),
        redirect_url: "https://rp.example/callback".into(),
        scopes: vec![],
        credential: TenantClientCredential::Secret(FactorSecret::Plain("secret".into())),
        dpop: TenantDpop::Advertised,
        revision: 0,
    }
}

type Directory = StoredTenantOAuthProviders<MemoryTenantOAuthProviderStore>;

fn directory() -> Directory {
    StoredTenantOAuthProviders::new_unencrypted(MemoryTenantOAuthProviderStore::new())
}

async fn refused(directory: &Directory) -> String {
    match directory.provider(&tenant(), "sso").await {
        Err(err) => refusal(err),
        Ok(_) => panic!("the provider was built"),
    }
}

fn refusal(err: OAuthError) -> String {
    match err {
        OAuthError::Config(text) => text,
        other => panic!("expected a refusal by name, got {other:?}"),
    }
}

#[tokio::test]
async fn a_loopback_issuer_is_refused_without_a_connection() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let directory = directory();
    // Written by another process, past `upsert`.
    directory.store().put(record(&issuer)).await.unwrap();

    let text = refused(&directory).await;

    assert!(text.contains("issuer URL"), "{text}");
    assert!(
        listener.accept().is_err(),
        "the server connected to a loopback issuer"
    );
}

#[tokio::test]
async fn upsert_refuses_issuers_in_reserved_ranges_by_name() {
    let directory = directory();
    for (issuer, range) in [
        ("https://127.0.0.1", "loopback"),
        ("https://[::1]", "loopback"),
        ("https://localhost", "loopback"),
        ("https://10.0.0.5", "private"),
        ("https://172.16.4.1", "private"),
        ("https://192.168.1.1", "private"),
        ("https://169.254.169.254", "metadata"),
        ("https://169.254.10.10", "link-local"),
        ("https://[fe80::1]", "link-local"),
        ("https://[fd00:ec2::254]", "metadata"),
        ("https://[fd12:3456::1]", "unique-local"),
        ("https://[::ffff:10.0.0.5]", "private"),
        ("https://100.64.0.1", "shared-address"),
        ("https://0.0.0.0", "unspecified"),
        ("http://idp.example", "HTTPS"),
    ] {
        let err = directory.upsert(record(issuer)).await.unwrap_err();
        let text = refusal(err);
        assert!(text.contains(range), "{issuer}: {text}");
    }
}

#[tokio::test]
async fn an_endpoint_the_document_names_is_refused_by_name() {
    for (field, url, range) in [
        (
            "token_endpoint",
            "https://169.254.169.254/token",
            "metadata",
        ),
        ("userinfo_endpoint", "https://10.0.0.5/userinfo", "private"),
        ("jwks_uri", "https://[fd12:3456::1]/jwks", "unique-local"),
        ("revocation_endpoint", "http://idp.example/revoke", "HTTPS"),
    ] {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let mut doc = oauth_discovery_document(&issuer);
        doc[field] = url.into();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(doc))
            .mount(&server)
            .await;
        // The issuer itself is on the loopback interface, which the test
        // opt-in allows; the endpoints are not.
        let directory =
            directory().with_egress_policy(EgressPolicy::screened_allowing_loopback_http());
        directory.upsert(record(&issuer)).await.unwrap();

        let text = refused(&directory).await;
        assert!(
            text.contains(field) && text.contains(range),
            "{field}: {text}"
        );
    }
}

#[tokio::test]
async fn the_unscreened_opt_out_reaches_a_loopback_idp() {
    let server = MockServer::start().await;
    let (_der, jwk, _kid) = oauth_generate_rsa_keypair();
    axess_core::testing::oauth_wiremock::oauth_mount_oidc_endpoints(&server, &jwk).await;
    let directory = directory().with_egress_policy(EgressPolicy::unscreened());
    directory.upsert(record(&server.uri())).await.unwrap();

    directory
        .provider(&tenant(), "sso")
        .await
        .expect("the opted-out directory reaches its identity provider")
        .expect("the record exists");
}
