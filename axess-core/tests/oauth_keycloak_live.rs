//! `private_key_jwt` against a running Keycloak: the one the FAPI example
//! ships (`examples/fapi/keycloak/compose.yml`, realm `fapi`).
//!
//! The test registers a client with the public half of a key it generates,
//! drives the browser leg of the login with an HTTP client (the login form,
//! the redirect with the code), and finishes the login through axess. A
//! second client registered with a different key must be refused.
//!
//! Ignored unless asked for, since it needs the container:
//!
//! ```text
//! podman compose -f examples/fapi/keycloak/compose.yml up -d
//! KEYCLOAK_URL=http://127.0.0.1:8080 cargo test -p axess-core \
//!     --features testing,oauth,jwt-aws-lc --test oauth_keycloak_live -- --ignored
//! ```
//!
//! `KEYCLOAK_URL` must be the host the issuer is served under: the realm's
//! `issuer` is derived from it.

#![cfg(all(feature = "testing", feature = "oauth"))]

use axess_core::authn::AuditContext;
use axess_core::authn::service::AuthnService;
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use axess_factors::client_assertion::ClientAssertionSigner;
use axess_factors::oauth::{OAuthError, OAuthLoginOptions, OAuthProviderConfig};
use axess_testing::oauth_wiremock::oauth_generate_rsa_keypair;
use jsonwebtoken::{Algorithm, EncodingKey};
use serde_json::{Value, json};

const REDIRECT: &str = "http://localhost:3000/auth/callback";

fn base() -> String {
    std::env::var("KEYCLOAK_URL")
        .expect("set KEYCLOAK_URL to the running Keycloak, e.g. http://127.0.0.1:8080")
}

async fn admin_token(http: &reqwest::Client) -> String {
    let response: Value = http
        .post(format!(
            "{}/realms/master/protocol/openid-connect/token",
            base()
        ))
        .form(&[
            ("grant_type", "password"),
            ("client_id", "admin-cli"),
            ("username", "admin"),
            ("password", "admin"),
        ])
        .send()
        .await
        .expect("admin token request")
        .json()
        .await
        .expect("admin token json");
    response["access_token"]
        .as_str()
        .expect("admin token")
        .to_string()
}

/// Register (or replace) a `client-jwt` client holding `jwk` as its key.
async fn register_client(http: &reqwest::Client, admin: &str, client_id: &str, jwk: &Value) {
    let clients = format!("{}/admin/realms/fapi/clients", base());
    let existing: Vec<Value> = http
        .get(&clients)
        .query(&[("clientId", client_id)])
        .bearer_auth(admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    for client in existing {
        let id = client["id"].as_str().unwrap();
        http.delete(format!("{clients}/{id}"))
            .bearer_auth(admin)
            .send()
            .await
            .unwrap();
    }
    let created = http
        .post(&clients)
        .bearer_auth(admin)
        .json(&json!({
            "clientId": client_id,
            "enabled": true,
            "protocol": "openid-connect",
            "publicClient": false,
            "clientAuthenticatorType": "client-jwt",
            "standardFlowEnabled": true,
            "directAccessGrantsEnabled": false,
            "redirectUris": [REDIRECT],
            "attributes": {
                "use.jwks.string": "true",
                "jwks.string": json!({ "keys": [jwk] }).to_string(),
                "token.endpoint.auth.signing.alg": "RS256",
                "pkce.code.challenge.method": "S256",
            },
        }))
        .send()
        .await
        .unwrap();
    assert!(
        created.status().is_success(),
        "client registration: {}",
        created.status()
    );
}

/// The browser leg: open the authorization URL, submit alice's credentials,
/// and return the `code`, `state` and `iss` of the redirect to the callback.
async fn browser_leg(auth_url: &url::Url) -> (String, String, Option<String>) {
    let browser = reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let mut page = browser.get(auth_url.as_str()).send().await.unwrap();
    while page.status().is_redirection() {
        let next = page.headers()["location"].to_str().unwrap().to_string();
        page = browser.get(next).send().await.unwrap();
    }
    let html = page.text().await.unwrap();
    let action = html
        .split("action=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("the login form")
        .replace("&amp;", "&");
    let submitted = browser
        .post(action)
        .form(&[
            ("username", "alice"),
            ("password", "alice"),
            ("credentialId", ""),
        ])
        .send()
        .await
        .unwrap();
    assert!(
        submitted.status().is_redirection(),
        "login answered {}",
        submitted.status()
    );
    let location = url::Url::parse(submitted.headers()["location"].to_str().unwrap()).unwrap();
    let get = |key: &str| {
        location
            .query_pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    };
    (
        get("code").expect("code"),
        get("state").expect("state"),
        get("iss"),
    )
}

async fn login_with(
    signer: ClientAssertionSigner,
) -> Result<axess_factors::oauth::OAuthClaims, OAuthError> {
    let issuer = format!("{}/realms/fapi", base());
    let provider =
        OAuthProviderConfig::discover_with_private_key_jwt("keycloak", &issuer, signer, REDIRECT)
            .await
            .expect("discovery")
            .build()
            .expect("build");
    let authn = AuthnService::builder(MockIdentityStore::new(), MockFactorStore::new())
        .with_oauth_provider(provider)
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();
    let (auth_url, _) = authn
        .begin_oauth_login("keycloak", &OAuthLoginOptions::default(), &session)
        .await
        .expect("begin");
    let (code, state, iss) = browser_leg(&auth_url).await;
    authn
        .finish_oauth_login_with_iss(&code, &state, iss.as_deref(), &session)
        .await
}

#[tokio::test]
#[ignore = "needs the Keycloak container; see the module documentation"]
async fn keycloak_authenticates_the_client_by_its_assertion() {
    axess_factors::jwt::ensure_crypto_provider();
    let http = reqwest::Client::new();
    let admin = admin_token(&http).await;

    let (der, mut jwk, _) = oauth_generate_rsa_keypair();
    jwk["kid"] = json!("live-key-1");
    register_client(&http, &admin, "axess-r10-private-key-jwt", &jwk).await;
    let signer = ClientAssertionSigner::new(
        "axess-r10-private-key-jwt",
        EncodingKey::from_rsa_der(&der),
        Algorithm::RS256,
    )
    .expect("the key signs under its algorithm")
    .with_key_id("live-key-1");

    let claims = login_with(signer)
        .await
        .expect("Keycloak accepted the assertion");
    assert_eq!(claims.email.as_deref(), Some("alice@bank.example.com"));
    assert!(!claims.subject.is_empty());

    // The same client id, signed by a key Keycloak does not hold.
    let (other_der, _, _) = oauth_generate_rsa_keypair();
    let impostor = ClientAssertionSigner::new(
        "axess-r10-private-key-jwt",
        EncodingKey::from_rsa_der(&other_der),
        Algorithm::RS256,
    )
    .expect("the key signs under its algorithm")
    .with_key_id("live-key-1");
    let refused = login_with(impostor).await;
    assert!(
        matches!(refused, Err(OAuthError::TokenExchange(_))),
        "{refused:?}"
    );
}
