//! `tests`: extracted from `social.rs` per the
//! 200-LoC inline-test rule in AGENTS.md.

use super::*;
use axess_rng::testing::MockRng;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn github_style_mapper(raw: &serde_json::Value) -> Result<SocialClaims, SocialError> {
    let id = raw
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| SocialError::ClaimMapping("missing numeric `id`".into()))?;
    Ok(SocialClaims {
        subject: id.to_string(),
        email: raw.get("email").and_then(|v| v.as_str()).map(String::from),
        display_name: raw.get("name").and_then(|v| v.as_str()).map(String::from),
        raw: raw.clone(),
    })
}

fn make_provider(
    mock: &MockServer,
) -> SocialProvider<impl Fn(&serde_json::Value) -> Result<SocialClaims, SocialError> + Send + Sync>
{
    SocialProvider::new(
        SocialProviderConfig {
            name: "github".into(),
            authorization_endpoint: format!("{}/login/oauth/authorize", mock.uri()),
            token_endpoint: format!("{}/login/oauth/access_token", mock.uri()),
            userinfo_endpoint: format!("{}/user", mock.uri()),
            client_id: "demo-client-id".into(),
            client_secret: "demo-client-secret".into(),
            redirect_uri: "https://app.example.com/auth/callback/github".into(),
            scopes: vec!["read:user".into(), "user:email".into()],
        },
        github_style_mapper,
    )
    // Pin the PKCE verifier so the assertion on the generated URL
    // is reproducible. `MockRng::new(seed)` is the standard DST
    // pattern used elsewhere in the workspace.
    .with_rng(std::sync::Arc::new(MockRng::new(42)))
}

#[test]
fn build_auth_url_includes_pkce_and_state_by_default() {
    let provider = SocialProvider::new(
        SocialProviderConfig {
            name: "github".into(),
            authorization_endpoint: "https://github.com/login/oauth/authorize".into(),
            token_endpoint: "https://github.com/login/oauth/access_token".into(),
            userinfo_endpoint: "https://api.github.com/user".into(),
            client_id: "demo-client".into(),
            client_secret: "demo-secret".into(),
            redirect_uri: "https://app.example.com/auth/callback".into(),
            scopes: vec!["read:user".into()],
        },
        github_style_mapper,
    )
    .with_rng(std::sync::Arc::new(MockRng::new(7)));

    let result = provider.build_auth_url("csrf-state-xyz");

    assert!(
        result
            .url
            .starts_with("https://github.com/login/oauth/authorize?")
    );
    assert!(result.url.contains("response_type=code"));
    assert!(result.url.contains("client_id=demo-client"));
    assert!(result.url.contains("state=csrf-state-xyz"));
    assert!(result.url.contains("code_challenge="));
    assert!(result.url.contains("code_challenge_method=S256"));
    assert!(
        !result.pkce_verifier.is_empty(),
        "PKCE verifier should be present by default"
    );
}

#[test]
fn without_pkce_omits_code_challenge() {
    let provider = SocialProvider::new(
        SocialProviderConfig {
            name: "discord".into(),
            authorization_endpoint: "https://discord.com/api/oauth2/authorize".into(),
            token_endpoint: "https://discord.com/api/oauth2/token".into(),
            userinfo_endpoint: "https://discord.com/api/users/@me".into(),
            client_id: "demo-client".into(),
            client_secret: "demo-secret".into(),
            redirect_uri: "https://app.example.com/auth/callback".into(),
            scopes: vec!["identify".into()],
        },
        github_style_mapper,
    )
    .without_pkce();

    let result = provider.build_auth_url("csrf-1");

    assert!(!result.url.contains("code_challenge"));
    assert!(result.pkce_verifier.is_empty());
}

#[tokio::test]
async fn happy_path_exchanges_code_then_fetches_userinfo() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .and(header("Accept", "application/json"))
        .and(body_string_contains("grant_type=authorization_code"))
        .and(body_string_contains("code=the-code"))
        .and(body_string_contains("client_id=demo-client-id"))
        .and(body_string_contains("code_verifier=pkce-verifier-stub"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "tok-abc",
            "token_type": "bearer",
        })))
        .expect(1)
        .mount(&mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/user"))
        .and(header("Authorization", "Bearer tok-abc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 12345,
            "login": "octocat",
            "name": "The Octocat",
            "email": "octocat@example.com",
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let provider = make_provider(&mock);
    let access_token = provider
        .exchange_code("the-code", "pkce-verifier-stub")
        .await
        .expect("exchange_code");
    assert_eq!(access_token, "tok-abc");

    let claims = provider
        .fetch_userinfo(&access_token)
        .await
        .expect("userinfo");
    assert_eq!(claims.subject, "12345");
    assert_eq!(claims.email.as_deref(), Some("octocat@example.com"));
    assert_eq!(claims.display_name.as_deref(), Some("The Octocat"));
    assert_eq!(
        claims.raw.get("login").and_then(|v| v.as_str()),
        Some("octocat")
    );
}

#[tokio::test]
async fn token_endpoint_without_access_token_is_invalid_response() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "error": "invalid_grant",
            "error_description": "authorization code expired",
        })))
        .mount(&mock)
        .await;

    let provider = make_provider(&mock);
    let err = provider
        .exchange_code("stale-code", "pkce-verifier-stub")
        .await
        .expect_err("missing access_token must error");
    assert!(
        matches!(err, SocialError::InvalidResponse(_)),
        "expected InvalidResponse, got {err:?}"
    );
}

#[tokio::test]
async fn userinfo_4xx_is_http_error() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Bad credentials"))
        .mount(&mock)
        .await;

    let provider = make_provider(&mock);
    let err = provider
        .fetch_userinfo("revoked-token")
        .await
        .expect_err("401 must error");
    assert!(
        matches!(err, SocialError::Http(_)),
        "expected Http, got {err:?}"
    );
}

#[tokio::test]
async fn claim_mapper_rejection_is_claim_mapping_error() {
    let mock = MockServer::start().await;

    // Userinfo lacks the `id` field the mapper requires.
    Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "login": "octocat",
            "email": "octocat@example.com",
        })))
        .mount(&mock)
        .await;

    let provider = make_provider(&mock);
    let err = provider
        .fetch_userinfo("tok-anything")
        .await
        .expect_err("missing id must reject");
    assert!(
        matches!(err, SocialError::ClaimMapping(_)),
        "expected ClaimMapping, got {err:?}"
    );
}

/// An adopter's existing config file must keep parsing unchanged: the
/// secret is a bare JSON string, and wrapping the field in a newtype
/// must not force them to restructure it.
#[test]
fn config_deserializes_a_client_secret_from_a_plain_json_string() {
    let raw = r#"{
        "name": "github",
        "authorization_endpoint": "https://github.com/login/oauth/authorize",
        "token_endpoint": "https://github.com/login/oauth/access_token",
        "userinfo_endpoint": "https://api.github.com/user",
        "client_id": "id-123",
        "client_secret": "s3cr3t-value",
        "redirect_uri": "https://app.example.com/cb",
        "scopes": ["read:user"]
    }"#;

    let config: SocialProviderConfig =
        serde_json::from_str(raw).expect("a plain string must still deserialize");

    assert_eq!(
        &*config.client_secret, "s3cr3t-value",
        "the secret must survive the newtype intact"
    );
}

/// The reason the field is a `ZeroizedString`: this type derives `Debug`
/// and is loaded from config files, so an adopter logging their own
/// configuration must not print the OAuth client secret.
#[test]
fn config_debug_does_not_leak_the_client_secret() {
    let config = SocialProviderConfig {
        name: "github".into(),
        authorization_endpoint: "https://github.com/login/oauth/authorize".into(),
        token_endpoint: "https://github.com/login/oauth/access_token".into(),
        userinfo_endpoint: "https://api.github.com/user".into(),
        client_id: "id-123".into(),
        client_secret: ZeroizedString::new("s3cr3t-value"),
        redirect_uri: "https://app.example.com/cb".into(),
        scopes: vec!["read:user".into()],
    };

    let rendered = format!("{config:?}");
    assert!(
        !rendered.contains("s3cr3t-value"),
        "Debug must not render the client secret, got: {rendered}"
    );
    // The non-secret fields are still useful for diagnosis.
    assert!(
        rendered.contains("id-123"),
        "client_id should remain visible"
    );
}
