//! Tests for the Azure AD Federated Identity Credentials adapter.
//!
//! Wiremock asserts on the form body shape (`grant_type`,
//! `client_id`, `scope`, `client_assertion_type`, `client_assertion`)
//! and the response parsing (success JSON, structured error JSON
//! with Azure's extra fields, non-JSON error body, malformed
//! success).

use super::*;
use serde_json::json;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn endpoint(server: &MockServer) -> Url {
    Url::parse(&format!("{}/tenant-guid/oauth2/v2.0/token", server.uri())).unwrap()
}

#[test]
fn default_endpoint_uses_public_cloud_login_url() {
    let client = AzureFicClient::new("my-tenant", "app-id");
    assert_eq!(
        client.token_endpoint().as_str(),
        "https://login.microsoftonline.com/my-tenant/oauth2/v2.0/token"
    );
    assert_eq!(client.client_id(), "app-id");
}

#[tokio::test]
async fn acquire_token_happy_path_returns_bearer() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/tenant-guid/oauth2/v2.0/token"))
        .and(header(
            "content-type",
            "application/x-www-form-urlencoded",
        ))
        .and(body_string_contains("grant_type=client_credentials"))
        .and(body_string_contains("client_id=app-id"))
        .and(body_string_contains(
            "scope=https%3A%2F%2Fgraph.microsoft.com%2F.default",
        ))
        .and(body_string_contains(
            "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer",
        ))
        .and(body_string_contains(
            "client_assertion=eyJraWQ.federated.token",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "azure-issued-token",
            "token_type": "Bearer",
            "expires_in": 3599,
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client =
        AzureFicClient::new("tenant-guid", "app-id").with_token_endpoint(endpoint(&server));
    let req = AzureFicRequest::new("eyJraWQ.federated.token")
        .with_scope("https://graph.microsoft.com/.default");
    let resp = client.acquire_token(&req).await.expect("acquire_token");
    assert_eq!(&*resp.access_token, "azure-issued-token");
    assert_eq!(resp.token_type, "Bearer");
    assert_eq!(resp.expires_in, Some(3599));
}

#[tokio::test]
async fn invalid_client_assertion_surfaces_structured_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/tenant-guid/oauth2/v2.0/token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "invalid_client",
            "error_description": "AADSTS70021: No matching federated identity record found.",
            "error_codes": [70021],
            "timestamp": "2026-05-15 10:00:00Z",
            "trace_id": "trace-1",
            "correlation_id": "corr-abc-123",
        })))
        .mount(&server)
        .await;

    let client =
        AzureFicClient::new("tenant-guid", "app-id").with_token_endpoint(endpoint(&server));
    let err = client
        .acquire_token(&AzureFicRequest::new("bad-token").with_scope("https://x/.default"))
        .await
        .expect_err("401 must propagate");
    match err {
        AzureFicError::AzureError {
            http_status,
            error,
            error_description,
            error_codes,
            correlation_id,
        } => {
            assert_eq!(http_status, 401);
            assert_eq!(error, "invalid_client");
            assert!(error_description.contains("AADSTS70021"));
            assert_eq!(error_codes, vec![70021]);
            assert_eq!(correlation_id.as_deref(), Some("corr-abc-123"));
        }
        other => panic!("expected AzureError, got {other:?}"),
    }
}

#[tokio::test]
async fn non_json_error_body_still_surfaces_as_azure_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/tenant-guid/oauth2/v2.0/token"))
        .respond_with(ResponseTemplate::new(502).set_body_raw("Bad Gateway", "text/plain"))
        .mount(&server)
        .await;
    let client =
        AzureFicClient::new("tenant-guid", "app-id").with_token_endpoint(endpoint(&server));
    let err = client
        .acquire_token(&AzureFicRequest::new("token"))
        .await
        .expect_err("502 must propagate");
    match err {
        AzureFicError::AzureError {
            http_status,
            error,
            error_description,
            error_codes,
            correlation_id,
        } => {
            assert_eq!(http_status, 502);
            assert_eq!(error, "unknown");
            assert!(error_description.contains("Bad Gateway"));
            assert!(error_codes.is_empty());
            assert!(correlation_id.is_none());
        }
        other => panic!("expected AzureError, got {other:?}"),
    }
}

#[tokio::test]
async fn empty_access_token_in_success_body_rejects() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/tenant-guid/oauth2/v2.0/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "",
            "token_type": "Bearer",
            "expires_in": 3599,
        })))
        .mount(&server)
        .await;
    let client =
        AzureFicClient::new("tenant-guid", "app-id").with_token_endpoint(endpoint(&server));
    let err = client
        .acquire_token(&AzureFicRequest::new("token"))
        .await
        .expect_err("empty access_token must reject");
    assert!(matches!(err, AzureFicError::MalformedResponse(_)));
}

#[tokio::test]
async fn multiple_scopes_join_with_spaces() {
    let server = MockServer::start().await;
    // Form encoding of "a/.default b/.default" → "a%2F.default+b%2F.default"
    Mock::given(method("POST"))
        .and(path("/tenant-guid/oauth2/v2.0/token"))
        .and(body_string_contains("scope=a%2F.default+b%2F.default"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok",
            "token_type": "Bearer",
            "expires_in": 3599,
        })))
        .expect(1)
        .mount(&server)
        .await;
    let client =
        AzureFicClient::new("tenant-guid", "app-id").with_token_endpoint(endpoint(&server));
    let req = AzureFicRequest::new("token").with_scopes(["a/.default", "b/.default"]);
    client.acquire_token(&req).await.expect("multi-scope path");
}

#[tokio::test]
async fn malformed_success_body_surfaces_as_malformed_response() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/tenant-guid/oauth2/v2.0/token"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("not json", "application/json"))
        .mount(&server)
        .await;
    let client =
        AzureFicClient::new("tenant-guid", "app-id").with_token_endpoint(endpoint(&server));
    let err = client
        .acquire_token(&AzureFicRequest::new("token"))
        .await
        .expect_err("non-JSON success body must reject");
    assert!(matches!(err, AzureFicError::MalformedResponse(_)));
}
