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

#[test]
fn request_debug_redacts_federated_token() {
    let req = AzureFicRequest::new("SECRET-JWT").with_scope("s");
    let shown = format!("{req:?}");
    assert!(!shown.contains("SECRET-JWT"), "{shown}");
}

#[test]
fn tenant_is_confined_to_one_path_segment() {
    let client = AzureFicClient::new("evil/../x?y#z@host", "app-id");
    assert_eq!(
        client.token_endpoint().host_str(),
        Some("login.microsoftonline.com")
    );
    assert_eq!(client.token_endpoint().query(), None);
    assert_eq!(client.token_endpoint().fragment(), None);
    assert!(
        client
            .token_endpoint()
            .path()
            .starts_with("/evil%2F..%2Fx%3Fy%23z@host/oauth2/v2.0/token"),
        "{}",
        client.token_endpoint()
    );
    for dots in [".", ".."] {
        let client = AzureFicClient::new(dots, "app-id");
        let segments: Vec<_> = client.token_endpoint().path_segments().unwrap().collect();
        assert_eq!(segments.len(), 4, "{}", client.token_endpoint());
        assert!(
            segments[0].starts_with("%25"),
            "{}",
            client.token_endpoint()
        );
    }
}

/// A token endpoint that never answers must not hold the caller forever:
/// the request ends in a transport error at the configured timeout, even
/// on an HTTP client supplied without one.
#[tokio::test]
async fn a_silent_token_endpoint_times_out() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/tenant-guid/oauth2/v2.0/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"access_token": "t"}))
                .set_delay(std::time::Duration::from_secs(5)),
        )
        .mount(&server)
        .await;
    let client = AzureFicClient::new("tenant", "client")
        .with_token_endpoint(endpoint(&server))
        .with_http_client(reqwest::Client::new())
        .with_timeout(std::time::Duration::from_millis(150));

    let started = std::time::Instant::now();
    let err = client
        .acquire_token(&AzureFicRequest::new("fed").with_scope("s"))
        .await
        .expect_err("must time out");
    assert!(matches!(err, AzureFicError::Transport(_)), "{err:?}");
    // The proof is that the call ended before the server would have
    // answered (its delay is 5 s), not how fast a loaded machine scheduled
    // it: a tighter bound measured the host and failed under a full build.
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "ended after the mock's delay, so the timeout did not end it: {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_plain_http_remote_endpoint_is_refused_before_any_request() {
    let client = AzureFicClient::new("tenant", "app-id")
        .with_token_endpoint(Url::parse("http://192.0.2.1:9/t/oauth2/v2.0/token").unwrap());
    let err = client
        .acquire_token(&AzureFicRequest::new("federated"))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, AzureFicError::Transport(m) if m.contains("must be https")),
        "{err}"
    );
}
