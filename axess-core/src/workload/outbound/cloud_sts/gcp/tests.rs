//! Tests for the GCP Workload Identity Federation adapter.
//!
//! Stage 1 (STS): wiremock asserts on the RFC 8693 form body shape
//! (grant_type / audience / scope / requested_token_type /
//! subject_token / subject_token_type) and parses GCP's JSON
//! response.
//!
//! Stage 2 (IAM Credentials): wiremock asserts on the URL templating
//! (the SA email appears in the path), the `Authorization: Bearer
//! <federated>` header, and the request body (`scope` array,
//! optional `lifetime`).

use super::*;
use serde_json::json;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn sample_audience() -> WorkloadIdentityPoolProvider {
    WorkloadIdentityPoolProvider::new(123_456_789, "axess-pool", "github-actions")
}

fn sts_endpoint(server: &MockServer) -> Url {
    Url::parse(&format!("{}/v1/token", server.uri())).unwrap()
}

fn iam_base(server: &MockServer) -> Url {
    Url::parse(&format!("{}/", server.uri())).unwrap()
}

#[test]
fn workload_identity_pool_provider_formats_audience_correctly() {
    let aud = WorkloadIdentityPoolProvider::new(123, "pool", "prov");
    assert_eq!(
        aud.as_str(),
        "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/prov"
    );
}

#[test]
fn workload_identity_pool_provider_from_audience_escape_hatch() {
    let aud = WorkloadIdentityPoolProvider::from_audience("//iam.googleapis.com/projects/9/...");
    assert_eq!(aud.as_str(), "//iam.googleapis.com/projects/9/...");
}

#[tokio::test]
async fn sts_happy_path_returns_federated_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/token"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(body_string_contains(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange",
        ))
        .and(body_string_contains(
            "audience=%2F%2Fiam.googleapis.com%2Fprojects%2F123456789",
        ))
        .and(body_string_contains(
            "subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt",
        ))
        .and(body_string_contains(
            "requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token",
        ))
        .and(body_string_contains("subject_token=external-jwt"))
        .and(body_string_contains(
            "scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "federated-token-xyz",
            "expires_in": 3600,
            "token_type": "Bearer",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = GcpStsClient::new().with_endpoint(sts_endpoint(&server));
    let token = client
        .exchange_token(
            "external-jwt",
            &sample_audience(),
            &["https://www.googleapis.com/auth/cloud-platform"],
        )
        .await
        .expect("STS exchange");
    assert_eq!(&*token.access_token, "federated-token-xyz");
    assert_eq!(token.expires_in, Some(3600));
    assert_eq!(token.token_type, "Bearer");
}

#[tokio::test]
async fn sts_invalid_target_audience_surfaces_as_sts_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_target",
            "error_description": "audience is invalid",
        })))
        .mount(&server)
        .await;
    let client = GcpStsClient::new().with_endpoint(sts_endpoint(&server));
    let err = client
        .exchange_token("token", &sample_audience(), &["scope"])
        .await
        .expect_err("400 must propagate");
    match err {
        GcpError::Sts { http_status, body } => {
            assert_eq!(http_status, 400);
            assert!(body.contains("invalid_target"));
        }
        other => panic!("expected Sts error, got {other:?}"),
    }
}

#[tokio::test]
async fn sts_empty_access_token_rejects_as_malformed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "",
            "token_type": "Bearer",
        })))
        .mount(&server)
        .await;
    let client = GcpStsClient::new().with_endpoint(sts_endpoint(&server));
    let err = client
        .exchange_token("token", &sample_audience(), &["scope"])
        .await
        .expect_err("empty access_token must reject");
    assert!(matches!(err, GcpError::MalformedResponse(_)));
}

#[tokio::test]
async fn impersonation_happy_path_returns_sa_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/v1/projects/-/serviceAccounts/axess-worker@my-project.iam.gserviceaccount.com:generateAccessToken",
        ))
        .and(header(
            "authorization",
            "Bearer federated-token-from-step-1",
        ))
        .and(body_string_contains("https://www.googleapis.com/auth/bigquery"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accessToken": "ya29.sa-scoped-token",
            "expireTime": "2030-01-01T00:00:00Z",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let imp = GcpServiceAccountImpersonator::new().with_endpoint_base(iam_base(&server));
    let token = imp
        .generate_access_token(
            "federated-token-from-step-1",
            "axess-worker@my-project.iam.gserviceaccount.com",
            &["https://www.googleapis.com/auth/bigquery"],
            None,
        )
        .await
        .expect("impersonation");
    assert_eq!(&*token.access_token, "ya29.sa-scoped-token");
    assert_eq!(
        token.expire_time,
        chrono::DateTime::parse_from_rfc3339("2030-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc),
    );
}

#[tokio::test]
async fn impersonation_carries_lifetime_when_set() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/v1/projects/-/serviceAccounts/sa@p.iam.gserviceaccount.com:generateAccessToken",
        ))
        .and(body_string_contains("\"lifetime\":\"1800s\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accessToken": "tok",
            "expireTime": "2030-01-01T00:00:00Z",
        })))
        .expect(1)
        .mount(&server)
        .await;
    let imp = GcpServiceAccountImpersonator::new().with_endpoint_base(iam_base(&server));
    imp.generate_access_token(
        "fed",
        "sa@p.iam.gserviceaccount.com",
        &["scope"],
        Some(1800),
    )
    .await
    .expect("lifetime path");
}

#[tokio::test]
async fn impersonation_403_surfaces_as_iam_credentials_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/v1/projects/-/serviceAccounts/sa@p.iam.gserviceaccount.com:generateAccessToken",
        ))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": {
                "code": 403,
                "message": "Permission iam.serviceAccounts.getAccessToken denied",
                "status": "PERMISSION_DENIED",
            }
        })))
        .mount(&server)
        .await;
    let imp = GcpServiceAccountImpersonator::new().with_endpoint_base(iam_base(&server));
    let err = imp
        .generate_access_token("fed", "sa@p.iam.gserviceaccount.com", &["scope"], None)
        .await
        .expect_err("403 must propagate");
    match err {
        GcpError::IamCredentials { http_status, body } => {
            assert_eq!(http_status, 403);
            assert!(body.contains("PERMISSION_DENIED"));
        }
        other => panic!("expected IamCredentials, got {other:?}"),
    }
}

#[tokio::test]
async fn impersonation_malformed_expire_time_rejects() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/v1/projects/-/serviceAccounts/sa@p.iam.gserviceaccount.com:generateAccessToken",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accessToken": "tok",
            "expireTime": "soon",
        })))
        .mount(&server)
        .await;
    let imp = GcpServiceAccountImpersonator::new().with_endpoint_base(iam_base(&server));
    let err = imp
        .generate_access_token("fed", "sa@p.iam.gserviceaccount.com", &["scope"], None)
        .await
        .expect_err("bad expireTime must reject");
    assert!(matches!(err, GcpError::MalformedResponse(_)));
}

#[test]
fn default_endpoints_point_at_production_gcp() {
    let sts = GcpStsClient::default();
    assert_eq!(
        sts.endpoint().as_str(),
        "https://sts.googleapis.com/v1/token"
    );
    let imp = GcpServiceAccountImpersonator::default();
    assert_eq!(
        imp.endpoint_base().as_str(),
        "https://iamcredentials.googleapis.com/"
    );
}

#[tokio::test]
async fn service_account_is_confined_to_one_path_segment() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/v1/projects/-/serviceAccounts/a%2F..%2Fb%3Fx:generateAccessToken",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accessToken": "tok",
            "expireTime": "2030-01-01T00:00:00Z",
        })))
        .expect(1)
        .mount(&server)
        .await;
    let imp = GcpServiceAccountImpersonator::new().with_endpoint_base(iam_base(&server));
    imp.generate_access_token("fed", "a/../b?x", &["scope"], None)
        .await
        .expect("slash and query characters stay inside the account segment");
}

/// A silent STS endpoint must not hold the caller: the exchange ends in a
/// transport error at the configured timeout, even on an HTTP client
/// supplied without one.
#[tokio::test]
async fn a_silent_sts_endpoint_times_out() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({
                    "access_token": "federated",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                }))
                .set_delay(std::time::Duration::from_secs(5)),
        )
        .mount(&server)
        .await;
    let client = GcpStsClient::new()
        .with_endpoint(sts_endpoint(&server))
        .with_http_client(reqwest::Client::new())
        .with_timeout(std::time::Duration::from_millis(150));

    let started = std::time::Instant::now();
    let err = client
        .exchange_token("jwt", &sample_audience(), &["scope"])
        .await
        .expect_err("must time out");
    assert!(matches!(err, GcpError::Transport(_)), "{err:?}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "ended after the mock's delay, so the timeout did not end it: {:?}",
        started.elapsed()
    );
}

/// The impersonation call carries the same bound.
#[tokio::test]
async fn a_silent_iam_credentials_endpoint_times_out() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({
                    "accessToken": "ya29.sa",
                    "expireTime": "2030-01-01T00:00:00Z",
                }))
                .set_delay(std::time::Duration::from_secs(5)),
        )
        .mount(&server)
        .await;
    let client = GcpServiceAccountImpersonator::new()
        .with_endpoint_base(iam_base(&server))
        .with_http_client(reqwest::Client::new())
        .with_timeout(std::time::Duration::from_millis(150));

    let started = std::time::Instant::now();
    let err = client
        .generate_access_token("federated", "sa@p.iam.gserviceaccount.com", &["s"], None)
        .await
        .expect_err("must time out");
    assert!(matches!(err, GcpError::Transport(_)), "{err:?}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "ended after the mock's delay, so the timeout did not end it: {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_plain_http_remote_sts_endpoint_is_refused_before_any_request() {
    let client =
        GcpStsClient::new().with_endpoint(Url::parse("http://192.0.2.1:9/v1/token").unwrap());
    let err = client
        .exchange_token("jwt", &sample_audience(), &["scope"])
        .await
        .unwrap_err();
    assert!(
        matches!(&err, GcpError::Transport(m) if m.contains("must be https")),
        "{err}"
    );
}

#[tokio::test]
async fn a_plain_http_remote_impersonation_base_is_refused_before_any_request() {
    let client = GcpServiceAccountImpersonator::new()
        .with_endpoint_base(Url::parse("http://192.0.2.1:9/").unwrap());
    let err = client
        .generate_access_token(
            "federated",
            "sa@p.iam.gserviceaccount.com",
            &["scope"],
            None,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(&err, GcpError::Transport(m) if m.contains("must be https")),
        "{err}"
    );
}
