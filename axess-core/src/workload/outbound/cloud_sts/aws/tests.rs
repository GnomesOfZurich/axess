//! Tests for the AWS STS `AssumeRoleWithWebIdentity` adapter.
//!
//! Wiremock stands up a fake STS endpoint and asserts on the
//! request shape (Action, Version, RoleArn, RoleSessionName,
//! WebIdentityToken, optional DurationSeconds / Policy /
//! PolicyArns.member.N.arn / ProviderId encoding) and the response
//! parsing (success XML, error XML, optional fields, malformed
//! bodies, error-attribution surface).

use super::*;
use chrono::TimeZone;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const VALID_SUCCESS_BODY: &str = r#"<?xml version="1.0"?>
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <SubjectFromWebIdentityToken>system:serviceaccount:default:axess</SubjectFromWebIdentityToken>
    <Audience>sts.amazonaws.com</Audience>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789012:assumed-role/axess-worker/test-session</Arn>
      <AssumedRoleId>AROAEXAMPLE:test-session</AssumedRoleId>
    </AssumedRoleUser>
    <Provider>https://oidc.example.com</Provider>
    <Credentials>
      <SessionToken>session-token-value</SessionToken>
      <SecretAccessKey>secret-access-key-value</SecretAccessKey>
      <AccessKeyId>ASIAEXAMPLEKEY</AccessKeyId>
      <Expiration>2030-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata>
    <RequestId>example-request-id</RequestId>
  </ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>
"#;

fn endpoint(server: &MockServer) -> Url {
    Url::parse(&server.uri()).unwrap()
}

fn client(server: &MockServer) -> AwsStsClient {
    AwsStsClient::new().with_endpoint(endpoint(server))
}

fn sample_request() -> AssumeRoleWithWebIdentityRequest {
    AssumeRoleWithWebIdentityRequest::new(
        "arn:aws:iam::123456789012:role/axess-worker",
        "test-session",
        "eyJraWQiOiJ0ZXN0In0.payload.sig",
    )
}

#[tokio::test]
async fn happy_path_returns_credentials_and_assumed_role() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(body_string_contains("Action=AssumeRoleWithWebIdentity"))
        .and(body_string_contains("Version=2011-06-15"))
        .and(body_string_contains(
            "RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Faxess-worker",
        ))
        .and(body_string_contains("RoleSessionName=test-session"))
        .and(body_string_contains(
            "WebIdentityToken=eyJraWQiOiJ0ZXN0In0.payload.sig",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/xml")
                .set_body_raw(VALID_SUCCESS_BODY, "text/xml"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let resp = client(&server)
        .assume_role_with_web_identity(&sample_request())
        .await
        .expect("happy path");

    assert_eq!(&*resp.credentials.access_key_id, "ASIAEXAMPLEKEY");
    assert_eq!(
        &*resp.credentials.secret_access_key,
        "secret-access-key-value"
    );
    assert_eq!(&*resp.credentials.session_token, "session-token-value");
    assert_eq!(
        resp.credentials.expiration,
        Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap(),
    );
    assert_eq!(
        resp.assumed_role_arn,
        "arn:aws:sts::123456789012:assumed-role/axess-worker/test-session"
    );
    assert_eq!(resp.assumed_role_id, "AROAEXAMPLE:test-session");
    assert_eq!(
        resp.subject_from_web_identity_token,
        "system:serviceaccount:default:axess"
    );
    assert_eq!(resp.provider.as_deref(), Some("https://oidc.example.com"));
    assert_eq!(resp.audience.as_deref(), Some("sts.amazonaws.com"));
}

#[tokio::test]
async fn optional_fields_appear_in_form_when_set() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("DurationSeconds=900"))
        .and(body_string_contains("Policy="))
        .and(body_string_contains(
            "PolicyArns.member.1.arn=arn%3Aaws%3Aiam%3A%3Aaws%3Apolicy%2FReadOnlyAccess",
        ))
        .and(body_string_contains(
            "PolicyArns.member.2.arn=arn%3Aaws%3Aiam%3A%3Aaws%3Apolicy%2FAmazonS3ReadOnlyAccess",
        ))
        .and(body_string_contains("ProviderId=www.amazon.com"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/xml")
                .set_body_raw(VALID_SUCCESS_BODY, "text/xml"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let req = sample_request()
        .with_duration_seconds(900)
        .with_policy(r#"{"Version":"2012-10-17","Statement":[]}"#)
        .with_policy_arn("arn:aws:iam::aws:policy/ReadOnlyAccess")
        .with_policy_arn("arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")
        .with_provider_id("www.amazon.com");
    client(&server)
        .assume_role_with_web_identity(&req)
        .await
        .expect("optional fields path");
}

#[tokio::test]
async fn invalid_identity_token_surfaces_structured_error() {
    let server = MockServer::start().await;
    let error_body = r#"<?xml version="1.0"?>
<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>InvalidIdentityToken</Code>
    <Message>The web identity token has expired or is invalid.</Message>
  </Error>
  <RequestId>aws-request-id-1234</RequestId>
</ErrorResponse>
"#;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("content-type", "text/xml")
                .set_body_raw(error_body, "text/xml"),
        )
        .mount(&server)
        .await;

    let err = client(&server)
        .assume_role_with_web_identity(&sample_request())
        .await
        .expect_err("400 must propagate as StsError");
    match err {
        AwsStsError::StsError {
            http_status,
            code,
            message,
            fault_type,
            request_id,
        } => {
            assert_eq!(http_status, 400);
            assert_eq!(code, "InvalidIdentityToken");
            assert!(message.contains("expired or is invalid"));
            assert_eq!(fault_type.as_deref(), Some("Sender"));
            assert_eq!(request_id.as_deref(), Some("aws-request-id-1234"));
        }
        other => panic!("expected StsError, got {other:?}"),
    }
}

#[tokio::test]
async fn non_xml_error_body_still_surfaces_as_sts_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(503).set_body_raw("Service Unavailable", "text/plain"))
        .mount(&server)
        .await;

    let err = client(&server)
        .assume_role_with_web_identity(&sample_request())
        .await
        .expect_err("503 must propagate");
    match err {
        AwsStsError::StsError {
            http_status,
            code,
            message,
            fault_type,
            request_id,
        } => {
            assert_eq!(http_status, 503);
            assert_eq!(code, "Unknown");
            assert!(message.contains("Service Unavailable"));
            assert!(fault_type.is_none());
            assert!(request_id.is_none());
        }
        other => panic!("expected StsError, got {other:?}"),
    }
}

#[tokio::test]
async fn malformed_xml_response_surfaces_as_malformed_response() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/xml")
                .set_body_raw("not actually xml", "text/xml"),
        )
        .mount(&server)
        .await;

    let err = client(&server)
        .assume_role_with_web_identity(&sample_request())
        .await
        .expect_err("non-XML success body must surface");
    assert!(
        matches!(err, AwsStsError::MalformedResponse(_)),
        "expected MalformedResponse, got {err:?}"
    );
}

/// Empty `AccessKeyId` in the success body must surface as
/// `MalformedResponse`, not silently produce a credential set with
/// empty strings (an adopter signing requests with `""` would get
/// SignatureDoesNotMatch from every AWS call).
#[tokio::test]
async fn empty_access_key_id_in_response_rejects() {
    let server = MockServer::start().await;
    let body = VALID_SUCCESS_BODY.replace("ASIAEXAMPLEKEY", "");
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/xml")
                .set_body_raw(body, "text/xml"),
        )
        .mount(&server)
        .await;

    let err = client(&server)
        .assume_role_with_web_identity(&sample_request())
        .await
        .expect_err("empty access_key_id must reject");
    assert!(matches!(err, AwsStsError::MalformedResponse(_)));
}

/// Non-RFC3339 `Expiration` must surface as malformed rather than
/// silently producing an unbounded credential.
#[tokio::test]
async fn non_rfc3339_expiration_rejects() {
    let server = MockServer::start().await;
    let body = VALID_SUCCESS_BODY.replace("2030-01-01T00:00:00Z", "tomorrow");
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/xml")
                .set_body_raw(body, "text/xml"),
        )
        .mount(&server)
        .await;

    let err = client(&server)
        .assume_role_with_web_identity(&sample_request())
        .await
        .expect_err("non-RFC3339 expiration must reject");
    assert!(matches!(err, AwsStsError::MalformedResponse(_)));
}

/// `with_http_client` override must be respected: adopter-supplied
/// reqwest::Client wiring (proxy / mTLS / connection pool) survives
/// the client construction chain.
#[tokio::test]
async fn with_http_client_override_is_used() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(header("user-agent", "axess-test-override"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/xml")
                .set_body_raw(VALID_SUCCESS_BODY, "text/xml"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let custom_http = reqwest::Client::builder()
        .user_agent("axess-test-override")
        .build()
        .unwrap();
    let client = AwsStsClient::new()
        .with_endpoint(endpoint(&server))
        .with_http_client(custom_http);
    client
        .assume_role_with_web_identity(&sample_request())
        .await
        .expect("custom http client must reach mock");
}

#[test]
fn default_endpoint_is_global_sts() {
    let client = AwsStsClient::default();
    assert_eq!(client.endpoint().as_str(), "https://sts.amazonaws.com/");
}
