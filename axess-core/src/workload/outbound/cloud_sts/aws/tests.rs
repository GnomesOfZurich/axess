//! Tests for the AWS STS `AssumeRoleWithWebIdentity` adapter.
//!
//! Wiremock stands up a fake STS endpoint and asserts on the
//! request shape (Action, Version, RoleArn, RoleSessionName,
//! WebIdentityToken, optional DurationSeconds / Policy /
//! PolicyArns.member.N.arn / ProviderId encoding) and the response
//! parsing (success XML, error XML, optional fields, malformed
//! bodies, error-attribution surface).

use super::*;
use axess_clock::Timestamp;
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
    AwsStsClient::new()
        .expect("client")
        .with_endpoint(endpoint(server))
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
        Timestamp::from_utc(2030, 1, 1, 0, 0, 0).unwrap(),
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
        .with_duration(std::time::Duration::from_secs(900))
        .expect("a duration AWS takes")
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
    let err = sts_error_for(error_body).await;
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

/// An error document whose message runs past the 1 KiB kept for a message
/// is read whole and keeps its code; the message that reaches the error is
/// still cut.
#[tokio::test]
async fn a_long_error_message_keeps_the_code() {
    let error_body = format!(
        r#"<?xml version="1.0"?>
<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Message>{}</Message>
    <Code>InvalidIdentityToken</Code>
  </Error>
  <RequestId>aws-request-id-1234</RequestId>
</ErrorResponse>
"#,
        "m".repeat(4096)
    );
    let err = sts_error_for(error_body).await;

    let AwsStsError::StsError { code, message, .. } = &err else {
        panic!("expected StsError, got {err:?}");
    };
    assert_eq!(code, "InvalidIdentityToken");
    assert!(message.len() <= 600, "{} bytes", message.len());
}

/// The error answer for `body`, served as `content_type` with `status`.
async fn refusal(status: u16, body: impl Into<Vec<u8>>, content_type: &str) -> AwsStsError {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(status).set_body_raw(body.into(), content_type))
        .mount(&server)
        .await;
    client(&server)
        .assume_role_with_web_identity(&sample_request())
        .await
        .expect_err("a refusal must propagate as an error")
}

/// The error answer for the XML document `body`, served with status 400.
async fn sts_error_for(body: impl Into<Vec<u8>>) -> AwsStsError {
    refusal(400, body, "text/xml").await
}

/// An error document of `fields` inside `Error`, as STS writes one.
fn error_document(fields: &str) -> String {
    format!(
        r#"<?xml version="1.0"?>
<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>{fields}</Error>
  <RequestId>aws-request-id-1234</RequestId>
</ErrorResponse>
"#
    )
}

/// A refusal longer than the read bound does not parse whole; the code and
/// fault type that came before the cut are still read, and the message cut
/// with the body reaches the error cut again.
#[tokio::test]
async fn a_refusal_cut_at_the_read_bound_keeps_a_code_before_the_cut() {
    let message = "m".repeat(axess_factors::http_body::ERROR_BODY_PARSE_BYTES);
    let err = sts_error_for(error_document(&format!(
        "<Type>Sender</Type><Code>InvalidIdentityToken</Code><Message>{message}</Message>"
    )))
    .await;

    let AwsStsError::StsError {
        code,
        message,
        fault_type,
        request_id,
        ..
    } = &err
    else {
        panic!("expected StsError, got {err:?}");
    };
    assert_eq!(code, "InvalidIdentityToken");
    assert_eq!(fault_type.as_deref(), Some("Sender"));
    assert_eq!(request_id.as_deref(), None);
    assert!(message.starts_with('m'), "{message}");
    assert_log_safe(message, "message", 512);
}

/// A code the read bound cut off is not guessed: the refusal reads as
/// `Unknown`, with the start of the body as its message.
#[tokio::test]
async fn a_code_past_the_read_bound_reads_as_unknown() {
    let message = "m".repeat(axess_factors::http_body::ERROR_BODY_PARSE_BYTES);
    let err = sts_error_for(error_document(&format!(
        "<Message>{message}</Message><Code>InvalidIdentityToken</Code>"
    )))
    .await;

    let AwsStsError::StsError { code, message, .. } = &err else {
        panic!("expected StsError, got {err:?}");
    };
    assert_eq!(code, "Unknown");
    assert!(message.contains("ErrorResponse"), "{message}");
    assert_log_safe(message, "message", 512 + NO_CODE_MESSAGE.len());
}

/// The fields of an error document read as XML text: entity and character
/// references resolved, CDATA taken as written, and the first element of a
/// name counted.
#[tokio::test]
async fn the_error_fields_resolve_references_and_cdata() {
    let err = sts_error_for(error_document(
        "<Code>Invalid&amp;Token&#x41;</Code>\
         <Message><![CDATA[a <b> c]]> &lt;d&gt;</Message>\
         <Code>Second</Code>",
    ))
    .await;

    let AwsStsError::StsError {
        code,
        message,
        request_id,
        ..
    } = &err
    else {
        panic!("expected StsError, got {err:?}");
    };
    assert_eq!(code, "Invalid&TokenA");
    assert_eq!(message, "a <b> c <d>");
    assert_eq!(request_id.as_deref(), Some("aws-request-id-1234"));
}

/// A refusal the read bound cuts inside its code reads as `Unknown`: the
/// start of a code is not taken for the code, since it can be another code.
#[tokio::test]
async fn a_code_the_read_bound_cuts_through_reads_as_unknown() {
    let head = "<ErrorResponse><Error><Type>Sender</Type><Message>";
    let before_code = "</Message><Code>ExpiredToken";
    let pad = axess_factors::http_body::ERROR_BODY_PARSE_BYTES - head.len() - before_code.len();
    let err = sts_error_for(format!(
        "{head}{}{before_code}Exception</Code></Error></ErrorResponse>",
        "m".repeat(pad)
    ))
    .await;

    let AwsStsError::StsError {
        code, fault_type, ..
    } = &err
    else {
        panic!("expected StsError, got {err:?}");
    };
    assert_eq!(code, "Unknown");
    assert_eq!(fault_type.as_deref(), None);
}

/// Where reading stops, by a cut or by text that is not well-formed XML, a
/// `Code`, `Type` or `RequestId` it stopped inside is not kept, a `Message`
/// keeps its text up to the stop, and every field closed before is kept.
#[test]
fn reading_stops_without_keeping_a_half_read_identifier() {
    let head = "<ErrorResponse><Error><Type>Sender</Type>";

    let cut_in_code = StsErrorFields::read(&format!("{head}<Code>ExpiredTok"));
    assert_eq!(cut_in_code.code, None);
    assert_eq!(cut_in_code.fault_type.as_deref(), Some("Sender"));

    let cut_in_type = StsErrorFields::read("<ErrorResponse><Error><Type>Send");
    assert_eq!(cut_in_type.fault_type, None);

    let cut_in_request_id =
        StsErrorFields::read(&format!("{head}<Code>C</Code></Error><RequestId>aws-req"));
    assert_eq!(cut_in_request_id.code.as_deref(), Some("C"));
    assert_eq!(cut_in_request_id.request_id, None);

    let cut_in_message = StsErrorFields::read(&format!("{head}<Code>C</Code><Message>abc<b>x"));
    assert_eq!(cut_in_message.code.as_deref(), Some("C"));
    assert_eq!(cut_in_message.message.as_deref(), Some("abcx"));

    let bad_reference_in_code = StsErrorFields::read(&format!(
        "{head}<Code>Invalid&bogus Token</Code><Message>x</Message></Error></ErrorResponse>"
    ));
    assert_eq!(bad_reference_in_code.code, None);

    let undefined_entity_in_code = StsErrorFields::read(&format!(
        "{head}<Code>C&foo;</Code><Message>x</Message></Error></ErrorResponse>"
    ));
    assert_eq!(undefined_entity_in_code.code, None);

    let undefined_entity_in_message = StsErrorFields::read(&format!(
        "{head}<Code>C</Code><Message>ab&foo;cd</Message></Error></ErrorResponse>"
    ));
    assert_eq!(undefined_entity_in_message.code.as_deref(), Some("C"));
    assert_eq!(undefined_entity_in_message.message.as_deref(), Some("ab"));
}

/// A field reads as its text exactly: an empty element is an empty field,
/// written either way, surrounding space is kept, and the text of an
/// element inside a field is part of it.
#[test]
fn a_field_reads_as_its_text_exactly() {
    let read = |error: &str| {
        StsErrorFields::read(&format!(
            "<ErrorResponse><Error>{error}</Error></ErrorResponse>"
        ))
    };
    assert_eq!(
        read("<Code/><Message>x</Message>").code.as_deref(),
        Some("")
    );
    assert_eq!(read("<Code></Code>").code.as_deref(), Some(""));

    let spaced = read("<Code> X </Code><Message> y </Message>");
    assert_eq!(spaced.code.as_deref(), Some(" X "));
    assert_eq!(spaced.message.as_deref(), Some(" y "));

    let mixed = read("<Code>C</Code><Message>abc<b>x</b>def</Message>");
    assert_eq!(mixed.message.as_deref(), Some("abcxdef"));

    let nested = read("<Detail><Code>Inner</Code></Detail><Code>Outer</Code>");
    assert_eq!(nested.code.as_deref(), Some("Outer"));
}

/// Only the root's `Error` holds the error's fields: a `Type`, `Code` or
/// `Message` inside any other element of the root is not read, even when it
/// comes first.
#[test]
fn a_field_outside_the_error_element_is_not_the_errors() {
    let fields = StsErrorFields::read(
        "<ErrorResponse>\
         <Other><Type>Receiver</Type><Code>Elsewhere</Code><Message>not this</Message></Other>\
         <Error><Code>InvalidIdentityToken</Code></Error>\
         </ErrorResponse>",
    );

    assert_eq!(fields.code.as_deref(), Some("InvalidIdentityToken"));
    assert_eq!(fields.fault_type, None);
    assert_eq!(fields.message, None);
}

/// An error document with a `Code` and no `Message` reads as that code with
/// an empty message, and an empty `Code` as an empty code, not `Unknown`.
#[tokio::test]
async fn a_code_without_a_message_keeps_the_code() {
    let err = sts_error_for(error_document("<Code>InvalidIdentityToken</Code>")).await;
    let AwsStsError::StsError { code, message, .. } = &err else {
        panic!("expected StsError, got {err:?}");
    };
    assert_eq!(code, "InvalidIdentityToken");
    assert_eq!(message, "");

    let err = sts_error_for(error_document("<Code/><Message>x</Message>")).await;
    let AwsStsError::StsError { code, message, .. } = &err else {
        panic!("expected StsError, got {err:?}");
    };
    assert_eq!(code, "");
    assert_eq!(message, "x");
}

#[tokio::test]
async fn non_xml_error_body_still_surfaces_as_sts_error() {
    let err = refusal(503, "Service Unavailable", "text/plain").await;
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

/// The text of an error that is meant for a log line: one line, no control
/// character, and short.
fn assert_log_safe(text: &str, what: &str, max_bytes: usize) {
    assert!(
        !text.chars().any(char::is_control),
        "{what} has a control character: {text:?}"
    );
    assert!(text.len() <= max_bytes, "{what} is {} bytes", text.len());
}

#[tokio::test]
async fn a_non_xml_error_body_is_sanitized_in_the_message() {
    let mut body = b"Service Unavailable\r\nINFO forged line\x1b[2J".to_vec();
    body.extend(std::iter::repeat_n(b'A', 10_000));
    let err = refusal(503, body, "text/plain").await;
    let AwsStsError::StsError { message, .. } = &err else {
        panic!("expected StsError, got {err:?}");
    };
    assert_log_safe(message, "message", 512 + NO_CODE_MESSAGE.len());
    assert!(message.contains("Service Unavailable"), "{message}");
    assert!(message.contains("forged line"), "{message}");
    assert_log_safe(&err.to_string(), "the Display text", 768);
}

#[tokio::test]
async fn the_xml_error_fields_are_sanitized() {
    let error_body = "<?xml version=\"1.0\"?>\
<ErrorResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">\
  <Error>\
    <Type>Sender\r\nINFO forged</Type>\
    <Code>InvalidIdentityToken\x1b[2J</Code>\
    <Message>expired\r\nERROR forged line\u{2028}after</Message>\
  </Error>\
  <RequestId>aws-request-id\r\n1234</RequestId>\
</ErrorResponse>";
    let err = sts_error_for(error_body).await;
    let AwsStsError::StsError {
        code,
        message,
        fault_type,
        request_id,
        ..
    } = &err
    else {
        panic!("expected StsError, got {err:?}");
    };
    assert_log_safe(code, "code", 128);
    assert_log_safe(message, "message", 512);
    assert_log_safe(fault_type.as_deref().unwrap_or(""), "fault type", 128);
    assert_log_safe(request_id.as_deref().unwrap_or(""), "request id", 128);
    assert!(!message.contains('\u{2028}'), "{message:?}");
    assert!(code.starts_with("InvalidIdentityToken"), "{code}");
    assert!(message.contains("forged line"), "{message}");
    assert_log_safe(&err.to_string(), "the Display text", 1024);
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

/// The adopter's client settings are respected: the `User-Agent` they name
/// is the one the STS call carries.
#[tokio::test]
async fn the_adopters_client_settings_are_used() {
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

    let client = AwsStsClient::new()
        .expect("client")
        .with_endpoint(endpoint(&server))
        .with_client_settings(|settings| settings.user_agent("axess-test-override"))
        .expect("client settings");
    client
        .assume_role_with_web_identity(&sample_request())
        .await
        .expect("the client with the adopter's settings must reach the mock");
}

#[test]
fn default_endpoint_is_global_sts() {
    let client = AwsStsClient::new().expect("client");
    assert_eq!(client.endpoint().as_str(), "https://sts.amazonaws.com/");
}

#[test]
fn request_debug_redacts_web_identity_token() {
    let req = AssumeRoleWithWebIdentityRequest::new("arn:aws:iam::1:role/r", "sess", "SECRET-JWT");
    let shown = format!("{req:?}");
    assert!(!shown.contains("SECRET-JWT"), "{shown}");
    assert!(shown.contains("arn:aws:iam::1:role/r"));
}

/// A token endpoint that never answers in time must not hold the caller:
/// the request ends in a transport error at the configured timeout, even
/// on a client whose own request timeout was set far longer.
#[tokio::test]
async fn a_silent_sts_endpoint_times_out() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(VALID_SUCCESS_BODY)
                .set_delay(std::time::Duration::from_secs(5)),
        )
        .mount(&server)
        .await;
    let client = client(&server)
        .with_client_settings(|settings| settings.timeout(std::time::Duration::from_secs(3600)))
        .expect("client settings")
        .with_timeout(std::time::Duration::from_millis(150));

    let started = axess_testing::stopwatch::Stopwatch::start();
    let err = client
        .assume_role_with_web_identity(&sample_request())
        .await
        .expect_err("must time out");
    assert!(matches!(err, AwsStsError::Transport(_)), "{err:?}");
    // The proof is that the call ended before the server would have
    // answered (its delay is 5 s), not how fast a loaded machine scheduled it.
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "ended after the mock's delay, so the timeout did not end it: {:?}",
        started.elapsed()
    );
}

#[test]
fn parsed_credentials_block_debug_does_not_print_the_secrets() {
    let body = r#"<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult>
<Credentials><AccessKeyId>AKIAEXAMPLEKEYID</AccessKeyId>
<SecretAccessKey>wJalrSECRETsecretKEYvalue</SecretAccessKey>
<SessionToken>FwoGZXIvYXdzSESSIONTOKEN</SessionToken>
<Expiration>2030-01-01T00:00:00Z</Expiration></Credentials>
<AssumedRoleUser><Arn>arn:aws:sts::1:assumed-role/r/s</Arn><AssumedRoleId>AROA:s</AssumedRoleId></AssumedRoleUser>
<SubjectFromWebIdentityToken>sub</SubjectFromWebIdentityToken>
</AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>"#;
    let parsed: StsSuccessEnvelope = quick_xml::de::from_str(body).expect("parses");
    let shown = format!("{parsed:?}");
    for secret in [
        "AKIAEXAMPLEKEYID",
        "wJalrSECRETsecretKEYvalue",
        "SESSIONTOKEN",
    ] {
        assert!(!shown.contains(secret), "Debug leaked {secret}: {shown}");
    }
}

#[tokio::test]
async fn a_plain_http_remote_endpoint_is_refused_before_any_request() {
    let client = AwsStsClient::new()
        .expect("client")
        .with_endpoint(Url::parse("http://192.0.2.1:9/").unwrap());
    let err = client
        .assume_role_with_web_identity(&sample_request())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, AwsStsError::Transport(m) if m.contains("must be https")),
        "{err}"
    );
}

#[tokio::test]
async fn the_default_client_does_not_follow_a_redirect() {
    let target = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(VALID_SUCCESS_BODY, "text/xml"))
        .expect(0)
        .mount(&target)
        .await;
    let first = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(307).insert_header("location", target.uri().as_str()))
        .expect(1)
        .mount(&first)
        .await;
    let result = client(&first)
        .assume_role_with_web_identity(&sample_request())
        .await;
    assert!(result.is_err());
}

/// A client that cannot be built is an error, never `reqwest::Client::default()`
/// (redirects followed, no connect timeout) in its place. A `User-Agent` that
/// is not a header value is a build failure a test can arrange whatever TLS
/// backend the feature set resolves to.
#[test]
fn a_client_that_cannot_be_built_is_an_error_not_a_default_client() {
    let err = AwsStsClient::new()
        .expect("client")
        .with_client_settings(|settings| settings.user_agent("not a\nheader value"))
        .err()
        .expect("a failed build must surface, not fall back to an unhardened client");
    assert!(matches!(err, AwsStsError::ClientBuild(_)), "{err:?}");
    assert!(
        std::error::Error::source(&err).is_some(),
        "the builder's error is kept as the source: {err:?}"
    );
    assert!(
        AwsStsClient::new().is_ok(),
        "the default build still succeeds"
    );
}

/// The request's web-identity token is held in a `ZeroizedString`, which
/// wipes its buffer when the request is dropped. The request has no `Drop` of
/// its own to keep in step with that field: taking the token out of it
/// compiles only while it has none.
#[test]
fn the_web_identity_token_is_held_in_a_zeroizing_string() {
    let AssumeRoleWithWebIdentityRequest {
        web_identity_token, ..
    } = AssumeRoleWithWebIdentityRequest::new("arn:aws:iam::123:role/r", "session", "the-token");
    let held: ZeroizedString = web_identity_token;
    assert_eq!(&*held, "the-token");
}

/// AWS takes `DurationSeconds` as a whole number of seconds from 900 to
/// 43200: a duration outside that range, or with a fraction of a second, is
/// refused by name where it is configured, in `with_duration`, so no request
/// can hold one; the bounds themselves are sent as written.
#[tokio::test]
async fn a_duration_aws_does_not_take_is_refused_where_it_is_configured() {
    use std::time::Duration;
    let server = MockServer::start().await;
    for (seconds, sent) in [
        (900, "DurationSeconds=900"),
        (43_200, "DurationSeconds=43200"),
    ] {
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_string_contains(sent))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/xml")
                    .set_body_raw(VALID_SUCCESS_BODY, "text/xml"),
            )
            .expect(1)
            .mount(&server)
            .await;
        let req = sample_request()
            .with_duration(Duration::from_secs(seconds))
            .expect("a bound AWS takes");
        assert_eq!(req.duration(), Some(Duration::from_secs(seconds)));
        client(&server)
            .assume_role_with_web_identity(&req)
            .await
            .expect("a bound AWS takes is sent");
    }
    for duration in [
        AssumeRoleWithWebIdentityRequest::MIN_DURATION - Duration::from_secs(1),
        AssumeRoleWithWebIdentityRequest::MAX_DURATION + Duration::from_secs(1),
        Duration::from_millis(900_500),
        AssumeRoleWithWebIdentityRequest::MAX_DURATION - Duration::from_nanos(1),
        Duration::ZERO,
    ] {
        match sample_request().with_duration(duration) {
            Err(err @ AwsStsError::InvalidDuration(refused)) => {
                assert_eq!(refused, duration);
                assert!(err.to_string().contains("`duration`"), "{err}");
            }
            other => panic!("a duration of {duration:?} must be refused, got {other:?}"),
        }
    }
    // A request with no duration sends none.
    assert_eq!(sample_request().duration(), None);
    // Only the two bounds reached the server.
    assert_eq!(
        server.received_requests().await.unwrap_or_default().len(),
        2
    );
}
