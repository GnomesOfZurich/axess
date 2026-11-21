//! The transport rail: the token URL is screened and must be HTTPS, a
//! redirect is an error, a hung endpoint times out, and a transport error
//! names no URL.

use super::*;

/// `new` screens by default: a loopback or private token URL is refused by
/// name, a public one is taken.
#[test]
fn new_screens_its_token_url_by_default() {
    for (url, range) in [
        ("https://127.0.0.1:8443/token", "loopback"),
        ("https://10.0.0.5/token", "private"),
    ] {
        let refused = OutboundOAuthClient::new(Url::parse(url).unwrap(), basic());
        assert!(
            matches!(
                &refused,
                Err(OAuthClientError::EgressRefused(r)) if r.setting == "token URL" && r.range == range
            ),
            "{url}: {:?}",
            refused.err()
        );
    }
    assert!(
        OutboundOAuthClient::new(Url::parse("https://idp.example/token").unwrap(), basic()).is_ok()
    );
}

/// A token URL that is not HTTPS, other than loopback, is refused before the
/// client secret can be sent anywhere.
#[test]
fn a_plain_http_token_url_to_a_remote_host_is_refused() {
    for url in [
        "http://idp.example.net/token",
        "http://localhost.evil.example/token",
        "http://localhost@evil.example/token",
        "ftp://idp.example.net/token",
    ] {
        let refused = loopback_new(Url::parse(url).unwrap(), basic());
        assert!(
            matches!(refused, Err(OAuthClientError::InsecureEndpoint)),
            "{url} must be refused"
        );
    }
    for url in [
        "https://idp.example.net/token",
        "http://localhost:8080/token",
        "http://127.0.0.1/token",
        "http://[::1]:9/token",
    ] {
        assert!(
            loopback_new(Url::parse(url).unwrap(), basic()).is_ok(),
            "{url} must be accepted"
        );
    }
}

/// The default client follows no redirect: a 307 from the token endpoint is
/// an error response, and the credentials are not sent to its `Location`.
#[tokio::test]
async fn a_redirecting_token_endpoint_is_an_error_and_the_target_is_never_called() {
    let target = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "stolen", "token_type": "Bearer", "expires_in": 60
        })))
        .mount(&target)
        .await;
    let origin = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("location", format!("{}/capture", target.uri())),
        )
        .mount(&origin)
        .await;

    let client = loopback_new(token_url(&origin), basic()).unwrap();
    let err = client
        .get_access_token()
        .await
        .expect_err("a redirect is an error");
    assert!(
        matches!(err, OAuthClientError::TokenEndpoint { status: 307, .. }),
        "got {err:?}"
    );
    assert!(
        target.received_requests().await.unwrap().is_empty(),
        "the redirect target must never be called"
    );
}

/// A client given settings of the caller's own is still the one the policy
/// built: it follows no redirect either, so the credentials are not sent to
/// the `Location` of a 307.
#[tokio::test]
async fn a_client_with_the_callers_settings_follows_no_redirect_either() {
    let target = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "stolen", "token_type": "Bearer", "expires_in": 60
        })))
        .mount(&target)
        .await;
    let origin = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("location", format!("{}/capture", target.uri())),
        )
        .mount(&origin)
        .await;

    let client = loopback_new(token_url(&origin), basic())
        .unwrap()
        .with_client_settings(|settings| settings.user_agent("billing-worker/2.1"))
        .expect("the settings build");
    let err = client
        .get_access_token()
        .await
        .expect_err("a redirect is an error");

    assert!(
        matches!(err, OAuthClientError::TokenEndpoint { status: 307, .. }),
        "got {err:?}"
    );
    assert!(
        target.received_requests().await.unwrap().is_empty(),
        "the redirect target must never be called"
    );
}

/// A token endpoint that never answers fails the fetch at the request
/// timeout and releases the gate, instead of holding every caller forever.
#[tokio::test]
async fn a_hung_token_endpoint_times_out_and_releases_the_gate() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(
                    json!({ "access_token": "late", "token_type": "Bearer", "expires_in": 60 }),
                )
                .set_delay(Duration::from_secs(5)),
        )
        .mount(&server)
        .await;
    let client = loopback_new(token_url(&server), basic())
        .unwrap()
        .with_request_timeout(Duration::from_millis(100));

    let started = axess_testing::stopwatch::Stopwatch::start();
    let err = client.get_access_token().await.expect_err("times out");
    assert!(matches!(err, OAuthClientError::Transport(_)), "got {err:?}");
    assert!(
        err.to_string().contains("100ms"),
        "the message names the timeout as set: {err}"
    );
    assert!(started.elapsed() < Duration::from_secs(3));

    // The gate is free: the next caller is not stuck behind the first.
    let again = tokio::time::timeout(Duration::from_secs(3), client.get_access_token()).await;
    assert!(again.expect("the second call must not hang").is_err());
}

/// A transport error names no URL: the token endpoint can carry a tenant
/// path or a key in its query, and the error reaches adopter logs.
#[tokio::test]
async fn a_transport_error_names_no_url() {
    // A port nothing listens on: bound, read, released.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let url = Url::parse(&format!("http://127.0.0.1:{port}/tenant-7f3a9c/token")).unwrap();
    let client = loopback_new(url, basic()).unwrap();
    let err = client
        .get_access_token()
        .await
        .expect_err("nothing listens");
    let OAuthClientError::Transport(message) = &err else {
        panic!("a connection refused is a transport error: {err:?}");
    };
    let shown = format!("{err} / {err:?}");
    assert!(
        !shown.contains("tenant-7f3a9c") && !shown.contains(&port.to_string()),
        "the error names the URL: {message}"
    );
}
