//! The social provider's HTTP client: whose `User-Agent` goes out, and the
//! caps on the token and userinfo bodies it reads.

use super::*;

// ── User-Agent ownership ─────────────────────────────────────────────

async fn userinfo_mock(server: &MockServer, user_agent: &str) {
    Mock::given(method("GET"))
        .and(path("/user"))
        .and(header("user-agent", user_agent))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "id": 7 })))
        .expect(1)
        .mount(server)
        .await;
}

/// The default client carries the `axess-social/<version>` agent.
#[tokio::test]
async fn default_client_sends_the_axess_user_agent() {
    let server = MockServer::start().await;
    userinfo_mock(&server, concat!("axess-social/", env!("CARGO_PKG_VERSION"))).await;
    let claims = make_provider(&server).fetch_userinfo("tok").await.unwrap();
    assert_eq!(claims.subject, "7");
}

/// A `User-Agent` the adopter's settings name is the one that goes out.
#[tokio::test]
async fn the_adopters_user_agent_is_the_one_sent() {
    let server = MockServer::start().await;
    userinfo_mock(&server, "adopter-app/3.1").await;
    let claims = make_provider(&server)
        .with_client_settings(|settings| settings.user_agent("adopter-app/3.1"))
        .unwrap()
        .fetch_userinfo("tok")
        .await
        .unwrap();
    assert_eq!(claims.subject, "7");
}

// ── response size caps ───────────────────────────────────────────────────────

/// A JSON object padded with a string member to exactly `total` bytes.
fn padded_json(prefix: &str, total: usize) -> Vec<u8> {
    let suffix = r#""}"#;
    let pad = total - prefix.len() - suffix.len();
    let mut body = prefix.as_bytes().to_vec();
    body.extend(std::iter::repeat_n(b'a', pad));
    body.extend_from_slice(suffix.as_bytes());
    assert_eq!(body.len(), total);
    body
}

async fn serve(server: &MockServer, route: &str, body: Vec<u8>) {
    Mock::given(method(if route == "/user" { "GET" } else { "POST" }))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
        .mount(server)
        .await;
}

#[tokio::test]
async fn a_token_body_over_the_cap_is_refused() {
    let server = MockServer::start().await;
    let body = padded_json(
        r#"{"access_token":"t","pad":""#,
        crate::http_body::MAX_TOKEN_BODY_BYTES + 1,
    );
    serve(&server, "/login/oauth/access_token", body).await;

    let err = make_provider(&server)
        .exchange_code(STATE, STATE, "c", VERIFIER)
        .await
        .expect_err("oversized token body");

    assert!(
        matches!(&err, SocialError::InvalidResponse(m) if m.contains("exceeds")),
        "got {err:?}"
    );
}

#[tokio::test]
async fn a_token_body_at_the_cap_is_read() {
    let server = MockServer::start().await;
    let body = padded_json(
        r#"{"access_token":"t","token_type":"Bearer","pad":""#,
        crate::http_body::MAX_TOKEN_BODY_BYTES,
    );
    serve(&server, "/login/oauth/access_token", body).await;

    let token = make_provider(&server)
        .exchange_code(STATE, STATE, "c", VERIFIER)
        .await
        .expect("a body of exactly the cap is read");

    assert_eq!(&*token, "t");
}

#[tokio::test]
async fn a_userinfo_body_over_the_cap_is_refused() {
    let server = MockServer::start().await;
    let body = padded_json(
        r#"{"id":1,"pad":""#,
        crate::http_body::MAX_USERINFO_BODY_BYTES + 1,
    );
    serve(&server, "/user", body).await;

    let err = make_provider(&server)
        .fetch_userinfo("tok")
        .await
        .expect_err("oversized userinfo body");

    assert!(
        matches!(&err, SocialError::InvalidResponse(m) if m.contains("exceeds")),
        "got {err:?}"
    );
}

#[tokio::test]
async fn a_userinfo_body_at_the_cap_is_read() {
    let server = MockServer::start().await;
    let body = padded_json(
        r#"{"id":1,"pad":""#,
        crate::http_body::MAX_USERINFO_BODY_BYTES,
    );
    serve(&server, "/user", body).await;

    let claims = make_provider(&server)
        .fetch_userinfo("tok")
        .await
        .expect("a body of exactly the cap is read");

    assert_eq!(claims.subject, "1");
}
