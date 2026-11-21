#![cfg(all(feature = "social", feature = "outbound-oauth"))]
//! The social-login provider and the outbound OAuth client build their HTTP
//! client through an egress policy, as the OIDC provider does: their
//! endpoints are checked against it, and under a screened policy a request
//! follows no proxy from the environment, where the client axess built
//! before followed one whatever the deployment asked.
//!
//! The environment is read when a client is built, and setting a variable in
//! this process is not safe beside other threads, so the proxy probe runs in
//! a child process that this binary starts with `HTTPS_PROXY` set.

use axess_clock::testing::MockClock;
use axess_factors::ZeroizedString;
use axess_factors::egress::EgressPolicy;
use axess_factors::outbound_oauth_client::{
    ClientAuthMethod, OAuthClientError, OutboundOAuthClient,
};
use axess_factors::social::{SocialClaims, SocialError, SocialProvider, SocialProviderConfig};
use std::net::TcpListener;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

const CHILD_FLAG: &str = "AXESS_EGRESS_CLIENTS_PROXY_PROBE";
const PROBE: &str = "a_screened_client_does_not_follow_a_proxy_from_the_environment";

fn mapper(_: &serde_json::Value) -> Result<SocialClaims, SocialError> {
    Err(SocialError::ClaimMapping("not reached".into()))
}

fn social_config(token_endpoint: &str) -> SocialProviderConfig {
    SocialProviderConfig {
        name: "idp".into(),
        authorization_endpoint: "https://idp.example/authorize".into(),
        token_endpoint: token_endpoint.into(),
        userinfo_endpoint: "https://idp.example/userinfo".into(),
        client_id: "client".into(),
        client_secret: ZeroizedString::new("secret".to_string()),
        redirect_uri: "https://rp.example/callback".into(),
        scopes: vec![],
    }
}

fn basic() -> ClientAuthMethod {
    ClientAuthMethod::ClientSecretBasic {
        client_id: "client".into(),
        client_secret: ZeroizedString::new("secret".to_string()),
    }
}

#[test]
fn an_endpoint_on_a_reserved_address_is_refused_under_a_screened_policy() {
    let clock = MockClock::at_reference();
    for (url, range) in [
        ("https://10.0.0.5/token", "private"),
        ("https://169.254.169.254/token", "metadata"),
    ] {
        let Err(err) =
            SocialProvider::new_screened(social_config(url), mapper, EgressPolicy::screened())
        else {
            panic!("social: {url} was accepted");
        };
        let message = err.to_string();
        assert!(
            message.contains("token_endpoint") && message.contains(range),
            "social: {message}"
        );
        assert!(
            !message.contains(url),
            "social: the URL is echoed: {message}"
        );

        let Err(err) = OutboundOAuthClient::new_screened(
            url.parse().unwrap(),
            basic(),
            EgressPolicy::screened(),
        ) else {
            panic!("outbound: {url} was accepted");
        };
        assert!(
            matches!(&err, OAuthClientError::EgressRefused(r) if r.setting == "token URL" && r.range == range),
            "outbound refuses by its own variant: {err:?}"
        );
        let message = err.to_string();
        assert!(
            message.contains("token URL") && message.contains(range),
            "outbound: {message}"
        );
        assert!(
            !message.contains(url),
            "outbound: the URL is echoed: {message}"
        );

        SocialProvider::new_screened(social_config(url), mapper, EgressPolicy::unscreened())
            .unwrap_or_else(|e| panic!("social: unscreened takes {url}: {e}"));
        OutboundOAuthClient::new_screened(
            url.parse().unwrap(),
            basic(),
            EgressPolicy::unscreened(),
        )
        .unwrap_or_else(|e| panic!("outbound: unscreened takes {url}: {e}"))
        .with_clock(Arc::new(clock.clone()));
    }
}

/// What the child does: one token request from each client to an HTTPS URL
/// on loopback where nothing listens. Under a proxy from the environment the
/// request goes to the proxy; without one it fails on the spot.
fn probe(policy: EgressPolicy) {
    let clock = MockClock::at_reference();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let token = "https://localhost:9/token";
        let social = SocialProvider::new_screened(social_config(token), mapper, policy)
            .expect("the social provider builds");
        let auth = social.build_auth_url();
        let _ = social
            .exchange_code(&auth.state, &auth.state, "code", &auth.pkce_verifier)
            .await;
        let outbound = OutboundOAuthClient::new_screened(token.parse().unwrap(), basic(), policy)
            .expect("the outbound client builds")
            .with_clock(Arc::new(clock.clone()))
            .with_request_timeout(Duration::from_secs(5));
        let _ = outbound.get_access_token().await;
    });
}

fn policy_named(name: &str) -> EgressPolicy {
    match name {
        "screened" => EgressPolicy::screened_allowing_loopback_http(),
        "unscreened" => EgressPolicy::unscreened(),
        other => panic!("unknown policy {other}"),
    }
}

/// How many connections the "proxy" accepted while a child under `policy`
/// made its requests. Each accepted connection is closed at once, so a
/// child that reaches the proxy fails fast instead of waiting out a timeout.
fn connections_seen_by_the_proxy(policy: &str) -> usize {
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    proxy.set_nonblocking(true).unwrap();
    let url = format!("http://{}", proxy.local_addr().unwrap());
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", PROBE, "--nocapture", "--test-threads=1"])
        .env(CHILD_FLAG, policy)
        .env("HTTPS_PROXY", &url)
        .env("https_proxy", &url)
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .spawn()
        .unwrap();
    let mut seen = 0;
    loop {
        match proxy.accept() {
            Ok((stream, _)) => {
                seen += 1;
                drop(stream);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success(), "the probe process failed");
                    while proxy.accept().is_ok() {
                        seen += 1;
                    }
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("the proxy listener failed: {e}"),
        }
    }
    seen
}

#[test]
fn a_screened_client_does_not_follow_a_proxy_from_the_environment() {
    if let Ok(policy) = std::env::var(CHILD_FLAG) {
        probe(policy_named(&policy));
        return;
    }
    assert_eq!(
        connections_seen_by_the_proxy("screened"),
        0,
        "a screened client's token request went to the proxy from the environment"
    );
}

/// The control: the probe does reach a proxy when the policy follows one, so
/// the zero above is a result and not a request that was never made.
#[test]
fn an_unscreened_client_still_follows_the_environment() {
    if std::env::var(CHILD_FLAG).is_ok() {
        return;
    }
    assert!(
        connections_seen_by_the_proxy("unscreened") >= 2,
        "the probe did not reach the proxy from both clients under the unscreened policy"
    );
}
