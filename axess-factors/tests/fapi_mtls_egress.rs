#![cfg(feature = "oauth")]
//! Under the FAPI profile with mTLS the provider swaps its HTTP client for
//! one that presents the client certificate. That client is built by the
//! egress policy discovery ran under, so the token, PAR, userinfo and
//! revocation requests keep the screen: no proxy from the environment, no
//! connection to a reserved address, and an advertised `mtls_endpoint_aliases`
//! entry is checked against the policy before a request can go to it.
//!
//! The environment is read when a client is built, and setting a variable in
//! this process is not safe beside other threads, so the proxy probe runs in
//! a child process that this binary starts with `HTTPS_PROXY` set.

use axess_factors::egress::EgressPolicy;
use axess_factors::oauth::{FapiConfig, OAuthProvider, OAuthProviderConfig, SenderConstraint};
use axess_testing::oauth_wiremock::oauth_discovery_document;
use std::net::TcpListener;
use std::process::Command;
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CHILD_FLAG: &str = "AXESS_FAPI_MTLS_PROXY_PROBE";
const PROBE: &str = "a_screened_fapi_mtls_provider_does_not_follow_a_proxy_from_the_environment";

/// A self-signed client certificate and key written under a temp directory
/// that is removed when the value drops.
struct ClientCert {
    dir: std::path::PathBuf,
}

impl ClientCert {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "axess-factors-mtls-egress-{tag}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["client.example".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        std::fs::write(dir.join("client.pem"), cert.pem()).unwrap();
        std::fs::write(dir.join("client.key"), key.serialize_pem()).unwrap();
        Self { dir }
    }

    fn constraint(&self) -> SenderConstraint {
        SenderConstraint::Mtls {
            client_cert_path: self.dir.join("client.pem").to_string_lossy().into_owned(),
            client_key_path: self.dir.join("client.key").to_string_lossy().into_owned(),
        }
    }
}

impl Drop for ClientCert {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// An identity provider on loopback whose document advertises a PAR endpoint
/// (the profile demands one) and `token_alias` as the mTLS token endpoint.
async fn idp_with_mtls_token_alias(token_alias: &str) -> MockServer {
    let server = MockServer::start().await;
    let issuer = server.uri();
    let mut doc = oauth_discovery_document(&issuer);
    doc["pushed_authorization_request_endpoint"] = serde_json::json!(format!("{issuer}/par"));
    doc["mtls_endpoint_aliases"] = serde_json::json!({ "token_endpoint": token_alias });
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(doc))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "keys": [] })))
        .mount(&server)
        .await;
    server
}

async fn fapi_mtls_provider(
    policy: EgressPolicy,
    issuer: &str,
    cert: &ClientCert,
) -> Result<OAuthProviderConfig, axess_factors::oauth::OAuthError> {
    let clock = axess_clock::testing::MockClock::at_reference();
    OAuthProviderConfig::discover_screened(
        "bank",
        issuer,
        "client",
        "unused-under-fapi",
        "https://rp.example/callback",
        policy,
    )
    .await?
    .with_clock(std::sync::Arc::new(clock.clone()))
    .with_fapi(FapiConfig {
        sender_constraint: cert.constraint(),
        ..FapiConfig::default()
    })
    .build()
}

/// What the child does: discover against a loopback identity provider whose
/// mTLS token alias is an HTTPS URL on loopback where nothing listens, then
/// make one token request. Under a proxy from the environment the request
/// goes to the proxy; without one it fails on the spot.
fn probe(policy: EgressPolicy) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let idp = idp_with_mtls_token_alias("https://localhost:9/token").await;
        let cert = ClientCert::new("probe");
        let provider = fapi_mtls_provider(policy, &idp.uri(), &cert)
            .await
            .expect("a FAPI mTLS provider over the loopback identity provider");
        let _ = provider
            .refresh_token_unchecked("refresh-token", None, None)
            .await;
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
/// made its token request. Each accepted connection is closed at once, so a
/// child that reaches the proxy fails fast instead of waiting out a timeout.
fn connections_seen_by_the_proxy(policy: &str) -> usize {
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    proxy.set_nonblocking(true).unwrap();
    let url = format!("http://{}", proxy.local_addr().unwrap());
    // HTTPS only: discovery itself runs over plain HTTP to the loopback
    // identity provider, and the control below must reach it directly.
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
fn a_screened_fapi_mtls_provider_does_not_follow_a_proxy_from_the_environment() {
    if let Ok(policy) = std::env::var(CHILD_FLAG) {
        probe(policy_named(&policy));
        return;
    }
    assert_eq!(
        connections_seen_by_the_proxy("screened"),
        0,
        "the mTLS token request of a screened provider went to the proxy from the environment"
    );
}

/// The control: the probe does reach a proxy when the policy follows one, so
/// the zero above is a result and not a request that was never made.
#[test]
fn an_unscreened_fapi_mtls_provider_still_follows_the_environment() {
    if std::env::var(CHILD_FLAG).is_ok() {
        return;
    }
    assert!(
        connections_seen_by_the_proxy("unscreened") > 0,
        "the probe did not reach the proxy even for an unscreened provider"
    );
}

/// An advertised mTLS alias on a private address is refused by name, with
/// the setting and the range and not the URL. Discovery performs the
/// refusal (it screens every alias of the document);
/// the builder's own check on the alias it installs repeats it, and no
/// alias discovery let through reaches that check.
#[tokio::test]
async fn a_screened_fapi_mtls_provider_refuses_a_token_alias_on_a_private_address() {
    if std::env::var(CHILD_FLAG).is_ok() {
        return;
    }
    let idp = idp_with_mtls_token_alias("https://10.0.0.5/secret-path/token").await;
    let cert = ClientCert::new("private");

    let err = match fapi_mtls_provider(
        EgressPolicy::screened_allowing_loopback_http(),
        &idp.uri(),
        &cert,
    )
    .await
    {
        Ok(_) => panic!("a private mTLS token alias was accepted"),
        Err(e) => e.to_string(),
    };

    assert!(
        err.contains("token_endpoint") && err.contains("private"),
        "{err}"
    );
    assert!(!err.contains("secret-path"), "{err}");
}
