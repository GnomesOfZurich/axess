#![cfg(feature = "oidc")]
//! A screened client never follows a proxy named in the environment: the
//! proxy would resolve the target's name itself, and the connect-time screen
//! would never see the address.
//!
//! The environment is read when a client is built, and setting a variable in
//! this process is not safe beside other threads, so the test runs its probe
//! in a child process that this binary starts with the proxy variables set.

use axess_factors::egress::EgressPolicy;
use std::net::TcpListener;
use std::process::Command;
use std::time::Duration;

const CHILD_FLAG: &str = "AXESS_EGRESS_PROXY_PROBE";
const PROBE: &str = "a_screened_client_does_not_follow_a_proxy_from_the_environment";

/// What the child does: build a client under `policy` and ask for a host that
/// resolves to loopback, over both schemes.
fn probe(policy: EgressPolicy) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let client = policy
            .client_builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        for url in ["http://localhost:9/", "https://localhost:9/"] {
            let _ = client.get(url).send().await;
        }
    });
}

fn policy_named(name: &str) -> EgressPolicy {
    match name {
        "screened" => EgressPolicy::screened(),
        "unscreened" => EgressPolicy::unscreened(),
        other => panic!("unknown policy {other}"),
    }
}

/// How many connections the "proxy" accepted while a child under `policy`
/// made its requests.
fn connections_seen_by_the_proxy(policy: &str) -> usize {
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    proxy.set_nonblocking(true).unwrap();
    let url = format!("http://{}", proxy.local_addr().unwrap());
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", PROBE, "--nocapture", "--test-threads=1"])
        .env(CHILD_FLAG, policy)
        .env("HTTP_PROXY", &url)
        .env("HTTPS_PROXY", &url)
        .env("ALL_PROXY", &url)
        .env("http_proxy", &url)
        .env("https_proxy", &url)
        .env("all_proxy", &url)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .status()
        .unwrap();
    assert!(status.success(), "the probe process failed");
    let mut seen = 0;
    while proxy.accept().is_ok() {
        seen += 1;
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
        "a screened client sent a request to the proxy from the environment"
    );
}

/// The control: the harness does reach a proxy when one is followed, so the
/// zero above is a finding and not a broken probe.
#[test]
fn an_unscreened_client_still_follows_the_environment() {
    if std::env::var(CHILD_FLAG).is_ok() {
        return;
    }
    assert!(
        connections_seen_by_the_proxy("unscreened") > 0,
        "the probe did not reach the proxy even for an unscreened client"
    );
}
