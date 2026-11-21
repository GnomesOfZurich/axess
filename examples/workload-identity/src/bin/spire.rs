//! # axess-example-workload-identity, `--bin spire`
//!
//! A workload that takes its identity from a local SPIRE agent with
//! `axess::workload::spire::SpireClient`: it prints the X.509 SVID the
//! agent issues it, optionally fetches a JWT SVID for an audience, and
//! then follows the agent, printing each rotation, each failed refresh
//! and, if it comes to that, the expiry.
//!
//! ## Running
//!
//! The binary needs a SPIRE agent on the node and a registration entry
//! that matches the process.
//!
//! ```sh
//! export SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/sockets/agent.sock
//! export SPIFFE_TRUST_DOMAIN=example.org
//! # Optional: also keep a JWT SVID for this audience.
//! export SPIFFE_JWT_AUDIENCE=https://api.example.org
//! cargo run -p axess-example-workload-identity --bin spire
//! ```
//!
//! ```text
//! X.509 SVID spiffe://example.org/billing/acme, valid until 2026-01-01T01:00:00+00:00
//!   bundles for: example.org, partner.test
//! JWT SVID for ["https://api.example.org"], valid until 2026-01-01T00:05:00+00:00
//! rotated x509_svid: spiffe://example.org/billing/acme until 2026-01-01T01:30:00+00:00
//! ```
//!
//! With no agent on the socket the binary does not exit: it reports each
//! failed attempt with the wait before the next, which is what a source
//! does for a workload that starts before its agent.
//!
//! ## What to copy
//!
//! The three steps of `main`: build one `SpireClient` for the process,
//! start a source for each credential the workload uses, and read the
//! source wherever the credential is needed. A source's read never waits
//! for the agent and never returns an expired SVID, so it belongs on the
//! request path; the listener is where the operator learns that a refresh
//! is failing while there is still time to act.

use std::sync::Arc;

use axess::workload::spire::{Endpoint, SpireClient, WorkloadApiEvent, WorkloadApiListener};
use axess_identity::TrustDomain;

/// Prints what the watchers report. A service would count these through
/// `MetricSinks` and log them through `tracing` (the client does the second
/// by itself, on the target `axess::workload::spire`).
struct PrintEvents;

impl WorkloadApiListener for PrintEvents {
    fn on_event(&self, event: &WorkloadApiEvent<'_>) {
        match event {
            WorkloadApiEvent::Rotated {
                kind,
                spiffe_id,
                expires_at,
                trust_domains,
            } => match (spiffe_id, expires_at) {
                (Some(spiffe_id), Some(expires_at)) => println!(
                    "rotated {}: {spiffe_id} until {}",
                    kind.as_str(),
                    expires_at.to_rfc3339_numeric_offset()
                ),
                _ => println!("rotated {}: {trust_domains} trust domains", kind.as_str()),
            },
            WorkloadApiEvent::RefreshFailed {
                kind,
                error,
                retry_in,
                still_serving,
                ..
            } => println!(
                "refresh of {} failed ({error}); next attempt in {retry_in:?}; still serving: {still_serving}",
                kind.as_str()
            ),
            WorkloadApiEvent::BundleSkipped { kind, key, error } => {
                println!(
                    "bundle {key} sent with the {} left out: {error}",
                    kind.as_str()
                )
            }
            WorkloadApiEvent::Withdrawn { kind, .. } => {
                println!("{} WITHDRAWN by the agent; no longer served", kind.as_str())
            }
            WorkloadApiEvent::WithdrawalDeferred { kind, until, .. } => match until.at() {
                Some(until) => println!(
                    "{} withdrawn by the agent; served under the withdrawal grace until {}",
                    kind.as_str(),
                    until.to_rfc3339_numeric_offset()
                ),
                // A grace too long to end at any reading.
                None => println!(
                    "{} withdrawn by the agent; served under a withdrawal grace that never ends",
                    kind.as_str()
                ),
            },
            WorkloadApiEvent::Stopped { kind, error } => {
                println!("{} is asked for no more: {error}", kind.as_str())
            }
            WorkloadApiEvent::Expired {
                kind, expired_at, ..
            } => println!(
                "{} RAN OUT at {} with no replacement",
                kind.as_str(),
                expired_at.to_rfc3339_numeric_offset()
            ),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = Endpoint::from_env()?;
    let trust_domain = TrustDomain::new(&std::env::var("SPIFFE_TRUST_DOMAIN")?)?;
    let client = SpireClient::builder(endpoint, trust_domain)
        .with_listener(Arc::new(PrintEvents))
        .build();

    // The X.509 SVID, with the bundles the workload verifies its peers with.
    let x509 = client.watch_x509()?;
    x509.ready().await;
    let context = x509.context()?;
    println!(
        "X.509 SVID {}, valid until {}",
        context.svid().spiffe_id(),
        context.svid().not_after().to_rfc3339_numeric_offset()
    );
    let bundles: Vec<&str> = context
        .bundles()
        .trust_domains()
        .map(TrustDomain::as_str)
        .collect();
    println!("  bundles for: {}", bundles.join(", "));

    // A JWT SVID for one audience, when one is named. The source is kept
    // for as long as the token is: dropping it stops its rotation.
    let jwt = match std::env::var("SPIFFE_JWT_AUDIENCE") {
        Ok(audience) => {
            let source = client.watch_jwt_svid([audience])?;
            source.ready().await;
            let svid = source.svid()?;
            println!(
                "JWT SVID for {:?}, valid until {}",
                svid.audience(),
                svid.expires_at().to_rfc3339_numeric_offset()
            );
            Some(source)
        }
        Err(_) => None,
    };

    // The watchers do the rest; the listener prints what they do.
    tokio::signal::ctrl_c().await?;
    drop(jwt);
    drop(x509);
    Ok(())
}
