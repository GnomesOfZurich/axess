//! The watchers, against the fake agent on a mock clock: first fetch,
//! rotation, failure, expiry, staleness and recovery.
//!
//! Every test runs on a paused runtime. The mock clock is what the watcher
//! reads to decide; the runtime's own time only paces its checks and its
//! back-off, and runs ahead by itself whenever nothing else can.

mod bundles;
mod jwt;
mod points;
mod x509;

use std::time::Duration;

const ID: &str = "spiffe://example.org/billing/acme";
const OTHER_ID: &str = "spiffe://example.org/reports/acme";
const HOUR: i64 = 3600;
const MINUTE: i64 = 60;

/// A maximum bundle age no test reaches: for the tests that are about an
/// SVID's own lifetime and jump the clock by hours at once, where the
/// bundles that came with it would otherwise go stale on the way.
const NEVER_STALE: Duration = Duration::from_secs(7 * 24 * 3600);

fn trust_domain(name: &str) -> axess_identity::TrustDomain {
    axess_identity::TrustDomain::new(name).expect("a trust domain")
}

/// Let the runtime's time run `seconds` ahead, the mock clock untouched:
/// time for the watcher to do whatever it is going to do.
async fn idle(seconds: u64) {
    tokio::time::sleep(Duration::from_secs(seconds)).await;
}
