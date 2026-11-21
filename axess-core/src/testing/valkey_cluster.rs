//! A Valkey cluster for the live tests that need one (`VALKEY_CLUSTER_URL`,
//! a `redis-cluster://` URL naming one node): the clustered client, the
//! primaries and the slots each serves, the server's own count of the
//! scripts it ran and refused, and the ledger that gives one test at a time
//! its turn at that count, kept by a lease any live test can take on its
//! own server.
//!
//! Compiled for this crate's own tests.

use fred::prelude::*;
use fred::types::{ClusterHash, CustomCommand};

/// The cluster URL the live tests connect to.
///
/// Every way to the cluster here starts from this URL, and only a test named
/// under a `valkey_cluster` module may take it: a run on one Valkey node
/// leaves the cluster tests out by that name (`--skip valkey_cluster`, and
/// the live mutation job's `test(valkey) - test(valkey_cluster)`), so a test
/// that reaches the cluster from anywhere else is one such a run selects
/// and fails. The convention is set out in docs/project/contributing.md,
/// and scripts/check-live-stores.sh counts the cluster suites under that
/// name. A test named elsewhere panics here, in the run that has the
/// cluster, before it connects (`partition_refusal`). No other Rust source
/// reads `VALKEY_CLUSTER_URL`, so no test reaches the cluster past this
/// guard: scripts/check-cluster-url-reads.sh refuses a read anywhere else,
/// and one here that the guard does not open.
pub(crate) fn cluster_url() -> String {
    if let Some(refusal) = partition_refusal(std::thread::current().name()) {
        panic!("{refusal}");
    }
    std::env::var("VALKEY_CLUSTER_URL").unwrap_or_else(|_| "redis-cluster://127.0.0.1:7001".into())
}

/// Why the test running on a thread of this name may not take the cluster's
/// URL, or `None` when it may.
///
/// The test harness runs each test on a thread named by the test's path
/// from the crate's root (`module::module::test`), under `cargo test` and
/// under cargo-nextest alike (`the_harness_names_the_test_thread_by_the_test`
/// holds both to it). A thread with no name, or with a name that holds no
/// `::`, is not taken for a test's: a thread a test spawns, a thread of a
/// runtime, the main thread, or a test at the crate's root, which no rule
/// here can tell apart; such a thread is let through.
fn partition_refusal(thread: Option<&str>) -> Option<String> {
    let name = thread?;
    if !name.contains("::") || name.contains("valkey_cluster") {
        return None;
    }
    Some(format!(
        "{name} takes the Valkey cluster's URL but its name holds no `valkey_cluster`: a run on \
         one Valkey node (`--skip valkey_cluster`, the live mutation job's `test(valkey) - \
         test(valkey_cluster)`) selects it and cannot reach a cluster. Put it in a \
         `valkey_cluster` module, the convention docs/project/contributing.md sets out and \
         scripts/check-live-stores.sh counts the cluster suites by."
    ))
}

/// The configuration of a clustered client on [`cluster_url`].
pub(crate) fn cluster_config() -> Config {
    Config::from_url(&cluster_url()).expect("a redis-cluster:// URL")
}

/// A connected clustered client.
pub(crate) async fn cluster_client() -> Client {
    let client = Client::new(cluster_config(), None, None, None);
    client.init().await.expect("connect to the cluster");
    assert!(
        client.is_clustered(),
        "{} is not a cluster URL",
        cluster_url()
    );
    client
}

/// One primary of the cluster: its `host:port` and the slot ranges it serves.
#[derive(Debug, Clone)]
pub(crate) struct Primary {
    /// The `host:port` it answers on.
    pub(crate) addr: String,
    /// The inclusive slot ranges it serves.
    pub(crate) slots: Vec<(u16, u16)>,
}

impl Primary {
    /// Whether this primary serves `slot`.
    pub(crate) fn serves(&self, slot: u16) -> bool {
        self.slots.iter().any(|&(lo, hi)| (lo..=hi).contains(&slot))
    }
}

/// The primaries, read from `CLUSTER NODES`.
pub(crate) async fn primaries(client: &Client) -> Vec<Primary> {
    let command = CustomCommand::new_static("CLUSTER", ClusterHash::Random, false);
    let nodes: String = client
        .custom(command, vec!["NODES"])
        .await
        .expect("CLUSTER NODES");
    super::valkey_sweep::primaries_of(&nodes)
        .into_iter()
        .map(|(addr, slots)| Primary { addr, slots })
        .collect()
}

/// The key the ledger's lease is kept under, on the cluster itself.
const LEDGER_KEY: &str = "axess-test:refused-scripts-ledger";

/// How long a lease nobody gave up (its process was stopped) keeps the next
/// holder waiting.
const LEDGER_LEASE_MS: i64 = 120_000;

/// A lease on a server or a cluster: this holder's token under a key, which
/// keeps every other holder of that key waiting, in this process or in any
/// other that uses the same server.
///
/// A holder gives it up with [`give_up`](Self::give_up). One that is
/// dropped while it still holds the lease (a failed assertion unwinding, a
/// test that returned early) gives it up as it is dropped, so the next
/// holder does not wait for the lease to run out. Either way only this
/// holder's own token is deleted: a holder that outlived its lease leaves
/// the token of the next one alone.
pub(crate) struct Lease {
    /// The client the lease was taken with, on the holder's runtime.
    client: Client,
    /// The server the lease is kept on, for a drop that connects anew.
    server: Config,
    key: String,
    token: String,
    /// Whether the lease is still to be given up.
    held: bool,
}

impl Lease {
    /// Wait for the lease under `key` on the server or cluster `server`
    /// names, and take it.
    pub(crate) async fn take(server: &Config, key: &str) -> Self {
        let client = Client::new(server.clone(), None, None, None);
        client.init().await.expect("connect for a lease");
        let token = crate::authn::ids::UserId::new(&axess_rng::SystemRng).to_string();
        loop {
            let taken: Option<String> = client
                .set(
                    key,
                    token.as_str(),
                    Some(Expiration::PX(LEDGER_LEASE_MS)),
                    Some(SetOptions::NX),
                    false,
                )
                .await
                .expect("SET NX on the cluster");
            if taken.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        Self {
            client,
            server: server.clone(),
            key: key.to_owned(),
            token,
            held: true,
        }
    }

    /// Give the lease up.
    pub(crate) async fn give_up(mut self) {
        delete_own_token(&self.client, &self.key, &self.token).await;
        self.held = false;
        let _ = self.client.quit().await;
    }
}

/// Delete the token under `key` while it is still `token`. A cluster that
/// cannot be asked leaves the lease to run out.
async fn delete_own_token(client: &Client, key: &str, token: &str) {
    let current = client.get::<Option<String>, _>(key).await.ok().flatten();
    if current.as_deref() == Some(token) {
        let _ = client.del::<(), _>(key).await;
    }
}

impl Drop for Lease {
    /// The path of a holder that did not reach [`give_up`](Self::give_up).
    /// The token is deleted from a thread and a runtime of its own, since
    /// the holder's runtime may be going away and a client belongs to the
    /// runtime it was made on; this thread waits for it. Whatever goes
    /// wrong there is left alone: the lease runs out by itself.
    fn drop(&mut self) {
        if !self.held {
            return;
        }
        let (server, key, token) = (self.server.clone(), self.key.clone(), self.token.clone());
        let given_up = std::thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            runtime.block_on(async {
                let client = Client::new(server, None, None, None);
                if client.init().await.is_ok() {
                    delete_own_token(&client, &key, &token).await;
                }
                let _ = client.quit().await;
            });
        })
        .join();
        if given_up.is_err() {
            tracing::warn!("a lease on the cluster could not be given up; it runs out by itself");
        }
    }
}

/// The turn of one test at the server's counts of scripts.
///
/// The counts are numbers for the whole cluster, and other parties' calls
/// show in them: the tests of this binary run side by side, and another
/// test run may be using the same cluster. So a test never asserts a count
/// itself, only the difference between two readings it took while it held
/// the ledger, and every test that sends the cluster a script, or makes the
/// server refuse one on purpose, holds the ledger for as long as it runs.
/// The ledger is a lock for the tests of this process and a [`Lease`] on
/// the cluster for every process.
///
/// A holder gives the ledger up with [`release`](Self::release) as its last
/// step. One that fails before that gives it up as it unwinds: the lease
/// first, then the lock, the order the fields are dropped in.
pub(crate) struct RefusedScriptsLedger {
    lease: Lease,
    in_process: tokio::sync::MutexGuard<'static, ()>,
}

/// Wait for the ledger and take it.
pub(crate) async fn refused_scripts_ledger() -> RefusedScriptsLedger {
    static LEDGER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let in_process = LEDGER.lock().await;
    let lease = Lease::take(&cluster_config(), LEDGER_KEY).await;
    RefusedScriptsLedger { lease, in_process }
}

impl RefusedScriptsLedger {
    /// Give the ledger up: the lease first, then the lock.
    pub(crate) async fn release(self) {
        let Self { lease, in_process } = self;
        lease.give_up().await;
        drop(in_process);
    }
}

/// `EVAL` calls summed over the primaries: `(calls, refused)`, where refused
/// counts the calls the server failed or rejected (a `CROSSSLOT` among
/// them). A script a client refused itself is in neither.
pub(crate) async fn eval_stats(primaries: &[Primary]) -> (u64, u64) {
    let (mut calls, mut refused) = (0, 0);
    for primary in primaries {
        let url = format!("redis://{}", primary.addr);
        let node = Client::new(Config::from_url(&url).expect("node url"), None, None, None);
        node.init().await.expect("connect to a primary");
        let command = CustomCommand::new_static("INFO", ClusterHash::FirstKey, false);
        let info: String = node
            .custom(command, vec!["commandstats"])
            .await
            .expect("INFO commandstats");
        let _ = node.quit().await;
        let Some(line) = info.lines().find(|l| l.starts_with("cmdstat_eval:")) else {
            continue;
        };
        for field in line["cmdstat_eval:".len()..].split(',') {
            let Some((name, value)) = field.split_once('=') else {
                continue;
            };
            let value: u64 = value.trim().parse().unwrap_or(0);
            match name {
                "calls" => calls += value,
                "rejected_calls" | "failed_calls" => refused += value,
                _ => {}
            }
        }
    }
    (calls, refused)
}

/// The lease's own tests, counted by this module's name where a run against
/// the live stores is judged.
#[cfg(test)]
mod lease_cluster {
    use super::*;
    use crate::testing::valkey_sweep::Swept;
    use std::time::Duration;

    /// A lease key of this test's own, so that no other test waits on it,
    /// held with the sweep that removes it when the test ends, also when it
    /// fails.
    fn own_key() -> Swept<String> {
        let sweep = crate::testing::valkey_sweep::on_cluster("lease");
        let key = format!("{}:lease", sweep.prefix());
        sweep.hold(key)
    }

    /// What is under `key` on the cluster.
    async fn under(client: &Client, key: &str) -> Option<String> {
        client.get(key).await.expect("GET")
    }

    /// A holder that fails while it holds a lease gives it up as it
    /// unwinds: its token is gone when the failure has been seen, and the
    /// next holder has the lease at once, not when the two minutes of the
    /// lease have run out.
    #[tokio::test]
    #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
    async fn a_holder_that_fails_gives_its_lease_up_at_once() {
        let key = own_key();
        let client = cluster_client().await;
        let failing = {
            let key = key.clone();
            std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("a runtime")
                    .block_on(async move {
                        let lease = Lease::take(&cluster_config(), &key).await;
                        assert!(
                            lease.token.is_empty(),
                            "the holder fails on purpose while it holds the lease"
                        );
                    });
            })
        };
        assert!(failing.join().is_err(), "the holder failed");

        assert_eq!(
            under(&client, &key).await,
            None,
            "the failed holder's token is gone"
        );
        let next = tokio::time::timeout(
            Duration::from_secs(10),
            Lease::take(&cluster_config(), &key),
        )
        .await
        .expect("the lease is free at once, not when it would have run out");
        assert_eq!(
            under(&client, &key).await.as_deref(),
            Some(next.token.as_str())
        );
        next.give_up().await;
        assert_eq!(under(&client, &key).await, None, "given up");
        let _ = client.quit().await;
    }

    /// A holder whose lease ran out, and whose key another holder has taken
    /// since, leaves that holder's token alone, whether it gives its lease
    /// up or is dropped holding it.
    #[tokio::test]
    #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
    async fn giving_a_lease_up_never_deletes_another_holders_token() {
        let key = own_key();
        let client = cluster_client().await;
        for dropped in [false, true] {
            let first = Lease::take(&cluster_config(), &key).await;
            let other = format!("another-holder-{dropped}");
            client
                .set::<(), _, _>(
                    key.as_str(),
                    other.as_str(),
                    Some(Expiration::PX(LEDGER_LEASE_MS)),
                    None,
                    false,
                )
                .await
                .expect("SET");

            if dropped {
                drop(first);
            } else {
                first.give_up().await;
            }

            assert_eq!(
                under(&client, &key).await.as_deref(),
                Some(other.as_str()),
                "dropped: {dropped}"
            );
            client.del::<(), _>(key.as_str()).await.expect("DEL");
        }
        let _ = client.quit().await;
    }
}

/// The guard on the cluster's URL, against the names the harness gives.
#[cfg(test)]
mod partition_tests {
    use super::partition_refusal;

    /// The name the guard reads is the test's own path, whichever harness
    /// runs the test.
    #[test]
    fn the_harness_names_the_test_thread_by_the_test() {
        assert_eq!(
            std::thread::current().name(),
            Some(
                "testing::valkey_cluster::partition_tests::the_harness_names_the_test_thread_by_the_test"
            )
        );
    }

    /// A test under a `valkey_cluster` module, at any depth, takes the URL.
    #[test]
    fn a_test_under_valkey_cluster_takes_the_url() {
        for name in [
            "replay::valkey::tests::valkey_cluster::a_jti_is_recorded_once_on_a_cluster",
            "session::storage::valkey::cluster_tests::valkey_cluster::session_cluster::a_test",
            "testing::valkey_cluster::lease_cluster::a_holder_that_fails_gives_its_lease_up_at_once",
        ] {
            assert_eq!(partition_refusal(Some(name)), None, "{name}");
        }
    }

    /// The logout store's cluster test as it stood at the top of its test
    /// module, which the live mutation job selected: its name holds
    /// `cluster`, not `valkey_cluster`.
    #[test]
    fn a_test_named_outside_valkey_cluster_is_refused() {
        let name = "federation::valkey_logout::name_tests::\
                    valkey_logout_cluster_the_store_runs_under_the_default_prefix";
        let refusal = partition_refusal(Some(name)).expect("refused");
        assert!(refusal.starts_with(name), "{refusal}");
        assert!(
            refusal.contains("Put it in a `valkey_cluster` module"),
            "{refusal}"
        );
    }

    /// A thread that is no test's is let through.
    #[test]
    fn a_thread_that_is_no_tests_is_let_through() {
        for thread in [None, Some("main"), Some("tokio-runtime-worker")] {
            assert_eq!(partition_refusal(thread), None, "{thread:?}");
        }
    }
}
