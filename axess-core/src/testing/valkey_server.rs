//! Server state a live Valkey test sets besides keys, put back when the
//! test ends, also when it fails: the `maxmemory-policy` of one server
//! ([`HeldPolicy`]) and a user of the server's own ([`AclUser`]). The keys
//! a test writes are removed by `valkey_sweep`; this is the rest.
//!
//! Each guard is made before the change it guards, so a failure while the
//! change is being made is put back as well. A test puts the change back
//! itself as its last step with the server changed
//! ([`HeldPolicy::restore`], [`AclUser::remove`]), where a server that
//! refuses fails the test.
//! A guard dropped before that, a failing assertion unwinding through it,
//! puts the change back from a thread and a runtime of its own, which the
//! dropping thread waits for: the test's runtime may be going away, and a
//! client belongs to the runtime it was made on.
//!
//! Compiled for this crate's own tests.

use fred::prelude::*;
use fred::types::{ClusterHash, CustomCommand, Value};

#[cfg(any(
    feature = "jwt",
    feature = "oauth",
    feature = "outbound-oauth",
    feature = "local-idp",
    feature = "device-keys"
))]
use super::valkey_cluster::Lease;

/// Send `command` with `args` to the one server `server` names, from a
/// thread and a runtime of its own, which this thread waits for. The
/// failure comes back as text, for a drop to report: a drop cannot fail
/// the test.
fn send_on_own_thread(
    server: Config,
    command: &'static str,
    args: Vec<String>,
) -> Result<(), String> {
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        runtime.block_on(async move {
            let client = Client::new(server, None, None, None);
            client.init().await.map_err(|e| e.to_string())?;
            let sent: Result<Value, Error> = client
                .custom(
                    CustomCommand::new_static(command, ClusterHash::FirstKey, false),
                    args,
                )
                .await;
            let _ = client.quit().await;
            sent.map(|_| ()).map_err(|e| e.to_string())
        })
    })
    .join()
    .map_err(|_| "the thread that sends it panicked".to_owned())?
}

/// The key of the lease a test holds while it changes a server's
/// `maxmemory-policy`.
#[cfg(any(
    feature = "jwt",
    feature = "oauth",
    feature = "outbound-oauth",
    feature = "local-idp",
    feature = "device-keys"
))]
const POLICY_LEASE_KEY: &str = "axess-test:maxmemory-policy";

/// `CONFIG`, sent to the one server a client or a cluster node handle
/// talks to.
#[cfg(any(
    feature = "jwt",
    feature = "oauth",
    feature = "outbound-oauth",
    feature = "local-idp",
    feature = "device-keys"
))]
fn config_command() -> CustomCommand {
    CustomCommand::new_static("CONFIG", ClusterHash::Random, false)
}

/// The `maxmemory-policy` one server had when a test found it, put back
/// when the test ends, also when it fails.
///
/// The test changes the policy itself, through its own client, once this
/// is made. Two runs that changed one server's policy at the same time
/// would each read the other's change as the policy it found, and the one
/// that put its policy back last would leave the server evicting. So this
/// holds a lease from before the policy is read until after it is put
/// back, and any other run that changes the policy waits for it.
#[cfg(any(
    feature = "jwt",
    feature = "oauth",
    feature = "outbound-oauth",
    feature = "local-idp",
    feature = "device-keys"
))]
pub(crate) struct HeldPolicy {
    /// The one server whose policy is changed, for a drop that connects
    /// anew.
    node: Config,
    /// The policy it had.
    found: String,
    /// The lease, while the policy is still to be put back.
    lease: Option<Lease>,
}

#[cfg(any(
    feature = "jwt",
    feature = "oauth",
    feature = "outbound-oauth",
    feature = "local-idp",
    feature = "device-keys"
))]
impl HeldPolicy {
    /// Wait for the lease on `leased` (the server itself, or the cluster
    /// whose primary it is), then read the policy of the server `node`
    /// names through `through`, a client of it.
    pub(crate) async fn take<C: ClientLike>(leased: &Config, node: Config, through: &C) -> Self {
        let lease = Lease::take(leased, POLICY_LEASE_KEY).await;
        let reply: Vec<String> = through
            .custom(config_command(), vec!["GET", "maxmemory-policy"])
            .await
            .expect("CONFIG GET maxmemory-policy");
        let found = reply
            .into_iter()
            .nth(1)
            .expect("CONFIG GET answers the policy");
        Self {
            node,
            found,
            lease: Some(lease),
        }
    }

    /// Put the policy back through `through`, the client the test changed
    /// it with, and give the lease up.
    pub(crate) async fn restore<C: ClientLike>(mut self, through: &C) {
        set_policy(through, &self.found).await;
        if let Some(lease) = self.lease.take() {
            lease.give_up().await;
        }
    }
}

/// Set the `maxmemory-policy` of the server, or the one cluster node,
/// behind `client`.
#[cfg(any(
    feature = "jwt",
    feature = "oauth",
    feature = "outbound-oauth",
    feature = "local-idp",
    feature = "device-keys"
))]
pub(crate) async fn set_policy<C: ClientLike>(client: &C, policy: &str) {
    let _: String = client
        .custom(config_command(), vec!["SET", "maxmemory-policy", policy])
        .await
        .expect("the server takes CONFIG SET");
}

#[cfg(any(
    feature = "jwt",
    feature = "oauth",
    feature = "outbound-oauth",
    feature = "local-idp",
    feature = "device-keys"
))]
impl Drop for HeldPolicy {
    /// The path of a test that did not reach [`restore`](Self::restore):
    /// the policy is put back first, then the lease is given up.
    fn drop(&mut self) {
        let Some(lease) = self.lease.take() else {
            return;
        };
        let args = vec!["SET".into(), "maxmemory-policy".into(), self.found.clone()];
        if let Err(error) = send_on_own_thread(self.node.clone(), "CONFIG", args) {
            tracing::warn!(%error, policy = %self.found, "a server's maxmemory-policy could not be put back");
        }
        drop(lease);
    }
}

/// A user of the server's own that a test made, removed when the test
/// ends, also when it fails.
pub(crate) struct AclUser {
    /// The server the user is on, for a drop that connects anew.
    server: Config,
    name: String,
    /// Whether the user is still to be removed.
    held: bool,
}

impl AclUser {
    /// Make the user `name` on the server `admin` talks to, with the ACL
    /// `rules` (`on`, `>password`, `~*`, `-publish`, ...). The guard is
    /// made first, so a user whose making failed half way is removed too.
    pub(crate) async fn make(admin: &Client, name: &str, rules: &[&str]) -> Self {
        let user = Self {
            server: admin.client_config(),
            name: name.to_owned(),
            held: true,
        };
        let mut args = vec!["SETUSER", name];
        args.extend_from_slice(rules);
        let _: String = admin
            .custom(acl_command(), args)
            .await
            .expect("ACL SETUSER");
        user
    }

    /// Remove the user through `admin`.
    pub(crate) async fn remove(mut self, admin: &Client) {
        let removed: i64 = admin
            .custom(acl_command(), vec!["DELUSER", self.name.as_str()])
            .await
            .expect("ACL DELUSER");
        assert_eq!(removed, 1, "the user {} was there to remove", self.name);
        self.held = false;
    }
}

/// `ACL`, which any node answers for itself.
fn acl_command() -> CustomCommand {
    CustomCommand::new_static("ACL", ClusterHash::FirstKey, false)
}

impl Drop for AclUser {
    /// The path of a test that did not reach [`remove`](Self::remove).
    fn drop(&mut self) {
        if !self.held {
            return;
        }
        let args = vec!["DELUSER".into(), self.name.clone()];
        if let Err(error) = send_on_own_thread(self.server.clone(), "ACL", args) {
            tracing::warn!(%error, user = %self.name, "a test's user could not be removed");
        }
    }
}
