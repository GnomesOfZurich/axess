//! The keys a test writes to a live Valkey, removed when the test ends.
//!
//! A test that writes to a shared server leaves what it wrote behind unless
//! it removes it, and a test that fails stops before any removal written at
//! its end. A [`KeySweep`] makes a prefix no other run has used and removes
//! every key whose name holds that prefix when it is dropped: at the end of
//! the test that holds it, whether the test passed or failed, since a
//! failing assertion unwinds through the drop as a return does. A live-store
//! helper hands its store back inside a [`Swept`], which reads as the store
//! and carries the sweep with it, so a test's own lines do not change.
//!
//! Every prefix holds the run's token ([`run`]): the value of
//! `AXESS_TEST_RUN` where it is set, a random one per process where it is
//! not. A run that sets it can ask the servers afterwards for any key that
//! still holds it; `scripts/live-keys-left.sh` is that check, and
//! `scripts/check-live-stores.sh` runs it after the live suites.
//!
//! ```no_run
//! # async fn example() {
//! use axess_core::testing::valkey_sweep::KeySweep;
//! use fred::prelude::*;
//!
//! let url = "redis://127.0.0.1:6379";
//! let sweep = KeySweep::node(url, "orders");
//! let client = Client::new(Config::from_url(url).unwrap(), None, None, None);
//! client.init().await.unwrap();
//! let key = format!("{}:one", sweep.prefix());
//! client.set::<(), _, _>(key.as_str(), "1", None, None, false).await.unwrap();
//! // `sweep` is dropped here, and `key` with it.
//! # }
//! ```

use std::ops::{Deref, DerefMut};
use std::sync::OnceLock;

use fred::prelude::*;
use fred::types::{ClusterHash, CustomCommand};

/// The variable a run names its token in. The token is part of every prefix
/// a [`KeySweep`] makes, so a check after the run finds what the run left.
pub const RUN_VARIABLE: &str = "AXESS_TEST_RUN";

/// Every prefix a [`KeySweep`] makes starts with this, after a hash tag's
/// opening brace where there is one.
pub const PREFIX_START: &str = "axt_";

/// The longest token [`run`] accepts.
const MAX_RUN_LEN: usize = 32;

/// How many keys one `SCAN` reply carries at most, and how many one
/// `UNLINK` on a single node removes.
const PAGE: usize = 1000;

/// The token of this run: `AXESS_TEST_RUN` where it is set, otherwise a
/// random one made once per process.
///
/// # Panics
///
/// Where `AXESS_TEST_RUN` is set to anything but 1 to 32 lowercase ASCII
/// letters and digits. The token goes into key names and into the pattern
/// that finds them; with those characters it can hold no character a
/// pattern reads as a wildcard and no brace that would change a key's slot.
pub fn run() -> &'static str {
    static RUN: OnceLock<String> = OnceLock::new();
    RUN.get_or_init(|| match std::env::var(RUN_VARIABLE) {
        Ok(token) => {
            assert!(
                is_token(&token),
                "{RUN_VARIABLE} must be 1 to {MAX_RUN_LEN} lowercase letters and digits"
            );
            token
        }
        Err(_) => uuid::Uuid::new_v4().simple().to_string()[..12].to_owned(),
    })
}

/// Whether `text` is 1 to [`MAX_RUN_LEN`] lowercase ASCII letters and
/// digits.
fn is_token(text: &str) -> bool {
    (1..=MAX_RUN_LEN).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// Whether `tag` may name a test in a prefix: lowercase ASCII letters,
/// digits and underscores, at least one. None of them is a wildcard of a
/// `SCAN` pattern or a brace.
fn is_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// The single node this crate's live tests use: `VALKEY_URL`, or the
/// default port on this host.
#[cfg(test)]
pub(crate) fn node_url() -> String {
    std::env::var("VALKEY_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into())
}

/// A sweep on the single node of this crate's live tests ([`node_url`]).
#[cfg(test)]
pub(crate) fn on_node(tag: &str) -> KeySweep {
    KeySweep::node(node_url(), tag)
}

/// A sweep on the cluster of this crate's live tests (`VALKEY_CLUSTER_URL`).
#[cfg(test)]
pub(crate) fn on_cluster(tag: &str) -> KeySweep {
    KeySweep::cluster(super::valkey_cluster::cluster_url(), tag)
}

/// The server a sweep removes keys from.
#[derive(Debug, Clone)]
enum Server {
    /// A single node, by its `redis://` URL.
    Node(String),
    /// A cluster, by the `redis-cluster://` URL of one of its nodes: the
    /// keys are removed from every primary.
    Cluster(String),
}

/// A prefix no other run has used, and the removal, when this is dropped,
/// of every key whose name holds it.
///
/// The prefix is `axt_<run>_<tag>_<random>`, where `run` is the run's token
/// ([`run`]); [`hash_tagged`](Self::hash_tagged) wraps it in a hash tag. A
/// key is removed when its name holds the prefix anywhere, so a test may
/// build names around it (a hash tag of its own, a suffix) and they are
/// removed too.
///
/// The removal runs on a thread and a runtime of its own, which this
/// thread waits for: the test's runtime may be going away, and a client
/// belongs to the runtime it was made on. A server that cannot be reached
/// then is left alone, with a warning; the check after a run is what finds
/// the keys that removal missed.
#[derive(Debug)]
pub struct KeySweep {
    server: Server,
    root: String,
    prefix: String,
    /// Texts a test's other keys hold, the ones not under the prefix
    /// ([`also_holding`](Self::also_holding)).
    also: Vec<String>,
}

/// The shortest text [`KeySweep::also_holding`] takes: long enough that
/// only the test's own keys hold it, where it is random.
pub const MIN_ALSO_LEN: usize = 16;

impl KeySweep {
    /// A fresh prefix named by `tag`, on the single node at `url`
    /// (`redis://host:port`).
    ///
    /// # Panics
    ///
    /// Where `tag` is empty or holds anything but lowercase ASCII letters,
    /// digits and underscores.
    pub fn node(url: impl Into<String>, tag: &str) -> Self {
        Self::on(Server::Node(url.into()), tag)
    }

    /// A fresh prefix named by `tag`, on the cluster one of whose nodes is
    /// at `url` (`redis-cluster://host:port`). The keys are removed from
    /// every primary.
    ///
    /// # Panics
    ///
    /// As [`node`](Self::node).
    pub fn cluster(url: impl Into<String>, tag: &str) -> Self {
        Self::on(Server::Cluster(url.into()), tag)
    }

    fn on(server: Server, tag: &str) -> Self {
        assert!(
            is_tag(tag),
            "a sweep's tag is lowercase letters, digits and underscores: {tag:?}"
        );
        let root = format!(
            "{PREFIX_START}{}_{tag}_{}",
            run(),
            uuid::Uuid::new_v4().simple()
        );
        Self {
            server,
            prefix: root.clone(),
            root,
            also: Vec::new(),
        }
    }

    /// The same sweep with its prefix inside a hash tag, `{axt_...}`, so
    /// every key under it lies in one slot.
    #[must_use]
    pub fn hash_tagged(mut self) -> Self {
        self.prefix = format!("{{{}}}", self.root);
        self
    }

    /// The same sweep, removing as well every key whose name holds `text`:
    /// for a test whose keys are not all under a prefix it chose (a store
    /// left on its default prefix, a name built from a random session).
    /// `text` should be random to the test, so that no other key holds it.
    ///
    /// # Panics
    ///
    /// Where `text` is shorter than [`MIN_ALSO_LEN`] or holds a character a
    /// `SCAN` pattern reads as more than itself (`*`, `?`, `[`, `]`, `\`)
    /// or a control character.
    #[must_use]
    pub fn also_holding(mut self, text: &str) -> Self {
        assert!(
            text.chars().count() >= MIN_ALSO_LEN
                && !text.contains(['*', '?', '[', ']', '\\'])
                && !text.chars().any(char::is_control),
            "a sweep's other text is {MIN_ALSO_LEN} or more plain characters: {text:?}"
        );
        self.also.push(text.to_owned());
        self
    }

    /// The prefix the test writes under.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// `value` held with this sweep: it reads as `value`, and the keys are
    /// removed when it is dropped, after `value` is.
    pub fn hold<T>(self, value: T) -> Swept<T> {
        Swept {
            held: value,
            sweep: self,
        }
    }

    /// The `SCAN` pattern of every key whose name holds the prefix. The
    /// root is lowercase letters, digits and underscores ([`is_tag`],
    /// [`is_token`], a simple UUID), none of which a pattern reads as more
    /// than itself.
    fn pattern(&self) -> String {
        format!("*{}*", self.root)
    }

    /// The pattern of the prefix and one for each text of
    /// [`also_holding`](Self::also_holding), which holds no wildcard.
    fn patterns(&self) -> Vec<String> {
        std::iter::once(self.pattern())
            .chain(self.also.iter().map(|text| format!("*{text}*")))
            .collect()
    }
}

impl Drop for KeySweep {
    fn drop(&mut self) {
        let (server, patterns) = (self.server.clone(), self.patterns());
        let swept = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            runtime.block_on(remove_matching(&server, &patterns))
        })
        .join();
        match swept {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                tracing::warn!(%error, "a test's keys could not all be removed");
            }
            Err(_) => tracing::warn!("a test's keys could not be removed"),
        }
    }
}

/// Remove every key matching one of `patterns` from `server`; for a
/// cluster, from each primary. Returns how many were removed.
async fn remove_matching(server: &Server, patterns: &[String]) -> Result<usize, String> {
    let (nodes, clustered) = match server {
        Server::Node(url) => (vec![url.clone()], false),
        Server::Cluster(url) => (primary_urls(url).await?, true),
    };
    let mut removed = 0;
    for url in nodes {
        let config = Config::from_url(&url).map_err(|e| e.to_string())?;
        let node = Client::new(config, None, None, None);
        node.init().await.map_err(|e| e.to_string())?;
        let mut result = Ok(0);
        for pattern in patterns {
            result = remove_on_node(&node, pattern, clustered).await;
            match &result {
                Ok(n) => removed += n,
                Err(_) => break,
            }
        }
        let _ = node.quit().await;
        result?;
    }
    Ok(removed)
}

/// Remove every key matching `pattern` from the one node `node` talks to.
/// On a primary of a cluster each key goes in a call of its own: a call
/// that names keys of two slots is refused there, even when one node
/// serves both.
async fn remove_on_node(node: &Client, pattern: &str, clustered: bool) -> Result<usize, String> {
    let mut cursor = "0".to_owned();
    let mut removed = 0;
    loop {
        let count = PAGE.to_string();
        let (next, page): (String, Vec<String>) = node
            .custom(
                CustomCommand::new_static("SCAN", ClusterHash::FirstKey, false),
                vec![cursor.as_str(), "MATCH", pattern, "COUNT", count.as_str()],
            )
            .await
            .map_err(|e| e.to_string())?;
        if clustered {
            for key in &page {
                let gone: i64 = node.unlink(key.as_str()).await.map_err(|e| e.to_string())?;
                removed += usize::try_from(gone).unwrap_or(0);
            }
        } else if !page.is_empty() {
            let gone: i64 = node.unlink(page).await.map_err(|e| e.to_string())?;
            removed += usize::try_from(gone).unwrap_or(0);
        }
        if next == "0" {
            return Ok(removed);
        }
        cursor = next;
    }
}

/// The `redis://` URL of every primary of the cluster one of whose nodes is
/// at `url`.
async fn primary_urls(url: &str) -> Result<Vec<String>, String> {
    let config = Config::from_url(url).map_err(|e| e.to_string())?;
    let client = Client::new(config, None, None, None);
    client.init().await.map_err(|e| e.to_string())?;
    let nodes: Result<String, _> = client
        .custom(
            CustomCommand::new_static("CLUSTER", ClusterHash::Random, false),
            vec!["NODES"],
        )
        .await;
    let _ = client.quit().await;
    let nodes = nodes.map_err(|e| e.to_string())?;
    Ok(primaries_of(&nodes)
        .into_iter()
        .map(|(addr, _)| format!("redis://{addr}"))
        .collect())
}

/// The primaries a `CLUSTER NODES` reply names: each one's `host:port` and
/// the inclusive slot ranges it serves.
pub(crate) fn primaries_of(nodes: &str) -> Vec<(String, Vec<(u16, u16)>)> {
    nodes
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 8 || !fields[2].contains("master") {
                return None;
            }
            let addr = fields[1].split('@').next()?.to_owned();
            let slots = fields[8..]
                .iter()
                .filter(|f| !f.starts_with('['))
                .filter_map(|range| {
                    let (lo, hi) = range.split_once('-').unwrap_or((range, range));
                    Some((lo.parse().ok()?, hi.parse().ok()?))
                })
                .collect();
            Some((addr, slots))
        })
        .collect()
}

/// A value held with the [`KeySweep`] of the keys it writes: a store, a
/// registry, a client. It reads as the value; when it is dropped the value
/// goes first, then the keys.
#[derive(Debug)]
pub struct Swept<T> {
    held: T,
    sweep: KeySweep,
}

impl<T> Swept<T> {
    /// The sweep, for the prefix it made.
    pub fn sweep(this: &Self) -> &KeySweep {
        &this.sweep
    }

    /// The value made from this one by `f`, held with the same sweep: for
    /// a builder that takes the value and returns it changed.
    pub fn map<U>(this: Self, f: impl FnOnce(T) -> U) -> Swept<U> {
        Swept {
            held: f(this.held),
            sweep: this.sweep,
        }
    }

    /// The value and its sweep, apart: for a test that hands the value on
    /// and keeps the sweep until it ends.
    pub fn into_parts(this: Self) -> (T, KeySweep) {
        (this.held, this.sweep)
    }
}

impl<T> Deref for Swept<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.held
    }
}

impl<T> DerefMut for Swept<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.held
    }
}

#[cfg(test)]
mod tests;
