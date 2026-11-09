//! An in-memory Valkey keyspace that records its commands and runs a hook
//! between two of them: the other pod of a race, made deterministic.
//!
//! It implements only the commands the code under test sends through a seam
//! (see `authz::cache::valkey_cache::index_ops`), and it is compiled for this
//! crate's own tests.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::Mutex;

use fred::error::Error;

use crate::authz::cache::valkey_cache::index_ops::IndexOps;

/// A hook the fake runs right after a command, with the fake itself, so it
/// can write as another client would.
type Hook = Box<dyn FnOnce(&FakeValkey) + Send>;

/// A keyspace of SETs and strings, a command log, and one-shot hooks.
#[derive(Default)]
pub(crate) struct FakeValkey {
    sets: Mutex<HashMap<String, BTreeSet<String>>>,
    strings: Mutex<HashMap<String, String>>,
    log: Mutex<Vec<String>>,
    hooks: Mutex<HashMap<&'static str, VecDeque<Hook>>>,
}

impl FakeValkey {
    /// Add `member` to the SET at `key`, as another client would.
    pub(crate) fn sadd_now(&self, key: &str, member: &str) {
        self.sets
            .lock()
            .expect("fake lock")
            .entry(key.to_owned())
            .or_default()
            .insert(member.to_owned());
    }

    /// Store `value` at `key`, as another client would.
    pub(crate) fn set_now(&self, key: &str, value: &str) {
        self.strings
            .lock()
            .expect("fake lock")
            .insert(key.to_owned(), value.to_owned());
    }

    /// Whether the SET at `key` holds `member`.
    pub(crate) fn is_member(&self, key: &str, member: &str) -> bool {
        self.sets
            .lock()
            .expect("fake lock")
            .get(key)
            .is_some_and(|s| s.contains(member))
    }

    /// Whether a string is stored at `key`.
    pub(crate) fn exists(&self, key: &str) -> bool {
        self.strings.lock().expect("fake lock").contains_key(key)
    }

    /// The commands received so far, in order.
    pub(crate) fn commands(&self) -> Vec<String> {
        self.log.lock().expect("fake lock").clone()
    }

    /// Run `hook` once, right after the next `command` (`"SPOP"`, `"DEL"`)
    /// completes: the moment another pod gets to write.
    pub(crate) fn after_next(
        &self,
        command: &'static str,
        hook: impl FnOnce(&FakeValkey) + Send + 'static,
    ) {
        self.hooks
            .lock()
            .expect("fake lock")
            .entry(command)
            .or_default()
            .push_back(Box::new(hook));
    }

    /// Delete the SETs and strings at `keys` (`DEL`).
    fn del_now(&self, keys: &[String]) {
        self.record(format!("DEL {}", keys.join(" ")), "DEL");
        for k in keys {
            self.sets.lock().expect("fake lock").remove(k);
            self.strings.lock().expect("fake lock").remove(k);
        }
    }

    fn record(&self, line: String, command: &'static str) {
        self.log.lock().expect("fake lock").push(line);
        let hook = self
            .hooks
            .lock()
            .expect("fake lock")
            .get_mut(command)
            .and_then(VecDeque::pop_front);
        if let Some(hook) = hook {
            hook(self);
        }
    }
}

impl IndexOps for FakeValkey {
    async fn pop_members(&self, key: &str, count: usize) -> Result<Vec<String>, Error> {
        let taken: Vec<String> = {
            let mut sets = self.sets.lock().expect("fake lock");
            let mut taken = Vec::new();
            let mut now_empty = false;
            if let Some(set) = sets.get_mut(key) {
                taken = set.iter().take(count).cloned().collect();
                for member in &taken {
                    set.remove(member);
                }
                now_empty = set.is_empty();
            }
            if now_empty {
                sets.remove(key);
            }
            taken
        };
        self.record(format!("SPOP {key} {count}"), "SPOP");
        Ok(taken)
    }

    async fn delete(&self, keys: Vec<String>) -> Result<(), Error> {
        self.del_now(&keys);
        Ok(())
    }
}
