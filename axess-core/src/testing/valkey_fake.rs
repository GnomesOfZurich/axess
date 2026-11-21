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
    faults: Mutex<HashMap<&'static str, VecDeque<bool>>>,
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

    /// Whether the SET at `key` holds `member`.
    pub(crate) fn is_member(&self, key: &str, member: &str) -> bool {
        self.sets
            .lock()
            .expect("fake lock")
            .get(key)
            .is_some_and(|s| s.contains(member))
    }

    /// The commands received so far, in order.
    pub(crate) fn commands(&self) -> Vec<String> {
        self.log.lock().expect("fake lock").clone()
    }

    /// Run `hook` once, right after the next `command` (`"SPOP"`, `"DEL"`,
    /// `"SADD"`, `"SET"`) completes: the moment another pod gets to write.
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

/// The string keyspace and the faults: what the entity index's commands
/// need beside the sets.
impl FakeValkey {
    /// Store `value` at `key`, as another client would.
    pub(crate) fn set_now(&self, key: &str, value: &str) {
        self.strings
            .lock()
            .expect("fake lock")
            .insert(key.to_owned(), value.to_owned());
    }

    /// Whether a string is stored at `key`.
    pub(crate) fn exists(&self, key: &str) -> bool {
        self.strings.lock().expect("fake lock").contains_key(key)
    }

    /// Fail the call of `command` (`"SADD"` for a whole `add_members`,
    /// `"DEL"`, `"SET"`) that comes `skip` calls from now, before it has any
    /// effect: Valkey stopped answering that one.
    pub(crate) fn fail_call(&self, command: &'static str, skip: usize) {
        let mut faults = self.faults.lock().expect("fake lock");
        let queue = faults.entry(command).or_default();
        while queue.len() < skip {
            queue.push_back(false);
        }
        queue.push_back(true);
    }

    /// Whether this call of `command` is one [`fail_call`](Self::fail_call)
    /// named, and the error it then answers.
    fn fault(&self, command: &'static str) -> Result<(), Error> {
        let fail = self
            .faults
            .lock()
            .expect("fake lock")
            .get_mut(command)
            .and_then(VecDeque::pop_front)
            .unwrap_or(false);
        if fail {
            self.log
                .lock()
                .expect("fake lock")
                .push(format!("{command} failed"));
            return Err(Error::new(fred::error::ErrorKind::IO, "connection lost"));
        }
        Ok(())
    }

    /// Delete the SETs and strings at `keys` (`DEL`).
    fn del_now(&self, keys: &[String]) {
        self.record(format!("DEL {}", keys.join(" ")), "DEL");
        for k in keys {
            self.sets.lock().expect("fake lock").remove(k);
            self.strings.lock().expect("fake lock").remove(k);
        }
    }

    /// Take up to `count` members out of the SET at `key` (`SPOP`).
    fn pop_now(&self, key: &str, count: usize) -> Vec<String> {
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
        taken
    }

    /// Empty the index SET at `key` and delete the entries it named, as the
    /// invalidation on another pod does, from inside a hook.
    pub(crate) fn drain_now(&self, key: &str) {
        loop {
            let members = self.pop_now(key, 256);
            if members.is_empty() {
                return;
            }
            self.del_now(&members);
        }
    }
}

impl IndexOps for FakeValkey {
    async fn pop_members(&self, key: &str, count: usize) -> Result<Vec<String>, Error> {
        Ok(self.pop_now(key, count))
    }

    async fn delete(&self, keys: Vec<String>) -> Result<(), Error> {
        self.fault("DEL")?;
        self.del_now(&keys);
        Ok(())
    }

    async fn add_members(
        &self,
        indexes: &[String],
        member: &str,
        ttl_ms: i64,
    ) -> Result<(), Error> {
        self.fault("SADD")?;
        for index in indexes {
            self.sadd_now(index, member);
            self.record(format!("SADD {index} {member} PEXPIRE {ttl_ms}"), "SADD");
        }
        Ok(())
    }

    async fn set_entry(&self, key: &str, value: &str, ttl_ms: i64) -> Result<(), Error> {
        self.fault("SET")?;
        self.set_now(key, value);
        self.record(format!("SET {key} PX {ttl_ms}"), "SET");
        Ok(())
    }
}
