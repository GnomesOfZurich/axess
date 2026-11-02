//! The ordered record of store calls shared by the mock stores.

use std::sync::{Arc, Mutex};

type Hook = Arc<dyn Fn() + Send + Sync>;

/// An ordered record of the store calls a flow makes, shared by a
/// [`MockIdentityStore`](super::MockIdentityStore) and a
/// [`MockFactorStore`](super::MockFactorStore) so one list shows the
/// interleaved sequence across both.
///
/// Attach it with `with_call_log` on each store. The names are the trait
/// method names (`"find_tenant"`, `"find_user"`, `"account_status"`,
/// `"ip_policy_for_tenant"`, `"available_methods"`, `"record_event"`). Tests
/// that must show two code paths make the same store calls in the same order
/// compare these lists.
///
/// A hook registered with [`on`](Self::on) runs each time the named call is
/// recorded, before the call does its work: the way a test changes the world
/// at an exact point inside a flow (a tenant suspended between a flow's
/// first status check and its commit).
#[derive(Clone, Default)]
pub struct CallLog {
    calls: Arc<Mutex<Vec<&'static str>>>,
    hooks: Arc<Mutex<Vec<(&'static str, Hook)>>>,
}

impl std::fmt::Debug for CallLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("CallLog").field(&self.calls()).finish()
    }
}

impl CallLog {
    /// An empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// The calls recorded so far, oldest first.
    pub fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Forget everything recorded so far. Hooks stay.
    pub fn clear(&self) {
        self.calls.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    /// Run `hook` each time the store call `name` is recorded, before the
    /// call does its work.
    pub fn on(&self, name: &'static str, hook: impl Fn() + Send + Sync + 'static) {
        self.hooks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((name, Arc::new(hook)));
    }

    pub(super) fn push(&self, name: &'static str) {
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(name);
        // Taken out of the lock before running, so a hook that records a
        // call of its own does not deadlock.
        let due: Vec<Hook> = self
            .hooks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(hooked, _)| *hooked == name)
            .map(|(_, hook)| Arc::clone(hook))
            .collect();
        for hook in due {
            hook();
        }
    }
}

pub(super) fn note(log: &Option<CallLog>, name: &'static str) {
    if let Some(log) = log {
        log.push(name);
    }
}
