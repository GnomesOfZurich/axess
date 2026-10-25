//! The ordered record of store calls shared by the mock stores.

use std::sync::{Arc, Mutex};

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
#[derive(Clone, Default, Debug)]
pub struct CallLog(Arc<Mutex<Vec<&'static str>>>);

impl CallLog {
    /// An empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// The calls recorded so far, oldest first.
    pub fn calls(&self) -> Vec<&'static str> {
        self.0.lock().unwrap().clone()
    }

    /// Forget everything recorded so far.
    pub fn clear(&self) {
        self.0.lock().unwrap().clear();
    }

    pub(super) fn push(&self, name: &'static str) {
        self.0.lock().unwrap().push(name);
    }
}

pub(super) fn note(log: &Option<CallLog>, name: &'static str) {
    if let Some(log) = log {
        log.push(name);
    }
}
