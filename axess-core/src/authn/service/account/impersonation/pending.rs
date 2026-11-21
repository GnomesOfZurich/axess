//! The registry entries an impersonation registers before it stands, held so
//! that a call dropped on the way cannot leave them behind.
//!
//! An impersonation registers the anchor under the administrator and then
//! the new session under the target, and writes its audit row after both.
//! Every refusal on the way ends what was registered; but the caller can
//! drop the future at any of those awaits (a client that hangs up, a
//! timeout), and nothing after the drop runs. An anchor left registered
//! counts against the administrator's sessions until an operator ends them,
//! and a target session registered without its audit row is an
//! impersonation nobody can see.
//!
//! [`PendingEntries`] owes the end of each entry from just before its
//! registration is asked for. [`settle`](PendingEntries::settle) says the
//! call accounted for them itself (it stood, or a refusal ended them); a
//! holder dropped unsettled ends every owed entry on a spawned task, which
//! outlives the cancelled caller.

use crate::authn::ids::UserId;
use crate::session::id::SessionKey;
use crate::session::store::{SessionRegistryHandle, note_revocation};
use std::sync::Arc;

/// Registry entries owed an end unless the impersonation settles them.
pub(super) struct PendingEntries {
    registry: Option<Arc<dyn SessionRegistryHandle>>,
    owed: Vec<(UserId, SessionKey)>,
    settled: bool,
}

impl PendingEntries {
    /// A holder with nothing owed. Without a registry nothing is registered
    /// and nothing is ever owed.
    pub(super) fn new(registry: Option<Arc<dyn SessionRegistryHandle>>) -> Self {
        Self {
            registry,
            owed: Vec::new(),
            settled: false,
        }
    }

    /// Owe the end of `session` under `user`; called before its registration
    /// is asked for, so a drop while the registry answers is covered.
    pub(super) fn owe(&mut self, user: UserId, session: SessionKey) {
        self.owed.push((user, session));
    }

    /// The call accounted for every owed entry: it stood, or its refusal
    /// ended them.
    pub(super) fn settle(mut self) {
        self.settled = true;
    }
}

impl Drop for PendingEntries {
    fn drop(&mut self) {
        if self.settled || self.owed.is_empty() {
            return;
        }
        let owed = std::mem::take(&mut self.owed);
        let Some(registry) = self.registry.clone() else {
            return;
        };
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                tracing::warn!(
                    entries = owed.len(),
                    "an impersonation was dropped before it stood; ending what it registered"
                );
                runtime.spawn(async move {
                    for (user, session) in owed {
                        note_revocation(
                            registry.invalidate_session(&user, &session).await,
                            "ending a dropped impersonation",
                        );
                    }
                });
            }
            Err(_) => tracing::error!(
                entries = owed.len(),
                "an impersonation was dropped outside a runtime; the entries it registered \
                 stay until the administrator's sessions are ended"
            ),
        }
    }
}
