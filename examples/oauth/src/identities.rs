//! The federated-identity table: which local user an `(issuer, subject)`
//! pair belongs to.
//!
//! An OIDC subject is only unique inside its issuer, and an e-mail address is
//! not unique at all: it changes hands, one IdP lets users type it, another
//! verifies it. So the link between an outside identity and a local user is
//! the pair `(issuer, subject)` and nothing else. The same address arriving
//! from a second issuer is a second identity and, unless the application
//! decides otherwise by some other means, a second user.
//!
//! The table in SQL is one unique key:
//!
//! ```sql
//! CREATE TABLE federated_identity (
//!     issuer   TEXT NOT NULL,
//!     subject  TEXT NOT NULL,
//!     user_id  TEXT NOT NULL REFERENCES users (id),
//!     PRIMARY KEY (issuer, subject)
//! );
//! ```

use axess::authn::UserId;
use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;

/// Storage for the `(issuer, subject)` to local-user link.
pub trait FederatedIdentities: Send + Sync + 'static {
    /// The local user linked to this outside identity, if any.
    fn find(&self, issuer: &str, subject: &str) -> impl Future<Output = Option<UserId>> + Send;

    /// Link an outside identity to a local user unless it is linked already,
    /// and return the user it is linked to afterwards. The call that loses a
    /// race gets the winner's user back, never an error and never a second
    /// row: this is the `INSERT .. ON CONFLICT DO NOTHING` followed by a read
    /// that a database-backed table would run.
    fn link_if_absent(
        &self,
        issuer: &str,
        subject: &str,
        user: UserId,
    ) -> impl Future<Output = UserId> + Send;
}

/// A [`FederatedIdentities`] that lives in memory and is gone on restart.
#[derive(Default)]
pub struct MemoryFederatedIdentities {
    rows: Mutex<HashMap<(String, String), UserId>>,
}

impl MemoryFederatedIdentities {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many outside identities are linked.
    pub fn len(&self) -> usize {
        self.rows.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Whether no outside identity is linked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl FederatedIdentities for MemoryFederatedIdentities {
    async fn find(&self, issuer: &str, subject: &str) -> Option<UserId> {
        let rows = self.rows.lock().unwrap_or_else(|e| e.into_inner());
        rows.get(&(issuer.to_string(), subject.to_string()))
            .copied()
    }

    async fn link_if_absent(&self, issuer: &str, subject: &str, user: UserId) -> UserId {
        let mut rows = self.rows.lock().unwrap_or_else(|e| e.into_inner());
        *rows
            .entry((issuer.to_string(), subject.to_string()))
            .or_insert(user)
    }
}
