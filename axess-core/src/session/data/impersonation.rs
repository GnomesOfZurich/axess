//! The impersonation marker an authenticated session carries.

use super::*;

/// An administrator acting in a user's name: who, and since when. Carried by
/// [`AuthState::Authenticated::impersonator`] and returned by
/// [`AuthSession::impersonation`](crate::session::extractor::AuthSession::impersonation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Impersonation {
    /// The administrator.
    pub admin: UserId,
    /// When `begin_impersonation` made the session.
    pub since: DateTime<Utc>,
}

impl Impersonation {
    /// The id under which the registry holds this impersonation for the
    /// administrator, beside the session's own entry under the target.
    ///
    /// The session's id changes on every rotation and its entry is the
    /// target's, so neither says whether the administrator is still in good
    /// standing. This id is derived from the administrator, the target and
    /// the start time, so it survives rotation; `begin_impersonation`
    /// registers it under the administrator and the session layer asks the
    /// registry about it on every request. Ending the administrator's
    /// sessions (a suspension, a deletion, a forced logout) removes it, and
    /// the impersonation ends with it. It is a registry key, not a
    /// credential: knowing it grants nothing.
    #[must_use]
    pub fn registry_anchor(&self, target: &UserId) -> axess_identity::SessionId {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"axess impersonation anchor v1");
        for part in [self.admin.to_string(), target.to_string()] {
            h.update((part.len() as u64).to_be_bytes());
            h.update(part.as_bytes());
        }
        h.update(
            self.since
                .timestamp_nanos_opt()
                .unwrap_or_default()
                .to_be_bytes(),
        );
        let digest = h.finalize();
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest[..16]);
        axess_identity::SessionId::from_bytes(id)
    }
}
