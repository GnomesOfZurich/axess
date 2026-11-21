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
    pub since: Timestamp,
}

impl Impersonation {
    /// The key under which the registry holds this impersonation for the
    /// administrator, beside the session's own entry under the target.
    ///
    /// The session's key changes on every rotation and its entry is the
    /// target's, so neither says whether the administrator is still in good
    /// standing. This key is the SHA-256 of a tag of its own, the
    /// administrator, the target and the start time, so it survives
    /// rotation; `begin_impersonation`
    /// registers it under the administrator and the session layer asks the
    /// registry about it on every request. Ending the administrator's
    /// sessions (a suspension, a deletion, a forced logout) removes it, and
    /// the impersonation ends with it. It is a registry key, not a
    /// credential: knowing it grants nothing. It names no session's row: a
    /// session's key is a digest under another tag, so the two are equal
    /// only where SHA-256 collides.
    #[must_use]
    pub fn registry_anchor(&self, target: &UserId) -> crate::session::id::SessionKey {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"axess impersonation anchor v1");
        for part in [self.admin.to_string(), target.to_string()] {
            h.update((part.len() as u64).to_be_bytes());
            h.update(part.as_bytes());
        }
        h.update(
            // Nanoseconds in 64 bits, as the anchor has always been hashed:
            // a start outside what they hold (before 1677 or after 2262)
            // hashes as the epoch does.
            i64::try_from(self.since.unix_nanos())
                .unwrap_or_default()
                .to_be_bytes(),
        );
        let mut key = [0u8; 32];
        key.copy_from_slice(&h.finalize());
        crate::session::id::SessionKey::from_bytes(key)
    }
}
