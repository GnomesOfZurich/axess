//! What a caller accepts when it reloads the FIDO2 provider.

/// Options for [`AuthnService::reload_fido2_with`](crate::authn::service::AuthnService::reload_fido2_with).
///
/// The default accepts nothing beyond a like-for-like swap: a candidate with
/// another relying-party id is refused, because a passkey is bound to its
/// relying-party id and a change orphans every registered credential.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReloadFido2 {
    allow_rp_id_change: bool,
}

impl ReloadFido2 {
    /// Accept a candidate whose relying-party id differs from the one in
    /// force. The change is counted and logged with both ids.
    #[must_use]
    pub fn allow_rp_id_change() -> Self {
        Self {
            allow_rp_id_change: true,
        }
    }

    /// Whether a changed relying-party id is accepted.
    pub(crate) fn allows_rp_id_change(self) -> bool {
        self.allow_rp_id_change
    }
}
