//! The [`LogoutAudit`] that writes `SessionInvalidated` rows.

use super::{AuthnService, RequestAuthnService};
use crate::authn::Actor;
use crate::authn::event::AuditContext;
use crate::authn::store::{FactorStore, IdentityStore};
use crate::federation::backchannel_logout::{IdpSessionEnded, LogoutAudit};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Writes one `SessionInvalidated` row per session an IdP logout ended, with
/// no actor (the system acted) and an audit context that has no client.
struct ServiceLogoutAudit<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    service: RequestAuthnService<I, F>,
}

impl<I, F> LogoutAudit for ServiceLogoutAudit<I, F>
where
    I: IdentityStore + 'static,
    F: FactorStore<Error = I::Error> + 'static,
{
    fn session_ended<'a>(
        &'a self,
        ended: &'a IdpSessionEnded,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            self.service
                .audit_invalidation(&ended.user_id, Some(&ended.session_id), Actor::System)
                .await
                .map_err(|e| e.to_string())
        })
    }
}

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore + 'static,
    F: FactorStore<Error = I::Error> + 'static,
{
    /// The audit hook for
    /// [`BackChannelLogoutHandler::with_audit`](crate::federation::backchannel_logout::BackChannelLogoutHandler::with_audit):
    /// a `SessionInvalidated` row for each session an IdP back-channel
    /// logout ends, written to this service's identity store.
    ///
    /// The request that carries the logout token comes from the IdP, not
    /// from the user, so the rows have no client address or user agent and no
    /// acting administrator.
    pub fn backchannel_logout_audit(&self) -> Arc<dyn LogoutAudit> {
        Arc::new(ServiceLogoutAudit {
            service: self.with_audit_context(AuditContext::default()),
        })
    }
}
