//! The [`SessionEndAudit`] that writes one audit row for each session the
//! session layer ends.

use super::{AuthnService, RequestAuthnService};
use crate::authn::error::AuthnError;
use crate::authn::event::{
    AuditContext, AuthEventBuilder, AuthEventStatus, AuthEventType, AuthFailureReason,
};
use crate::authn::store::{FactorStore, IdentityStore};
use crate::session::{LayerSessionEnded, SessionEndAudit};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Writes one row per session the layer ends, with an audit context that
/// has no client: the request that met the session is not what ended it.
struct ServiceSessionEndAudit<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    service: RequestAuthnService<I, F>,
}

impl<I, F> SessionEndAudit for ServiceSessionEndAudit<I, F>
where
    I: IdentityStore + 'static,
    F: FactorStore<Error = I::Error> + 'static,
{
    fn session_ended<'a>(
        &'a self,
        ended: &'a LayerSessionEnded,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            self.service
                .audit_layer_ending(ended)
                .await
                .map_err(|e| e.to_string())
        })
    }
}

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore + 'static,
    F: FactorStore<Error = I::Error> + 'static,
{
    /// Write the row for a session the session layer is ending:
    /// `SessionExpired` with the status `Expired` for an age cap,
    /// `SessionInvalidated` with `Success` for every other reason, naming
    /// the user, the tenant and the session and, in `error`, the reason.
    ///
    /// Everything in the row comes from the session itself. Nothing is read
    /// from the identity store, so the row is the same for a user who was
    /// deleted since, and the one thing that can fail is the write.
    async fn audit_layer_ending(
        &self,
        ended: &LayerSessionEnded,
    ) -> Result<(), AuthnError<I::Error>> {
        let (event_type, status) = if ended.reason.is_expiry() {
            (AuthEventType::SessionExpired, AuthEventStatus::Expired)
        } else {
            (AuthEventType::SessionInvalidated, AuthEventStatus::Success)
        };
        let mut builder =
            AuthEventBuilder::attributed(ended.user_id, ended.tenant_id, event_type, status)
                .with_session(ended.session_id)
                .with_error(AuthFailureReason::from(ended.reason.as_str()));
        if let Some(administrator) = ended.impersonator {
            builder = builder.with_actor(administrator);
        }
        self.emit_audit(builder).await
    }
}

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore + 'static,
    F: FactorStore<Error = I::Error> + 'static,
{
    /// The audit sink a [`SessionLayer`](crate::session::SessionLayer) is
    /// built with: one row, written to this service's identity store, for
    /// each session the session layer ends by itself.
    ///
    /// A session that outlived an age cap is a `SessionExpired` row with the
    /// status `Expired`; one that ended for any other reason (the registry
    /// no longer holds it, it was revoked while its id rotated, the registry
    /// could not track its rotated id, the store could not rotate it) is a
    /// `SessionInvalidated` row with the status `Success`. Each names the
    /// user, the tenant the session authenticated into and the session, and
    /// carries the reason in `error`
    /// ([`SessionEndReason::as_str`](crate::session::SessionEndReason::as_str)).
    ///
    /// The row of a session that carried an impersonation names the
    /// administrator as its actor, whatever the reason, so the end of an
    /// impersonation is never recorded as the end of the user's own
    /// session. Every other row has no actor: the layer ended the session,
    /// not an administrator. No row has a client address or a user agent:
    /// the client whose request met the session did not end it.
    ///
    /// The layer calls the sink before it removes the session's row, and
    /// leaves the session stored when the write fails (see
    /// [`SessionEndAudit`]).
    pub fn session_end_audit(&self) -> Arc<dyn SessionEndAudit> {
        Arc::new(ServiceSessionEndAudit {
            service: self.with_audit_context(AuditContext::default()),
        })
    }
}

#[cfg(test)]
mod tests;
