//! Session validity check and the axum middleware that enforces it.

use crate::authn::ids::{TenantId, UserId};
use crate::authn::store::IdentityLookup;
use crate::session::extractor::AuthSession;
use crate::session::layer::{SessionEndAudit, SessionEndReason};
use crate::session::store::SessionRegistryHandle;
use axum::response::IntoResponse;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Surfaces a misconfigured `AuthnService` (no session registry) on the
/// admin paths that need one.
#[derive(Debug, thiserror::Error)]
#[error(
    "no session registry configured on AuthnService; call AuthnServiceBuilder::with_registry at construction"
)]
pub struct NoSessionRegistryError;

/// Why [`AuthnService::active_sessions`](super::AuthnService::active_sessions)
/// could not list a user's sessions.
#[derive(Debug, thiserror::Error)]
pub enum ActiveSessionsError {
    /// No session registry is configured.
    #[error(transparent)]
    NoRegistry(#[from] NoSessionRegistryError),
    /// The registry could not answer.
    #[error("session registry could not list the user's sessions: {0}")]
    Registry(crate::session::store::RevocationError),
}

/// Cloneable, non-generic handle used by [`require_valid_session`] to check
/// authentication state and (when wired) tenant identity against the registry.
#[derive(Clone)]
pub struct SessionValidator {
    pub(super) registry: Option<Arc<dyn SessionRegistryHandle>>,
    pub(super) identity: Option<Arc<dyn IdentityHandle>>,
    /// Told of a session the validator ends when no session layer stands
    /// behind the handle to record it.
    pub(super) audit: Arc<dyn SessionEndAudit>,
}

/// What the validator finds a session to be, with the cause when it is not
/// valid.
enum Verdict {
    Valid,
    /// Not authenticated: a guest, a login in progress, a step-up that has
    /// not completed. Nothing to end.
    NotSignedIn,
    /// The registry does not hold the session.
    NotRegistered,
    /// The identity store did not confirm the tenant the session names.
    TenantNotConfirmed,
}

impl SessionValidator {
    /// Returns `true` when the session is authenticated, present in the
    /// registry (if configured) under the key the registry holds it under
    /// ([`AuthSession::registered_key`]), and (if configured) carries the
    /// user's current `tenant_id`.
    #[tracing::instrument(skip(self, session))]
    pub async fn is_valid(&self, session: &AuthSession) -> bool {
        matches!(self.verdict(session).await, Verdict::Valid)
    }

    /// The one judgement [`is_valid`](Self::is_valid) and
    /// [`enforce`](Self::enforce) read.
    async fn verdict(&self, session: &AuthSession) -> Verdict {
        if !session.is_authenticated().await {
            return Verdict::NotSignedIn;
        }
        let user_id = match session.user_id().await {
            Some(id) => id,
            None => return Verdict::NotSignedIn,
        };
        // The key the registry holds: after a rotation in the same handler
        // it holds the key it held before, until the response is written.
        let sid = session.registered_key().await;
        let stated = session.tenant_id().await;

        // The registry and the identity store are independent, so they are
        // asked together: the check costs the slower of the two round trips,
        // not their sum. Both outcomes are read before deciding, and an
        // unanswered or negative registry fails closed.
        let registry_check = async {
            match &self.registry {
                Some(reg) => reg.is_valid(&user_id, &sid).await,
                None => true,
            }
        };
        let tenant_check = async {
            let Some(identity) = &self.identity else {
                return true;
            };
            let Some(stated) = stated else {
                return false;
            };
            match identity.get_user_tenant(&user_id).await {
                Some(actual) if actual == stated => true,
                Some(actual) => {
                    tracing::warn!(
                        user_id = %user_id,
                        session_tenant = %stated,
                        actual_tenant = %actual,
                        "session tenant_id does not match user's actual tenant; invalidating"
                    );
                    false
                }
                None => false,
            }
        };
        let (registry_ok, tenant_ok) = tokio::join!(registry_check, tenant_check);
        // A session neither check confirms is named for the registry: the
        // registry's answer is the one every other check of the session
        // reads.
        match (registry_ok, tenant_ok) {
            (true, true) => Verdict::Valid,
            (false, _) => Verdict::NotRegistered,
            (true, false) => Verdict::TenantNotConfirmed,
        }
    }

    /// [`is_valid`](Self::is_valid), and when an authenticated session fails
    /// the check, end it through the session layer's ending protocol: the
    /// handle is a guest's at once, and the stored session is claimed,
    /// recorded and removed as the response is written, with the reason
    /// `session_not_registered` (the registry no longer holds it) or
    /// `session_tenant_not_confirmed` (the identity store does not confirm
    /// its tenant). With no session layer behind the handle the record goes
    /// to the validator's own sink, the service's
    /// ([`AuthnService::session_end_audit`](super::AuthnService::session_end_audit)).
    /// A session that is not authenticated (a guest, a login in progress, a
    /// step-up that has not completed) is refused and ends nothing.
    ///
    /// This is what [`require_valid_session`] and the validator form of
    /// `require_authn!` run; call it from a hand-written guard that needs the
    /// same behaviour.
    pub async fn enforce(&self, session: &AuthSession) -> bool {
        let reason = match self.verdict(session).await {
            Verdict::Valid => return true,
            Verdict::NotSignedIn => return false,
            Verdict::NotRegistered => SessionEndReason::NotRegistered,
            Verdict::TenantNotConfirmed => SessionEndReason::TenantNotConfirmed,
        };
        if let Some(record) = session.end_through_layer(reason).await
            && let Err(e) = self.audit.session_ended(&record).await
        {
            tracing::error!(
                user_id = %record.user_id,
                error = %e,
                ending = record.reason.as_str(),
                "the record of a session the validator ended could not be written"
            );
        }
        false
    }
}

/// Axum middleware that returns 401 when the session is unauthenticated
/// or no longer valid in the registry.
///
/// When the session claims to be authenticated but the check fails (revoked
/// in the registry, or a tenant the identity store does not confirm), the
/// session is ended through the ending protocol with its audit record
/// ([`SessionValidator::enforce`]): the 401 replaces the cookie, and the
/// stored row is claimed, recorded and removed.
pub fn require_valid_session(
    validator: SessionValidator,
) -> impl tower::Layer<
    axum::routing::Route,
    Service = impl tower::Service<
        axum::http::Request<axum::body::Body>,
        Response = axum::response::Response,
        Error = std::convert::Infallible,
        Future = impl Send,
    > + Clone
              + Send,
> + Clone
+ Send
+ 'static {
    axum::middleware::from_fn(
        move |session: AuthSession,
              req: axum::http::Request<axum::body::Body>,
              next: axum::middleware::Next| {
            let v = validator.clone();
            async move {
                if v.enforce(&session).await {
                    next.run(req).await
                } else {
                    axum::http::StatusCode::UNAUTHORIZED.into_response()
                }
            }
        },
    )
}

pub(super) trait IdentityHandle: Send + Sync + 'static {
    fn get_user_tenant<'a>(
        &'a self,
        user_id: &'a UserId,
    ) -> Pin<Box<dyn Future<Output = Option<TenantId>> + Send + 'a>>;
}

pub(super) struct IdentityWrapper<I: IdentityLookup>(pub(super) Arc<I>);

impl<I: IdentityLookup> IdentityHandle for IdentityWrapper<I> {
    fn get_user_tenant<'a>(
        &'a self,
        user_id: &'a UserId,
    ) -> Pin<Box<dyn Future<Output = Option<TenantId>> + Send + 'a>> {
        Box::pin(async move {
            match self.0.get_user_tenant(user_id).await {
                Ok(opt) => opt,
                Err(e) => {
                    // Fail closed: store error means tenant consistency cannot
                    // be verified, treat session as invalid.
                    tracing::warn!(
                        user_id = %user_id,
                        error = %e,
                        "identity store get_user_tenant failed during tenant cross-check"
                    );
                    None
                }
            }
        })
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod tenant_lookup;

#[cfg(test)]
mod ending_tests;
