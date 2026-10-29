//! Session validity check and the axum middleware that enforces it.

use crate::authn::ids::{TenantId, UserId};
use crate::authn::store::IdentityLookup;
use crate::session::extractor::AuthSession;
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

/// Cloneable, non-generic handle used by [`require_valid_session`] to check
/// authentication state and (when wired) tenant identity against the registry.
#[derive(Clone)]
pub struct SessionValidator {
    pub(super) registry: Option<Arc<dyn SessionRegistryHandle>>,
    pub(super) identity: Option<Arc<dyn IdentityHandle>>,
}

impl SessionValidator {
    /// Returns `true` when the session is authenticated, present in the
    /// registry (if configured), and (if configured) carries the user's
    /// current `tenant_id`.
    #[tracing::instrument(skip(self, session))]
    pub async fn is_valid(&self, session: &AuthSession) -> bool {
        if !session.is_authenticated().await {
            return false;
        }
        let user_id = match session.user_id().await {
            Some(id) => id,
            None => return false,
        };
        let sid = session.session_id().await;
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
        if !(registry_ok && tenant_ok) {
            return false;
        }
        true
    }

    /// [`is_valid`](Self::is_valid), and when an authenticated session fails
    /// the check (revoked in the registry, or a tenant mismatch), clear the
    /// stored session and rotate its id so the row stops saying
    /// `Authenticated` and the cookie stops matching it.
    ///
    /// This is what [`require_valid_session`] and the validator form of
    /// `require_authn!` run; call it from a hand-written guard that needs the
    /// same behaviour.
    pub async fn enforce(&self, session: &AuthSession) -> bool {
        if self.is_valid(session).await {
            return true;
        }
        if session.is_authenticated().await {
            session.clear().await;
        }
        false
    }
}

/// Axum middleware that returns 401 when the session is unauthenticated
/// or no longer valid in the registry.
///
/// When the session claims to be authenticated but the check fails (revoked
/// in the registry, or a tenant mismatch), the stored session is cleared and
/// its id rotated before the 401 goes out, so the row no longer says
/// `Authenticated` and the cookie stops matching it.
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
