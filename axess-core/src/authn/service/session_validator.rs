//! Session validity check and the axum middleware that enforces it.

use crate::authn::ids::UserId;
use crate::authn::store::IdentityStore;
use crate::authn::types::User;
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
    "no session registry configured on AuthnService; call AuthnService::with_registry at construction"
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
        if let Some(reg) = &self.registry
            && !reg.is_valid(&user_id, &sid).await
        {
            return false;
        }
        if let Some(identity) = &self.identity {
            let stated = match session.tenant_id().await {
                Some(t) => t,
                None => return false,
            };
            match identity.get_user(&user_id).await {
                Some(user) if user.tenant_id == stated => {}
                Some(user) => {
                    tracing::warn!(
                        user_id = %user_id,
                        session_tenant = %stated,
                        actual_tenant = %user.tenant_id,
                        "session tenant_id does not match user's actual tenant; invalidating"
                    );
                    return false;
                }
                None => {
                    return false;
                }
            }
        }
        true
    }
}

/// Axum middleware that returns 401 when the session is unauthenticated
/// or no longer valid in the registry.
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
                if v.is_valid(&session).await {
                    next.run(req).await
                } else {
                    axum::http::StatusCode::UNAUTHORIZED.into_response()
                }
            }
        },
    )
}

pub(super) trait IdentityHandle: Send + Sync + 'static {
    fn get_user<'a>(
        &'a self,
        user_id: &'a UserId,
    ) -> Pin<Box<dyn Future<Output = Option<User>> + Send + 'a>>;
}

pub(super) struct IdentityWrapper<I: IdentityStore>(pub(super) Arc<I>);

impl<I: IdentityStore + 'static> IdentityHandle for IdentityWrapper<I> {
    fn get_user<'a>(
        &'a self,
        user_id: &'a UserId,
    ) -> Pin<Box<dyn Future<Output = Option<User>> + Send + 'a>> {
        Box::pin(async move {
            match self.0.get_user(user_id).await {
                Ok(opt) => opt,
                Err(e) => {
                    // Fail closed: store error means tenant consistency cannot
                    // be verified, treat session as invalid.
                    tracing::warn!(
                        user_id = %user_id,
                        error = %e,
                        "identity store get_user failed during tenant cross-check"
                    );
                    None
                }
            }
        })
    }
}

#[cfg(test)]
mod tests;
