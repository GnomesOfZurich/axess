use crate::{
    authn::{
        backend::{AuthUser, AuthnBackend},
        session::auth_session::AuthSession,
    },
    axum::http::{Request, Response, StatusCode},
    // storage::session_registry::SessionRegistry,
    tracing::{Instrument, Span, error, field, info_span},
};
use std::{
    fmt::Debug,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower_cookies::CookieManager;
use tower_layer::Layer;
use tower_service::Service;
use tower_sessions::{
    Session, SessionManager, SessionManagerLayer, SessionStore,
    service::{CookieController, PlaintextCookie},
};

#[derive(Debug, Clone)]
pub struct AuthnManager<S, B>
where
    B: AuthnBackend,
{
    inner: S,
    backend: B,
    data_key: &'static str,
    // session_registry: Option<Arc<Registry>>,
}

impl<ReqBody, ResBody, S, B> Service<Request<ReqBody>> for AuthnManager<S, B>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Default + Send,
    B: AuthnBackend + Debug + PartialEq + 'static,
    B::UserId: From<<B::User as AuthUser>::Id>,
    B::TenantId: From<<B::User as AuthUser>::TenantId>,
    B::TenantId: From<<B::Tenant as crate::authn::backend::AuthTenant>::Id>,
    // Registry: SessionRegistry,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let span = info_span!("call", user.id = field::Empty);
        let backend = self.backend.clone();
        let data_key = self.data_key;
        // let session_registry = self.session_registry.clone();

        // Because the inner service can panic until ready, we need to ensure we only
        // use the ready service.
        //
        // See: https://docs.rs/tower/latest/tower/trait.Service.html#be-careful-when-cloning-inner-services
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(
            async move {
                let Some(session) = req.extensions().get::<Session>().cloned() else {
                    error!("session not found in request extensions");
                    let mut res = Response::default();
                    *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    return Ok(res);
                };

                let auth_session = match AuthSession::from_session(session, backend, data_key).await
                {
                    Ok(auth_session) => auth_session,
                    Err(err) => {
                        error!(
                            err = ?err,
                            "could not create auth session from session"
                        );
                        let mut res = Response::default();
                        *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                        return Ok(res);
                    }
                };

                if let Ok(ref user) = auth_session.user() {
                    Span::current().record("user.id", format!("{:?}", user.id()));
                }

                req.extensions_mut().insert(Arc::new(auth_session));

                inner.call(req).await
            }
            .instrument(span),
        )
    }
}

/// A layer for providing [`AuthSession`] as a request extension.
#[derive(Debug, Clone)]
pub struct AuthnLayer<
    B: AuthnBackend,
    Sessions: SessionStore,
    // Registry: SessionRegistry,
    C: CookieController = PlaintextCookie,
> {
    backend: B,
    session_manager_layer: SessionManagerLayer<Sessions, C>,
    data_key: &'static str,
    // session_registry: Option<Arc<Registry>>,
}

impl<Backend: AuthnBackend, Sessions: SessionStore, C: CookieController>
    AuthnLayer<Backend, Sessions, C>
{
    /// Create a new [`AuthManagerLayer`] with the provided access controller.
    pub(crate) fn new(
        backend: Backend,
        data_key: &'static str,
        session_manager_layer: SessionManagerLayer<Sessions, C>,
        // session_registry: Option<Arc<Registry>>,
    ) -> Self {
        Self {
            backend,
            session_manager_layer,
            data_key,
            // session_registry,
        }
    }
}

impl<
    S,
    B: AuthnBackend,
    Sessions: SessionStore,
    // Registry: SessionRegistry,
    C: CookieController,
> Layer<S> for AuthnLayer<B, Sessions, C>
{
    type Service = CookieManager<SessionManager<AuthnManager<S, B>, Sessions, C>>;

    fn layer(&self, inner: S) -> Self::Service {
        let login_manager = AuthnManager {
            inner,
            backend: self.backend.clone(),
            data_key: self.data_key,
            // session_registry: self.session_registry.clone(),
        };

        self.session_manager_layer.layer(login_manager)
    }
}

#[derive(Debug, Clone)]
pub struct AuthnLayerBuilder<
    B: AuthnBackend,
    Sessions: SessionStore,
    // Registry: SessionRegistry,
    C: CookieController = PlaintextCookie,
> {
    backend: B,
    session_manager_layer: SessionManagerLayer<Sessions, C>,
    data_key: Option<&'static str>,
    // session_registry: Option<Arc<Registry>>,
}

// #[derive(Debug, Clone)]
// pub struct NoOpSessionRegistry;

impl<B: AuthnBackend, Sessions: SessionStore, C: CookieController>
    AuthnLayerBuilder<B, Sessions, C>
{
    pub fn new(
        backend: B,
        session_manager_layer: SessionManagerLayer<Sessions, C>,
        // session_registry: Option<Arc<Registry>>,
    ) -> Self {
        Self {
            backend,
            session_manager_layer,
            data_key: None,
            // session_registry,
        }
    }

    /// Configure the `data_key` optional property of the builder. If not
    /// configured it will default to "axess.data".
    pub fn with_data_key(mut self, data_key: &'static str) -> AuthnLayerBuilder<B, Sessions, C> {
        self.data_key = Some(data_key);
        self
    }

    /// Build the [`AuthManagerLayer`].
    pub fn build(self) -> AuthnLayer<B, Sessions, C> {
        AuthnLayer::new(
            self.backend,
            self.data_key.unwrap_or("axess.data"),
            self.session_manager_layer,
            // self.session_registry,
        )
    }
}
