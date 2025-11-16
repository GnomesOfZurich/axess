//! Authentication middleware integrating Axess sessions with tower-sessions.
//!
//! Exposes the [`AuthnService`] layer and supporting [`AuthnManager`] service
//! used to attach [`AuthSession`] instances to incoming requests, while
//! handling session lookups, registry coordination, and backend wiring.

use crate::{
    authn::{
        backend::{AuthUser, AuthnBackend, EntityState},
        session::{AuthSession, registry::SessionRegistry},
    },
    axum::http::{Request, Response, StatusCode},
    tracing::{error, info},
    utils::random::SystemRng,
};
use std::{
    fmt::Debug,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    // str::FromStr,
};
use tower_cookies::CookieManager;
use tower_layer::Layer;
use tower_service::Service;
use tower_sessions::{
    Session, SessionManager, SessionManagerLayer, SessionStore,
    service::{CookieController, PlaintextCookie},
};

#[derive(Debug, Clone)]
pub struct AuthnManager<S, B, R>
where
    B: AuthnBackend,
    R: SessionRegistry + Debug,
{
    inner: S,
    backend: Arc<B>,
    data_key: &'static str,
    session_registry: Option<Arc<R>>,
}

impl<ReqBody, ResBody, S, B, R> Service<Request<ReqBody>> for AuthnManager<S, B, R>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Default + Send,
    B: AuthnBackend + Debug + PartialEq + 'static,
    B::UserId: From<<B::User as AuthUser>::Id>,
    B::TenantId: From<<B::User as AuthUser>::TenantId>,
    B::TenantId: From<<B::Tenant as crate::authn::backend::AuthTenant>::Id>,
    R: SessionRegistry + Send + Sync + Debug + 'static,
    // Rng: SecureRng + Default + Clone + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let backend = self.backend.clone();
        let data_key = self.data_key;
        let session_registry = self.session_registry.clone();
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        info!("TEST: begining of call...");

        Box::pin(async move {
            // Always get the session from extensions
            let session = match req.extensions().get::<Session>().cloned() {
                Some(s) => s,
                None => {
                    error!("Session not found in request extensions");
                    let mut res = Response::default();
                    *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    return Ok(res);
                }
            };

            // Ensure session is persisted and has an ID
            if session.id().is_none() {
                // Save the session to assign an ID
                if let Err(e) = session.save().await {
                    error!("Session save error: {:?}", e);
                    let mut res = Response::default();
                    *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    return Ok(res);
                }
            }

            info!("TEST: Create AuthSession from session...");

            // Now construct AuthSession, which will initialize guest user/data if needed
            match AuthSession::from_session_with_rng(
                session.clone(),
                backend.clone(),
                data_key,
                session_registry.clone(),
                SystemRng,
            )
            .await
            {
                Ok(mut auth_session) => {
                    // If session data is missing, initialize guest user/data
                    if auth_session.get_user_state() == EntityState::Guest
                        && auth_session.get_user_id().is_none()
                    {
                        let guest_user = backend
                            .get_new_guest_user(auth_session.get_tenant_id())
                            .await
                            .ok();
                        if let Some(guest) = guest_user {
                            info!("TEST: Guest user created successfully...");
                            auth_session.set_guest_user(guest);
                            auth_session.save_user_data().await.ok();
                            info!("TEST: Successfully saved new Guest user and related data...");
                        }
                    }

                    info!(
                        "AuthSession construction: session_id={:?}, user_id={:?}, tenant_id={:?}, state={:?}, user_state={:?}, session_data={:?}",
                        auth_session.session.id(),
                        auth_session.get_user_id(),
                        auth_session.get_tenant_id(),
                        auth_session.get_auth_state(),
                        auth_session.get_user_state(),
                        auth_session.get_session_data().await,
                    );

                    // Always generate and persist a session hash, even for guests
                    let session_hash = auth_session.generate_session_hash();
                    if let Some(registry) = &session_registry {
                        if let Some(session_id) = auth_session.session.id() {
                            registry
                                .register_session(
                                    &session_id.to_string(),
                                    auth_session.get_user_id().as_ref(),
                                    auth_session.get_tenant_id().as_ref(),
                                    session_hash.clone(),
                                )
                                .await
                                .ok();
                            info!("Persisted session hash for session: {:?}", session_hash);
                        } else {
                            info!("Session ID not present, skipping registry registration");
                        }
                    }
                    // Optionally, insert hash into session data
                    // auth_session.session.insert("session_hash", &session_hash).await.ok();

                    info!(
                        "Inserting AuthSession<{}, {}, Rng> into extensions",
                        std::any::type_name::<B>(),
                        std::any::type_name::<R>(),
                    );
                    req.extensions_mut().insert(auth_session);
                }
                Err(e) => {
                    error!(
                        "AuthSession construction failed: error={:?}, session_id={:?}",
                        e,
                        session.id()
                    );
                    // Do NOT insert a guest session if backend fails
                    let mut res = Response::default();
                    *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    return Ok(res);
                }
            }

            let ext_debug = format!("{:?}", req.extensions());
            info!("Request extensions after AuthSession insert: {}", ext_debug);

            info!("Calling inner service...");
            let result = inner.call(req).await;
            match &result {
                Ok(response) => info!("Inner service returned... {}", response.status()),
                Err(_) => info!("Inner service returned an error"),
            }
            result

            // inner.call(req).await;
        })
    }
}

/// A layer for providing [`AuthSession`] as a request extension.
#[derive(Debug, Clone)]
pub struct AuthnService<
    B: AuthnBackend,
    Sessions: SessionStore,
    R: SessionRegistry,
    C: CookieController = PlaintextCookie,
> {
    backend: Arc<B>,
    session_manager_layer: SessionManagerLayer<Sessions, C>,
    data_key: &'static str,
    session_registry: Option<Arc<R>>,
}

impl<Backend: AuthnBackend, Sessions: SessionStore, R: SessionRegistry, C: CookieController>
    AuthnService<Backend, Sessions, R, C>
{
    /// Create a new [`AuthnService`] with the provided access controller.
    pub(crate) fn new(
        backend: Arc<Backend>,
        data_key: &'static str,
        session_manager_layer: SessionManagerLayer<Sessions, C>,
        session_registry: Option<Arc<R>>,
    ) -> Self {
        Self {
            backend,
            session_manager_layer,
            data_key,
            session_registry,
        }
    }
}

impl<S, B: AuthnBackend, Sessions: SessionStore, R: SessionRegistry + Debug, C: CookieController>
    Layer<S> for AuthnService<B, Sessions, R, C>
{
    type Service = CookieManager<SessionManager<AuthnManager<S, B, R>, Sessions, C>>;

    fn layer(&self, inner: S) -> Self::Service {
        let login_manager = AuthnManager {
            inner,
            backend: self.backend.clone(),
            data_key: self.data_key,
            session_registry: self.session_registry.clone(),
        };

        self.session_manager_layer.layer(login_manager)
    }
}

#[derive(Debug, Clone)]
pub struct AuthnServiceBuilder<
    B: AuthnBackend,
    Sessions: SessionStore,
    R: SessionRegistry,
    C: CookieController = PlaintextCookie,
> {
    backend: Arc<B>,
    session_manager_layer: SessionManagerLayer<Sessions, C>,
    data_key: Option<&'static str>,
    session_registry: Option<Arc<R>>,
}

impl<B: AuthnBackend, Sessions: SessionStore, R: SessionRegistry, C: CookieController>
    AuthnServiceBuilder<B, Sessions, R, C>
{
    pub fn new(backend: Arc<B>, session_manager_layer: SessionManagerLayer<Sessions, C>) -> Self {
        Self {
            backend,
            session_manager_layer,
            data_key: None,
            session_registry: None,
        }
    }

    pub fn with_session_registry(mut self, registry: Arc<R>) -> Self {
        self.session_registry = Some(registry);
        self
    }

    /// Configure the `data_key` optional property of the builder. If not
    /// configured it will default to "axess.data".
    pub fn with_data_key(
        mut self,
        data_key: &'static str,
    ) -> AuthnServiceBuilder<B, Sessions, R, C> {
        self.data_key = Some(data_key);
        self
    }

    /// Build the [`AuthnService`].
    pub fn build(self) -> AuthnService<B, Sessions, R, C> {
        AuthnService::new(
            self.backend,
            self.data_key.unwrap_or("axess.data"),
            self.session_manager_layer,
            self.session_registry,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authn::session::registry::SessionRegistryStore,
        utils::{
            random::SystemRng,
            testing::{mock_backend::MockBackend, mock_tracing::init_tracing},
        },
    };
    use axum::http::{Request, StatusCode};
    // use axum::body::Body;
    use std::str::FromStr;
    use tower_sessions::{MemoryStore, SessionManagerLayer};
    // use std::sync::Arc;
    use axum::extract::Extension;
    use tower::ServiceExt;

    fn build_test_app(store: Arc<MemoryStore>) -> axum::Router {
        let backend = Arc::new(MockBackend::default());
        let registry = Arc::new(SessionRegistryStore::new((*store).clone(), 0));
        let session_manager_layer = SessionManagerLayer::new(store.as_ref().clone());
        let auth_service = AuthnServiceBuilder::new(backend.clone(), session_manager_layer.clone())
            .with_data_key("test.data")
            .with_session_registry(registry.clone())
            .build();

        axum::Router::new()
            .route(
                "/check",
                axum::routing::get(
                    |Extension(session): Extension<
                        AuthSession<MockBackend, SessionRegistryStore<MemoryStore>, SystemRng>,
                    >| async move {
                        info!("TEST: Extracted AuthSession: {:?}", session);
                        assert_eq!(session.get_user_state(), EntityState::Guest);
                        info!("TEST: user_id: {:?}", session.get_user_id());
                        StatusCode::OK
                    },
                ),
            )
            .layer(auth_service)
    }

    /// Test that the middleware correctly inserts an AuthSession into request extensions.
    #[tokio::test]
    async fn test_middleware_inserts_auth_session_extension() {
        init_tracing();
        info!("starting test_middleware_inserts_auth_session_extension");

        let store = Arc::new(MemoryStore::default());
        let app = build_test_app(store.clone());
        info!("Created app...");

        let req = Request::builder()
            .uri("/check")
            .body(axum::body::Body::empty())
            .unwrap();

        info!("Created request...");
        let res = app.clone().oneshot(req).await.unwrap();
        info!("res: {:?}", res);
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_session_id_is_created_and_persisted_for_new_visitor() {
        init_tracing();
        info!("starting test_session_id_is_created_and_persisted_for_new_visitor");

        let store = Arc::new(MemoryStore::default());
        let app = build_test_app(store.clone());

        let req = Request::builder()
            .uri("/check")
            .body(axum::body::Body::empty())
            .unwrap();

        let res = app.clone().oneshot(req).await.unwrap();
        info!(status = %res.status(), "received response");
        assert_eq!(res.status(), StatusCode::OK);

        let cookie_header = res.headers().get("set-cookie").map(|v| v.to_str().unwrap());
        let cookie = cookie_header
            .and_then(|h| h.split(';').next())
            .unwrap_or("");
        let session_id = cookie.split('=').nth(1).unwrap_or("");
        assert!(
            !session_id.is_empty(),
            "Session ID extracted from cookie is empty!"
        );

        // Second request with cookie to ensure session persists
        let req2 = Request::builder()
            .uri("/check")
            .header("cookie", cookie)
            .body(axum::body::Body::empty())
            .unwrap();

        let res2 = app.oneshot(req2).await.unwrap();
        assert_eq!(res2.status(), StatusCode::OK);

        let session_id_obj =
            tower_sessions::session::Id::from_str(session_id).expect("invalid session id format");
        let session_opt = store.load(&session_id_obj).await.expect("session load");
        assert!(
            session_opt.is_some(),
            "Session not found in store after creation"
        );
        let session = session_opt.unwrap();
        assert!(
            session.id != tower_sessions::session::Id::default(),
            "Session object does not have a valid id after creation"
        );
    }

    #[tokio::test]
    async fn test_session_manager_persists_session_on_response() {
        init_tracing();
        info!("starting test_session_manager_persists_session_on_response");

        let store = Arc::new(MemoryStore::default());
        let app = build_test_app(store.clone());

        let req = Request::builder()
            .uri("/check")
            .body(axum::body::Body::empty())
            .unwrap();

        let res = app.clone().oneshot(req).await.unwrap();
        info!(status = %res.status(), "received response");
        assert_eq!(res.status(), StatusCode::OK);

        let cookie_header = res.headers().get("set-cookie").map(|v| v.to_str().unwrap());
        let cookie = cookie_header
            .and_then(|h| h.split(';').next())
            .unwrap_or("");
        let session_id = cookie.split('=').nth(1).unwrap_or("");
        assert!(
            !session_id.is_empty(),
            "Session ID extracted from cookie is empty!"
        );

        let session_id_obj =
            tower_sessions::session::Id::from_str(session_id).expect("invalid session id format");
        let session_opt = store.load(&session_id_obj).await.expect("session load");
        assert!(
            session_opt.is_some(),
            "Session not found in store after creation"
        );
        let session = session_opt.unwrap();
        assert!(
            session.id != tower_sessions::session::Id::default(),
            "Session object does not have a valid id after creation"
        );
    }
}
