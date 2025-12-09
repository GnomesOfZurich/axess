//! Axum extractor for retrieving an [`AuthSession`] that was stored by the
//! `AuthnService` middleware.

use crate::{
    authn::{
        backend::AuthnBackend,
        session::{AuthSession, registry::SessionRegistry},
    },
    axum::{
        extract::FromRequestParts,
        http::{StatusCode, request::Parts},
    },
    tracing::{error, info},
    utils::random::SecureRng,
};
// use async_trait::async_trait;

// #[async_trait]
// impl<S, B, R, Rng> FromRequestParts<S> for AuthSession<B, R, Rng>
// where
//     S: Send + Sync,
//     B: AuthnBackend + Send + Sync + 'static,
//     R: SessionRegistry + Send + Sync + Clone + 'static,
//     Rng: SecureRng + Clone + 'static,
// {
//     type Rejection = (StatusCode, &'static str);

//     async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
//         info!(
//             "Attempting to extract AuthSession<{}, {}, {}> from extensions",
//             std::any::type_name::<B>(),
//             std::any::type_name::<R>(),
//             std::any::type_name::<Rng>()
//         );

//         let found = parts.extensions.get::<AuthSession<B, R, Rng>>().is_some();
//         info!("AuthSession present in extensions: {}", found);

//         if let Some(session) = parts.extensions.get::<AuthSession<B, R, Rng>>() {
//             info!("AuthSession found in request extensions (direct)");
//             return Ok(session.clone());
//         }
//         error!(
//             "AuthSession NOT found in request extensions. Extensions: {:?}",
//             parts.extensions
//         );
//         Err((
//             StatusCode::INTERNAL_SERVER_ERROR,
//             "Unable to extract authentication session from middleware; ensure AuthnService is applied.",
//         ))
//     }
// }

impl<S, B, R, Rng> FromRequestParts<S> for AuthSession<B, R, Rng>
where
    S: Send + Sync,
    B: AuthnBackend + Send + Sync + 'static,
    R: SessionRegistry + Send + Sync + Clone + 'static,
    Rng: SecureRng + Clone + 'static,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        info!(
            "Attempting to extract AuthSession<{}, {}, {}> from extensions",
            std::any::type_name::<B>(),
            std::any::type_name::<R>(),
            std::any::type_name::<Rng>()
        );

        let found = parts.extensions.get::<AuthSession<B, R, Rng>>().is_some();
        info!("AuthSession present in extensions: {}", found);

        if let Some(session) = parts.extensions.get::<AuthSession<B, R, Rng>>() {
            info!("AuthSession found in request extensions (direct)");
            return Ok(session.clone());
        }
        error!(
            "AuthSession NOT found in request extensions. Extensions: {:?}",
            parts.extensions
        );
        Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to extract authentication session from middleware; ensure AuthnService is applied.",
        ))
    }
}

// impl<S, B, R, Rng> FromRequestParts<S> for Arc<AuthSession<B, R, Rng>>
// where
//     S: Send + Sync,
//     B: AuthnBackend + Send + Sync + 'static,
//     R: SessionRegistry + Send + Sync + 'static,
//     Rng: SecureRng,
// {
//     type Rejection = (StatusCode, &'static str);

//     async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
//         parts.extensions.get::<Arc<AuthSession<B, R, Rng>>>()
//             .cloned()
//             .ok_or((
//                 StatusCode::INTERNAL_SERVER_ERROR,
//                 "Unable to extract Arc<AuthSession> from extensions.",
//             ))
//     }
// }

// #[cfg(test)]
// mod tests {
//     // use super::*;
//     use axum::{Router, extract::FromRequestParts, http::Request, response::IntoResponse, routing::get};
//     use tower::ServiceExt;
//     use tower_sessions::MemoryStore;
//     // use axum::http::header::COOKIE;
//     use tracing::info;
//     // use std::sync::Arc;
//     // use time::{Duration, OffsetDateTime};

//     use crate::{
//         authn::session::{extractor::AuthSession, SessionRegistryStore},
//         utils::testing::{mock_authn::create_test_session, mock_backend::MockBackend, mock_random::MockRng, mock_tracing::init_tracing},
//     };

//     async fn protected(session: AuthSession<MockBackend, SessionRegistryStore<MemoryStore>, MockRng>) -> impl IntoResponse {
//         match session.get_user_id() {
//             Some(_) => (axum::http::StatusCode::OK, ""),
//             None => (
//                 axum::http::StatusCode::INTERNAL_SERVER_ERROR,
//                 "Unable to extract authentication session",
//             ),
//         }
//     }

//     #[tokio::test]
//     async fn test_extractor_without_extension() {
//         // Build the router
//         let app = Router::new().route("/protected", get(protected));

//         // Build a request without AuthSession in extensions
//         let req = Request::builder()
//             .uri("/protected")
//             .body(axum::body::Body::empty())
//             .unwrap();

//         // Should fail (status 500)
//         let res = app.oneshot(req).await.unwrap();
//         assert_eq!(res.status(), 500);
//     }

//     #[tokio::test]
//     async fn test_extractor_direct() {

//         let (auth_session, _) = create_test_session().await.expect("session setup");

//         // Build Parts with AuthSession in extensions
//         let req = Request::builder().body(()).unwrap();
//         let mut parts = req.into_parts().0;
//         parts.extensions.insert(auth_session);

//         // Call the extractor directly
//         let result = AuthSession::<MockBackend, SessionRegistryStore<MemoryStore>, MockRng>::from_request_parts(&mut parts, &()).await;
//         assert!(result.is_ok());
//     }

//     #[tokio::test]
//     async fn test_extractor_with_middleware() {
//         use axum::http::header::COOKIE;
//         use tower_sessions::{MemoryStore, SessionManagerLayer};
//         use std::sync::Arc;
//         // use time::{Duration, OffsetDateTime};

//         use crate::authn::{middleware::AuthnService, session::SessionRegistryStore};
//         use crate::utils::testing::mock_backend::MockBackend;
//         use crate::utils::testing::mock_authn::create_initialized_session;

//         init_tracing();

//         info!("Testing extractor with middleware");

//         let backend = Arc::new(MockBackend::default());
//         let store = MemoryStore::default();
//         let registry = Arc::new(SessionRegistryStore::new(store.clone(), 0, None, None));
//         let session_manager_layer = SessionManagerLayer::new(store.clone());
//         let auth_layer = AuthnService::new(
//             backend.clone(),
//             "test.data",
//             session_manager_layer,
//             Some(registry.clone()),
//         );

//         let app = axum::Router::new()
//             .route("/protected", axum::routing::get(protected))
//             .layer(auth_layer);

//         // Use the helper to create a valid session
//         let session = create_initialized_session(store.clone()).await;
//         // build cookie header from the session id expected by the session manager
//         let cookie = format!(
//             "test.data={}",
//             session.id().expect("initialized session must have an id")
//         );

//         let req = axum::http::Request::builder()
//             .uri("/protected")
//             .header(COOKIE, cookie)
//             .body(axum::body::Body::empty())
//             .unwrap();

//         let res = app.oneshot(req).await.unwrap();
//         assert_eq!(res.status(), 200);
//     }
// }
