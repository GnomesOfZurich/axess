//! Router construction: SessionLayer + AuthnService in Axum state + routes.

use crate::{
    models::backend::OurBackend,
    web::{auth, protected},
};
use axess::{AuthnService, SessionLayer, SqliteSessionStore};
use axum::{Router, routing::get, routing::post};
use sqlx::SqlitePool;
use std::{sync::Arc, time::Duration};

/// Application state shared across all handlers.
#[derive(Clone)]
pub struct AppState {
    pub service: Arc<AuthnService<OurBackend, OurBackend>>,
}

/// Build the top-level Axum [`Router`].
///
/// Call once at startup, after migrations have run.
pub async fn build_router(pool: SqlitePool) -> Router {
    let backend = OurBackend::new(pool.clone());

    // SQLite-backed session store — creates the `sessions` table if absent.
    let session_store = SqliteSessionStore::new(pool.clone());
    session_store
        .init_schema()
        .await
        .expect("failed to create sessions table");

    // IMPORTANT: Use a real random key loaded from config in production.
    // This fixed zero key means sessions are valid across restarts but is NOT
    // secure against an attacker who can read the binary or its memory.
    let signing_key: [u8; 32] = [0u8; 32];

    let session_layer = SessionLayer::new(session_store, signing_key)
        .with_ttl(Duration::from_secs(86400))
        .with_secure(false); // Allow HTTP in local dev; set true behind TLS in prod.

    let service = Arc::new(AuthnService::new(backend.clone(), backend));
    let state = AppState { service };

    Router::new()
        .route("/login", get(auth::login_page).post(auth::post_login))
        .route("/totp", get(auth::totp_page).post(auth::post_totp))
        .route("/logout", post(auth::logout))
        .route("/dashboard", get(protected::dashboard))
        .route("/health", get(|| async { "OK" }))
        .with_state(state)
        .layer(session_layer)
}
