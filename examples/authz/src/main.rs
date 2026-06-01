//! # axess-example-authz
//!
//! Standalone Cedar Policy authorization example; no database, no sessions,
//! no authentication. Demonstrates RBAC, ReBAC (ownership), and ABAC (MFA)
//! patterns using the Axess authorization layer.
//!
//! ## Running
//!
//! ```sh
//! cargo run -p axess-example-authz
//! ```
//!
//! ## Test users
//!
//! | User  | Role   | Notes |
//! |-------|--------|-------|
//! | alice | admin  | Can do everything |
//! | bob   | viewer | Can only view documents |
//! | carol | editor | Can view + edit; also owns doc-1 |
//!
//! ## Test documents
//!
//! | Document | Owner | Title |
//! |----------|-------|-------|
//! | doc-1    | carol | Q4 Financial Report |
//! | doc-2    | alice | Board Minutes |
//! | doc-3    | bob   | Public Handbook |
//!
//! ## Example requests
//!
//! ```sh
//! # Bob can view any document (viewer role):
//! curl http://localhost:3000/users/bob/documents/doc-1
//!
//! # Bob cannot edit (viewer role):
//! curl -X POST http://localhost:3000/users/bob/documents/doc-1/edit
//! # → 403
//!
//! # Carol can edit doc-1 (she owns it):
//! curl -X POST http://localhost:3000/users/carol/documents/doc-1/edit
//!
//! # Carol cannot edit doc-2 (not owner, editor role doesn't apply here...
//! # wait; editor CAN edit any doc):
//! curl -X POST http://localhost:3000/users/carol/documents/doc-2/edit
//!
//! # Alice can delete, but only with MFA:
//! curl -X DELETE "http://localhost:3000/users/alice/documents/doc-1?mfa=false"
//! # → 403 (MFA required)
//!
//! curl -X DELETE "http://localhost:3000/users/alice/documents/doc-1?mfa=true"
//! # → 200
//!
//! # Check what bob can do with doc-3:
//! curl http://localhost:3000/users/bob/documents/doc-3/permissions
//!
//! # Check bob's capabilities across all documents:
//! curl http://localhost:3000/users/bob/capabilities
//! ```

pub mod handlers;
pub mod provider;

use axess::authorization::{AuthzStore, PolicyStore};
use axum::{
    Router,
    routing::{delete, get, post},
};
use provider::{AppData, DocEntityProvider};
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Application state shared across all handlers.
#[derive(Clone)]
pub struct AppState {
    pub authz: Arc<AuthzStore<DocEntityProvider>>,
    pub data: AppData,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(
            |_| "axess_example_authz=debug,axess=debug".into(),
        )))
        .with(tracing_subscriber::fmt::layer())
        .try_init()?;

    info!("Starting axess-example-authz");

    // 1. Load Cedar policies and schema.
    let policy_store = Arc::new(PolicyStore::from_text(
        include_str!("../policies/app.cedar"),
        include_str!("../policies/app.cedarschema.json"),
    )?);
    info!("Cedar policies loaded and validated");

    // 2. Seed in-memory data.
    let data = AppData::seed();

    // 3. Build the AuthzStore with our entity provider.
    let namespace = "DocApp";
    let provider = Arc::new(DocEntityProvider::new(data.clone(), namespace));
    let authz = Arc::new(AuthzStore::new(policy_store, provider, namespace));

    // 4. Optional: validate provider ↔ schema consistency at startup.
    authz.validate()?;
    info!("Entity provider validated against Cedar schema");

    let state = AppState { authz, data };

    // 5. Build the router.
    let app = Router::new()
        .route("/", get(handlers::index))
        .route(
            "/users/{user_id}/documents/{doc_id}",
            get(handlers::view_document),
        )
        .route(
            "/users/{user_id}/documents/{doc_id}/edit",
            post(handlers::edit_document),
        )
        .route(
            "/users/{user_id}/documents/{doc_id}",
            delete(handlers::delete_document),
        )
        .route(
            "/users/{user_id}/documents/{doc_id}/permissions",
            get(handlers::document_permissions),
        )
        .route(
            "/users/{user_id}/capabilities",
            get(handlers::user_capabilities),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    info!("Listening on http://127.0.0.1:3000");
    info!("Try: curl http://localhost:3000/users/bob/documents/doc-1");
    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}
