use std::sync::Arc;

use axum::Router;
use axum_messages::MessagesManagerLayer;
use sqlx::{SqlitePool, migrate};
use time::Duration;
use tokio::{signal, task::AbortHandle};
use tower_sessions::{ExpiredDeletion, Expiry, SessionManagerLayer, cookie::Key};
use tower_sessions_sqlx_store::SqliteStore;

use crate::{
    models::backend::OurBackend,
    web::{auth::router as auth_router, protected::router as protected_router},
};
use axess::{AuthnServiceBuilder, SessionRegistryStore};

// #[derive(Clone)]
// pub struct AppState {
//     pub db: SqlitePool,
// }

pub struct App {
    // db: SqlitePool,
    // pub backend: std::sync::Arc<OurBackend>,
    // pub session_store: Arc<SqliteStore>,
    // pub registry: Arc<StoreSessionRegistry>
}

impl App {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {})
    }

    pub async fn serve(
        self,
        address: &str,
        db_url: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let db = SqlitePool::connect(db_url).await?;
        // Run migrations from the "migrations" directory at runtime.
        // static MIGRATOR: Migrator = sqlx::migrate!("./migrations");
        // MIGRATOR.run(&db).await?;
        migrate!().run(&db).await?;

        // let session_store = MemoryStore::default();
        let session_store = SqliteStore::new(db.clone());
        session_store.migrate().await?;

        let deletion_task = tokio::task::spawn(
            session_store
                .clone()
                .continuously_delete_expired(tokio::time::Duration::from_secs(60)),
        );

        // Generate a cryptographic key to sign the session cookie.
        let key = Key::generate();

        let session_layer = SessionManagerLayer::new(session_store.clone())
            .with_secure(false)
            .with_expiry(Expiry::OnInactivity(Duration::days(1)))
            .with_signed(key);

        /*
        Authn service.
        This combines the session layer with our backend and session registry to establish an
        authentication service layer which will provide the auth session as a request extension.
        */
        let session_registry = Arc::new(SessionRegistryStore::new(session_store, 100, None, None));
        let backend = Arc::new(OurBackend::new(db));
        let authn_service = Arc::new(
            AuthnServiceBuilder::new(backend, session_layer)
                .with_session_registry(session_registry.clone())
                .build(),
        );

        /*
        Ensure all merged routers share the same application state (Arc<OurBackend>).
        This avoids mismatched Router<State> types when merging by setting the top-level
        router state to the backend before merging other routers that expect the same state.
        */
        let app_router = Router::new()
            // .with_state(backend.clone())
            // Apply login_required to protected routes before merging
            .merge(protected_router())
            // Auth routes need backend state for handlers that use State extractor
            .merge(auth_router())
            .route("/health", axum::routing::get(|| async { "OK" }))
            .layer(MessagesManagerLayer)
            .layer(authn_service.as_ref().clone());
        // .with_state(()); // Convert to Router<()> for compatibility

        // Propagate bind errors instead of panicking.
        let listener = tokio::net::TcpListener::bind(address).await?;

        // Ensure we use a shutdown signal to abort the deletion task.
        axum::serve(listener, app_router.into_make_service())
            .with_graceful_shutdown(shutdown_signal(deletion_task.abort_handle()))
            .await?;

        deletion_task.await??;

        Ok(())
    }
}

async fn shutdown_signal(deletion_task_abort_handle: AbortHandle) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => { deletion_task_abort_handle.abort() },
        _ = terminate => { deletion_task_abort_handle.abort() },
    }
}
