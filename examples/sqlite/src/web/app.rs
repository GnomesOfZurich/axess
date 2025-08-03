use axum_messages::MessagesManagerLayer;
use sqlx::SqlitePool;
use time::Duration;
use tokio::{signal, task::AbortHandle};
use tower_sessions::cookie::Key;
use tower_sessions::{ExpiredDeletion, Expiry, SessionManagerLayer};
use tower_sessions_sqlx_store::SqliteStore;

use crate::{
    models::backend::OurBackend,
    web::{auth, protected},
};
use axess::{
    AuthnLayerBuilder,
    // SessionRegistry,
    login_required,
};

pub type AuthSession = axess::AuthSession<OurBackend>;

// #[derive(Clone)]
// pub struct AppState {
//     pub db: SqlitePool,
// }

pub struct App {
    db: SqlitePool,
}

impl App {
    pub async fn new(db_url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let db = SqlitePool::connect(db_url).await?;
        sqlx::migrate!().run(&db).await?;

        Ok(Self { db })
    }

    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error>> {
        // Session layer.
        //
        // This uses `tower-sessions` to establish a layer that will provide the session
        // as a request extension.
        let session_store = SqliteStore::new(self.db.clone());
        session_store.migrate().await?;

        let deletion_task = tokio::task::spawn(
            session_store
                .clone()
                .continuously_delete_expired(tokio::time::Duration::from_secs(60)),
        );

        // Generate a cryptographic key to sign the session cookie.
        let key = Key::generate();

        let session_layer = SessionManagerLayer::new(session_store)
            .with_secure(false)
            .with_expiry(Expiry::OnInactivity(Duration::days(1)))
            .with_signed(key);

        // Auth service.
        //
        // This combines the session layer with our backend to establish the auth
        // service which will provide the auth session as a request extension.
        let backend = OurBackend::new(self.db.clone());
        // let session_registry = SessionRegistry::new();  // TODO: Is Registry still needed here ???
        let auth_layer = AuthnLayerBuilder::new(backend, session_layer).build();
        // let state = AppState {
        //     db: self.db.clone(),
        // };

        let protected_router =
            protected::router().route_layer(login_required!(OurBackend, login_url = "/login"));

        let auth_router = auth::router().with_state(OurBackend::new(self.db.clone()));

        let app = protected_router
            .merge(auth_router)
            .layer(MessagesManagerLayer)
            .layer(auth_layer);

        let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

        // Ensure we use a shutdown signal to abort the deletion task.
        axum::serve(listener, app.into_make_service())
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
