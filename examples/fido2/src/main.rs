//! Serve the FIDO2 example on `127.0.0.1:3000`.

use axess_example_fido2::app::{Settings, build_router};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// How often expired sessions are dropped from the in-memory store; nothing
/// else removes them.
const PURGE_EVERY: std::time::Duration = std::time::Duration::from_secs(300);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(
            |_| "axess_example_fido2=debug,axess=info".into(),
        )))
        .with(tracing_subscriber::fmt::layer())
        .try_init()?;

    let settings = Settings::from_env()?;
    let (app, sessions) = build_router(&settings).await?;

    tokio::spawn(async move {
        let mut tick = tokio::time::interval(PURGE_EVERY);
        loop {
            tick.tick().await;
            sessions.purge_expired();
        }
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    tracing::info!(
        "Listening on 127.0.0.1:3000; open {} (the relying party is `{}`, so use that name)",
        settings.origin(),
        settings.rp_id()
    );
    // `with_connect_info` is what puts the peer address where the
    // client-IP layer can read it.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}
