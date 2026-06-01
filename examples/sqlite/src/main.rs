//! # axess-example-sqlite
//!
//! Reference example showing how to use the axess library with a SQLite backend.
//!
//! ## Running
//!
//! ```sh
//! cargo run -p axess-example-sqlite
//! ```
//!
//! The server starts on <http://127.0.0.1:3000>.
//!
//! ## Test credentials
//!
//! ### Password-only login
//!
//! | Username  | Tenant  | Password     |
//! |-----------|---------|--------------|
//! | alice     | default | Gnomes2+      |
//!
//! ### Password + TOTP login
//!
//! | Username  | Tenant  | Password     |
//! |-----------|---------|--------------|
//! | bob       | default | Gnomes2+      |
//!
//! Bob's TOTP secret is printed in the server log at startup (search for "TOTP secret").
//! Use any TOTP app (Aegis, Authy, Google Authenticator) to scan it.
//!
//! ### Self-service signup + TOTP enrollment
//!
//! 1. Visit <http://127.0.0.1:3000/signup> to create a new account.
//! 2. After signup, click "Enroll TOTP" on the dashboard.
//! 3. Scan the secret with your TOTP app, enter the 6-digit code to verify.
//! 4. Future logins will require password + TOTP.
//!
//! ## Database
//!
//! SQLite file: `db/axess-example.db` relative to the current working directory.
//! Migrations run automatically at startup. The DB is seeded with test users on
//! first run (idempotent; subsequent runs skip existing rows).
//!
//! ## Session signing key
//!
//! This example generates a random key on every restart (existing sessions
//! become invalid). **In production, load a persistent random key from a
//! secret store and keep it stable across restarts.**

use axess::SystemClock;
use axess_example_sqlite::{models, web};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::{error::Error, str::FromStr};
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::registry()
        .with(EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(
            |_| "axess_example_sqlite=debug,axess=debug,sqlx=warn".into(),
        )))
        .with(tracing_subscriber::fmt::layer())
        .try_init()?;

    info!("Starting axess-example-sqlite");

    // Resolve the DB path relative to the working directory.
    let db_dir = std::env::current_dir()?.join("db");
    std::fs::create_dir_all(&db_dir)?;
    let db_path = db_dir.join("axess-example.db");

    info!("Database path: {}", db_path.display());

    let connect_options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.display()))?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(connect_options)
        .await?;

    // Run all migrations from the `migrations/` directory.
    sqlx::migrate!().run(&pool).await?;
    info!("Migrations applied");

    // Seed test data (idempotent).
    let totp_secret = models::backend::seed(&SystemClock, &pool).await?;
    info!(
        totp_secret = %totp_secret,
        "Test data seeded. Bob's TOTP secret is shown above; scan it with your TOTP app."
    );

    let (router, session_store) = web::app::build_router(pool).await;

    // Background task: purge expired sessions from SQLite every hour.
    // In production, adjust the interval based on session TTL and traffic volume.
    tokio::spawn({
        let store = session_store.clone();
        async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            interval.tick().await; // first tick completes immediately; skip it
            loop {
                interval.tick().await;
                match store.cleanup_expired().await {
                    Ok(n) => tracing::info!(deleted = n, "Session cleanup completed"),
                    Err(e) => tracing::warn!(error = %e, "Session cleanup failed"),
                }
            }
        }
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    info!("Listening on http://127.0.0.1:3000");
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}
