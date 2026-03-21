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
//! | alice     | default | hunter2      |
//!
//! ### Password + TOTP login
//!
//! | Username  | Tenant  | Password     |
//! |-----------|---------|--------------|
//! | bob       | default | hunter2      |
//!
//! Bob's TOTP secret is printed in the server log at startup (search for "TOTP secret").
//! Use any TOTP app (Aegis, Authy, Google Authenticator) to scan it.
//!
//! ## Database
//!
//! SQLite file: `db/axess-example.db` relative to the current working directory.
//! Migrations run automatically at startup. The DB is seeded with test users on
//! first run (idempotent — subsequent runs skip existing rows).
//!
//! ## Session signing key
//!
//! For simplicity this example uses a fixed all-zero 32-byte signing key.
//! **In production, load a random key from a secret store and persist it across restarts.**

pub mod models;
pub mod web;

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
    let totp_secret = models::backend::seed(&pool).await?;
    info!(
        totp_secret = %totp_secret,
        "Test data seeded. Bob's TOTP secret is shown above — scan it with your TOTP app."
    );

    let router: axum::Router = web::app::build_router(pool).await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    info!("Listening on http://127.0.0.1:3000");
    axum::serve(listener, router.into_make_service()).await?;

    Ok(())
}
