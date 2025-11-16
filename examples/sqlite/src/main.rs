//! Run with
//!
//! ```not_rust
//! cargo run -p axess-example-sqlite
//! ```
//!
pub mod models;
pub mod web;

use crate::web::App;

use std::error::Error;
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::registry()
        .with(EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(
            |_| "axess=debug,tower_sessions=debug,sqlx=warn,tower_http=debug".into(),
        )))
        .with(tracing_subscriber::fmt::layer())
        .try_init()?;

    info!("Starting example-sqlite");
    info!("Current working directory: {:?}", std::env::current_dir()?);
    let db_path = std::env::current_dir()?.join("db/axess-example.db");
    let db_url = format!("sqlite://{}", db_path.display());
    info!("DB Path exists: {}", db_path.exists());
    info!("Attempting to setup connection to database {}", db_url);
    App::new().await?.serve("127.0.0.1:3000", &db_url).await
}
