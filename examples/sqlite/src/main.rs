//! Run with
//!
//! ```not_rust
//! cargo run -p example-sqlite
//! ```
//!
use std::error::Error;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use crate::web::App;

pub mod models;
mod web;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv::dotenv().ok(); // Loads .env file if present
    let db_url: &str = &std::env::var("DATABASE_URL")?;
    tracing_subscriber::registry()
        .with(EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(
            |_| "axess=debug,tower_sessions=debug,sqlx=warn,tower_http=debug".into(),
        )))
        .with(tracing_subscriber::fmt::layer())
        .try_init()?;

    App::new().await?.serve("0.0.0.0:3000", db_url).await
}
