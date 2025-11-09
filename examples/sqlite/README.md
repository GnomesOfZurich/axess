# Axess Example: SQLite Backend

This example demonstrates how to use the [Axess](https://github.com/GnomesOfZurich/axess) authentication and authorization library with an Axum web application backed by SQLite for session and credential storage.

## Features

- **Session-based authentication** using Axess middleware
- **Multi-factor authentication**: password + TOTP (Time-based One-Time Password)
- **Tenant and user management**
- **Account signup, login, logout, and factor setup flows**
- **Protected routes requiring authentication**
- **Axum integration with Askama templates**
- **Persistent session storage via [tower-sessions-sqlx-store](https://crates.io/crates/tower-sessions-sqlx-store)**

## Running the Example

1. **Clone the repository and enter the workspace:**

    ```sh
    git clone https://github.com/GnomesOfZurich/axess.git
    cd axess/examples/sqlite
    ```

2. **Set up your environment:**

    - Ensure you have a recent Rust toolchain (`rustup update`)
    - Create a `.env` file with your database URL (optional, defaults to in-memory):

      ```
      DATABASE_URL=sqlite://axess-example.db
      ```

3. **Run database migrations:**

    ```sh
    cargo run -p axess-example-sqlite --bin migrate
    ```

    *(Or let the app run migrations at startup)*

4. **Start the web server:**

    ```sh
    cargo run -p axess-example-sqlite
    ```

    The app will listen on `0.0.0.0:3000` by default.

5. **Open in your browser:**

    ```
    http://localhost:3000/login
    ```

## Project Structure

- `src/web/` — Axum routes, templates, and handlers
- `src/models/` — Backend implementation, entities, and database logic
- `templates/` — Askama HTML templates for login, signup, protected pages, factor setup
- `migrations/` — SQLx migration scripts for SQLite schema
- `.env` — Optional environment configuration

## Key Flows

- **Signup:** Create a new user and tenant, stage password and TOTP factors
- **Login:** Authenticate with password, then verify TOTP if enabled
- **TOTP Setup:** Provision TOTP secret and URI for authenticator apps
- **Protected Route:** `/main` requires authentication via Axess middleware

## Example Code Snippet

```rust
use axess::{AuthnServiceBuilder, SessionRegistryStore, SystemRng, login_required};
use axum::{Router, routing::get};
use tower_sessions_sqlx_store::SqliteStore;
use sqlx::SqlitePool;
use std::sync::Arc;

type Session = axess::AuthSession<OurBackend, SessionRegistryStore<SqliteStore>, SystemRng>;

let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
let backend = Arc::new(OurBackend::new(pool.clone()));
let session_store = SqliteStore::new(pool.clone());
let session_registry = Arc::new(SessionRegistryStore::new(session_store.clone(), 100));

let auth_layer = AuthnServiceBuilder::new(backend.clone(), session_layer)
    .with_session_registry(session_registry.clone())
    .build();

let app = Router::new()
    .merge(auth_router())
    .merge(protected_router())
    .layer(auth_layer);
```

## License

MIT

## Links

- [Axess Project](https://github.com/GnomesOfZurich/axess)
- [API Docs](https://docs.rs/axess)
- [Axum](https://github.com/tokio-rs/axum)