# Axess Example: SQLite Backend

This example demonstrates how to use the [Axess](https://github.com/GnomesOfZurich/axess) authentication and authorization library with an Axum web application backed by SQLite for session and credential storage.

## Features

- **Session-based authentication** using Axess custom `SessionLayer` with HMAC-signed cookies
- **Multi-factor authentication**: password + TOTP (Time-based One-Time Password)
- **Tenant and user management**
- **Account signup, login, logout, and factor setup flows**
- **Protected routes requiring authentication**
- **Axum integration with Askama templates**
- **Persistent session storage via `SqliteSessionStore`**

## Current API (v0.0.14)

The example code below reflects the target API after the planned update:

```rust
use axess::{
    AuthSession, AuthnService, SessionLayer, MemorySessionStore,
    LoginOutcome, PrepareOutcome, FactorOutcome, FactorCredential,
    login_required,
};
use axum::{Router, routing::{get, post}};
use std::sync::Arc;

// 1. Create session layer with HMAC signing key.
let store = MemorySessionStore::new(); // or SqliteSessionStore
let signing_key: [u8; 32] = /* load from secrets */;
let session_layer = SessionLayer::new(store, signing_key)
    .with_ttl(std::time::Duration::from_secs(24 * 60 * 60))
    .with_secure(false); // set true in production

// 2. Create the authentication service.
let authn = Arc::new(AuthnService::new(my_identity_store, my_factor_store));

// 3. Build the router.
let app = Router::new()
    .route("/dashboard", get(dashboard_handler))
    .layer(login_required!("/login"))
    .route("/login", post(login_handler))
    .layer(session_layer);
```

### Login handler pattern

```rust
async fn login_handler(
    session: AuthSession,
    State(authn): State<Arc<AuthnService<MyStore, MyStore>>>,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    // Step 1: Identify the user.
    let outcome = authn.begin_login(&form.email, &form.tenant, &session).await?;

    match outcome {
        LoginOutcome::FactorRequired(kind) => {
            // Step 2: Prepare the factor (generates OTP for EmailOtp, no-op for Password).
            let prep = authn.prepare_factor(&session).await?;
            if let PrepareOutcome::SendOtp { code, destination } = prep {
                email_service.send_otp(&destination, &code).await?;
            }
            // Render factor input form...
        }
        LoginOutcome::InvalidCredentials => { /* show error */ }
        LoginOutcome::Locked { until } => { /* show lockout message */ }
    }
}
```

## Running the Example

1. **Clone the repository and enter the workspace:**

    ```sh
    git clone https://github.com/GnomesOfZurich/axess.git
    cd ./axess/examples/sqlite
    cargo build
    ```

2. **Set up your environment:**

    - Ensure you have a recent Rust toolchain (`rustup update`)
    - Create a `.env` file with your database URL (optional, defaults to in-memory):

      ```
      DATABASE_URL=sqlite://db/axess-example.db
      ```

3. **Run the application:**

    ```sh
    cargo run -p axess-example-sqlite
    ```

    The app will listen on `127.0.0.1:3000` by default.

## Project Structure

- `src/web/` — Axum routes, templates, and handlers
- `src/models/` — Backend implementation (`IdentityStore` + `FactorStore`), entities, and database logic
- `templates/` — Askama HTML templates for login, signup, protected pages, factor setup
- `migrations/` — SQLx migration scripts for SQLite schema
- `.env` — Optional environment configuration

## Key Flows

- **Signup:** Create a new user and tenant, stage password and TOTP factors
- **Login:** `begin_login` → `prepare_factor` → `verify_factor` (password, then TOTP if enabled)
- **TOTP Setup:** Provision TOTP secret and URI for authenticator apps
- **Protected Route:** `/main` requires authentication via `login_required!()` macro

## License

MIT

## Links

- [Axess Project](https://github.com/GnomesOfZurich/axess)
- [Axum](https://github.com/tokio-rs/axum)
