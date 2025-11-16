# Axess

**Axess** is an authentication and authorization library for the [Axum](https://github.com/tokio-rs/axum) web framework in Rust. It provides robust, modular middleware and extractors for secure, session-based, policy-driven access control of web services.

## 🔆 Features

- **Authentication Middleware:** Session-based authentication with pluggable backends.
- **Authorization via Cedar Policy:** Flexible, fine-grained ABAC, RBAC, and ReBAC support.
- **Multi-factor Authentication:** Built-in support for password, TOTP, HOTP, and OAuth factors.
- **Session Management:** Pluggable registry and storage (in-memory, Valkey/Redis).
- **Request Tracing & ID Generation:** Built-in request ID and trace ID middleware.
- **Extensible Storage:** Abstract interfaces for authentication policies, sessions, and user data.
- **Idiomatic Rust:** Async-first APIs, strong type safety, and DST-friendly testing.
- **Procedural Macros:** Ergonomic Axum middleware macros for authentication and partial authentication.

## 📦 Installation

Add to your project:

```toml
[dependencies]
axess = { version = "0.0.9", features = ["full"] }
```

Or select features as needed:

```toml
[dependencies]
axess = { version = "0.0.9", features = ["authn", "authz", "admin", "request_id", "trace_id", "memory", "valkey"] }
```

## 🤸 Example Usage

Create a minimal Axum web application and initiate Axess layers from your backend and session store:

```rust
use axess::{AuthnServiceBuilder, AuthSession, SessionRegistryStore, SystemRng, login_required};
use axum::{Router, routing::get};
use tower_sessions_sqlx_store::SqliteStore;
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::net::TcpListener;
use crate::{
    handlers::{protected_handler, login_handler, logout_handler, hello_world, // Your route handlers
    models::OurBackend, // Your custom backend implementation, handling interactions with the database
};

type Session = AuthSession<OurBackend, SessionRegistryStore<SqliteStore>, SystemRng>;

// Create backend and session store
let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
let backend = Arc::new(OurBackend::new(pool.clone()));
let session_store = SqliteStore::new(pool.clone());
let session_registry = Arc::new(SessionRegistryStore::new(session_store.clone(), 100, None, None));

// Build the authentication layer
let auth_layer = AuthnServiceBuilder::new(backend.clone(), session_registry.clone()).build();

// Definition of protected routes
let protected_router = Router::new()
    .route("/main", get(protected_handler))
    .route_layer(login_required!(Arc<Session>, "/login"));

// Defintion of some other routes
let public_router = Router::new()
    .route("/", get(hello_world))
    .route("/login", get(login_handler))
    .route("/logout", get(logout_handler));

// Assemble the router
let app = Router::new()
    .merge(protected_router)
    .merge(public_router)
    .layer(auth_layer);

// Start serving the application.
let address = "127.0.0.1:3000".parse()?;
let listener = TcpListener::bind(address).await?;
axum::serve(listener, app.into_make_service()).await?;
```

## 💡 Concepts

- **Authentication Middleware:** Easily authenticate requests using sessions and pluggable backends.
- **Authorization via Cedar Policy:** Integrates with [Cedar](https://cedarpolicy.com/) for flexible, fine-grained authorization policies.
- **Request Tracing & ID Generation:** Built-in support for request IDs and tracing.
- **Extensible Storage:** Abstract storage interfaces for authentication policies, sessions, and user data.
- **Deterministic Simulation Testing (DST):** Designed for testability and reproducibility.

## ☑️ Features

- `authn`: Enable **Authentication** layer and related extractors.
- `authz`: Enable **Authorization** layer via Cedar Policy.
- `admin`: Enable additional capabilities for managing users, tenants, and authentication parameters.
- `request_id`: Add **Request ID** to headers.
- `trace_id`: Add **Tracing ID** and tracing helpers.
- `memory`: Enable **in-memory** session and storage backends.
- `valkey`: Enable **Valkey** (Redis-compatible) session and storage backends.

## 📚 Documentation

- [API Docs](https://docs.rs/axess)
- [Examples](examples/)
- [Cedar Policy Language](https://cedarpolicy.com/)

## 🔗 Related Crates

- [axess-core](../axess-core)
- [axess-factors](../axess-factors)
- [axess-macros](../axess-macros)

## 📃 License

Licensed under the MIT License.

---

*Axess: Secure, policy-driven authentication and authorization for Axum.*