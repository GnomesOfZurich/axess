# axess-core

`axess-core` is the foundation of the [Axess](https://github.com/GnomesOfZurich/axess) authentication and authorization library for the Axum web framework. It provides the core types, traits, middleware, and utilities for building secure, policy-driven, session-based authentication and authorization flows.

## Features

- **Authentication Primitives:** Strongly-typed factor and method definitions, state transitions, and ergonomic builders for password, TOTP, HOTP, and OAuth.
- **Authorization via Cedar Policy:** Integrates with [Cedar](https://cedarpolicy.com/) for ABAC, RBAC, and ReBAC models.
- **Session Management:** Pluggable session registry and in-memory or Valkey (Redis-compatible) stores.
- **Middleware:** Axum-compatible layers for authentication, authorization, request tracing, and request ID injection.
- **Extensible Storage:** Async traits for custom backends, plus a reference in-memory mock backend for testing.
- **Utilities:** Input validation, secure random number generation, time helpers, and deterministic simulation testing (DST) support.
- **Comprehensive Error Handling:** Uses `thiserror` for ergonomic error types across forms, sessions, and backends.

## Installation

Add to your workspace or project:

```toml
[dependencies]
axess-core = "0.0.9"
```

Enable features as needed:

```toml
[dependencies]
axess-core = { version = "0.0.9", features = ["authn", "authz", "admin", "request_id", "trace_id", "memory", "valkey"] }
```

## Usage

See [Axess README](../README.md) for high-level usage. Example:

```rust
use axess_core::{
    authn::{
        backend::{AuthnBackend, AuthTenant, AuthUser},
        methods::{FactorConfigBuilder, MethodBuilder},
        session::{AuthSession, SessionRegistryStore},
        middleware::AuthnServiceBuilder,
    },
    utils::random::SystemRng,
};

let backend = Arc::new(MyBackend::new());
let session_store = MySessionStore::new();
let session_registry = Arc::new(SessionRegistryStore::new(session_store, 100, None, None));

let auth_layer = AuthnServiceBuilder::new(backend.clone(), session_layer)
    .with_session_registry(session_registry.clone())
    .build();
```

## Modules

- `authn/` — Authentication primitives, forms, factor/method builders, session flows, and middleware.
- `authz/` — Cedar Policy-based authorization logic.
- `storage/` — Pluggable storage interfaces (in-memory, Valkey).
- `utils/` — Validation, random, time, and testing helpers.
- `extras/` — Request ID and trace ID middleware.

## Documentation

- [API Docs](https://docs.rs/axess-core)
- [Examples](../../examples/)
- [Cedar Policy Language](https://cedarpolicy.com/)

## 📃 License

Licensed under [MIT License](../LICENSE).

## 🛡️ Security

See [SECURITY.md](../SECURITY.md) for vulnerability reporting and security recommendations.

## Links

- [Axess Project](https://github.com/GnomesOfZurich/axess)
- [Axess-factors](../axess-factors)
- [Axess-macros](../axess-macros)

---

*Axess: Secure, policy-driven authentication and authorization for Axum.*