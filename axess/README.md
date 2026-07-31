# axess

[![CI](https://github.com/GnomesOfZurich/axess/actions/workflows/ci.yml/badge.svg)](https://github.com/GnomesOfZurich/axess/actions/workflows/ci.yml)
[![Version](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/version.svg)](https://crates.io/crates/axess)
[![Status](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/status.svg)](https://github.com/GnomesOfZurich/axess)
[![License](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/license.svg)](https://github.com/GnomesOfZurich/axess#licence)

[crates.io](https://crates.io/crates/axess) · [docs.rs](https://docs.rs/axess) · [Book](https://gnomesofzurich.github.io/axess/) · [GitHub](https://github.com/GnomesOfZurich/axess)

Public API facade for the [Axess](https://github.com/GnomesOfZurich/axess) authentication and authorization library for [Axum](https://github.com/tokio-rs/axum).

This is the crate most applications should depend on. It re-exports the curated public surface from `axess-core`, `axess-factors`, `axess-identity`, and `axess-macros` through a single import path and decides the canonical module layout (`axess::backends::{sqlite, postgres, mysql, valkey, memory}`, `axess::session::*`, `axess::middleware::*`, etc.).

## What you get

- Multi-factor authentication (password, TOTP, HOTP, email OTP, FIDO2, OAuth/OIDC, LDAP bind)
- Cedar Policy authorization (RBAC, ABAC, ReBAC)
- Session management with HMAC-signed cookies and optional AES-256-GCM encryption at rest
- Session binding, concurrent-session limits, forced logout via registry
- Workload identity (SPIFFE, K8s SA, GitHub Actions OIDC); unified `Principal` with humans
- Token-bucket rate limiting per IP / user / tenant / header
- Metrics hooks (`AuthnMetrics`) and health checks (`HealthCheck`, `CompositeHealthCheck`)
- Deterministic simulation testing throughout (injectable RNG, clock, mock stores)

## Quick start

```toml
[dependencies]
axess = { version = "0.2.2", features = ["sqlite", "authz"] }
```

```rust,no_run
use axess::{AuthnService, InMemoryBackend, SessionLayer};
use axess::backends::sqlite::SessionStore as SqliteSessionStore;
use axum::{Router, routing::get};
use sqlx::SqlitePool;
use std::{sync::Arc, time::Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = SqlitePool::connect("sqlite:app.db").await?;
    let session_store = SqliteSessionStore::plaintext(pool.clone());
    session_store.init_schema().await?;

    let backend = InMemoryBackend::new()
        .with_user_password("alice", "default", "Gnomes2+");
    let _service = Arc::new(AuthnService::new(backend.clone(), backend));

    let signing_key: [u8; 32] = [/* load from your secret store */ 0; 32];
    let session_layer = SessionLayer::new(session_store, signing_key)
        .with_ttl(Duration::from_secs(86400));

    let app = Router::new()
        .route("/", get(|| async { "hello" }))
        .layer(session_layer);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

See [`examples/sqlite`](https://github.com/GnomesOfZurich/axess/tree/main/examples/sqlite) for a complete working application (login, signup, TOTP enrollment, route guards, rate limiting, health probes). For OAuth/OIDC, FAPI, FIDO2, and Cedar examples, see the sibling directories under [`examples/`](https://github.com/GnomesOfZurich/axess/tree/main/examples).

## Feature flags

Default features `["authz", "device"]` cover the most common build. Storage backends, federated authn protocols, and workload-identity resolvers are opt-in. See the [workspace README](https://github.com/GnomesOfZurich/axess#feature-flags) for the full table.

## Related crates

| Crate | Purpose |
|---|---|
| [axess-core](https://crates.io/crates/axess-core) | Orchestrator: session/authn/authz flow, device identity, workload hub, delegated/OBO, storage, middleware |
| [axess-factors](https://crates.io/crates/axess-factors) | Verifier and protocol primitives: password/TOTP/HOTP, FIDO2, LDAP, OAuth/OIDC/JWT, mTLS, bearer |
| [axess-identity](https://crates.io/crates/axess-identity) | Typed identifiers and the `Principal { Human, Workload }` model |
| [axess-macros](https://crates.io/crates/axess-macros) | `require_authn!`, `require_partial_authn!`, `require_authz!` |
| [axess-clock](https://crates.io/crates/axess-clock) | `Clock` / `MockClock`, the time seam for deterministic simulation testing |
| [axess-rng](https://crates.io/crates/axess-rng) | `SecureRng` / `MockRng`, the entropy seam for deterministic simulation testing |
| [axess-cache](https://crates.io/crates/axess-cache) | TTL + LRU cache with single-flight, DST-friendly |
| [axess-events](https://crates.io/crates/axess-events) | rkyv-serialisable audit-event payloads |
| [axess-strings](https://crates.io/crates/axess-strings) | `Arc<str>` interning |

## Licence

Dual-licensed under [MIT](https://github.com/GnomesOfZurich/axess/blob/main/LICENSE-MIT)
and [Apache-2.0](https://github.com/GnomesOfZurich/axess/blob/main/LICENSE-APACHE).

## Security

See [SECURITY.md](https://github.com/GnomesOfZurich/axess/blob/main/SECURITY.md) for the production integration checklist and the private vulnerability-reporting channel.
