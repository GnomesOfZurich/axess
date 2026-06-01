# axess-core

[![Version](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/version.svg)](https://crates.io/crates/axess-core)
[![Status](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/status.svg)](https://github.com/GnomesOfZurich/axess)
[![License](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/license.svg)](https://github.com/GnomesOfZurich/axess#licence)

[crates.io](https://crates.io/crates/axess-core) · [docs.rs](https://docs.rs/axess-core) · [GitHub](https://github.com/GnomesOfZurich/axess)

Core implementation for the [Axess](https://github.com/GnomesOfZurich/axess authentication and authorization library: session state machine, multi-factor authentication engine, Cedar Policy evaluation, and pluggable storage backends.

**Most applications should depend on the [`axess`](https://crates.io/crates/axess)
facade crate instead.** Use `axess-core` directly only if you're building a custom integration that needs internals the facade doesn't re-export.

## Module layout

| Module | Contents |
|---|---|
| `authn/` | `IdentityStore` / `FactorStore`, `AuthnService`, factor pipeline, OAuth/OIDC, JWT, device identity, audit, federation resolvers |
| `authz/` | Cedar Policy evaluation, `AuthzStore`, `PolicyStore`, entity caches |
| `session/` | `SessionLayer`, `AuthSession`, `SessionStore`, `SessionRegistry`, binding, crypto, refresh tokens, storage backends |
| `middleware/` | `RateLimitLayer`, `RequestIdLayer`, `TraceIdLayer`, CSRF |
| `principal/` | `Principal { Human, Workload }`, `PrincipalResolver`, Cedar entity bridge |
| `store/` | Shared key/value-with-TTL store abstraction (`Store<K, V>`); per-backend value codecs live with each store impl |
| `workload/` | Inbound workload-identity hub, outbound mTLS / OAuth clients |
| `health/`, `metrics/` | `HealthCheck`, `CompositeHealthCheck`, `AuthnMetrics` |
| `testing/` | `MockIdentityStore`, `MockFactorStore`, `MockClock`, `MockRng`, `LocalIdpFixture` (gated by `testing` feature) |

## Usage

```rust,no_run
use axess_core::{AuthnService, SessionLayer, InMemoryBackend};
use axess_core::backends::sqlite::SessionStore as SqliteSessionStore;
use axess_core::session::SessionCrypto;
use std::{sync::Arc, time::Duration};

// SQLite-backed session store with AES-256-GCM at rest.
let key: [u8; 32] = load_key_from_secrets();
let store = SqliteSessionStore::new(pool, SessionCrypto::new(key));
store.init_schema().await?;

let signing_key: [u8; 32] = load_signing_key();
let session_layer = SessionLayer::new(store, signing_key)
    .with_ttl(Duration::from_secs(86400));

let authn = Arc::new(
    AuthnService::new(identity_store, factor_store)
        .with_metrics(my_metrics)
        .with_registry(session_registry),
);
```

See the [workspace README](https://github.com/GnomesOfZurich/axess#readme) for the full integration walkthrough.

## Feature flags

`axess-core` exposes a fine-grained feature set so adopters opt into only what they need. See [`Cargo.toml`](Cargo.toml) for the authoritative list, or the [workspace README feature-flags table](https://github.com/GnomesOfZurich/axess#feature-flags) for the curated set of facade-relevant flags.

## Licence

Dual-licensed under [MIT](https://github.com/GnomesOfZurich/axess/blob/main/LICENSE-MIT) and [Apache-2.0](https://github.com/GnomesOfZurich/axess/blob/main/LICENSE-APACHE).
