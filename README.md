# Axess

[![CI](https://github.com/GnomesOfZurich/axess/actions/workflows/ci.yml/badge.svg)](https://github.com/GnomesOfZurich/axess/actions/workflows/ci.yml)
![Coverage](.github/badges/coverage.svg)
![Version](.github/badges/version.svg)
![Status](.github/badges/status.svg)
![License](.github/badges/license.svg)

[crates.io](https://crates.io/crates/axess) · [docs.rs](https://docs.rs/axess) · [Book](https://gnomesofzurich.github.io/axess/) · [GitHub](https://github.com/GnomesOfZurich/axess)

**Authentication and authorization for [Axum](https://github.com/tokio-rs/axum).**

Axess is a session-based multi-factor authentication and Cedar Policy authorization library, built around a trait-based design that supports deterministic simulation testing (DST) from the ground up. It exists because the existing landscape (primarily [axum-login](https://github.com/maxcountryman/axum-login)) did not expose enough of its internals to extend with arbitrary factor chains or compose with Cedar / ReBAC without significant custom work.

> **Status:** `v0.3.0` on crates.io. The 0.x line is pre-1.0; the public
> API may evolve between minor versions based on adopter feedback before
> stabilising.

---

## 60-second look

```toml
[dependencies]
axess = { version = "0.3.0", features = ["sqlite", "authz", "testing"] }
axum = "0.8"
sqlx = { version = "0.8", features = ["sqlite", "runtime-tokio"] }
tokio = { version = "1", features = ["full"] }
```

```rust,no_run
use axess::authn::AuthnService;
use axess::backends::sqlite::SessionStore as SqliteSessionStore;
use axess::{InMemoryBackend, SessionLayer};
use axum::{Router, routing::get};
use sqlx::SqlitePool;
use std::{sync::Arc, time::Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = SqlitePool::connect("sqlite:app.db").await?;
    let session_store = SqliteSessionStore::plaintext(pool.clone());
    session_store.init_schema().await?;

    // Replace InMemoryBackend with your DB-backed `IdentityStore` +
    // `FactorStore` impl. See `examples/sqlite/src/models/backend.rs`
    // and `docs/identity/store.md`.
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

A complete application (login pages, factor enrollment, route guards, rate limiting, health probes) lives in [`examples/sqlite/`](examples/sqlite/). For OAuth/OIDC, plain-OAuth social login, FAPI, Cedar authorization, device identity, in-process IdP, and workload-identity recipes, see the sibling directories under [`examples/`](examples/). Axess supports generic OIDC-based external login and SSO, including standard providers such as Google and Microsoft Entra ID when configured with the appropriate issuer metadata and client credentials; SAML / Shibboleth federation is not currently supported out of the box.

---

## Design concepts

Three ideas shape the library. Understanding them makes the rest easier to read.

### Explicit session state machine

Authentication is an enum, `AuthState`, not a boolean. States: `Guest`, `Identifying`, `Authenticating`, `Authenticated`, `PendingWorkflow`. Each transition is validated before mutation; invalid transitions return a typed error. A partially-authenticated session cannot be mistaken for a fully-authenticated one.

`Authenticating` carries the remaining factors, attempt counts, and timestamps as first-class data. Transition logic lives on `AuthState` itself and is unit-testable without `AuthSession`, `SessionData`, async, or `RwLock` scaffolding. `AuthSession` is the lock-holding orchestrator that delegates to the pure mutation and dispatches side effects (id rotation, fingerprint binding) on the outcome.

### Deterministic simulation testing (DST)

Any code that calls `rand::rng()` or `SystemTime::now()` is non-deterministic. For authentication code that matters; session hash generation, OTP windows, lockout timing, and nonce creation all depend on time and randomness.

Axess uses injectable `SecureRng` and `Clock` traits throughout. `SystemRng` and `SystemClock` delegate to the OS in production; `MockRng::new(seed)` produces the same byte sequence for the same seed in tests, and `MockClock` can be advanced to any timestamp. `MockBackend` and `MockRegistry` extend this to the full flow; a complete login including session-registry interactions can be exercised without a database.

### Cedar Policy for authorization

Most authorization in web services is `if user.roles.contains("admin")`, scattered across handlers, with RBAC and ownership checks using different patterns and no schema validation.

[Cedar Policy](https://cedarpolicy.com/) is declarative, has formal semantics, and is deny-by-default. The same policy file expresses RBAC (`principal in Role::"finance-viewer"`), ABAC (`context.ip like "192.168.*"`), and ReBAC (`resource.owner == principal`) in one language. Any evaluation error (malformed UID, attribute missing, type mismatch) produces `Deny`, never `Allow`.

In Axess, `PolicyStore` is loaded once at startup and is `Send + Sync`. Entity sets are built per-request from the backend; the policies live outside the Rust code so they can be reviewed and audited independently.

---

## Workspace layout

10 library crates plus 8 examples. See [`docs/intro/architecture.md`](docs/intro/architecture.md) for the dependency diagram and "what belongs where" rationale.

| Crate | Role |
|---|---|
| `axess` | Facade: re-exports the public API. Depend on this. |
| `axess-core` | Orchestrator: session/authn/authz flow, device identity, workload hub, delegated/OBO, storage, middleware |
| `axess-factors` | Verifier and protocol primitives: password/TOTP/HOTP plus FIDO2, LDAP, OAuth/OIDC/JWT, mTLS, bearer, outbound OAuth |
| `axess-macros` | `require_authn!`, `require_partial_authn!` |
| `axess-identity` | Typed IDs, `Principal { Human, Workload }` |
| `axess-cache` | TTL+LRU cache with single-flight, DST-friendly |
| `axess-clock` | `Clock` / `MockClock` for DST |
| `axess-rng` | `SecureRng` / `MockRng` for DST |
| `axess-events` | rkyv-serialisable audit-event payloads |
| `axess-strings` | `Arc<str>` interning |

## Naming conventions

| Prefix | Layer | Examples |
|--------|-------|----------|
| `Auth*` | Shared (session + authn + authz) | `AuthSession`, `AuthState`, `AuthEvent`, `AuthMethod` |
| `Authn*` | Authentication only | `AuthnService`, `AuthnError`, `AuthnBackend`, `AuthnScope` |
| `Authz*` | Authorization only | `AuthzStore`, `AuthzSession`, `AuthzDecision`, `AuthzError` |

Suffixes: `*Store` (persistence), `*Config` (settings), `*Provider` (external integration), `*Outcome` (multi-variant operation result).

## Public API shape

For new code, prefer the namespaced facade surface over the flat root:

- `axess::session::*` for session and refresh primitives
- `axess::authn::*` for authentication types, services, and verifier helpers
- `axess::authz::*` for authorization types (long form: `axess::authorization::*`)
- `axess::federation::{oauth, ldap, fido2, mtls, jwt, pkce}::*` for external IdP integrations
- `axess::device::*`, `axess::workload::*`, `axess::delegated::*`, `axess::local_idp::*` for specialized integrations
- `axess::backends::*` for storage backends
- `axess::testing::*` for mocks, fixtures, and DST helpers (behind the `testing` feature)

The root namespace stays small: `SessionLayer`, `AuthSession`, `AuthState`, `SessionStore`, the macros (`require_authn!`, `require_partial_authn!`, `require_authz!`), and the DST primitives `Clock` / `SecureRng`. Everything else lives under one of the namespaces above.

---

## What's in the box

axess covers a long list of concerns; the table below points at the cookbook docs that go into detail. The README only summarises.

| Concern | Where to read |
|---|---|
| Multi-factor flows + state machine | this README + [`docs/authentication/session-state-machine.md`](docs/authentication/session-state-machine.md) |
| Cedar authorization (RBAC / ABAC / ReBAC) | `examples/authz/` |
| Principal model | [`docs/authentication/principal.md`](docs/authentication/principal.md) |
| Multi-tenant model | [`docs/identity/tenancy.md`](docs/identity/tenancy.md) |
| Device identity (`device` feature, default-on) | [`docs/identity/device.md`](docs/identity/device.md) |
| OAuth 2.0 / OIDC | `examples/oauth/` |
| FAPI 2.0 (PAR / DPoP / JARM) | `examples/fapi/` |
| FIDO2 / WebAuthn (passkeys) | [`docs/factors/fido2.md`](docs/factors/fido2.md) |
| Workload identity (SPIFFE, K8s SA, GitHub OIDC) | [`docs/workload-identity/README.md`](docs/workload-identity/README.md) |
| Cloud STS exchange (AWS / GCP / Azure) | [`docs/workload-identity/cloud-sts.md`](docs/workload-identity/cloud-sts.md) |
| On-behalf-of (OBO) downstream access | [`docs/identity/delegated-obo.md`](docs/identity/delegated-obo.md) |
| Local IdP for testing and on-host issuance | [`docs/factors/local-idp.md`](docs/factors/local-idp.md) |
| Audit events + SOC/SIEM integration | [`docs/production/audit-events.md`](docs/production/audit-events.md) |
| Audit-log archival to cold storage | [`docs/production/audit-pipeline.md`](docs/production/audit-pipeline.md) |
| Analytics path (Iggy + rkyv + ClickHouse / DuckDB) | [`docs/production/audit-pipeline.md`](docs/production/audit-pipeline.md) |
| Crypto + transport posture, FIPS routing | [`docs/production/security-posture.md`](docs/production/security-posture.md) |
| Production deployment runbook | [`OPERATIONS.md`](OPERATIONS.md) |
| Version-to-version migration | [`docs/production/migrating.md`](docs/production/migrating.md) |
| Release runbook (maintainers) | [`docs/production/release.md`](docs/production/release.md) |

For the complete docs index, see [`docs/README.md`](docs/README.md).

---

## Installation

```toml
[dependencies]
axess = { version = "0.3.0", features = ["sqlite", "authz"] }
```

To track the development branch instead of a release:

```toml
[dependencies]
axess = { git = "https://github.com/GnomesOfZurich/axess", features = ["sqlite", "authz"] }
```

### Feature flags

Names are kebab-case throughout. The `axess` facade's default features are `["authz", "device"]`; everything else is opt-in. (Note: `axess-core` itself carries a wider default set including `"default-error-response"` and `"serde"`; adopters who depend on the facade get the facade's narrower defaults.)

#### Core + storage

| Feature | What it enables | Default |
|---|---|---|
| `authz` | Cedar Policy authorization, `PolicyStore`, entity builders | yes |
| `device` | First-class `Device` aggregate + binding factors | yes |
| `memory` | `MemorySessionStore` / `MemorySessionRegistry` / `MemoryStore<K, V>` (dev/test) | no |
| `testing` | Test doubles + fixtures (`MockIdentityStore`, `MockClock`, `LocalIdpFixture`, …). Implies `memory`. | no |
| `sqlite` | SQLite session store with optional AES-256-GCM encryption | no |
| `postgres` | PostgreSQL session store with optional AES-256-GCM encryption | no |
| `mysql` | MySQL / MariaDB session store with optional AES-256-GCM encryption | no |
| `valkey` | Valkey/Redis session store and registry with optional encryption | no |

#### Federated authn

| Feature | What it enables | Default |
|---|---|---|
| `fido2` | FIDO2/WebAuthn passkey authentication | no |
| `ldap` | LDAP bind authentication (Active Directory, OpenLDAP) | no |
| `oauth` | OAuth 2.0 / OIDC (AuthCode+PKCE, Client Credentials, Device Code) | no |
| `fapi` | FAPI 2.0 Security Profile (PAR, DPoP, JARM). Implies `oauth`. | no |
| `social` | Plain OAuth 2.0 user login (GitHub user / Twitter / Discord / Reddit / Spotify / …). **Weaker security model than OIDC**: claims come from a TLS-trusted userinfo endpoint, not from a signed assertion. See `axess::social` module docs for the delta. | no |

#### Workload identity

| Feature | What it enables | Default |
|---|---|---|
| `mtls` | Inbound mTLS / X.509-SVID workload identity resolver | no |
| `jwt-svid` | Inbound SPIFFE JWT-SVID workload identity resolver (spec-bound: mandatory `spiffe://` URI in `sub`) | no |
| `workload-id` | Umbrella over the SPIFFE / mTLS / outbound surfaces below | no |
| `outbound-mtls` | axess presenting an mTLS identity to downstream services | no |
| `outbound-oauth` | axess as an OAuth client to downstream services | no |
| `aws-sts` | AWS STS exchange (federated workload identity → AWS creds) | no |
| `gcp-wif` | GCP Workload Identity Federation exchange | no |
| `azure-fic` | Azure Federated Identity Credentials exchange | no |
| `cloud-sts` | Umbrella: `aws-sts` + `gcp-wif` + `azure-fic` | no |

For JWT-bearer workload identity from any non-SPIFFE issuer (GitHub Actions OIDC, Kubernetes service-account projected tokens, GitLab CI OIDC, Okta, Azure AD, Auth0, axess `LocalIdP`, …), use the generic `WorkloadResolver` under `jwt-svid`'s feature set. It takes an adopter-supplied claim parser plus mapping closure; there are deliberately no per-company features. See [`examples/workload-identity/`](examples/workload-identity/) for ready-made claim parsers (GitHub Actions, Kubernetes SA) you can copy or depend on.

#### Adjacent flows + audit

| Feature | What it enables | Default |
|---|---|---|
| `delegated` | On-behalf-of (OBO) access + token exchange | no |
| `local-idp` | `LocalIdpFixture` in-process IdP for tests / on-host issuance | no |
| `audit-archive-fs` | Filesystem-backed `AuditArchiver` reference implementation | no |

#### Authz cache decorators

These are opt-in alternatives to the in-process `EntityCache` for the Cedar entity graph. Most adopters do not need them.

| Feature | What it enables | Default |
|---|---|---|
| `moka-cache` | Moka-backed authz entity cache decorator (breaks DST, opt-in only) | no |
| `valkey-cache` | Valkey-backed authz entity cache decorator (shared across replicas) | no |

#### HTTP middleware

| Feature | What it enables | Default |
|---|---|---|
| `request-id` | UUID-based request ID injected into response headers | no |
| `trace-id` | W3C Trace Context propagation via headers | no |
| `accept-client-id` | `X-Client-ID` header extraction | no |
| `ws` | WebSocket session middleware | no |

#### Umbrella

| Feature | What it enables | Default |
|---|---|---|
| `full` | Discoverability umbrella: turns on the common combinations | no |

`axess-factors` has its own default feature flags: `password` (Argon2id), `totp` (RFC 6238), `hotp` (RFC 4226), `email_otp`. The rest of its surface (`fido2`, `ldap`, `mtls`, `jwt`, `oidc`, `oauth`, `fapi`, `bearer`, `outbound-oauth`, federation adapters) is opt-in and wired through the matching feature flags on the `axess` facade.

---

## Security

Axess is a library; its security depends on correct integration. See [`SECURITY.md`](SECURITY.md) for the production integration checklist (TLS, cookies, CSRF, session binding, rate limiting, key management) and the private vulnerability-reporting channel.

---

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the contributor workflow, local-check script, and repository conventions (module layout, DST non-negotiable, no `#[non_exhaustive]`, etc.).

## Licence

Dual-licensed under [MIT](LICENSE-MIT) and [Apache-2.0](LICENSE-APACHE).
