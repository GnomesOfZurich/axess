# Axess Examples

Each example is a standalone crate demonstrating a specific aspect of the Axess library. Most are runnable Axum applications; `workload-identity/` is a library-only recipes crate (no `main`). Run any runnable example with:

```sh
cargo run -p <example-name>
```

## Examples

| Directory | Package | What it demonstrates |
|-----------|---------|---------------------|
| [`sqlite/`](sqlite/) | `axess-example-sqlite` | **Authentication.** Signup, password + TOTP login (with conditional enrollment via `FactorStore::load_factor`), forgot/reset password, session management, lockout, logout. SQLite for identity and session storage. |
| [`authz/`](authz/) | `axess-example-authz` | **Authorization.** Cedar Policy evaluation with RBAC, ReBAC (ownership), and ABAC (MFA requirement). In-memory data, no database needed. |
| [`oauth/`](oauth/) | `axess-example-oauth` | **OAuth/OIDC.** Federated login via Google (or any OIDC provider). Full redirect flow with PKCE, CSRF protection, and ID token validation. |
| [`social/`](social/) | `axess-example-social` | **Plain OAuth 2.0 social login.** Generic `SocialProvider` wired to GitHub user login: claims sourced from a TLS-trusted userinfo endpoint instead of a signed assertion. Use only for IdPs that lack OIDC (GitHub, Twitter/X, Discord, Reddit, Spotify, Strava, …); prefer the `oauth/` example when OIDC is available. |
| [`fapi/`](fapi/) | `axess-example-fapi` | **FAPI 2.0.** Financial-grade API security: PAR, DPoP sender-constrained tokens, form_post response mode, RP-Initiated Logout, token revocation. Ships with a pre-configured Keycloak realm under [`fapi/keycloak/`](fapi/keycloak/); one `podman compose up` plus env vars gets a working end-to-end FAPI flow. Falls back to an in-process mock provider if no `FAPI_ISSUER` is set. |
| [`device/`](device/) | `axess-example-device` | **Device identity.** `SqliteSessionStore` + `SqliteDeviceStore` sharing one pool, fingerprint extractor with per-tenant pepper, `CachedDeviceStore` decorator, `DeviceLifecycleService`, `LifecycleDeviceResolver`, and the background three-stage retention sweep. |
| [`local_idp/`](local_idp/) | `axess-example-local-idp` | **In-process IdP.** Production `LocalIdp` minting workload JWTs against a file-backed RSA key store with atomic key rotation, RFC 8414 discovery document, JWKS endpoint. Useful when running workload-identity flows without standing up a real Okta / Azure AD / SPIRE. |
| [`workload-identity/`](workload-identity/) | `axess-example-workload-identity` | **Workload-identity recipes.** Copy-paste claim structs + mapper closures for GitHub Actions OIDC and Kubernetes service-account projected tokens, plugged into the generic `WorkloadResolver`. Read as documentation for writing your own recipe (GitLab CI, CircleCI, Buildkite, internal JWTs, …). |

## Which example should I look at?

- **"I want to add login to my Axum app"** → start with `sqlite/`
- **"I want to add access control / permissions"** → start with `authz/`
- **"I want to add Google or any OIDC SSO login"** → start with `oauth/`
- **"I want Login with GitHub (or another non-OIDC provider)"** → start with `social/`
- **"I need financial-grade security (PSD2, Open Banking)"** → start with `fapi/`
- **"I want to track devices (cookie binding, fingerprinting, retention)"** → start with `device/`
- **"I need a local IdP fixture for integration tests"** → start with `local_idp/`
- **"I want CI / Kubernetes workloads to authenticate to my service"** → start with `workload-identity/`
- **"I want to combine them"** → read them independently, then combine

## Running

Most examples listen on `http://127.0.0.1:3000` by default and run with just `cargo run`, no external services required. Exceptions:

- `oauth/` and `social/` need OAuth client credentials from the chosen IdP (Google / GitHub); see each crate's README for the env vars.
- `fapi/` optionally talks to a Keycloak container (see [`fapi/README.md`](fapi/README.md)) and falls back to an in-process mock provider otherwise.
- `workload-identity/` is a recipes crate (claim structs + mappers), not a server; it ships unit tests rather than a `cargo run` entry point.

```sh
# Authentication example:
cargo run -p axess-example-sqlite

# Authorization example:
cargo run -p axess-example-authz
```

## Using Valkey instead of SQLite for sessions

The `sqlite` example uses `SqliteSessionStore`. To swap in Valkey (requires a running Valkey/Redis instance):

```rust
// Replace this:
let session_store = SqliteSessionStore::new(pool.clone(), crypto.clone());

// With this:
use axess::{ValkeySessionStore, ValkeySessionRegistry};
use fred::prelude::*;

// Valkey uses the redis:// URI scheme (full wire-protocol compatibility).
let config = Config::from_url("redis://127.0.0.1:6379")?;
let client = Client::new(config, None, None, None);
client.init().await?;

let session_store = ValkeySessionStore::new(client.clone(), encryption_key);
let registry = ValkeySessionRegistry::new(client);
let authn = AuthnService::new(identity, factors).with_registry(registry);
```

Everything else (handlers, macros, auth flow) stays the same.
