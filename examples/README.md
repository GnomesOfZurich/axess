# Axess Examples

Each example is a standalone Axum application demonstrating a specific aspect of the Axess library. Run any example with:

```sh
cargo run -p <example-name>
```

## Examples

| Directory | Package | What it demonstrates |
|-----------|---------|---------------------|
| [`sqlite/`](sqlite/) | `axess-example-sqlite` | **Authentication** — password + TOTP login, session management, lockout, logout. SQLite for identity and session storage. |
| [`authz/`](authz/) | `axess-example-authz` | **Authorization** — Cedar Policy evaluation with RBAC, ReBAC (ownership), and ABAC (MFA requirement). In-memory data, no database needed. |
| [`oauth/`](oauth/) | `axess-example-oauth` | **OAuth/OIDC** — federated login via Google (or any OIDC provider). Full redirect flow with PKCE, CSRF protection, and ID token validation. |

## Which example should I look at?

- **"I want to add login to my Axum app"** → start with `sqlite/`
- **"I want to add access control / permissions"** → start with `authz/`
- **"I want to add Google/GitHub/SSO login"** → start with `oauth/`
- **"I want to combine them"** → read them independently, then combine

## Running

All examples listen on `http://127.0.0.1:3000` by default. No external services required — just `cargo run`.

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
let session_store = SqliteSessionStore::new(pool.clone());

// With this:
use axess::{ValkeySessionStore, ValkeySessionRegistry};
use fred::prelude::*;

let config = Config::from_url("redis://127.0.0.1:6379")?;
let client = Client::new(config, None, None, None);
client.init().await?;

let session_store = ValkeySessionStore::encrypted(client.clone(), encryption_key);
let registry = ValkeySessionRegistry::new(client);
let authn = AuthnService::new(identity, factors).with_registry(registry);
```

Everything else (handlers, macros, auth flow) stays the same.
