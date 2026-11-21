# Axess Examples

Seven crates, each a runnable starting point you can copy from. Pick by what
you are building:

| Crate | Run with | What it shows |
|---|---|---|
| [`minimal/`](minimal/) | `cargo run -p axess-example-minimal` | **The smallest working login.** Password login with in-memory stores, in one file. It is the code the *Getting started* chapter walks through. |
| [`sqlite/`](sqlite/) | `cargo run -p axess-example-sqlite` | **The reference application.** Signup, password and TOTP login, recovery codes when the authenticator is lost, password reset, lockout, CSRF, rate limiting, sessions, health and metrics, all on SQLite, with tests that drive it as a browser does. |
| | `cargo run -p axess-example-sqlite --bin device` | **Device identity.** Fingerprinting with a per-tenant pepper, the Unknown → Seen → Trusted ladder, a cached device store, and the retention sweep, on the same SQLite pool. |
| [`authz/`](authz/) | `cargo run -p axess-example-authz` | **Authorization.** Cedar policies for roles (RBAC), ownership (ReBAC) and attributes such as "MFA was used" (ABAC). In memory, no database. |
| [`oauth/`](oauth/) | `cargo run -p axess-example-oauth` | **Sign in with an OpenID Connect provider** (Google, Keycloak, Auth0, …): discovery, PKCE, ID-token validation. |
| | `cargo run -p axess-example-oauth --bin social` | **Sign in with a provider that lacks OIDC** (GitHub, Discord, Twitter/X, …), and why that is weaker. |
| [`fapi/`](fapi/) | `cargo run -p axess-example-fapi` | **Financial-grade API security (FAPI 2.0).** `private_key_jwt` client authentication, PAR, DPoP sender-constrained tokens, form_post, RP-initiated logout, revocation. Ships a Keycloak realm; `FAPI_MOCK=1` runs a mock provider. |
| [`fido2/`](fido2/) | `cargo run -p axess-example-fido2` | **Passkeys and security keys (FIDO2 / WebAuthn).** Browser-side JavaScript and the server behind it: passkey, security-key and attested registration, username-first and passwordless sign-in, a passkey on another device (cross-device authentication), and a step-up the page runs when a Cedar policy answers `step_up_required`. In memory, no database. |
| [`workload-identity/`](workload-identity/) | `cargo test -p axess-example-workload-identity` | **Machine callers.** Recipes for GitHub Actions and Kubernetes service accounts, and, as the last resort for a caller with no identity of its own, signed requests over a shared secret. Each recipe is tested. |
| | `cargo run -p axess-example-workload-identity --bin local-idp` | **An in-process identity provider** minting workload JWTs from a file-backed, rotating key store, for flows without a real IdP. |
| | `cargo run -p axess-example-workload-identity --bin spire` | **A workload on a SPIRE node.** It takes its X.509 and JWT SVIDs from the local agent's socket and follows the agent's rotation. Needs a SPIRE agent. |

## Which one should I look at?

- **"I want to see the least code that logs someone in"** → `minimal/`
- **"I want to add login to my Axum app"** → `sqlite/`
- **"I want two-factor login, with a way back in when the phone is lost"** → `sqlite/`
- **"I want to track devices (fingerprinting, trust, retention)"** → `sqlite/`, `--bin device`
- **"I want to add access control / permissions"** → `authz/`
- **"I want Google or any OIDC single sign-on"** → `oauth/`
- **"I want Login with GitHub (or another non-OIDC provider)"** → `oauth/`, `--bin social`
- **"I want passkeys, or a hardware key as a second step"** → `fido2/`
- **"I want a sensitive action to ask for a stronger login first"** → `fido2/`
- **"I need financial-grade security (PSD2, Open Banking)"** → `fapi/`
- **"I want CI or Kubernetes workloads to call my service"** → `workload-identity/`
- **"An internal job or relay can only be given a secret"** → `workload-identity/src/shared_secret.rs`, after reading why it is the last resort
- **"I need an IdP for integration tests"** → `workload-identity/`, `--bin local-idp`
- **"My workload gets its identity from a SPIRE agent"** → `workload-identity/`, `--bin spire`
- **"I want to combine them"** → read them independently, then combine

The `sqlite/` and `fapi/` examples run their authentication service under
`SecurityProfile::Strict` (`axess::profile`), applied before their own
settings so those stay as written; read `docs/production/strict-profile.md`
for each value and why. The `oauth/` example refuses to provision a user
whose e-mail address the provider did not verify.

## Running

Everything that serves listens on `http://127.0.0.1:3000` (so run one at a
time) and needs no outside services, except:

- `oauth/` needs OAuth client credentials from the provider (Google for the
  default binary, GitHub for `--bin social`); its README lists the variables.
- `fapi/` talks to a Keycloak container (see
  [`fapi/README.md`](fapi/README.md)), or runs an in-process mock provider
  when started with `FAPI_MOCK=1`.

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
// The registry refuses to start on a server that does not run scripts.
let registry = ValkeySessionRegistry::new(client).await?;
let authn = AuthnService::builder(identity, factors)
    .with_registry(registry.clone())
    .build();
// The session layer takes the same registry as its third argument.
```

Everything else (handlers, macros, auth flow) stays the same.
