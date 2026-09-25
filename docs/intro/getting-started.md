# Getting started

By the end you have a running Axum application that logs a user in with
a password, holds the session in a signed cookie, and refuses a
protected route until the login completes. No database: the in-memory
backend is a one-trait swap away from SQLite, covered at the end and in
[`examples/sqlite/`](https://github.com/GnomesOfZurich/axess/tree/main/examples/sqlite).

**Already have an Axum application?** Add the dependencies in
*Dependencies*, drop in the `SessionLayer` and `AuthnService` from *The
minimum viable wiring*, and wire the handler from *Adding password
login*. The rest is rationale and a tour of the production-shaped
example.

## Prerequisites

You need Rust 1.94.0 or later on the stable channel (the workspace MSRV),
Axum 0.8.x, and a Tokio runtime in your binary (`#[tokio::main]` is
fine). Axess does not depend on system libraries, message brokers, or
external IdPs by default. The defaults are deliberately zero-infra: the
in-memory session store, the in-memory backend, and the password, TOTP,
HOTP, and email-OTP factors all work out of the box for development and
tests.

## Dependencies

The shortest functional `Cargo.toml` looks like this.

```toml
[dependencies]
axess = "0.7"             # facade -- depend on this, never on the internal crates
axum = "0.8"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
tower = "0.5"             # transitively from axum, but listed for clarity
```

The defaults of the `axess` facade enable `authz` and `device`.
Everything else is opt-in via features. For this chapter we will also
turn on `memory` for the in-memory session store and `testing` for
`InMemoryBackend`. Both are development conveniences; a deployment with a
real database needs neither.

```toml
axess = { version = "0.7.0", features = ["memory", "testing"] }
```

The complete feature reference lives in the
[crate-level docs on docs.rs](https://docs.rs/axess) and is surveyed in
the project's
[`README`](https://github.com/GnomesOfZurich/axess/blob/main/README.md).
Per-feature chapters in this book (*Backends*, *OAuth*, and so on)
state their required feature at the top.

## The minimum viable wiring

Four moving pieces, in the order you wire them:

1. **The backend** looks up users and verifies their factors.
2. **The session store** persists session data across requests.
3. **A signing key** HMAC-signs the cookie so it cannot be tampered with.
4. **`AuthnService`** is what handlers reach for to drive the state machine.

Two Tower layers sit on top. `SessionLayer` reads the cookie at the start
of every request, hydrates the session, and writes it back on response.
`client_ip::layer` works out the client's address once, from the TCP peer
and the proxies you say you trust, so that nothing downstream has to read
a header and guess. Serve the router with
`into_make_service_with_connect_info::<SocketAddr>()` or there is no peer
for it to work from.

Here is the whole thing in one file. We will walk through each line
right after.

```rust,ignore
{{#include ../../examples/minimal/src/main.rs:wiring}}
```

This compiles and runs. Visiting `http://127.0.0.1:3000/` returns
"everyone can see this". Visiting `/dashboard` returns 401, because no
session is authenticated yet. Adding the login flow is the next
section.

### What each line is doing

`InMemoryBackend::new()` constructs a backend that holds users, factor
configurations, and authentication-attempt logs in memory. The
convenience method `with_user_password` seeds one user (`alice`, in
tenant `default`, with the Argon2id-hashed password `Gnomes2+`).
Production replaces this with a real backend that implements
`IdentityStore` and `FactorStore` against your database. The trait
surface is identical.

`MemorySessionStore::new()` is the trivial session backend. Session
data lives in a `HashMap` behind an `RwLock`, and disappears on
process exit. The first replacement is
`axess::backends::sqlite::SessionStore` (with the `sqlite` feature),
covered in *Backends*.

`AuthnService::new(backend.clone(), backend)` takes two arguments
because the identity store and the factor store can be different
types. In the in-memory case they are the same object, hence the
clone. In production they typically remain the same struct (a single
backend implementing both traits), again with a clone.

`SessionLayer::new(store, key)` constructs the Tower layer. The
chained `.with_ttl(86_400)` sets a one-day session lifetime, and
`.with_secure(false)` permits HTTP cookies for local development. See
*Cookie security* below for the production setting.

`AuthSession` is an Axum extractor. Receiving it as a handler argument
hydrates the session for the current request, and `is_authenticated()`
returns true only when the state is `AuthState::Authenticated`. There
are also `is_guest()`, `is_authenticating()`, and a typed `.state()`
accessor if you want to match on the enum directly.

## Adding password login

The convenience seeded by `with_user_password` configures a
single-factor method called `password`. A login is two HTTP requests.
The first is `POST /login` with a JSON body carrying the username and
password. Axess transitions the session from `Guest` to
`Authenticating`, verifies the password, and on success transitions to
`Authenticated`. Every request after that carries the cookie that
identifies the session, and `AuthSession` reads `Authenticated`.

```rust,ignore
use axess::authn::{AuditContext, AuthnService, FactorCredential, FactorOutcome, LoginOutcome};
use axess::{AuthSession, InMemoryBackend};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use std::sync::Arc;

{{#include ../../examples/minimal/src/main.rs:login}}
```

Two different outcome types appear there, and the difference is the
point.

`begin_login` returns a `LoginOutcome`: the answer to "can this
identifier start a login at all, and what does it need first?"
`FactorRequired(FactorKind)` says the flow is open and names the first
factor. `InvalidCredentials` and `Locked` say it is not. Handle those
two here rather than falling through, or the code goes on to offer a
password prompt for an account that is locked or does not exist.

`verify_factor` returns a `FactorOutcome`: the answer to "did this one
credential check out, and are we done?" `Authenticated` is the terminal
success: every required factor has passed and the session is now
`Authenticated`. `FactorRequired(FactorKind)` means this factor
verified but another is needed; the state stays `Authenticating` and
the variant names what comes next. `InvalidCredential` is a wrong
password, and `Locked` is the lockout policy firing on this attempt.

Both calls take the session, but in different positions:
`begin_login(identifier, tenant, session)` and
`verify_factor(credential, session)`. The credential comes first
because it is the subject of the verb. Neither takes a client address:
that rides on the handle, resolved once by `client_ip::layer`.

The branching is the whole point of the explicit state machine. There
is no version of "logged in" that means "we believe one factor, you
can let them in". `is_authenticated()` returns true only when every
required factor has passed.

## Wiring the login route

The minimum-viable router picks up the new handler:

```rust,ignore
let app = Router::new()
    .route("/", get(public_page))
    .route("/login", axum::routing::post(login))
    .route("/dashboard", get(protected_page))
    .with_state(service)
    .layer(session_layer);
```

A login flow now works end-to-end. Start the server, `curl` once to
log in, hold the cookie, `curl` again to reach `/dashboard`.

```bash
$ curl -c jar -X POST http://127.0.0.1:3000/login \
       -H 'content-type: application/json' \
       -d '{"username":"alice","password":"Gnomes2+"}'
logged in

$ curl -b jar http://127.0.0.1:3000/dashboard
welcome
```

## What just happened

A full request walks the following path. The numbers correspond to
the wiring steps from *The minimum viable wiring*.

The browser sends the request with a `Cookie:` header carrying the
session id. `SessionLayer` (5) extracts the cookie, verifies its HMAC
signature against the signing key, looks up the session in the
`MemorySessionStore` (2), and rebuilds the `AuthState`. Axum
invokes the handler with the hydrated `AuthSession` extractor. The
handler reads or mutates the session through `AuthnService` (4), and
mutations flag the session dirty. On response, `SessionLayer`
re-serialises the session if it is dirty, re-signs the cookie, and
sets it on the response.

The state machine, the backend, the session store, and the layer are
independent moving parts. Swapping the in-memory backend for a
SQLite-backed one does not touch the state machine or the session
store. Swapping the session store for Postgres does not touch the
state machine or the backend.

## Signing keys

The example uses `[0; 32]` as the signing key. That is fine for a
five-minute demonstration. It is not fine for anything else.

In production the signing key is a 32-byte random value loaded from a
secrets manager (AWS Secrets Manager, GCP Secret Manager, HashiCorp
Vault, sealed Kubernetes secrets, or your platform's equivalent). The
key must be stable across process restarts; the HMAC of an existing
session cookie is computed with this key, and if the key changes
underneath, every existing session becomes invalid on the next
request.

Rotating the signing key is supported via
`SessionLayer::with_previous_signing_key`, which keeps the old key
available for a transitional period so sessions signed with the
previous key continue to validate while new sessions sign with the new
one. (`SessionCrypto` has a similarly named `with_previous_key` for the
at-rest envelope; they rotate different keys.)
The *Operations runbook* walks through the rotation sequence in
detail.

## Cookie security

Setting `.with_secure(false)` in the example permits the cookie to be
sent over HTTP, which is necessary for `localhost` development. In
production, you terminate TLS at the edge and call `.with_secure(true)`.
The cookie will then only be sent over HTTPS. The other defaults are
already production-shaped: `HttpOnly` is on, `SameSite=Lax` is set,
and the cookie path is the application root.

The *Cookies, fingerprinting, hijack detection* chapter covers the
rest of the surface: the HMAC fingerprint binding that detects when a
session cookie is replayed from a different user agent, the
trusted-proxy configuration that controls how `X-Forwarded-For` is
interpreted, and the `SameSite=Strict` trade-off.

## Going further

This chapter is deliberately the minimum. The real
[`examples/sqlite/`](https://github.com/GnomesOfZurich/axess/tree/main/examples/sqlite)
extends the same shape with everything you will actually want in
production:

- A real SQLite backend: `OurBackend` implements `IdentityStore` and
  `FactorStore` over a `sqlx::SqlitePool`.
- A SQLite-backed session store with AES-256-GCM encryption at rest.
- Password plus TOTP two-factor login for a second user, self-service
  signup and TOTP enrollment, and a password-reset flow over email OTP.
- Rate limiting on the auth routes, a health check on the session
  store, and atomic auth-attempt counters exposed at `/metrics`.
- A background interval task that purges expired sessions.

Read the
example, run it, compare its `app.rs` to the snippet in this chapter.
The shape is the same; there are simply more pieces wired in.

After that, the order in which you read the rest of the book depends
on your goal.

| Goal | Next chapter |
|---|---|
| Add a second factor (TOTP, FIDO2, OAuth) | *Factors and methods* |
| Replace `InMemoryBackend` with your database | *Identity store implementation* |
| Switch the session store to Postgres, MySQL, or Valkey | *Backends: SQLite, Postgres, MySQL, Valkey* |
| Add authorisation policies | *Cedar policy fundamentals* |
| Run multiple tenants | *Multi-tenancy* |
| Federated login (Google, Okta, Azure AD) | *OAuth 2.0 and OIDC* |
| Workload identity for non-human callers | *Workload identity overview* |
| Production deployment | *Operations runbook* |

## Common stumbling points

A handful of failures bite first-time integrators. They are worth
naming up front so the chapter that solves them is easy to find.

If your handler cannot see `AuthSession`, the extractor needs the
layer to populate request extensions. Add `use axess::AuthSession;`
and check that `SessionLayer` is in `.layer(...)` on the router.

If `begin_login` returns `InvalidCredentials` for a user you are sure
exists, check the tenant. The example seeds `alice` in tenant `default`,
and naming a different tenant gives the same `InvalidCredentials` as a
wrong password: axess does not tell a caller that a user exists
elsewhere, or that they exist at all. That makes this particular typo
quiet to debug, which is the cost of not leaking tenant membership.

If sessions disappear on process restart, that is correct for
`MemorySessionStore`. Use `SqliteSessionStore`,
`PostgresSessionStore`, or `ValkeySessionStore` (with their
respective features) for persistence. See *Backends*.

If you need to attach application data to a session, `SessionData` has
a `custom` field for that. The size cap is 64 KiB to keep oversize
cookies from becoming a DoS surface. See *Session lifecycle and
crypto envelope* §"Custom session data".

If the user logs out, `AuthSession::clear()` or
`service.logout(&session).await` resets the state to `Guest`, rotates
the session id (defeating fixation), and clears the cookie on
response.

Each of these has a dedicated chapter or section later in the book.
The goal here was to get you running, not to be complete. You are
running. The rest is detail.
