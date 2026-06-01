# Getting started

This chapter is the on-ramp. It assumes you can read Rust and have seen
Axum, but it does not assume you know axess. The goal by the end is a
small running Axum application that logs a user in with a password,
holds the session in a signed cookie, and rejects requests to a
protected route until the login is complete.

We will skip the database for as long as possible. Replacing the
in-memory backend with a real SQLite backend is a one-trait swap,
covered at the end and walked through in detail in *Identity store
implementation* and the working
[`examples/sqlite/`](https://github.com/GnomesOfZurich/axess/tree/main/examples/sqlite)
reference application.

If you already have an Axum application and want the punch list: add
the dependencies in *Dependencies*, drop in the `SessionLayer` and
`AuthnService` from *The minimum viable wiring*, and wire the login
handler from *Adding password login*. The rest of the chapter is
rationale and a tour of the production-shaped example.

## Prerequisites

You need Rust 1.87 or later on the stable channel (the workspace MSRV),
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
axess = "0.2"             # facade -- depend on this, never on the internal crates
axum = "0.8"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
tower = "0.5"             # transitively from axum, but listed for clarity
```

The defaults of the `axess` facade enable `authz` and `device`.
Everything else is opt-in via features. For this chapter we will also
turn on `memory`, the in-memory session store used for development and
tests.

```toml
axess = { version = "0.2", features = ["memory"] }
```

The complete feature reference lives in the
[crate-level docs on docs.rs](https://docs.rs/axess) and is surveyed in
the project's
[`README`](https://github.com/GnomesOfZurich/axess/blob/main/README.md).
Per-feature chapters in this book (*Backends*, *OAuth*, and so on)
state their required feature at the top.

## The minimum viable wiring

A minimum axess setup has four moving pieces, used in the same order
they are wired. The backend looks up users and verifies their factors.
The session store persists session data across requests. A signing key
HMAC-signs the session cookie so it cannot be tampered with. The
`AuthnService` is what handlers reach for to drive the state machine.
On top of those four pieces sits one Tower layer, `SessionLayer`,
which reads the cookie at the start of every request, hydrates the
session, and writes it back on response.

Here is the whole thing in one file. We will walk through each line
right after.

```rust,no_run
use axess::{
    AuthnService, InMemoryBackend, InMemorySessionStore,
    SessionLayer, AuthSession,
};
use axum::{Router, routing::get, response::IntoResponse, http::StatusCode};
use std::{sync::Arc, time::Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Backend -- one type implements both IdentityStore and FactorStore.
    let backend = InMemoryBackend::new()
        .with_user_password("alice", "default", "Gnomes2+");

    // 2. Session store + 3. signing key.
    let session_store = InMemorySessionStore::new();
    let signing_key: [u8; 32] = [0; 32]; // PLACEHOLDER, see "Signing keys" below.

    // 4. AuthnService -- type-erased over clock and RNG; production wires
    //    SystemClock + SystemRng.
    let service = Arc::new(AuthnService::new(backend.clone(), backend));

    // 5. SessionLayer threads the session through each request.
    let session_layer = SessionLayer::new(session_store, signing_key)
        .with_ttl(Duration::from_secs(86_400))
        .with_secure(false); // dev only -- see "Cookie security" below.

    let app = Router::new()
        .route("/", get(public_page))
        .route("/dashboard", get(protected_page))
        .with_state(service)
        .layer(session_layer);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn public_page() -> &'static str {
    "everyone can see this"
}

async fn protected_page(session: AuthSession) -> impl IntoResponse {
    if session.is_authenticated() {
        (StatusCode::OK, "welcome").into_response()
    } else {
        (StatusCode::UNAUTHORIZED, "log in first").into_response()
    }
}
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

`InMemorySessionStore::new()` is the trivial session backend. Session
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
use axess::{AuthnService, AuthSession, LoginOutcome};
use axum::{extract::State, response::IntoResponse, http::StatusCode, Json};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

async fn login(
    session: AuthSession,
    State(service): State<Arc<AuthnService<InMemoryBackend, InMemoryBackend>>>,
    Json(form): Json<LoginForm>,
) -> impl IntoResponse {
    // 1. Begin the login. Transitions Guest -> Authenticating.
    match service.begin_login(&session, &form.username, "default").await {
        Ok(_) => {}
        Err(e) => return (StatusCode::UNAUTHORIZED, format!("{e}")).into_response(),
    }

    // 2. Verify the password factor.
    use axess::FactorCredential;
    match service
        .verify_factor(
            &session,
            FactorCredential::Password(form.password.clone()),
        )
        .await
    {
        Ok(LoginOutcome::Authenticated { .. }) => {
            (StatusCode::OK, "logged in").into_response()
        }
        Ok(LoginOutcome::AwaitingFactor { remaining }) => {
            // Unreachable for a password-only method, but the branch matters
            // when chaining factors (password + TOTP, etc).
            (StatusCode::OK, format!("need more factors: {remaining:?}")).into_response()
        }
        Err(e) => (StatusCode::UNAUTHORIZED, format!("{e}")).into_response(),
    }
}
```

The call to `begin_login` is what transitions the session from
`Guest` to `Authenticating`. The transition records the user id, the
tenant, and the list of factors still required (just `Password` for a
single-factor method). Then `verify_factor` consumes one factor and
returns a `LoginOutcome`. The successful terminal case is
`LoginOutcome::Authenticated`, meaning every required factor has
passed. The intermediate case is `LoginOutcome::AwaitingFactor`,
meaning the factor verified but more are required; the state stays
`Authenticating` and `remaining` lists what is still needed.

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
`InMemorySessionStore` (2), and rebuilds the `AuthState`. Axum
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
`SessionLayer::with_previous_key`, which keeps the old key available
for a transitional period so that sessions signed with the previous
key continue to validate while new sessions sign with the new one.
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
production: a real SQLite backend (`OurBackend` implements
`IdentityStore` and `FactorStore` over a `sqlx::SqlitePool`), a
SQLite-backed session store with AES-256-GCM encryption at rest, a
password + TOTP two-factor login for a second user, self-service
signup and TOTP enrollment, a password-reset flow with email-OTP,
rate limiting on the auth routes, a health check on the session
store, atomic auth-attempt counters exposed at `/metrics`, and a
background interval task that purges expired sessions. Read the
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

If `begin_login` returns `UserNotFound`, the tenant probably does
not match. The example seeds `alice` in tenant `default`; passing a
different tenant returns `UserNotFound` deliberately, not
"user exists in a different tenant". Axess never leaks tenant
membership across tenant boundaries.

If sessions disappear on process restart, that is correct for
`InMemorySessionStore`. Use `SqliteSessionStore`,
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
