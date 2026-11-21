# Getting started

By the end you have a running Axum application that logs a user in with
a password, holds the session in a signed cookie, and refuses a
protected route until the login completes. No database: the backend and
the session store live in memory, and replacing them with SQLite ones is
covered at the end and in
[`examples/sqlite/`](https://github.com/GnomesOfZurich/axess/tree/main/examples/sqlite).

**Already have an Axum application?** Add the dependencies in
*Dependencies*, drop in the `SessionLayer` and `AuthnService` from *The
minimum viable wiring*, and wire the handler from *Adding password
login*. The rest is rationale and a tour of the production-shaped
example.

## Prerequisites

You need Rust 1.95.0 or later on the stable channel (the workspace MSRV),
Axum 0.8.x, and a Tokio runtime in your binary (`#[tokio::main]` is
fine). Axess does not depend on system libraries, message brokers, or
external IdPs by default. The defaults need no infrastructure: the
password, TOTP, HOTP, and email-OTP factors work out of the box, and the
in-memory session store and backend for development and tests need only
the `memory` and `testing` features (see *Dependencies*).

## Dependencies

The shortest functional `Cargo.toml` looks like this.

```toml
[dependencies]
axess = "0.20"             # facade -- depend on this, never on the internal crates
axum = "0.8"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
tower = "0.5"             # transitively from axum, but listed for clarity
```

The defaults of the `axess` facade enable `authz` and `device`.
Everything else is opt-in via features. This chapter also
turns on `memory` for the in-memory session store and `testing` for
`InMemoryBackend`. Both are development conveniences; a deployment with a
real database needs neither, and a release build with `testing` on
refuses to compile (see *Test doubles in a release build* in the security
posture chapter).

```toml
axess = { version = "0.20.0", features = ["memory", "testing"] }
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
and the proxies you configure as trusted, so that nothing downstream has
to read a header and guess. Serve the router with
`into_make_service_with_connect_info::<SocketAddr>()`; without it the
layer has no peer address.

The whole wiring fits in one file; the next section walks through each
line.

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
convenience method `with_default_tenant` registers the tenant `default`, which a
login names and looks up, and `with_user_password` seeds one user (`alice`, in
that tenant, with the Argon2id-hashed password `Sample2+`).
Production replaces this with a real backend that implements
`IdentityStore` and `FactorStore` against your database. The trait
surface is identical.

`MemorySessionStore::new()` is the simplest session backend. Session
data lives in a `HashMap` behind an `RwLock` and disappears on
process exit. The first replacement is
`axess::backends::sqlite::SessionStore` (with the `sqlite` feature),
covered in *Backends*.

`AuthnService::builder_from_backend(backend)` starts a service whose
identity store and factor store are the same object: it is shorthand for
`AuthnService::builder(backend.clone(), backend)`. The two can be
different types, but in production they are typically the same struct
(a single backend implementing both traits). `.with_registry` hands the
service the session registry it records logins in.

`SessionLayer::new(store, key, registry, audit)` constructs the Tower
layer. The registry is the one the service records logins in, so a password
reset or a forced logout ends the session on every route. The audit sink
is the service's `session_end_audit()`, which writes an audit row for each
session the layer ends by itself. The
chained `.with_ttl` sets a 15-minute idle lifetime,
`.with_max_session_age` ends an authenticated session ten hours after its
login (the library defaults are 24 hours idle and 7 days from login), and `.with_secure` keeps
the `Secure` cookie attribute on unless `AXESS_DEV_INSECURE_COOKIES=1` is
set. See *Cookie security* below.

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
`Authenticated`. The second, and every request after it, carries the cookie that
identifies the session, and `AuthSession` reads `Authenticated`.

```rust,ignore
use axess::authn::{
    AuditContext, AuthnService, FactorCredential, FactorOutcome, LoginOutcome,
    RequestAuthnService,
};
use axess::{AuthSession, InMemoryBackend};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use std::sync::Arc;

{{#include ../../examples/minimal/src/main.rs:login}}
```

The handler meets two outcome types, and the difference matters.

`begin_login` returns a `LoginOutcome`: the answer to "can this
identifier start a login at all, and what does it need first?"
`FactorRequired(FactorKind)` says the flow is open and names the first
factor. `InvalidCredentials` and `Locked` say it is not. Handle those
two here rather than falling through, or the code goes on to offer a
password prompt for an account that is locked or does not exist.
(`Locked` is answered only when the service is built with
`with_lockout_revealed_on_begin`; by default a locked account gets
`InvalidCredentials`, as an unknown identifier does, so nothing is
learned about the account before any proof.)

Before each of those early refusals the handler calls
`burn_password_check`, which spends one Argon2id verification against a
fixed dummy hash. Without it an unknown username is answered in about a
millisecond and a real one in tens of milliseconds, and the difference tells a guesser which usernames exist.
`login_with_password` makes both calls and does this for you.

A refused attempt also ends the login it began: `login` clears the session
on every answer that is not a success. Otherwise, after a wrong password, the session would say which usernames
exist: `begin_login` opens a login in the session for a username that
exists and leaves the session untouched for one that does not, and the
session layer sets a cookie for a changed session. `login_with_password` clears on every refusal too.

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
because it is what the verb acts on. Neither takes a client address:
that rides on the handle, resolved once by `client_ip::layer`.

This branching is why the state machine is explicit: no variant means
"logged in after one factor of several". `is_authenticated()` returns true only when every
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
       -d '{"username":"alice","password":"Sample2+"}'
logged in

$ curl -b jar http://127.0.0.1:3000/dashboard
welcome
```

## What just happened

A full request walks the following path. The numbers are those of the
numbered comments in the example's wiring.

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

## The second walkthrough: signing in with an identity provider

The first walkthrough ends with a user who typed a password. Many
applications never ask for one: the user signs in at an identity provider
(Entra, Google, Keycloak) and the application accepts its word. The login ends
in the same place (an `Authenticated` session behind the same cookie), but
the application has to decide which local user the provider's answer
names.
[`examples/oauth/`](https://github.com/GnomesOfZurich/axess/tree/main/examples/oauth)
is that path from the redirect to a profile page. It needs the `oauth` and
`jwt-rust-crypto` features on the facade.

The login is three calls, and the middle one is yours:

1. `begin_oauth_login_in_tenant` sends the browser to the provider. Naming
   the tenant here makes `complete_oauth_login` refuse a user from any other.
2. `finish_oauth_login` runs when the browser comes back. It checks
   that the callback arrived on the route of the provider the login began
   with (`OAuthCallbackRoute::global(name)` here), and it checks the
   state, the PKCE verifier, the ID token's signature, issuer, audience,
   nonce and expiry, and the `iss` parameter of the response (RFC 9207). It
   returns the claims. It also leaves a claim lock in the session, a value
   derived from this provider, this subject and this session.
3. `complete_oauth_login` takes a local `User` and those claims, checks the
   lock, and makes the session `Authenticated`. Claims that did not come out
   of step 2 for this session do not pass.

Between 2 and 3 the application turns claims into a user. The example keeps a
**federated-identity table** of `(issuer, subject)` to local user id, and
nothing else is ever the link. The email address is not: it changes hands,
and one provider lets users type it while another verifies it. The same
address from a second issuer is a second identity, and a second user.

```rust,ignore
{{#include ../../examples/oauth/src/app.rs:callback}}
```

An identity with no link goes to the tenant's **provisioning policy**. A
tenant that provisions just in time creates the local user on the spot and
links it; a tenant that does not (`Provisioning::LinkedOnly`) refuses the
login with a 403, and an administrator links people beforehand. Either way
the next login of a known identity finds the same user.

The page after login reads the axess session, not the claims:

```rust,ignore
{{#include ../../examples/oauth/src/app.rs:profile}}
```

Logout works from both ends. `POST /auth/logout` ends the local session and
sends the browser to the provider's logout endpoint with the ID token as the
hint (RP-initiated logout); `POST /auth/backchannel-logout` takes the signed
logout token the provider posts when the user signs out there, and ends the
session it names. The example's test drives all of this as a browser does,
against an in-process provider: `cargo test -p axess-example-oauth`. The
*OAuth 2.0 and OIDC* chapter has the rest: refresh, FAPI, and what each
provider needs registered.

## Signing keys

The example draws a fresh random 32-byte signing key each time it
starts, so a restart signs everyone out. That is fine for a
five-minute demonstration and for nothing else.

In production the signing key is a 32-byte random value loaded from a
secrets manager (AWS Secrets Manager, GCP Secret Manager, HashiCorp
Vault, sealed Kubernetes secrets, or your platform's equivalent). The
key must stay the same across process restarts: every session cookie's
HMAC is computed with it, so a changed key invalidates every existing
session on its next request.

To rotate the signing key, use
`SessionLayer::with_previous_signing_key`: it keeps the old key
available for a transition period, so sessions signed with the
previous key continue to validate while new sessions sign with the new
one. (`SessionCrypto` has a similarly named `with_previous_key` for the
at-rest envelope; they rotate different keys.)
The *Operations runbook* walks through the rotation sequence in
detail.

## Cookie security

The example turns `Secure` off only when `AXESS_DEV_INSECURE_COOKIES=1`
is set, which permits the cookie over plain HTTP for `localhost`
development. In production you terminate TLS at the edge and leave
`Secure` on, as it is by default (`.with_secure(true)`). The cookie is
then sent only over HTTPS. The other defaults are
already production-shaped: `HttpOnly` is on, `SameSite=Lax` is set,
and the cookie path is the application root.

The *Cookies, fingerprinting, hijack detection* chapter covers the
rest of the surface: the HMAC fingerprint binding that detects when a
session cookie is replayed from a different user agent, the
trusted-proxy configuration that controls how `X-Forwarded-For` is
interpreted, and the `SameSite=Strict` trade-off.

## Going further

This chapter is the minimum. The
[`examples/sqlite/`](https://github.com/GnomesOfZurich/axess/tree/main/examples/sqlite)
extends the same shape with what a production deployment needs:

- A real SQLite backend: `OurBackend` implements `IdentityStore` and
  `FactorStore` over a `sqlx::SqlitePool`.
- A SQLite-backed session store with AES-256-GCM encryption at rest.
- Password plus TOTP two-factor login for a second user, self-service
  signup and TOTP enrollment, and a password-reset flow over email OTP.
- Rate limiting on the auth routes, a health check on the session
  store, and atomic auth-attempt counters exposed at `/metrics`.
- A background interval task that purges expired sessions.

Read the
example, run it, and compare its `app.rs` with this chapter's snippet:
the shape is the same, with more pieces wired in.

After that, choose the next chapter by goal.

| Goal | Next chapter |
|---|---|
| Add a second factor (TOTP, FIDO2, OAuth) | *Factors and methods* |
| Replace `InMemoryBackend` with your database | *Identity store implementation* |
| Switch the session store to Postgres, MySQL, or Valkey | *Backends: SQLite, Postgres, MySQL, Valkey* |
| Add authorisation policies | *Cedar policy fundamentals* |
| Run multiple tenants | *Multi-tenancy* |
| Federated login (Google, Okta, Entra ID) | *OAuth 2.0 and OIDC* |
| Workload identity for non-human callers | *Workload identity overview* |
| Production deployment | *Operations runbook* |

## Common stumbling points

These failures are common in a first integration.

If your handler cannot see `AuthSession`, the extractor needs the
layer to populate request extensions. Add `use axess::AuthSession;`
and check that `SessionLayer` is in `.layer(...)` on the router.

If `begin_login` returns `InvalidCredentials` for a user you are sure
exists, check the tenant. The example seeds `alice` in tenant `default`,
and naming a different tenant gives the same `InvalidCredentials` as a
wrong password: axess does not tell a caller that a user exists
elsewhere, or that they exist at all. A wrong tenant is therefore hard to spot; that is the cost of not
leaking tenant membership.

If sessions disappear on process restart, that is correct for
`MemorySessionStore`. Use `axess::backends::sqlite::SessionStore`,
`axess::backends::postgres::SessionStore`,
`axess::backends::mysql::SessionStore`, or
`axess::backends::valkey::SessionStore` (each behind the feature of the
same name) for persistence. See *Backends*.

If you need to attach application data to a session, `SessionData` has
a `custom` field for that. Its serialised size is capped at 64 KiB by
default (`SessionLayer::with_max_custom_bytes` changes it), so a session
cannot grow without bound. See *The session state machine* §"Custom
session data".

To log a user out, call `AuthSession::clear()` or
`service.logout(&session).await`; either resets the state to `Guest`, rotates
the session id (defeating fixation), and clears the cookie on
response.

Each of these has a chapter or section later in the book.
