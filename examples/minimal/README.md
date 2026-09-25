# axess-example-minimal

The wiring the *Getting started* chapter walks through: a password login
over an in-memory backend, in one file, with nothing optional switched on.

It exists so that chapter's code is compiled rather than asserted. The
book pulls the body in with mdBook's `{{#include}}` and an `ANCHOR`
comment, so change the API and this crate stops compiling, which fails CI
before the chapter is wrong. Edit this file, never the chapter's block.

What it wires, in the order the chapter introduces it:

- `InMemoryBackend` as both `IdentityStore` and `FactorStore`, seeded with
  one user under tenant `default`.
- `MemorySessionStore` plus a signing key, behind `SessionLayer`.
- `AuthnService`, kept in application state.
- `client_ip::layer` with `TrustedProxies::loopback_only()`, outermost,
  so the address is resolved once before anything reads one.
- `AuthnService::with_audit_context` in the handler, deriving the
  `RequestAuthnService` that `begin_login` and `verify_factor` live on.

## Running

```bash
cargo run -p axess-example-minimal
```

```bash
# Public route: no session needed.
curl -s http://localhost:3000/

# Protected route before logging in: 401.
curl -s -i http://localhost:3000/dashboard

# Log in, keeping the cookie.
curl -s -c jar.txt -X POST http://localhost:3000/login \
  -H 'content-type: application/json' \
  -d '{"username":"alice","password":"Gnomes2+"}'

# Protected route with the cookie: 200.
curl -s -b jar.txt http://localhost:3000/dashboard
```

## Two lines that are easy to leave out

`axum::serve` is called with
`into_make_service_with_connect_info::<SocketAddr>()`. Without it there is
no peer address in the request, so `client_ip::layer` has nothing to check
a forwarded chain against and every request resolves to no address: audit
rows record `ip_source = 'unknown'`, the rate limiter keys everything into
one bucket, and a tenant IP policy cannot be satisfied.

`TrustedProxies::loopback_only()` suits a dev server bound to
`127.0.0.1`. A deployment behind a proxy names that proxy's ranges with
`TrustedProxies::from_cidrs`, or asserts the topology with
`private_transport()` where the ranges cannot be pinned. Getting this
wrong is not a crash: it is a forged address that looks like a real one,
which is why *Session security* in the book spends a section on it.

## What it deliberately leaves out

No database, no TOTP, no OAuth, no CSRF layer, no rate limiting. Each has
its own example, and mixing them in here would cost the chapter the
property it is built on: that a reader can hold the whole file in their
head. `examples/sqlite` is the same flow against a real store, with an
audit trail and password reset.
