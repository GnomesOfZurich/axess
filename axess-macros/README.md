# axess-macros

`axess-macros` packages the procedural helpers that power Axess authentication middleware. It focuses on ergonomic Axum integrations by generating ready-to-use layers for enforcing authentication state (fully or partially authenticated users) and for building predicate-based guards.

## Features

- Middleware macros for enforcing authentication flows:
  - [`login_required!`](../axess-macros/src/lib.rs): ensures a user is authenticated before accessing a route.
  - [`require_partial_authn!`](../axess-macros/src/lib.rs): restricts routes to partially authenticated sessions (e.g., MFA verification).
  - [`predicate_required!`](../axess-macros/src/lib.rs): wraps arbitrary async predicates and applies redirects or fallback responses.
- Query-string helper `url_with_redirect_query` for preserving original destinations during redirects.
- Designed to pair with the core [`AuthSession`](../axess-core/src/authn/session/auth_session.rs) in `axess-core`.

## Installation

The macros ship with the main Axess workspace. Enable them via Cargo:

```toml
[dependencies]
axess = { version = "0.0.9", features = ["authn"] }
```

## Quick start

```rust
use axess::{AuthSession, SessionRegistryStore, SystemRng, login_required};
use axum::{routing::get, Router};

type Session = AuthSession<MyBackend, SessionRegistryStore<MyStore>, SystemRng>;

fn router() -> Router {
    Router::new()
        .route("/dashboard", get(dashboard_handler))
        .layer(login_required!(Session, "/login"))
}
```

The macro automatically redirects unauthenticated users to `/login?next=/dashboard`. Replace the URL or redirect field as needed.

## Additional examples

- Guard an MFA verification page until the user completes step one:

```rust
use axess_macros::require_partial_authn;

app.route("/mfa/verify", get(verify_mfa))
   .layer(require_partial_authn!(Session, login_url = "/login"));
```

- Wrap an arbitrary predicate (e.g., tenant-based access) and return a custom response:

```rust
use axess_macros::predicate_required;
use axum::http::StatusCode;

app.layer(predicate_required!(
    |session: Session| async move { session.tenant_is("acme").await },
    StatusCode::FORBIDDEN
));
```

## Testing

`cargo test -p axess-macros`