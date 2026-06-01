# axess-macros

[![Version](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/version.svg)](https://crates.io/crates/axess-macros)
[![Status](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/status.svg)](https://github.com/GnomesOfZurich/axess)
[![License](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/license.svg)](https://github.com/GnomesOfZurich/axess#licence)

[crates.io](https://crates.io/crates/axess-macros) · [docs.rs](https://docs.rs/axess-macros) · [GitHub](https://github.com/GnomesOfZurich/axess)

Procedural macros for the [Axess](https://github.com/GnomesOfZurich/axess) authentication library. Generates Axum middleware layers that enforce authentication state on routes.

## Macros

### `require_authn!`

Gates routes by authentication state; caller must be fully `Authenticated`. Redirects unauthenticated users to a login page, or returns 401 for API endpoints.

(Replaces the previous `login_required!` macro; same shape, name updated for consistency with the axess `Authn*` / `Authz*` convention.)

```rust
use axess::require_authn;

// Redirect to /login with ?next= query param:
let app = Router::new()
    .route("/dashboard", get(dashboard))
    .route_layer(require_authn!("/login"));

// Return 401 Unauthorized (API mode, no redirect):
let api = Router::new()
    .route("/api/data", get(api_handler))
    .layer(require_authn!());
```

### `require_partial_authn!`

Restricts routes to sessions in the `Authenticating` state (mid-MFA). Useful for TOTP verification pages that should only be accessible after the first factor passes.

```rust
use axess::require_partial_authn;

let app = Router::new()
    .route("/totp", get(totp_page).post(verify_totp))
    .route_layer(require_partial_authn!("/login"));
```

### `require_valid_session`

For registry-enforced session checks (forced logout), use the middleware function directly:

```rust
use axess::require_valid_session;

let validator = authn.session_validator();
let app = Router::new()
    .route("/api/data", get(handler))
    .layer(require_valid_session(validator));
```

## Installation

These macros are re-exported from the `axess` facade crate. No separate dependency needed:

```rust
use axess::{require_authn, require_partial_authn};
```

Or depend on `axess-macros` directly if you only need the macros:

```toml
[dependencies]
axess-macros = "0.2"
```

## License

[MIT](https://github.com/GnomesOfZurich/axess/blob/main/LICENSE-MIT) OR [Apache-2.0](https://github.com/GnomesOfZurich/axess/blob/main/LICENSE-APACHE)

## Security

See [SECURITY.md](https://github.com/GnomesOfZurich/axess/blob/main/SECURITY.md) for vulnerability reporting.
