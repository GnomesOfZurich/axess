# Axess Roadmap

> Forward-looking items. For what's built, see [README.md](README.md);
> for lasting design notes, see [`docs/`](docs/README.md).

---

## Planned

- **Device-bound session credentials, the remainder.** The `device-keys` feature binds a session to a non-exportable device key so that an exfiltrated cookie is useless without the key: the proof verifier, the key service, the proof cookie, enforcement in the session layer and refresh tokens held to the key are built. Still to build: the mutation sweep of the new modules, and a walk with a real browser, before which the browser draft's wire names are checked against its text. The list is kept in [Design: device-bound sessions](docs/sessions/device-bound-sessions.md).

---

## Awaiting upstream

Each entry waits on a release of a crate axess depends on, and a weekly workflow opens an issue when that release exists: `webauthn-argon2-watch` for the first, `advisory-fix-watch` for the three accepted advisories a release fixes (`deny.toml` has the reasoning for each). The `chrono` entry waits on three crates and no release of chrono, and the `ES512` entry waits on `jsonwebtoken`, read against its 11.1.0 source; no workflow watches for either.

- **One `argon2` line in the tree.** `webauthn-rs` 0.6.2 reaches `argon2` 0.5 through `crypto-glue` 0.2 (0.2.2, the newest, requires `argon2` ^0.5.2), so a build with `fido2` carries `argon2`, `password-hash` and `blake2` in two majors beside the 0.6 line axess uses; without `fido2` the tree has one. Resolves when a `crypto-glue` release that `webauthn-rs-core` accepts moves to `argon2` 0.6; the weekly `webauthn-argon2-watch` workflow opens an issue when one does.

- **`rsa` 0.9 out of the tree (RUSTSEC-2023-0071).** The fix is `rsa` 0.10.0. `jsonwebtoken` 11.1.0 requires `rsa` ^0.9.6 for its `rust_crypto` backend and `openidconnect` 4.1.0 requires ^0.9.2, so a build with `jwt-rust-crypto` or `oauth` carries the 0.9 line; `axess-core` requires it under `local-idp-rsa` for RSA key generation and parsing (`local-idp` alone compiles none), and `axess-testing`, the dev-dependencies of `axess-core` and `axess-factors` and two examples require it for fixture keys. A build with `fido2` carries `rsa` 0.10.0-rc.19 through `crypto-glue` 0.2.2, which asks for an `rsa` feature (`sha2`) that 0.10.0 dropped, so cargo cannot move it to the release, and the advisory counts the pre-release as affected. `axess-core`'s own requirement cannot move first: cargo keeps one version of a compatible release line, and `crypto-glue`'s requirement is met only by the 0.10 pre-releases, so a build with `fido2` and `rsa` 0.10.0 does not resolve. Resolves when `crypto-glue` takes `rsa` 0.10.0 and `jsonwebtoken` and `openidconnect` accept it, with every `rsa` requirement of the workspace moving in the same change; until then a signature with an RSA key under `jwt-rust-crypto` is the exposed path (the local IdP with `local-idp-rsa`, and a `private_key_jwt` client assertion signed with an RSA key under `client-assertion-rsa`), and `jwt-aws-lc` signs outside the crate.

- **`crypto-bigint` 0.5 out of the tree (RUSTSEC-2026-0387).** The fix is `crypto-bigint` 0.7.6, which `p256` 0.14 uses. `jsonwebtoken` 11.1.0 requires `p256` ^0.13.2 (and `p384` 0.13) for its `rust_crypto` backend, so a build with `jwt-rust-crypto` carries `crypto-bigint` 0.5; `axess-core` and `axess-factors` are on `p256` 0.14, so a build on `jwt-aws-lc` does not. Resolves when `jsonwebtoken` has moved both `p256` and `p384` to 0.14.

- **Bundled SQLite 3.54.0 or later (RUSTSEC-2026-0459).** The fix is `libsqlite3-sys` 0.39.0. `sqlx-sqlite` 0.9.0 requires `libsqlite3-sys` below 0.38, so the `sqlite` feature bundles an affected SQLite; `sqlite-unbundled` links the system library instead. Resolves when an `sqlx` release accepts `libsqlite3-sys` 0.39.

- **`chrono` out of the tree (RUSTSEC-2026-0543).** chrono is declared unmaintained and no release fixes the advisory. axess's own time types are axess-clock's and no public signature names chrono, but `cedar-policy-core` (authorization, which the `axess` facade always enables), `oauth2` and `openidconnect` (`oidc`, `oauth`) depend on it, so it stays in `Cargo.lock`, and with it `axess-factors`' private conversion of the time openidconnect hands over (`oauth`) and axess-clock's agreement test against it. Resolves when the three have dropped chrono: the conversion and the dev-dependency go, `scripts/check-chrono-edges.sh` is tightened to refuse chrono anywhere, and the ignore entry in `deny.toml` and `.cargo/audit.toml` goes.

- **`ES512` for JWT SVIDs.** The JWT-SVID standard lists `ES512` (ECDSA on P-521) among the algorithms a validator supports; `jsonwebtoken` 11.1.0 has `ES256` and `ES384` and no `ES512`, so `JwtSvidResolver` refuses a JWT SVID signed with it, and the SPIRE chapter lists that under what is not built. A SPIRE server signs with P-256 or P-384 keys or with RSA, so its tokens are not affected; an issuer configured for P-521 is. Resolves when a `jsonwebtoken` release has the algorithm in both of its crypto backends: `ES512` then joins the algorithms `JwtSvidResolver` admits, with a test on a P-521 key.

---

## Current non-goals

- **SAML 2.0.** Very large effort. Use OIDC via an IdP proxy
  (Azure AD supports both).

- **Kerberos / SPNEGO.** Reverse-proxy concern. Pre-authenticated header to a trusted user ID is the integration shape.

- **JWT-based sessions for humans.** Forced logout requires server state; session cookies are correct. Workload-to-workload bearer JWT verification on Axum endpoints IS in scope; that's a distinct middleware path, never a session replacement.

- **Built-in user management UI.** Rendering belongs in the application.

- **Role taxonomy / permission names.** Application-specific; the Cedar namespace is configurable.

- **Full OAuth Authorization Server.** Keycloak / Ory Hydra territory. axess is a client of an AS, not an AS itself.

- **`Box<dyn SessionStore>`.** Vtable dispatch on the hottest path (every request). Monomorphised generics inline and optimise; runtime backend selection belongs at startup via `match`.

- **CORS configuration.** Belongs in the application's Axum layer, not the auth library.

- **Session anomaly detection.** Too application-specific. Provide data via `AuditContext`; let apps decide.

- **SCXML flow engine.** Auth flows are linear; the typed `AuthState` state machine covers it. Mermaid diagrams in the docs cover visualisation.

- **Admin sub-crate.** Admin APIs are application-specific. The `IdentityAdmin` trait surface (`suspend_user`, `activate_user`, `delete_user`, etc.) provides the primitives.
