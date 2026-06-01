# Axess Roadmap

> Forward-looking items. For what's built, see [README.md](README.md);
> for lasting design notes, see [`docs/`](docs/README.md).

---

## Planned

---

## Awaiting upstream

The FIDO2 work waits on `webauthn-rs` 0.6 stable. We ride the `0.6.0-dev` pin today and will bump in lockstep when the release lands.

- **Per-ceremony UV / attestation policy.** Configure `UserVerificationPolicy::{Required,Preferred,Discouraged}` and `AttestationConveyancePreference::{None,Indirect,Direct,Enterprise}` per FIDO2 operation (registration vs. authentication vs. step-up). `webauthn-rs` 0.6.0-dev applies these at `WebauthnBuilder` time and has no per-ceremony override surface; the `Fido2Provider` trait is already shaped to accept the per-ceremony arguments, which pass through once upstream allows it.

- **Pin `webauthn-rs` to stable.** Single-file bump in `axess-core/Cargo.toml` once `0.6` lands on crates.io.

- **FIDO2 example app.** Standalone example with browser-side JS demonstrating registration (Direct attestation), authentication (Preferred UV), and discoverable credentials (Required UV for step-up). Depends on the per-ceremony policy.

- **Cross-Device Authentication (CDA).** `begin_cross_device_authn` / `complete_cross_device_authn` on `Fido2Service` per the FIDO Alliance hybrid-transport spec (QR + BLE proximity); reference example in `examples/fido2/`. Depends on the per-ceremony policy.

---

## On adopter demand

- **SPIRE Workload API client.** Talk to a local SPIRE agent socket to fetch SVIDs (JWT or X.509), maintain credential rotation, retrieve trust bundles. Per the [workload-identity overview](docs/workload-identity/README.md). Feature `spire`. Lands when an adopter actually needs an axess-shaped wrapper (axess-clock-driven rotation, axess-rng-driven ceremony nonces, `Principal::Workload` symmetry on the fetch side). Until then, the [fetch-side recipe in jwt-svid.md](docs/workload-identity/jwt-svid.md) points adopters at the upstream `spire-workload` / `spire-api` crates.

- **Device-bound session credentials.** Cryptographically bind a session to a non-exportable device key so that an exfiltrated cookie is useless without the key. The server-side substrate already exists: the `DeviceBinding` enum (extend with a key-backed variant), the ES256/JWT verifier and JWKS handling, the nonce and replay-state pattern from the OAuth surfaces, and refresh-token rotation with family cascade-revocation. What is missing is the protocol layer. For browsers that is the Google/W3C Device Bound Session Credentials scheme (`Sec-Session-Registration` / `Sec-Session-Challenge` / `Sec-Session-Id` headers plus a refresh endpoint that verifies a device-key-signed challenge before minting the next short-lived cookie); for native apps it is a DPoP-style session proof (axess already implements DPoP for OAuth access tokens, not for sessions). Both front-ends feed one device-bound-key abstraction. Lands when an adopter needs it and the browser scheme has settled: it is Chromium-only and still stabilising.

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
