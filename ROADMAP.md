# Axess Roadmap

> Forward-looking items. For what's built, see [README.md](README.md);
> for lasting design notes, see [`docs/`](docs/README.md).

---

## Planned

- **Live Cedar policy reload without restart.** `PolicyStore` is
  currently immutable after construction; changing policy text or the
  compiled schema means a process restart. The trait
  [`AuthzEntityProvider`] already re-reads role/group/ownership state
  per request via the entity provider (so admin role reassignments
  are live today, given proper cache invalidation), but policy TEXT
  authoring and schema evolution are restart-bound. Landing this
  requires: an `ArcSwap<PolicyStore>` swap slot inside `AuthzStore`
  (or equivalent), a `reload(text, schema)` entry point that runs
  [`validate_policies`] BEFORE swapping (never leave the authorizer
  holding a bad policy set), a cross-instance coordination mechanism
  so a single admin change reaches every pod (Valkey pub/sub is the
  obvious fit given existing `ValkeyEntityCache`), and an automatic
  `invalidate_all()` after every successful swap (cached entity
  attributes may reference retired policies). The validation helper
  [`validate_policies`] is already extracted for exactly this
  future use; the entity-provider trait's [`validate_schema`] is
  similarly re-runnable on schema change. Design doc pending.

- **Observability + metrics coherence pass.** Metrics have grown
  organically via the `AuthnMetrics` trait — every subsystem that
  wanted a counter added a method (`auth_attempt`, `session_binding_mismatch`,
  `factor_attempt`, `rate_limit_rejected`, etc.). New capabilities
  (CSRF failures, provider-registry duplicate registrations, signing-
  key rotation-fallback frequency, sid_map capacity evictions,
  fingerprint-fallback frequency) mostly land as `tracing::debug!` /
  `tracing::warn!` because the metrics surface is inconsistent and
  extending it drags every existing implementor. Goal of the pass:
  design a coherent observability contract — likely one or more
  narrower capability traits by concern (auth-flow metrics, session-
  layer metrics, rotation-window metrics, provider-registry metrics)
  with default `NoopMetrics` blanket impls so adopters opt in per
  concern rather than override a growing monolithic trait. Also:
  decide what belongs as metric (numeric aggregation) vs
  event/tracing (individual observation with structured fields).
  This is scoped as a spike — not part of the current release cycle,
  but should land before more capabilities accrete piecemeal on top
  of `AuthnMetrics`. Design doc pending.

- **Live OAuth / FIDO2 / LDAP provider reload without restart.**
  Same shape as the Cedar-policy reload item above. Providers today
  are attached at `AuthnService` construction via `with_oauth_provider`
  / `with_fido2` / `with_ldap` and cannot be swapped afterwards.
  Runtime changes require rebuilding the service and rewiring Axum
  state. Landing this needs: an `ArcSwap`-backed slot per provider
  category, a `reload_oauth_provider(...)` / `reload_fido2(...)` /
  `reload_ldap(...)` API that validates before swap (OAuth discovery
  network call, FIDO2 relying-party parse, LDAP TCP reachability),
  cross-instance coordination (Valkey pub/sub like the cache
  invalidation surface), and — for OAuth — a `remove_oauth_provider`
  companion so tenants that stop federating leave no stale
  registration. Multi-tenant IdP-per-tenant use cases hinge on
  this; the documented current pattern (register at startup only)
  works for platform-wide IdPs but not for tenant-supplied ones.
  Design doc pending.

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
