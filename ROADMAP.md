# Axess Roadmap

> Forward-looking items. For what's built, see [README.md](README.md);
> for lasting design notes, see [`docs/`](docs/README.md).

---

## Planned

- **`EntityState::Suspended` conflates an administrative disablement with a
  lockout, and nothing can tell them apart.** `AuthnError::Locked`'s own doc
  says the state is reached by *"suspension or accumulated failed attempts"*,
  and tells callers to show a generic message *"rather than distinguishing
  failed-attempt vs admin-suspension reasons"*. That is right for a login
  screen and wrong for anything that must decide **eligibility**: an account an
  administrator disabled must never self-recover, and an account locked by
  failed attempts is exactly the person a recovery flow exists for. The two
  arrive as one variant, and the only field that could separate them is
  `StatusDetail::reason`, which is free text, so distinguishing them means
  parsing prose, which is keying a security decision on a spelling. `until` does
  not help either: it is `None` both for an indefinite admin lock and (per the
  same doc) for the failed-attempt lockout.

  Found 2026-10-23 while reviewing platform's AA-116 second-factor-reset route,
  and worth recording even though it changed nothing there: in platform a
  lockout is **not** an `EntityState` at all (it is derived from
  `failed_attempts`, and `users.status` carries no lockout value), so that
  route's `Active`-only arm is correct and `Suspended` does mean
  administratively disabled. The hazard is for the next adopter who reads
  `AuthnError::Locked`'s doc, concludes `Suspended` includes lockout, and
  widens an eligibility check, which would admit disabled accounts to
  self-recovery. One reviewer reached exactly that conclusion from the doc.

  Shape, for whoever takes it: either a machine-readable cause on
  `StatusDetail` (an enum beside `reason`, so the error's two sources stay
  joined for display and separable for a decision), or a distinct variant.
  Either way the doc on `AuthnError::Locked` should say that its two sources
  are an error-level union and not a statement about the state.

- **A `SessionStore` query must not default to `Ok(empty)`.**
  [`SessionStore::find_sessions_for_user`] carries a default
  implementation returning `std::future::ready(Ok(Vec::new()))`, and the
  SQLite backend (`session/storage/sqlite.rs`) does not override it. So on
  that backend the query answers "this user has no sessions" (truthfully
  shaped, and wrong) rather than failing or being absent. A caller
  enumerating a user's sessions to revoke them sweeps nothing and reports
  success, which is worse than a missing method because the absence
  presents as coverage.
  Found 2026-10-22 while designing a second-factor reset in an adopter
  (GnomesOfZurich platform): the reset's effect would have "cleared every
  session" by iterating that result. The adopter's fix is to use
  [`SessionRegistry::invalidate_user`] instead, which is a *required*
  method and is honoured on the read path by
  `authn/service/session_validator.rs`, so nothing is blocked on axess;
  but the trap stays for the next adopter who reaches for the obvious
  name.
  Three ways out, in preference order: implement it for SQLite (the
  `sessions` table is `id, data, expires_at` with the user inside the JSON
  blob, so this means either a `user_id` column or a scan, and the column
  is the honest answer); or make it a required method so every backend
  must answer; or remove it and let `SessionRegistry` own the question,
  since that is where the working mechanism already lives. A default that
  silently answers "none" for a *query* is the one option that should not
  survive.

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
  organically via the `AuthnMetrics` trait: every subsystem that
  wanted a counter added a method (`auth_attempt`, `session_binding_mismatch`,
  `factor_attempt`, `rate_limit_rejected`, etc.). New capabilities
  (CSRF failures, provider-registry duplicate registrations, signing-
  key rotation-fallback frequency, sid_map capacity evictions,
  fingerprint-fallback frequency) mostly land as `tracing::debug!` /
  `tracing::warn!` because the metrics surface is inconsistent and
  extending it drags every existing implementor. Goal of the pass:
  design a coherent observability contract: likely one or more
  narrower capability traits by concern (auth-flow metrics, session-
  layer metrics, rotation-window metrics, provider-registry metrics)
  with default `NoopMetrics` blanket impls so adopters opt in per
  concern rather than override a growing monolithic trait. Also:
  decide what belongs as metric (numeric aggregation) vs
  event/tracing (individual observation with structured fields).
  This is scoped as a spike: not part of the current release cycle,
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
  invalidation surface), and (for OAuth) a `remove_oauth_provider`
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

- **One `argon2` line in the tree.** `webauthn-rs` reaches `argon2` 0.5 through `crypto-glue`, so a build with `fido2` carries `argon2`, `password-hash` and `blake2` in two majors beside the 0.6 line axess uses; without `fido2` the tree has one. Resolves when `webauthn-rs` moves to `argon2` 0.6.

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
