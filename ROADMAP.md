# Axess — Roadmap

> **Current version:** `v0.0.13` — pre-release, not yet published to crates.io.
> This document tracks what is done, what is in progress, and what is planned.
> It is intentionally opinionated: it records *why* each item is or is not a priority, not just what needs doing.

---

## Design principles (non-negotiable)

These govern every change. New features that contradict these principles need a very good reason.

1. **Fail-closed authorization** — any evaluation error returns `Deny`. Cedar's permissive defaults are overridden by explicit schema validation.
2. **DST-first** — every component that touches time, randomness, or I/O must be injectable. `MockRng`, `MockClock`, and `MockRegistry` exist so tests never depend on wall time or system entropy.
3. **Trait-based extensibility** — `AuthnBackend`, `SessionRegistry`, `SecureRng`, `Clock` are all traits. Users implement the interface; we provide the orchestration.
4. **No application knowledge in library crates** — role taxonomies, permission names, Cedar namespaces for specific applications all belong in the consuming application, not here.
5. **Explicit over magic** — prefer verbose but auditable code over clever macros that obscure the security boundary.

---

## What is done

### Core authentication flow
- [x] `AuthState` state machine: `NotAuthenticated → PartialAuthn → Authenticated → PendingWorkflow`
- [x] Session ID cycling on authentication (session fixation prevention)
- [x] `AuthnBackend` trait — connect any database or identity provider
- [x] Multi-factor method composition: factors are chained; all must pass in order
- [x] `SessionRegistry` trait + in-memory `MockRegistry` — forced logout per user or tenant
- [x] Audit logging: all state transitions emit `AuthEventRecord` via the backend trait

### Authentication factors (`axess-factors`)
- [x] Password factor — argon2id hashing, constant-time verification, zeroize on drop
- [x] TOTP factor — RFC 6238, configurable window, replay protection via `last_totp_step`
- [x] HOTP factor — RFC 4226, counter-based, atomic increment before return
- [x] Random secret generation — `SecureRng`-injectable, no direct `OsRng` calls

### Authorization (`axess-core`)
- [x] Cedar Policy evaluation — `PolicyStore` (compiled policy set + schema + authorizer)
- [x] `PolicyEvaluator` trait — injectable; `MockPolicyEvaluator` for DST tests without policy files
- [x] `AuthzEntityProvider` trait — application implements entity graph materialisation; decouples DB schema from Cedar
- [x] `AuthzStore` — holds evaluator, provider, configurable Cedar namespace; UID builder methods (`user_uid`, `role_uid`, `action_uid`, `tenant_uid`, `entity_uid`)
- [x] `AuthzSession` — per-request handle with `require`, `is_permitted`, `batch_check`; request-scoped entity cache deduplicates repeated checks
- [x] `BuildRequestContext` trait + `StandardRequestContext` — ABAC context (MFA status, IP, timestamp) passed to Cedar; `NoContext` zero-overhead default
- [x] RBAC via Cedar — `principal in Role::"name"` patterns
- [x] ReBAC via Cedar — `resource has owner && resource.owner == principal` patterns
- [x] ABAC via Cedar context — `context.mfa_verified`, `context.ip_address`, `context.timestamp`
- [x] Fail-closed: any error in entity building, UID construction, or Cedar evaluation returns `Deny`
- [x] Configurable Cedar namespace — set per application via `AuthzStore::new`

### Session management
- [x] SQLite session backend (via `tower-sessions-sqlx-store`)
- [x] `AuthSession` Axum extractor — typed session state access in handlers
- [x] Session expiry (hardcoded 3600 s — see planned work)
- [x] Hash-bound session validation (session cookie bound to fingerprint hash)

### Multi-tenancy
- [x] Three-tier scope hierarchy: Global → Tenant → User
- [x] Factor configuration resolves scope: User overrides Tenant overrides Global
- [x] `AuthnBackend::get_factor_config` supports all three scopes

### Testing infrastructure
- [x] `MockBackend` — in-memory `AuthnBackend` implementation for unit tests
- [x] `MockRng` — deterministic byte source implementing `SecureRng`
- [x] `MockRegistry` — in-memory session registry implementing `SessionRegistry`
- [x] `MockClock` — injectable wall-clock implementing `Clock` trait

### Middleware and macros (`axess`, `axess-macros`)
- [x] `AuthnLayer` — tower middleware injecting session state into request extensions
- [x] `#[require_authn]` and `#[require_permission]` proc-macros for route-level guards
- [x] Request ID injection middleware
- [x] Trace ID propagation middleware

---

## In progress

### Valkey encrypted session backend
**Status:** AES-256-GCM encryption wired; session read/write path incomplete.
The `valkey` feature flag builds but the backend is not production-ready.

- [ ] Complete `ValkeySessions::load` / `save` / `delete` round-trip
- [ ] Key rotation support (decrypt with old key, re-encrypt with new key on read)
- [ ] Cluster-aware connection pool (currently single-node only)
- [ ] Integration test: session survives a Valkey restart with key rotation

**Why this matters:** SQLite session storage is durable but contended under concurrent writes. Valkey removes that contention and enables horizontal scaling.

---

## Planned

### Authorization example
**Priority: High**
The SQLite example demonstrates authentication but not authorization. A working `AuthzEntityProvider` implementation with Cedar policies and schema would be the primary onboarding reference.

- [ ] Add `AuthzEntityProvider` implementation to `examples/sqlite` backed by the SQLite schema
- [ ] Add Cedar policy file + JSON schema to `examples/sqlite/policies/`
- [ ] Demonstrate RBAC, ReBAC, and a simple ABAC (MFA) check in the example handlers
- [ ] Show `MockPolicyEvaluator` usage in the example's test suite

### Session expiry as configuration parameter
**Priority: High**
The session TTL is a hardcoded constant. Any application that needs a different TTL must patch the library.

- [ ] Expose `session_ttl: Duration` on the middleware builder
- [ ] Thread it through to both the SQLite store and (when ready) the Valkey backend
- [ ] Document the idle vs absolute expiry distinction

### Account lockout — complete enforcement
**Priority: High**
`AuthnBackend::max_auth_attempts` is defined and respected in password verification. It is not consistently enforced for factor setup flows and HOTP counter desync recovery.

- [ ] Audit every auth flow that calls `record_failed_attempt`; verify lockout fires in all paths
- [ ] Lockout for factor setup attempts (not just login)
- [ ] Configurable lockout window (currently permanent until manual reset)
- [ ] Unlock workflow — admin-initiated or time-based unlock

### Signup flow
**Priority: Medium**
The `AuthState` flowchart documents a `PendingWorkflow(Signup)` state but the library provides no implementation. Each application currently implements signup from scratch.

- [ ] Define `SignupBackend` sub-trait (or extend `AuthnBackend`) with `create_principal`, `set_initial_factor`
- [ ] Provide a default `SignupOrchestrator` that drives the state machine
- [ ] Integrate with the existing `axess-macros` guards so that `PendingWorkflow(Signup)` routes can be declared declaratively

### FIDO2 (WebAuthn + hardware security keys)
**Priority: Medium**
FIDO2 is the umbrella standard covering WebAuthn (the W3C browser/RP protocol) and CTAP2 (the protocol spoken by roaming hardware authenticators — YubiKeys, FIDO2 USB/NFC/BLE keys). Both surface in Axess as a `FactorKind` variant; the difference is in the credential and authenticator types involved.

**Concepts to get right before coding:**
- *Platform authenticators* — bound to a device (Touch ID, Face ID, Windows Hello). Credentials can be *discoverable* (resident), enabling passwordless "just press your fingerprint" flows.
- *Roaming authenticators* — hardware security keys (CTAP2). Same WebAuthn registration/authentication ceremony, but the credential lives on the physical key.
- *Passkeys* — a specific profile of discoverable WebAuthn credentials, designed to sync across devices via the OS keychain (Apple, Google, Microsoft ecosystems). They are a subset of FIDO2, not a synonym.
- *User verification (UV)* — whether the authenticator verifies the user locally (PIN, biometric). Must be required for passwordless; can be preferred for MFA second-factor use.
- *Attestation* — the authenticator's proof of its own identity and model. Useful for high-assurance applications (e.g., requiring a specific YubiKey model). Usually `none` for consumer passkeys.
- *FIDO MDS (Metadata Service)* — FIDO Alliance's registry of authenticator metadata; used to validate attestation statements when attestation is required.

**Scope for Axess:**
Axess implements the *relying party* (RP) side only. Browser/client-side JavaScript (the `navigator.credentials` API) and the authenticator hardware are outside scope.

**Tasks:**
- [ ] Add `fido2` feature flag (pulls in `webauthn-rs` crate — covers both WebAuthn and CTAP2 RP logic)
- [ ] `FactorKind::Fido2 { uv_required: bool, attachment: Option<AuthenticatorAttachment> }` — a single variant parameterised by requirements, covering both platform and roaming authenticators
- [ ] Registration ceremony: `begin_registration` / `finish_registration` handlers; return and consume `PublicKeyCredentialCreationOptions`
- [ ] Authentication ceremony: `begin_authentication` / `finish_authentication` handlers; return and consume `PublicKeyCredentialRequestOptions`
- [ ] `AuthnBackend` extension methods: `store_credential`, `load_credentials`, `update_credential_counter` (counter monotonicity is a clone-detection mechanism for hardware keys)
- [ ] Discoverable credential / passwordless flow: if the user has a passkey with UV, allow the credential assertion to stand in for the password factor entirely — `AuthState` should reach `Authenticated` after a single FIDO2 step
- [ ] Attestation handling: default `none`; `direct` (and MDS validation) as an opt-in feature flag `fido2_attestation`
- [ ] `MockFido2Factor` implementing the same `SecureRng` / `Clock` injection pattern used by TOTP — tests should not require a real authenticator
- [ ] `examples/fido2` — complete registration + login example with a minimal HTML/JS frontend fragment showing `navigator.credentials` usage
- [ ] Document the security properties: origin binding (phishing-resistant by design), counter-based clone detection, UV requirement implications

### Typed config accessors
**Priority: Medium**
Factor configuration is passed around as `HashMap<String, serde_json::Value>`. Callers do manual `.get("field")` with fallback conversions, which is error-prone and untestable.

- [ ] Introduce `TotpConfig`, `HotpConfig`, `PasswordConfig` structs with `TryFrom<&FactorConfig>`
- [ ] Replace all manual map lookups with typed accessors
- [ ] Add validation at the point of config construction, not at use

### Session registry — persistent backend
**Priority: Medium**
`MockRegistry` is in-memory and evicted on restart. Forced logout requires a durable store to survive restarts.

- [ ] Implement `ValKeyRegistry` using Valkey sorted sets (TTL-based cleanup)
- [ ] Provide migration path from `MockRegistry` for small deployments

### crates.io publication
**Priority: Low (deferred until API stabilises)**
API is still changing. Publishing too early locks in bad decisions.

Prerequisites before publishing:
- [ ] Stable public API with semver guarantees (target: `v0.1.0`)
- [ ] Configurable Cedar namespace (breaks current implicit `"Ekekrantz"` assumption)
- [ ] Session expiry as parameter (current hardcoded value is a breaking change waiting to happen)
- [ ] At least one integration test covering the full login + TOTP flow against a real SQLite file
- [ ] `CHANGELOG.md` maintained from this point forward

### Email OTP factor
**Priority: Low**
Designed for but not implemented. Email OTP is useful as a recovery path when the user loses their TOTP device.

- [ ] Implement `EmailOtpFactor` — generate, send, and verify a short-lived numeric code
- [ ] Rate limiting: max N sends per hour per user
- [ ] `AuthnBackend` extension: `send_otp_email(principal, code, expiry)`

### Integration test suite
**Priority: High for before crates.io publication**
Unit tests cover individual components well. End-to-end flows (login → MFA → forced logout → re-login) are not covered.

- [ ] Full login flow: password → TOTP → session established
- [ ] Forced logout: registry invalidation causes subsequent requests to return 401
- [ ] Session fixation: verify session ID changes after successful authentication
- [ ] Lockout: N+1 failed attempts returns locked error and stays locked
- [ ] TOTP replay: re-using a valid TOTP code within the same time step is rejected

### OAuth 2.0 / OIDC provider
**Priority: Low**
Axess currently handles only first-party (credential-based) authentication. Adding OAuth 2.0 would allow users to log in via external identity providers (Google, GitHub, enterprise IdP) as an alternative or additional factor.

- [ ] Design: OAuth login should produce the same `Authenticated` session state as password + TOTP; the `AuthnBackend` trait needs an `exchange_oauth_code` hook
- [ ] Feature flag: `oauth` — pulls in `oauth2` crate
- [ ] PKCE support (required for public clients)
- [ ] OIDC discovery (`/.well-known/openid-configuration`) so provider config is not hardcoded
- [ ] Link external identity to an existing principal (account linking), not just auto-create
- [ ] Note: this makes axess an OAuth *relying party*, not an authorization server — building a full AS is a separate, much larger undertaking

### PostgreSQL session / registry backend
**Priority: Low**
SQLite is the primary target. PostgreSQL is relevant for deployments that already run Postgres and do not want a separate SQLite file, or for multi-node write-heavy configurations.

- [ ] Feature flag: `postgres` — `tower-sessions-sqlx-store` already has a Postgres variant
- [ ] `PostgresRegistry` implementing `SessionRegistry` via a `session_invalidations` table
- [ ] Ensure connection pool configuration is exposed through the middleware builder (not hardcoded)
- [ ] Integration test running against a real Postgres instance in CI (Docker service)

### Headless management API (optional, scope-expanding)
**Priority: Speculative — decide after ekekrantz experience**
Rather than a UI, `axess` could optionally expose a set of Axum route handlers for user management operations (create user, assign factor, reset password, revoke session, list active sessions). This would make it possible to wire a frontend — or a CLI tool — to a standard interface without re-implementing the logic in every application.

The framing to keep in mind: this is the direction of products like Keycloak, Ory Kratos, and Supertokens, but as a *library* rather than a standalone service. It sidesteps the operational cost of running a separate auth service while offering more than a bare trait.

Design considerations:
- [ ] Implement as a feature-gated `axess-admin` sub-crate (keeps the core small)
- [ ] Handlers as plain Axum `Router` fragments the application can mount at any path
- [ ] Default implementations via trait methods — override to add application-specific logic
- [ ] JSON API only; no server-side HTML — rendering is the application's concern
- [ ] WASM packaging is probably not warranted; a clean JSON API consumed by any frontend is simpler and more composable
- [ ] Gating: admin endpoints must themselves be protected by Cedar policy — uses the same authz infrastructure, not a separate mechanism

---

## Not planned (and why)

| Feature | Reason |
|---|---|
| JWT-based sessions | Stateless JWTs make forced logout and session registry semantics impossible without a deny-list, which reintroduces statefulness. Session cookies are the right choice here. |
| Built-in user management UI | Rendering belongs in the application. A headless JSON API (see above) is the right boundary. |
| Role taxonomy / permission names | Application-specific concerns; see `AuthzError::InvalidEntityUid` for why they must not live here. |
| Full OAuth Authorization Server | Building a compliant AS (issuing tokens, managing clients, consent flows) is an entirely different product. That is Keycloak/Ory Hydra territory, not a middleware library. |
