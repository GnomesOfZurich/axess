# Axess — Roadmap

> **Current version:** `v0.0.14` — pre-release, not yet published to crates.io.
> This document tracks what is done, what is in progress, and what is planned.
> It is intentionally opinionated: it records *why* each item is or is not a priority, not just what needs doing.

---

## Design principles (non-negotiable)

These govern every change. New features that contradict these principles need a very good reason.

1. **Fail-closed authorization** — any evaluation error returns `Deny`. Cedar's permissive defaults are overridden by explicit schema validation.
2. **DST-first** — every component that touches time, randomness, or I/O must be injectable. `MockRng`, `MockClock`, and `MemorySessionRegistry` exist so tests never depend on wall time or system entropy.
3. **Trait-based extensibility** — `IdentityStore`, `FactorStore`, `SessionStore`, `SessionRegistry`, `SecureRng`, `Clock`, `PolicyEvaluator`, `AuthzEntityProvider` are all traits. Users implement the interface; we provide the orchestration.
4. **No application knowledge in library crates** — role taxonomies, permission names, Cedar namespaces, email templates all belong in the consuming application, not here.
5. **Explicit over magic** — prefer verbose but auditable code over clever macros that obscure the security boundary.

---

## What is done

### Core authentication flow
- [x] `AuthState` state machine: `Guest → Identifying → Authenticating → Authenticated → PendingWorkflow`
- [x] `AuthnService` orchestrator with 3-step flow: `begin_login` → `prepare_factor` → `verify_factor`
- [x] `IdentityStore` trait — user/tenant lookup, account status, lockout, audit events (8 required methods)
- [x] `FactorStore` trait — load/save factor config, available methods (3 required methods)
- [x] `AuthnBackend` convenience supertrait — blanket impl for `IdentityStore + FactorStore`
- [x] Multi-factor method composition: factors are chained; all must pass in order
- [x] `PrepareOutcome` for challenge-based factors: `Ready`, `SendOtp`, `AlreadySent`, `Fido2Challenge`
- [x] `LoginOutcome` / `FactorOutcome` typed enums for clean handler pattern matching
- [x] Lockout enforcement via DB counter exclusively — not bypassable via new session
- [x] Failed-attempt counter only resets after ALL factors pass (prevents brute-force of later factors)
- [x] Two-step identify flow with documented user-enumeration trade-off
- [x] Audit logging: `AuthEvent` / `AuthEventBuilder` with injectable clock timestamps

### Authentication factors (`axess-factors`)
- [x] Password factor — Argon2id hashing, constant-time verification, zeroize on drop
- [x] TOTP factor — RFC 6238, configurable window, replay protection via `last_step`, constant-time code comparison
- [x] HOTP factor — RFC 4226, counter-based with lookahead window, constant-time comparison, counter persisted via `PassWithUpdate`
- [x] Email OTP factor — `prepare_factor` generates code via injectable RNG, hashes with Argon2id, stores with TTL-based expiry; cooldown prevents email bombing; `verify_factor` checks hash + expiry and clears pending state
- [x] Typed `FactorConfig` enum — `Password`, `Totp`, `Hotp`, `EmailOtp`, `Fido2` (no `HashMap<String, JsonValue>`)
- [x] `ZeroizedString` for all secrets in memory (password hashes, OTP secrets)
- [x] `FactorCredential` enum — typed credentials for each factor kind
- [x] OTP code generation with rejection sampling (no modulo bias)
- [x] Random secret generation — `SecureRng`-injectable, no direct `OsRng` calls

### Authorization (`axess-core`, feature-gated)
- [x] Cedar Policy evaluation — `PolicyStore` (compiled policy set + schema + authorizer)
- [x] `PolicyEvaluator` trait — injectable; `MockPolicyEvaluator` for DST tests without policy files
- [x] `AuthzEntityProvider` trait — application implements entity graph materialisation
- [x] `AuthzStore` — holds evaluator, provider, configurable Cedar namespace; UID builder methods
- [x] `AuthzSession` — per-request handle with `require`, `is_permitted`, `batch_check`; request-scoped entity cache
- [x] `BuildRequestContext` trait + `StandardRequestContext` — ABAC context with injectable clock (`::new()` for production, `::at()` for DST)
- [x] RBAC, ReBAC, ABAC patterns via Cedar
- [x] Fail-closed: any error in entity building, UID construction, or evaluation returns `Deny`

### Session management (custom Tower middleware)
- [x] Custom `SessionLayer` — HMAC-SHA256 signed cookies, typed `SessionData`, one serialize/deserialize per request
- [x] `SessionId` — UUID v4, 16 bytes stack-allocated, generated via injectable `SecureRng`
- [x] `SessionStore` trait + `MemorySessionStore` (DashMap-backed) + `SqliteSessionStore`
- [x] `SessionRegistry` trait + `MemorySessionRegistry` (DashMap-backed) — forced logout per user
- [x] Session ID cycling on authentication and logout (session fixation prevention)
- [x] Cookie: `HttpOnly`, `Secure`, `SameSite=Lax`, `Max-Age` matching store TTL
- [x] Configurable TTL via `SessionLayer::with_ttl()`
- [x] Conditional `Set-Cookie` — only written when session is modified or new
- [x] Constant-time HMAC verification via `subtle::ConstantTimeEq`
- [x] Signing key zeroized on drop
- [x] Cookie parsing via `cookie` crate (not hand-rolled)
- [x] `AuthSession` Axum extractor — zero generics, typed session state access
- [x] `SessionInner.modified`/`.regenerate` are `pub(crate)` — external code cannot bypass session integrity
- [x] `check_session` method for registry validation (documented `from_fn` middleware pattern)
- [x] Fingerprint hash field in `SessionData` for session binding

### Multi-tenancy
- [x] Three-tier scope hierarchy: Global → Tenant → User
- [x] Factor config resolution: User → Tenant → Global fallback (with Global as final fallback)
- [x] Per-user mutable state (TOTP `last_step`, HOTP `counter`) saved to user scope even when config inherited from higher scope

### Testing infrastructure
- [x] `MockIdentityStore` / `MockFactorStore` — in-memory implementations for unit tests
- [x] `MockRng` — deterministic byte source implementing `SecureRng`
- [x] `MemorySessionStore` / `MemorySessionRegistry` — DashMap-backed in-memory implementations
- [x] `MockClock` — injectable wall-clock with `advance_secs()` and `set()`
- [x] `MockPolicyEvaluator` / `MockEntityProvider` — DST-compatible authz testing without Cedar files

### Middleware and macros (`axess`, `axess-macros`)
- [x] `login_required!()` — Axum middleware macro, zero type parameters, with optional redirect URL
- [x] `require_partial_authn!()` — guards MFA factor-verification routes
- [x] `predicate_required!()` — general-purpose predicate middleware base
- [x] Request ID injection middleware (`request_id` feature)
- [x] Trace ID propagation middleware (`trace_id` feature)

### DST (Deterministic Simulation Testing)
- [x] `Clock` trait with `SystemClock` and `MockClock` implementations
- [x] `SecureRng` trait with `SystemRng` and `MockRng` implementations
- [x] `AuthnService<I, F, R, C>` generic over RNG and Clock with `with_rng()` / `with_clock()` builders
- [x] All timestamps in auth flows use injectable clock (no `Utc::now()` in library code)
- [x] `StandardRequestContext::at()` for DST-controlled authz timestamps
- [x] `WorkflowState::new()` accepts explicit timestamp

---

## In progress

### Valkey session backend
**Status:** Feature flag exists but emits `compile_error!` — the old `tower-sessions` implementation was removed during the rewrite. A new implementation against the `SessionStore` trait is needed.

- [ ] Implement `ValkeySessionStore` implementing `crate::session::store::SessionStore`
- [ ] Implement `ValkeySessionRegistry` implementing `crate::session::store::SessionRegistry`
- [ ] AES-256-GCM encryption of session data at rest
- [ ] Key rotation support (decrypt with old key, re-encrypt with new key on read)
- [ ] Cluster-aware connection pool via `fred` crate
- [ ] Integration test: session survives a Valkey restart with key rotation

**Why this matters:** `MemorySessionStore` is lost on restart. `SqliteSessionStore` is durable but contended under concurrent writes. Valkey removes that contention and enables horizontal scaling.

---

## Planned

### Integration test suite
**Priority: High — required before crates.io publication**

The library has 5 unit tests (SessionId and RNG determinism). The security-critical authentication logic is verified only by code review, not by automated tests. This is the most significant quality gap.

- [ ] Full login flow: `begin_login` → `prepare_factor` → `verify_factor(password)` → `verify_factor(totp)` → session is `Authenticated`
- [ ] Email OTP flow: `prepare_factor` returns `SendOtp`, `verify_factor` with correct/wrong/expired code
- [ ] Email OTP cooldown: second `prepare_factor` within TTL returns `AlreadySent`
- [ ] Lockout: N+1 failed attempts returns `Locked` and stays locked
- [ ] Lockout counter not reset per-factor: password success + TOTP failures across multiple `begin_login` cycles accumulates correctly
- [ ] TOTP replay: re-using a valid code within the same time step is rejected
- [ ] HOTP counter: counter advances past matched value, old counter values rejected
- [ ] Session fixation: session ID changes after successful authentication
- [ ] Forced logout: registry invalidation causes `check_session` to return `false`
- [ ] Scope fallback: user → tenant → global factor config resolution
- [ ] `MockClock` / `MockRng` determinism: same seed produces same session IDs and OTP codes

### Update SQLite example to new API
**Priority: High**

The `examples/sqlite` project references the old `tower-sessions` API, `AuthnServiceBuilder`, generic `AuthSession<Backend, Registry, Rng>`, and proc-macros that no longer exist. It needs a full rewrite against the current `SessionLayer` + `AuthnService` + zero-generic `AuthSession` API.

- [ ] Rewrite `main.rs` to use `SessionLayer::new(store, signing_key)` + `AuthnService::new(identity, factors)`
- [ ] Implement `IdentityStore` and `FactorStore` for the SQLite backend (replacing `AuthnBackend`)
- [ ] Update handlers to use `AuthSession` (no generics) and the `begin_login` → `prepare_factor` → `verify_factor` flow
- [ ] Update README to reflect the new API and remove all `tower-sessions` references
- [ ] Add Cedar authorization example (`AuthzEntityProvider` + policies + schema)

### Authorization example
**Priority: High**

No working example demonstrates the Cedar authorization layer. This is the primary onboarding gap for new users evaluating the library.

- [ ] Add `AuthzEntityProvider` implementation to the SQLite example
- [ ] Add Cedar policy file + JSON schema to `examples/sqlite/policies/`
- [ ] Demonstrate RBAC, ReBAC, and ABAC (MFA context) checks in example handlers
- [ ] Show `MockPolicyEvaluator` usage in the example's test suite

### FIDO2 (WebAuthn + hardware security keys)
**Priority: Medium**

`FactorKind::Fido2` and `Fido2Config` exist as placeholders. `verify_credential` returns `Fail` for FIDO2. `PrepareOutcome::Fido2Challenge` exists but is never produced.

- [ ] Add `fido2` feature flag (pulls in `webauthn-rs`)
- [ ] Registration ceremony: `prepare_factor` returns `Fido2Challenge` with `PublicKeyCredentialCreationOptions`
- [ ] Authentication ceremony: `verify_factor` validates the assertion
- [ ] `FactorStore` extension: `store_credential`, `load_credentials`, `update_credential_counter`
- [ ] Discoverable credential / passwordless flow
- [ ] Attestation handling: default `none`; `direct` as opt-in
- [ ] `MockFido2Factor` for DST

### Signup flow
**Priority: Medium**

`AuthState::PendingWorkflow(Signup)` and `WorkflowState::new()` exist but the library provides no orchestration. Each application currently implements signup from scratch.

- [ ] Define signup trait methods on `IdentityStore` (`create_user`, `set_initial_factor`)
- [ ] Provide a default `SignupOrchestrator` that drives the `PendingWorkflow` state machine
- [ ] Integrate with `require_partial_authn!()` for signup route guards

### OAuth 2.0 / OIDC relying party
**Priority: Low**

Axess currently handles only first-party (credential-based) authentication. `FactorKind::Federated(provider)` exists as a variant but has no implementation.

- [ ] Feature flag: `oauth` — pulls in `oauth2` crate
- [ ] PKCE support (required for public clients)
- [ ] OIDC discovery (`/.well-known/openid-configuration`)
- [ ] Link external identity to existing user (account linking)
- [ ] Produce the same `Authenticated` session state as password + TOTP

### crates.io publication
**Priority: Low (deferred until API stabilises)**

Prerequisites before publishing:
- [ ] Stable public API with semver guarantees (target: `v0.1.0`)
- [ ] Integration test suite passing (see above)
- [ ] SQLite example updated and working against current API
- [ ] `CHANGELOG.md` maintained from this point forward

### Headless management API
**Priority: Speculative — decide after ekekrantz experience**

Optional Axum route handlers for user management (create user, assign factor, reset password, revoke session). Library-as-a-service rather than library-as-a-framework.

- [ ] Feature-gated `axess-admin` sub-crate
- [ ] Handlers as Axum `Router` fragments mountable at any path
- [ ] JSON API only; no server-side HTML
- [ ] Admin endpoints protected by Cedar policy

---

## Not planned (and why)

| Feature | Reason |
|---|---|
| JWT-based sessions | Stateless JWTs make forced logout and session registry semantics impossible without a deny-list, which reintroduces statefulness. Signed session cookies are the right choice. |
| Built-in user management UI | Rendering belongs in the application. A headless JSON API (see above) is the right boundary. |
| Role taxonomy / permission names | Application-specific; Cedar namespace is configurable via `AuthzStore::new`. |
| Full OAuth Authorization Server | Building a compliant AS is an entirely different product (Keycloak/Ory Hydra territory). |
| PostgreSQL backend | SQLite is the primary target. Applications needing Postgres can implement `SessionStore` against their pool. |
| `tower-sessions` integration | Removed in v0.0.14. The custom `SessionLayer` with HMAC-signed cookies is simpler, has fewer dependencies, and provides typed `SessionData` with one ser/de per request. |
