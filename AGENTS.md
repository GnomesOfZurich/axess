# axess Agent Guide

This file is the canonical, repo-shared instruction source for AI coding agents and automation helpers working in this repository.

Tool-specific files should stay thin and point back here:

- `.claude/CLAUDE.md`
- `.github/copilot-instructions.md`

If project guidance changes, update this file first and only keep tool-specific deltas in the adapters.

## Overview

axess is a modular, policy-driven authentication and authorization library for the Axum web framework in Rust. Multi-factor authentication with an explicit session state machine, Cedar Policy authorization (RBAC + ABAC + ReBAC), and deterministic simulation testing (DST) from the ground up.

Rust edition `2024`, MSRV `1.87`, latest stable toolchain.

## Core Boundaries

Keep these boundaries intact:

- **axess-core = orchestrator, axess-factors = verifiers.** axess-factors holds per-credential algorithms + data (e.g. `Fido2Config`, `LdapBindFactorConfig`); axess-core holds the sum types that compose them (`FactorKind`, `FactorConfig`, `FactorCredential`, `FactorStep`, `FederatedProvider`). On-behalf-of (OBO) access lives in `axess-core/src/delegated/` and is exposed as `axess_core::delegated` behind the `delegated-*` features.
- **Defaults run zero-infra.** Infra-bound features (`sqlite`, `postgres`, `valkey`, `ldap`, etc.) stay opt-in. Hard rule.
- **All non-determinism is injectable.** Production code depends on traits; tests inject deterministic implementations.

## Repository Map

10 crates. One facade + one orchestrator + one verifier crate hold most public surface; the rest are foundation / specialised carve-outs.

```
axess/              Facade crate. Re-exports the public API from
                    axess-core + axess-factors. Adopters depend on this.

axess-core/         Orchestrator. Session state machine, AuthnService,
                    AuthzStore (Cedar), middleware (csrf / ratelimit /
                    request_id / trace_id), session storage
                    backends, principal abstraction, workload identity,
                    LocalIdp, OBO delegated access, store unification.

axess-factors/      Verifiers. Every per-credential algorithm:
                    password (Argon2id), TOTP, HOTP, email OTP, FIDO2,
                    LDAP bind, mTLS, OAuth/OIDC (incl. discovery + JWKS
                    cache + logout-token claim validation), JWT
                    validation (incl. JWT-SVID), generic workload-identity
                    resolver (single `WorkloadResolver` with adopter-
                    supplied claim mapping closure; covers GitHub
                    Actions, k8s SA, GitLab CI, Okta, Azure AD, …),
                    plain-OAuth-2.0 social login (`SocialProvider`,
                    weaker security model than OIDC; gated on
                    `social`, off by default), bearer token extractor,
                    outbound OAuth client. PKCE + secret helpers.
                    axess-core composes these into methods.

axess-cache/        ClockTtlCache. Asymmetric defaults: cache authz
                    decisions, do not cache authn.

axess-clock/        Clock trait + SystemClock + testing::MockClock.
                    DST foundation; production code injects the trait.

axess-rng/          SecureRng trait + SystemRng + testing::MockRng.
                    DST foundation.

axess-identity/     Typed IDs (UserId, TenantId, WorkloadId,
                    Principal enum). Strict UUID parsing. Shared
                    across every other crate.

axess-events/       Event types and (forthcoming) async sinks.

axess-strings/      Shared string newtypes / helpers.

axess-macros/       require_authn!, require_partial_authn!,
                    require_authz! procedural macros.

examples/
  sqlite/    reference app: SQLite sessions + full auth flow
  oauth/     OAuth 2.0 / OIDC login
  authz/     Cedar Policy authorization
  fapi/      FAPI 2.0 (PAR, DPoP, JARM, RP-initiated logout)
  device/    device identity (Unknown → Seen → Trusted ladder)
  local_idp/ in-process IdP minting workload-identity JWTs
```

axess-core's `src/` layout (top-level modules):

```
authn/       authn-flow primitives + AuthnService orchestrator
authz/       Cedar Policy authorization
federation/  external-IdP / federation surface (OAuth, LDAP, FIDO2, JWT,
             mTLS, OIDC, PKCE, back/front-channel logout, federation
             adapters)
device/      first-class device identity (ladder + cascade + storage)
session/     state machine, layer, storage backends, refresh, codec
store/       generic Store<K,V> trait
principal/   AuthPrincipal { Human | Workload }
workload/    workload-identity hub
delegated/   OBO access (RFC 6749 §4.1 + RFC 8693)
local_idp/   in-process IdP (feature local-idp)
middleware/  Axum/Tower middleware
testing/     DST mocks + fixtures (always-on)
```

## Coding Rules

- `snake_case` functions, `CamelCase` types.
- `async`/`await` for all IO.
- `thiserror` for errors. Never `anyhow`.
- `tracing` for logging. `#[tracing::instrument]` on public async methods. Skip sensitive fields.
- Prefer traits for abstraction over concrete types.
- All code supports DST: depend on traits, not concrete implementations.
- **No lint suppressions.** Never use `_` prefixes on unused variables, `#[allow(...)]`, `#[allow(clippy::...)]`, or equivalent. Fix the root cause: remove unused params/fields/code, extract structs for too-many-args, etc.
- **No `#[non_exhaustive]`.** Bump semver instead. CI guard (`ban_non_exhaustive`) rejects PRs that add it.
- **No `cargo-mutants` markers** in committed source. CI guard (`ban_cargo_mutants_markers`) rejects the literal `~ changed by cargo-mutants ~` string in first-party `*.rs` files. Use `scripts/mutants.sh` to run mutations in an isolated git worktree.

## Naming Conventions

### Type prefixes

| Prefix | Scope | Examples |
|--------|-------|----------|
| `Authn*` | Authentication-layer-specific | `AuthnService`, `AuthnError`, `AuthnScope`, `AuthnBackend` |
| `Auth*` | Shared across authn and authz | `AuthSession`, `AuthState`, `AuthEvent`, `AuthMethod`, `AuthPrincipal` |
| `Authz*` | Authorization-layer-specific | `AuthzStore`, `AuthzSession`, `AuthzDecision`, `AuthzError` |

### Type suffixes

| Suffix | Meaning | Examples |
|--------|---------|----------|
| `*Outcome` | Multi-variant result from an authn operation | `LoginOutcome`, `FactorOutcome`, `SignupOutcome` |
| `*Decision` | Binary allow/deny verdict from policy engine | `AuthzDecision` |
| `*Config` | Configuration / parameters | `SessionConfig`, `TotpConfig`, `RateLimitConfig` |
| `*Store` | Persistence trait or implementation | `SessionStore`, `IdentityStore`, `ValkeySessionStore`, `DeviceStore` |
| `*Registry` | Session validity tracking | `SessionRegistry`, `MemorySessionRegistry` |
| `*Provider` | External integration trait | `OAuthProvider`, `Fido2Provider`, `AuthzEntityProvider`, `LdapProvider` |
| `*Resolver` | Extract typed value from request | `DeviceResolver`, `PrincipalResolver`, `SessionResolver` |
| `*Error` | Error type | `AuthnError`, `OAuthError`, `CryptoError`, `OidcError` |
| `*Builder` | Builder pattern | `SessionConfigBuilder`, `AuthEventBuilder`, `SweepConfigBuilder` |

### Method verb conventions

| Verb | Semantics | Examples |
|------|-----------|----------|
| `get_*` | Lookup by primary key, deterministic, O(1) | `get_user(id)` |
| `find_*` | Search by business criteria, may scan | `find_user(identifier, tenant)` |
| `load_*` / `save_*` | Deserialize/serialize persisted state | `load_factor(scope, kind)` |
| `begin_*` / `complete_*` | Multi-step ceremony start/finish | `begin_login()`, `complete_oauth_login()` |
| `verify_*` | Check a credential or assertion | `verify_factor()` |

### Visibility

Internal types for cross-module access within `axess-core` (e.g. `SessionHandle`, `SessionInner`, `LoadOutcome`, `FinalizeOutcome`) should be `pub(crate)`, not `pub`. The public API surface is defined by re-exports in `lib.rs`. Default new types to `pub(crate)`; promote on concrete demand.

## Architecture Essentials

### Session State Machine

Authentication progresses through typed states: `Guest → Identifying → Authenticating → Authenticated` (plus `PendingWorkflow`). The `AuthState` enum enforces valid transitions at the type level. Pure state mutation lives in `pub(crate)` inherent methods on `AuthState`; `AuthSession`'s async wrappers hold the `RwLock`, delegate, and dispatch orchestration (id rotation, fingerprint binding, dirty flag) on `AdvanceOutcome`.

### Session layer / state machine shape

Vocabulary for the load → finalize → cookie pipeline and the typed `AuthState` machine; match this shape when extending or reviewing session-related code:

- **`load_session` / `finalize_session` / `build_set_cookie`**; three `pub(crate)` free helpers in `session/layer.rs` that compose `SessionService::call()`. The free-helper shape is deliberate; no `SessionLifecycle` struct or `LifecycleRequest` trait wraps them.
- **`LoadOutcome` / `FinalizeOutcome`**; `pub(crate)` outcome types in `session/layer.rs`. The invariant "handler never runs under a client-supplied id we don't trust the data behind" lives in `existing_id: Option<SessionId>` (`Some` only when fully trusted).
- **`SessionCodec`**; `pub(crate)` struct in `session/storage/session_codec.rs` owning MessagePack serialization + optional AES-256-GCM envelope via `SessionCrypto`. All three encrypted backends (SQLite, Postgres, Valkey) share this one codec contract.
- **`AuthState` transition methods**; `pub(crate)` inherent methods on `AuthState` own the pure state mutation; `AuthSession`'s async wrappers hold the `RwLock`, delegate to those, and dispatch orchestration on `AdvanceOutcome { NotApplicable, StillAuthenticating, Completed }`.

### Multi-Factor Authentication

Factors (password, TOTP, HOTP, email OTP, FIDO2, OAuth/OIDC, LDAP, mTLS, bearer JWT) compose into methods via `FactorStep`. A method is a sequence of steps; each step is either a single factor or `AnyOf(factors)` (user's choice). Methods can vary per tenant or user via the three-tier scope hierarchy (Global, Tenant, User).

### Cedar Policy Authorization

`AuthzStore` loads Cedar policies at startup, validates them against a schema, and evaluates deny-by-default. The application provides entity graphs per request via `AuthzEntityProvider`. `StandardRequestContext` makes MFA status and IP available as Cedar context for ABAC policies.

### Device identity

`device` feature adds first-class device identity with a three-stage assurance ladder (`Unknown` → `Seen` → `Trusted`, plus terminal `Revoked`), per-tenant fingerprint pepper, refresh-family cascade revocation, retention sweep, and a `CachedDeviceStore` decorator. Backends under `SqliteDeviceStore` / `PostgresDeviceStore` / `MysqlDeviceStore` / `ValkeyDeviceStore`. Step-up policy lives in `axess_core::authn::service::step_up`.

### Deterministic Simulation Testing (DST)

All non-determinism is injectable. Production code depends on traits; tests inject deterministic implementations.

| Trait | Production | Test Mock | Crate |
|-------|-----------|-----------|-------|
| `Clock` | `SystemClock` | `MockClock` (manual advance) | axess-clock |
| `SecureRng` | `SystemRng` (OS entropy) | `MockRng` (seeded) | axess-rng |
| `AuthnBackend` | Real DB | `MockBackend` | axess-core::testing |
| `SessionRegistry` | Valkey/SQLite | `MemorySessionRegistry` | axess-core |
| `OAuthProvider` | HTTP discovery | `MockOAuthProvider` | axess-factors |
| `Fido2Provider` | WebAuthn ceremonies | `MockFido2Provider` | axess-factors |
| `LdapProvider` | LDAP directory | `MockLdapProvider` | axess-factors |
| `DeviceStore` | SQL / Valkey | `MemoryDeviceStore` | axess-core |
| `DeviceResolver` | header / IP | `RedactedResolver` / `NoopDeviceResolver` | axess-core |

All tests deterministic and reproducible, no flaky timing dependencies.

## Security Principles

- **No `unsafe` code in production paths.** `#![forbid(unsafe_code)]` enforced on 10 of 11 crates. The exception is `axess-strings`, which uses `#![deny(unsafe_code)]` + a scoped `#![allow(unsafe_code)]` in `repr.rs` for the Umbra-style raw heap representation (allocation, `NonNull` dereference, `unsafe impl Sync`). Every `unsafe` block in `repr.rs` cites the invariant it relies on. No other module in any crate may use `unsafe`.
- **Constant-time comparisons** (`subtle::ConstantTimeEq`): HMAC cookie verification, TOTP/HOTP codes, OAuth CSRF state, session fingerprint, refresh token device binding.
- **Secret zeroization**: password hashes (`ZeroizedString`), TOTP/HOTP secrets (`Zeroizing`), signing key (`Drop` zeroing).
- **Timing equalization**: `begin_login` runs dummy queries on unknown-user path to prevent user enumeration.
- **Refresh token security**: SHA-256 hash-only storage, family tracking (reuse of rotated token revokes entire family); `device` feature adds cascade revocation across refresh families.
- **Session hardening**: ID cycling (fixation prevention), HMAC fingerprint binding, `max_custom_bytes` DoS limit (64 KiB).
- **OAuth/OIDC**: HTTPS enforced on discovery URLs (loopback exempted), PKCE on all authorization code flows. `openidconnect` activated with `timing-resistant-secret-traits` (secret-bearing types refuse `PartialEq` / `Hash`, forcing constant-time comparison). `azp` checked when `aud` is multi-element array.
- **Back-channel logout token validation**: claim helpers in `axess_factors::oidc::logout_token` enforce 8 KiB size cap, ±60 s clock-skew + 5 min `iat` window, `aud`/`azp` checks, `events` URI match. Signature verification uses the per-provider JWKS cache.

## Feature Flags

### axess-core (default = `authz`, `device`, `default-error-response`, `serde`)

| Feature | What it enables |
|---------|----------------|
| `authz` | Cedar Policy authorization (default) |
| `device` | Device identity ladder + cascade revoke (default) |
| `memory` | In-memory session store + registry |
| `admin` | Administrative user/tenant management APIs |
| `accept_client_id` | `X-Client-ID` header extraction |
| `request_id` | `X-Request-Id` middleware |
| `trace_id` | W3C Trace Context (`traceparent`) middleware |
| `sqlite` / `postgres` / `valkey` | Encrypted session stores (AES-256-GCM) |
| `fido2` | WebAuthn passkeys (pulls `axess-factors/fido2`) |
| `ldap` | LDAP bind (pulls `axess-factors/ldap`) |
| `oauth` | OAuth 2.0 / OIDC inbound (pulls `axess-factors/oauth`) |
| `fapi` | FAPI 2.0 (PAR, DPoP, JARM). Implies `oauth`. |
| `mtls` | mTLS verifier (pulls `axess-factors/mtls`) |
| `jwt-svid` | SPIFFE JWT-SVID resolver (spec-bound) |
| `social` | Plain-OAuth-2.0 user login (`SocialProvider`; weaker than OIDC, off by default) |
| `outbound-oauth` / `outbound-mtls` | Outbound client-credential flows |
| `aws-sts` / `gcp-wif` / `azure-fic` / `cloud-sts` | Cloud workload-identity exchange |
| `local-idp` | In-process IdP (mints workload JWTs against an adopter key store) |
| `workload-id` | Umbrella for the workload-identity feature bundle |
| `delegated-stored` / `delegated-exchange` / `delegated-stored-encrypted` / `delegated` | OBO access |
| `ws` | WebSocket helpers |

### axess-factors (default = `password`, `totp`, `hotp`, `email_otp`)

| Feature | What it enables |
|---------|----------------|
| `password` | Argon2id (default) |
| `totp` | RFC 6238 (default) |
| `hotp` | RFC 4226 (default) |
| `email_otp` | Email OTP (default) |
| `fido2` | WebAuthn passkey verifier |
| `ldap` | LDAP bind verifier |
| `mtls` | mTLS verifier |
| `oidc` | OIDC discovery + JWKS cache + logout-token claim validation |
| `jwt` | JWT validation (incl. `JwtVerifier`) |
| `jwt-svid` | SPIFFE JWT-SVID resolver (pulls `jwt`; spec-bound; mandatory `spiffe://` URI in `sub`) |
| `oauth` | Inbound OAuth ceremony (pulls `oidc` + `jwt`) |
| `fapi` | FAPI 2.0 add-ons (pulls `oauth`) |
| `social` | Plain-OAuth-2.0 user login (`SocialProvider`; see module docs for the weaker security model vs OIDC) |
| `bearer` | Bearer-token axum extractor |
| `outbound-oauth` | Outbound OAuth client (pulls `jwt`) |
| `federation` | Umbrella over all federation + adjacent features |

The generic `axess_factors::federation::workload::WorkloadResolver` is gated on `jwt` and covers every non-SPIFFE JWT-bearer workload-identity flow (GitHub Actions, k8s SA, GitLab CI, Okta, Azure AD, Auth0, `LocalIdP`, …) via an adopter-supplied claim parser + mapping closure. There are deliberately no per-company features; see `examples/workload-identity/` for ready-made recipes.

### Common feature combinations

| Use Case | Features |
|----------|----------|
| Minimal authn | `memory` |
| OAuth + FIDO2 | `memory`, `oauth`, `fido2` |
| Workload identity | `workload-id`, `local-idp` |
| OBO mailbox integration | `delegated-stored`, `delegated-stored-encrypted` |
| Testing/DST | `memory`, `admin` |

### Choosing features (no `full` umbrella)

axess intentionally ships **no `full` feature**. Pick the features your deployment actually uses:

- **Exactly one session backend.** `sqlite`, `postgres`, `mysql`, or `valkey`; never two. They're mutually exclusive at the deployment level, so an umbrella that bundled them would compile dead code, balloon link size, and tempt accidental cross-backend coupling.
- **Capability features stack additively.** `oauth`, `fido2`, `ldap`, `mtls`, `ws`, `request-id`, `trace-id`, `workload-id` (which is itself an additive umbrella over `jwt + jwt-svid + mtls + outbound-oauth + outbound-mtls`), `delegated` (over `delegated-stored + delegated-exchange`). Enable what you use.
- **`testing` and `memory` stay out of production builds.** They live behind named features specifically so they can't sneak into a release.
- **For CI, docs.rs, local clippy:** use `cargo … --all-features`. That's the supported "compile everything" path and is what every workspace-wide script in `scripts/` does already.

## Testing Expectations

```bash
./scripts/test-all.sh                            # full pipeline (lib+tests+doc+clippy+fmt)
cargo test --workspace --all-features            # all tests
cargo test --workspace --all-features --lib      # unit tests only
cargo test --workspace --all-features -- --ignored  # integration tests (needs Valkey)
cargo test --doc --workspace --all-features      # doc-tests
cargo clippy --workspace --all-features --all-targets -- -D warnings
./scripts/mutants.sh [args]                      # cargo-mutants in isolated worktree
```

Integration tests require a running Valkey instance at `redis://localhost:6379`. Postgres / MySQL backends also have integration suites; CI spins up service containers for all three plus CockroachDB.

`./scripts/test-all.sh` runs every step regardless of prior failure (independent-verdict shape mirroring CI), prints per-step elapsed, and lists failed steps in the summary.

### Test-module layout

Inline `#[cfg(test)] mod tests { … }` blocks inside production files are fine when small. Once a block grows past **~200 LoC**, move it to a sibling file:

- For a leaf file `foo.rs` with one inline test mod, create `foo/tests.rs` and replace the inline block with `#[cfg(test)] mod tests;`.
- For multiple inline test mods (e.g. `mod foo_tests`, `mod bar_tests`), extract each to its own sibling under `foo/`: `foo/foo_tests.rs`, `foo/bar_tests.rs`.
- For integration-test binaries under `tests/`, prefer topic-named sibling files (one binary per topic) over deeply-nested inner mods, capping each file at the same ~200-LoC threshold per logical area.

Rationale: production-file size grows linearly with the feature coverage of its tests, drowning the actual logic. A 1000-LoC file with 700 LoC of inline tests is harder to navigate than 300 LoC of prod plus a separate test sibling.

## Key Design Decisions

1. **Explicit state machine** for authentication flow; typed `AuthState` transitions prevent invalid moves.
2. **Trait-based DST**; all non-determinism injectable, making every test deterministic and reproducible.
3. **Cedar Policy** for authorization; single policy language covers RBAC, ABAC, and ReBAC.
4. **Guards as named predicates**; factor verification is data-driven, not hard-coded.
5. **Session data versioning**; `SessionData` auto-migrates across schema changes without invalidating sessions.
6. **Refresh token families**; reuse of a rotated-out token revokes the entire family (theft detection).
7. **Three-tier scope hierarchy** (Global, Tenant, User); policies, factors, and methods configurable at each level.
8. **No unsafe in production paths**; `#![forbid(unsafe_code)]` on every crate except `axess-strings`, which scopes its localized exception in one file.
9. **axess-core = orchestrator, axess-factors = verifiers** (boundary). OBO (on-behalf-of) lives under `axess-core/src/delegated/`. axess-cache = TTL caching. axess-clock / axess-rng = DST foundations.
10. **Defaults run zero-infra**; infra backends are opt-in features.

## Instruction File Policy

This repository intentionally keeps agent instruction files tracked.

Policy:

- `AGENTS.md` (this file) is the canonical project guidance.
- `.claude/CLAUDE.md` is a thin adapter for Claude-compatible tooling.
- `.github/copilot-instructions.md` is a thin adapter for Copilot-compatible tooling.
- Do not add these files to `.gitignore` unless the project explicitly decides to stop shipping agent guidance.
- Do not maintain multiple full copies of the same project instructions; update this file first and keep the adapters thin.

## Default Agent Behavior

When making changes in this repo:

- preserve the `axess-core = orchestrator, axess-factors = verifiers` boundary
- keep production code DST-friendly (depend on traits, inject mocks in tests)
- preserve zero-infra defaults; new infra-bound features stay opt-in
- prefer precise, minimal edits
- validate behavior after changes
- avoid speculative features that blur a crate boundary
- never weaken security defaults (constant-time, zeroize, HTTPS-on-OIDC, PKCE-on-OAuth)

License: MIT OR Apache-2.0. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
