# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/spec/v2.0.0.html).

---

## [0.3.3] - 2026-08-08

### Fixed

- `session` + `csrf`: a fresh guest's session id is now stable across
  `finalize_session`, so a CSRF token minted during a request stays valid on
  the client's next state-changing request. Previously a fresh guest (no
  trusted `existing_id`) took the id-cycling branch and minted a *second*,
  different id for the response cookie — even though the request, and the
  `CsrfLayer` token HMAC-bound to it, already ran under the id `load_session`
  minted. The client was left holding a `csrf-token` bound to the old id and an
  `axess.sid` carrying the new one, so its next state-changing request
  (typically the login `POST`) failed validation with `csrf: token validation
  failed` → `403`. The id-cycle branch is now gated on `regenerate` alone; a
  fresh guest is saved under its already-fixation-safe load-minted id. Session
  fixation protection is unchanged — privilege changes and binding-mismatch
  resets still rotate the id via the `regenerate` path.

---

## [0.3.2] - 2026-08-06

### Added

- `axess-rng`: opt-in `numeric` feature adds a reproducible statistical
  RNG surface alongside the always-on cryptographic `SecureRng`:
  - `NumericRng` trait: number-oriented (`next_u64`, `next_uniform`),
    stateful, deterministic given a seed. For Monte Carlo, statistical
    sampling, and DST.
  - `Xoshiro256pp`: xoshiro256++ 256-bit PRNG (Blackman & Vigna 2019).
    Bit-exact reproducible: same seed yields the same sequence
    permanently, independent of any dependency updates.
  - `MockNumericRng` (under `testing`): DST test mock with two
    constructors. `from_seed(u64)` wraps a seeded `Xoshiro256pp` behind
    a `Mutex`; `from_sequence(...)` replays a pre-programmed `u64`
    sequence and panics on exhaustion.
- Default consumers (feature not enabled) see zero API surface change;
  additive minor. Downstream integrators opt in via
  `axess-rng = { version = "0.3.2", features = ["numeric"] }`.

---

## [0.3.1] - 2026-08-02

### Fixed

- `CsrfLayer` self-heals a stale double-submit cookie by re-minting on
  the response when the session id changes mid-request (e.g. after
  `AuthSession::regenerate()` on login completion, MFA add, or tenant
  switch). The fail-closed reject on state-changing requests is
  unchanged; only the recovery path is new.

---

## [0.3.0] - 2026-08-01

Breaking release: the MSRV rises and `jsonwebtoken`'s `Algorithm` type —
re-exposed through this crate's public API — becomes `#[non_exhaustive]`.

### Added

- `EventSubjectRef<'a>` and `EventPayload::subject_ref()` — a borrowed,
  zero-allocation view of the entity an event is *about*
  (`User` / `Tenant` / `Device` / `Session` / `Other { kind, id }`),
  mirroring the owned envelope-level `EventSubject`. Fills the hot-path gap
  the owned type doesn't cover: per-tick routing, per-tenant fan-out,
  per-subject bucketing, and tracing-span tagging without allocating.
  Additive — `subject_ref()` defaults to `None`, so existing `EventPayload`
  implementations are unaffected.

### Changed

- **BREAKING:** `jsonwebtoken` 10 → 11. Its `Algorithm` enum is now
  `#[non_exhaustive]` and is re-exposed via `ALLOWED_ALGORITHMS`,
  `JwtVerifier::with_algorithms`, and the local-IdP helpers, so exhaustive
  `match`es on it downstream must add a wildcard arm. Internally, the
  `alg_family` mirror is replaced by the now-public `Algorithm::family()`.
- **BREAKING:** MSRV raised to **1.93.1**. The library itself builds on 1.88
  (raised from 1.87 by `jsonwebtoken` 11); the declared floor is set to the
  workspace-wide requirement so the full build+test suite runs on a single
  toolchain — `serial_test` 4.0.1 (dev-only) requires 1.93.1.
- Dependency bumps: `base64` 0.22 → **0.23** (SIMD engines; API unchanged for
  our usage), `cedar-policy` → **4.12.0** (unified across the workspace),
  `tokio` → **1.53.1**, `thiserror` → **2.0.19**, `zeroize` → **1.9.0**,
  `serial_test` (dev) → **4.0.1**; versions unified across the workspace.
- Inter-crate and example `axess-*` dependencies are now pinned exactly
  (`=0.3.0`) so the family always resolves as one tested, audited unit.

### Security

- Transitive `event-listener` 5.4.1 → **5.4.2**, closing
  [RUSTSEC-2026-0221] (`!Send` tags could cross thread boundaries via
  `StackSlot`). Lockfile-only; no public-API change.

[RUSTSEC-2026-0221]: https://rustsec.org/advisories/RUSTSEC-2026-0221

## [0.2.2] - 2026-07-19

### Security

Transitive-dependency security patch — no adopter-facing API changes,
same public surface as 0.2.1.

- `crossbeam-epoch` 0.9.18 → 0.9.20 (fixes [RUSTSEC-2026-0204]: invalid pointer dereference in the `fmt::Pointer` impl for `Atomic` / `Shared`).
- `quinn-proto` 0.11.14 → 0.11.16 (fixes [RUSTSEC-2026-0185], severity 7.5 high: remote memory exhaustion via unbounded out-of-order stream reassembly). Pulled by `reqwest` for HTTP/3.
- `anyhow` 1.0.102 → 1.0.104 (fixes [RUSTSEC-2026-0190]: unsoundness in `Error::downcast_mut()`).
- `spin` 0.9.8 → 0.9.9 (0.9.8 was yanked upstream).

Lockfile-only update; no `Cargo.toml` semver constraints changed. All
1469 tests still pass under the new lockfile; `cargo audit --deny warnings`
now clean.

[RUSTSEC-2026-0204]: https://rustsec.org/advisories/RUSTSEC-2026-0204
[RUSTSEC-2026-0185]: https://rustsec.org/advisories/RUSTSEC-2026-0185
[RUSTSEC-2026-0190]: https://rustsec.org/advisories/RUSTSEC-2026-0190

---

## [0.2.1] - 2026-07-19

### Security

- **CSRF token bound to session id.** The double-submit token is now `HMAC(signing_key, nonce || session_id)`, so a token minted under one session cannot be replayed after the session regenerates (e.g. after login). When the `SessionHandle` request extension is absent on a state-changing request, `CsrfLayer` fails closed (403) rather than validating an unbound token, so a mis-ordered middleware stack surfaces as a hard failure. `CsrfLayer` must be layered inside (i.e. run after) the session layer; the module docs and the example in the docstring make the ordering explicit.

### Changed

- Dependency bumps: `aes-gcm` 0.10.3 → 0.11.0, `quick-xml` 0.40.1 → 0.41.0, `chrono` 0.4.44 → 0.4.45, `uuid` 1.23.2 → 1.24.0, `rand` 0.10.1 → 0.10.2.

---

## [0.2.0] - 2026-06-01

First public release.

Axess is a modular, policy-driven authentication and authorization library for the [Axum](https://github.com/tokio-rs/axum) web framework. It is built around a trait-based design that supports deterministic simulation testing (DST) from the ground up: every source of non-determinism (clock, RNG, identity store, factor store, session registry, principal resolver) is an injectable trait with a production implementation and a deterministic test double.

Adopters depend on the `axess` facade crate. The 0.x line is pre-1.0: the public API may evolve based on adopter feedback before stabilising.

### Identity and tenancy

- **Multi-tenant model.** Cross-tenant operations refuse by default. Tenant-level `Suspended` status locks out all users before factor prompts. Atomic `create_tenant(bootstrap)` enforces "every tenant has at least one factor and one enabled method". Reserved `system()` principals for internal callers. See [`docs/identity/tenancy.md`](docs/identity/tenancy.md).
- **Three-tier identity store split.** `IdentityLookup` (10 read verbs) ← `IdentityAuthnLog` (4 per-attempt audit-write verbs) ← `IdentityAdmin` (9 verbs for privileged provisioning, suspension, and GDPR erasure). `IdentityStore: IdentityAdmin` umbrella alias preserves the full-tier shape for production backends. `NoopAuthnLog` adapter wraps an `IdentityLookup` for fixtures and read-replica integrations. See [`docs/identity/store.md`](docs/identity/store.md).
- **Typed identifiers.** `UserId`, `TenantId`, `WorkloadId`, `Principal { Human, Workload }`, all UUID-backed with strict parsing. Shared via the `axess-identity` crate.

### Authentication and session machinery

- **Explicit session state machine** (`AuthState`): `Guest`, `Identifying`, `Authenticating`, `Authenticated`, `PendingWorkflow`. Typed transitions reject invalid moves at compile time.
- **Multi-factor authentication.** Sequential and choice-based verification via `FactorStep::AnyOf`. Factors compose into named methods scoped per tenant or per user.
- **Factor implementations.** Password (Argon2id), TOTP (RFC 6238), HOTP (RFC 4226), email OTP (8-digit, Argon2-hashed, TTL-bound), FIDO2 / WebAuthn (registration, authentication, discoverable / passwordless, clone detection), OAuth 2.0 / OIDC (Authorization Code + PKCE, Client Credentials, Device Code RFC 8628), LDAP bind, mTLS, JWT (incl. JWT-SVID), bearer-token extractors.
- **DST-friendly verification.** TOTP verification, the FAPI `nbf` validator, and the DPoP `jti` replay cache all consume time through `axess_clock::Clock`. Default is `SystemClock`; swap in a `MockClock` for deterministic simulation. `OAuthProviderConfig::with_clock` and `MemoryJtiCache::with_clock` expose the injection point on the OAuth surfaces; `verify_totp` accepts the `DateTime<Utc>` the application's clock returns.
- **Plain-OAuth-2.0 social login.** Generic `SocialProvider` (gated on `social`, **off by default**) for IdPs that don't support OIDC (GitHub user login, Twitter/X, Discord, Reddit, Spotify, …). Identity comes from a TLS-trusted userinfo endpoint rather than a signed assertion; the security model is weaker than OIDC. Parallel types (`SocialClaims` vs `IdTokenClaims`, `SocialProvider` vs `OAuthProviderConfig`) make the difference visible at every call site. PKCE on by default; RNG injectable via `Arc<dyn SecureRng>` for DST.
- **Session lifecycle.** ID cycling for fixation prevention; HMAC-SHA256 fingerprint binding at completion; registry-backed forced logout; concurrent-session limits with oldest-eviction; versioned session data with auto-migration; refresh-token rotation with family revocation on reuse.
- **Session revocation API.** `AuthnService::invalidate_user_sessions`, `invalidate_session`, `active_sessions`, `has_session_registry()`. Returns `NoSessionRegistryError` when no registry is attached.
- **`SessionRevoker` + `SessionRegistryHandle` supertrait pair.** Logout handlers take `Arc<dyn SessionRevoker>` (2 methods); `AuthnService` holds `Arc<dyn SessionRegistryHandle>` (5 methods).

### Workload identity

- **`Principal { Human, Workload }` abstraction** unifying inbound authn across humans and non-human workloads (services, K8s pods, CI/CD runners, batch jobs). `PrincipalResolver` trait + per-feature resolvers; the same `ToCedarEntity` bridge for both shapes so Cedar policies authorise both consistently.
- **SPIFFE adapters.** `JwtSvidResolver` (`jwt-svid`) and `MtlsResolver` (`mtls`) extract SPIFFE identities from JWT-SVID tokens and X.509-SVID leaf certs respectively.
- **Generic federation resolver.** `WorkloadResolver<C, F, R>` (gated on `jwt`) for any non-SPIFFE JWT-bearer workload token (Kubernetes service-account, GitHub Actions OIDC, GitLab CI OIDC, Okta, Azure AD, Auth0, `LocalIdP`, …). Adopter supplies a claim struct + mapping closure per issuer they care about; no per-company feature flags. Ready-made recipes for GitHub Actions + Kubernetes ship in [`examples/workload-identity/`](examples/workload-identity/). The resolver synthesises a SPIFFE-shape `WorkloadId` so policies see uniform entity shape.
- **`axess::workload` hub**; inbound resolvers and outbound primitives behind the `workload-id` umbrella feature.
- **Cloud STS exchange.** `aws-sts`, `gcp-wif`, `azure-fic` adapters for exchanging federated workload identity for cloud temporary credentials. See [`docs/workload-identity/cloud-sts.md`](docs/workload-identity/cloud-sts.md).
- **Outbound identity.** `outbound-oauth` (axess as an OAuth client) and `outbound-mtls` (axess presenting an mTLS identity to downstream services).

### On-behalf-of (OBO) access

- **Two flows under `axess_core::delegated`.** `delegated-stored` implements RFC 6749 §4.1 (Authorization Code + PKCE with persisted refresh token) for long-lived offline access. `delegated-exchange` implements RFC 8693 Token Exchange for short-lived per-request exchange. The `delegated` umbrella feature enables both.
- **`EncryptedDelegatedCredentialStore<S, K>`** decorator wraps any delegated-credential backend with AES-256-GCM at rest. Available via `delegated-stored-encrypted`.

### Authorization

- **Cedar Policy engine** for RBAC + ABAC + ReBAC. `AuthzStore` orchestrates policy evaluation; `ToCedarEntity` bridges principals, resources, and contexts into Cedar entities.
- **Layered policy bundle** (base + overlay); adopters drop additional `.cedar` and `.schema.cedar.json` files into an `overlay/` directory that the loader concatenates onto the base on startup.
- **`require_authn!`, `require_partial_authn!`, `require_authz!`** procedural macros from `axess-macros` guard handler functions at compile time.

### Session storage

- **Five session backends.** `Memory`, `SQLite`, `Postgres`, `MySQL` / MariaDB, `Valkey`. The four persistent backends share `SessionCodec` (MessagePack + optional AES-256-GCM) so byte-level wire-format compatibility is preserved when migrating between databases. The MySQL backend is compatible with MySQL 5.7+, 8.x, and MariaDB 10.x+. See [`docs/sessions/backends.md`](docs/sessions/backends.md).
- **CockroachDB compatibility validated.** Postgres wire protocol works unmodified. A dedicated `cockroach_compat` CI job runs the Postgres integration suite against `cockroachdb/cockroach:latest` to catch dialect divergence.
- **`Store<SessionId, SessionData>` cross-backend surface** shipped on every session backend. Adopters can hold `Arc<dyn Store<…>>` or generic `S: Store<…>` for backend-agnostic dispatch. `SessionStore` remains the primary surface; it carries the `cycle` and `find_sessions_for_user` primitives that `Store` omits.
- **`HealthCheck` trait** on every session and cache backend (bounded 2-second probe). Fail-soft on Valkey: errors degrade to miss + warn-log, so an unhealthy result is operational signal rather than a hard failure.
- **`MemoryStore<K, V>` shared backend** with `axess_clock::Clock` injection. Used by `MemorySessionStore` and the in-memory refresh-token store, with deterministic test mocks driving manual clock advance.

### Caching

- **`axess-cache::ClockTtlCache`**; in-process TTL cache with clock injection for DST. Asymmetric defaults: cache authz decisions, do not cache authn.
- **`CacheInvalidator` trait + scoped invalidation** on `EntityCache` / `MokaEntityCache` / `ValkeyEntityCache` so policy-update, role-change, and tenant-suspension handlers can dispatch through a single trait without naming the concrete cache.
- **`AuthnMetrics::authz_cache_*` methods** (`hit` / `miss` / `eviction` / `invalidation`) with no-op defaults. `EntityCache::flush_metrics` snapshots `axess_cache::CacheStats` counters into per-event trait calls then resets.

### Audit and analytics

- **`AuditArchiver` trait + `AuditRetentionPolicy`** for hot / cold tiering of authn audit rows. Three-stage retention (`archive_after` / `purge_hot_after_archive` / `delete_archive_after`) with conservative finance-aware defaults (90d / 7d / never). `AuditRetentionLoop<S, A>` handles the schedule, retry, and batch-sizing pipeline. `FilesystemAuditArchiver` (behind `audit-archive-fs`) is a reference implementation with day-partitioned JSONL and fsync per batch. See [`docs/production/audit-pipeline.md`](docs/production/audit-pipeline.md).
- **`AuthnAnalyticsSink` + `RichAuthnEvent`**; a denormalised analytics path parallel to the regulatory `AuthEvent`. Optional enrichment fields (device trust, geo, ASN, parsed UA, tags); serde + rkyv derives so adopters can stream to Apache Iggy, ClickHouse, DuckDB, or Snowflake. `AuditLogWithAnalytics<L, S, E>` decorator wraps an `IdentityAuthnLog` + sink + enrichment closure with fire-and-forget dispatch for the analytics path.
- **Device-identity audit events.** Six `AuthEvent` variants (`DeviceFirstSeen` / `DeviceTrustGranted` / `DeviceRevoked` / `DevicePurged` / `DeviceBindingAdded` / `DeviceFingerprintMismatch`) wired into SIEM rules in [`docs/production/audit-events.md`](docs/production/audit-events.md).

### Device identity

- **First-class `Device` aggregate** under `axess-core/src/device/`. Unknown → Seen → Trusted ladder; cascade revocation; pluggable storage. Reference example under `examples/device/`.
- **Five `DeviceStore` backends.** `Memory`, `SQLite`, `Postgres`, `MySQL` / MariaDB, `Valkey`; surface-equivalent across SQL dialects + Valkey hash storage, optional AES-256-GCM envelope on the bindings blob (SQL backends). Adopters needing a custom backend (DynamoDB, MongoDB, …) follow the recipe in [`docs/identity/device.md`](docs/identity/device.md).

### IdP fixtures and workload-token issuance

- **`LocalIdpFixture`**; in-process test IdP minting workload JWTs against an in-memory RSA-2048 keypair, with a matching JWKS endpoint. Multi-key JWKS + rotation, adopter-supplied keypairs, ES256 (P-256) alongside RS256, max-TTL policy, issuance audit hook, RFC 8414 discovery document, file-backed adopter example. See [`docs/factors/local-idp.md`](docs/factors/local-idp.md).

### Middleware

- **Axum / Tower middleware** under `axess-core::middleware`: `csrf` (signed double-submit cookie), `ratelimit` (composable token bucket), `request_id` (X-Request-Id), `trace_id` (W3C Trace Context), `ws` (revocation-aware WebSocket wrapper).

### Deterministic simulation testing

- **Clock, RNG, identity store, factor store, session registry, principal resolver, entity provider, policy evaluator**; all behind traits with `testing::Mock*` doubles under the `testing` feature.
- **`TracingCapture`** test subscriber for asserting on emitted `tracing` events from inside tests.
- **`InMemoryBackend`** assembling a complete in-memory stack for end-to-end test flows.

### Reference examples

| Example | Demonstrates |
|---|---|
| `examples/sqlite/` | Reference app: SQLite sessions + full auth flow |
| `examples/oauth/` | OAuth 2.0 / OIDC login against a public IdP |
| `examples/social/` | Plain-OAuth-2.0 social login (Login with GitHub) |
| `examples/authz/` | Cedar Policy authorization |
| `examples/fapi/` | FAPI 2.0 (PAR, DPoP, JARM, RP-initiated logout) |
| `examples/device/` | Device-identity ladder |
| `examples/local_idp/` | In-process IdP minting workload-identity JWTs |
| `examples/workload-identity/` | Adopter recipes for `WorkloadResolver` (GitHub Actions, Kubernetes service accounts) |

### Conventions

- **Kebab-case feature flags throughout** (`request-id`, `trace-id`, `accept-client-id`, `jwt-svid`, `mtls`, …). No mixed-case or underscored alternatives.
- **`memory`-gated dev backends.** `MemorySessionStore`, `MemorySessionRegistry`, `MemoryStore<K, V>` ship behind the `memory` feature so production builds cannot accidentally pull in a non-persistent store.
- **`testing` feature** (`testing = ["memory"]`) gates all test doubles and fixtures: `MockIdentityStore`, `MockFactorStore`, `MockClock`, `MockRng`, `MockResolver`, `MockEntityProvider`, `MockPolicyEvaluator`, `TracingCapture`, `MemoryRefreshTokenStore`, `LocalIdpFixture`, `InMemoryBackend`.
- **Defaults run zero-infra.** Infra-bound features (`sqlite`, `postgres`, `valkey`, `ldap`, …) are opt-in. Hard rule.
- **Exhaustive enums.** No first-party enum carries `#[non_exhaustive]`; consumer `match` expressions get exhaustive arms and a CI guard rejects any new occurrence.

### Minimum Supported Rust Version

`1.87`, Rust 2024 edition. Latest stable toolchain expected.
