# Axess — Roadmap

> **Current version:** `v0.0.14` — pre-release, not yet published to crates.io.

---

## Design principles (non-negotiable)

1. **Fail-closed authorization** — any evaluation error returns `Deny`.
2. **DST-first** — every component that touches time, randomness, or I/O must be injectable.
3. **Trait-based extensibility** — `IdentityStore`, `FactorStore`, `SessionStore`, `SessionRegistry`, `SecureRng`, `Clock`, `PolicyEvaluator`, `AuthzEntityProvider`, `Fido2Provider` are all traits.
4. **No application knowledge in library crates** — role taxonomies, permission names, Cedar namespaces, email templates belong in the consuming application.
5. **Explicit over magic** — prefer verbose but auditable code over clever macros that obscure the security boundary.

---

## What is done

### Core authentication
- `AuthState` machine, `AuthnService` orchestrator (`begin_login` → `prepare_factor` → `verify_factor`)
- `IdentityStore` (8 methods) + `FactorStore` (3 methods) + `AuthnBackend` supertrait
- Multi-factor composition, lockout via DB counter, counter resets only after ALL factors pass
- `complete_factor_step` shared helper, audit events with injectable clock

### Authentication factors
- **Password** — Argon2id, constant-time, zeroize on drop
- **TOTP** — RFC 6238, replay protection, constant-time
- **HOTP** — RFC 4226, counter advancement, constant-time
- **Email OTP** — code generation, Argon2id hash, TTL expiry, cooldown (`AlreadySent`)
- **FIDO2/WebAuthn** — `Fido2Provider` trait, `DefaultFido2Provider` + `MockFido2Provider`, registration + authentication + discoverable/passwordless ceremonies, `Fido2Credential` with metadata, credential management, ceremony timeout, clone detection
- **OAuth 2.0 / OIDC** — Authorization Code + PKCE flow, OIDC discovery, ID token validation, CSRF + nonce protection, multi-provider, `complete_oauth_login` helper, failure audit events

### Authorization (Cedar Policy)
- `PolicyStore`, `PolicyEvaluator` trait, `AuthzEntityProvider` trait
- `AuthzStore` + `AuthzSession` with `require`, `is_permitted`, `batch_check`
- RBAC, ReBAC, ABAC via Cedar, fail-closed, `Mutex`-based cache for Axum `Send`

### Session management
- Custom `SessionLayer` — HMAC-SHA256 signed cookies, typed `SessionData`
- `MemorySessionStore`, `SqliteSessionStore`, `ValkeySessionStore` (encrypted, key rotation)
- `MemorySessionRegistry`, `ValkeySessionRegistry`
- Session fixation prevention, configurable TTL, `Max-Age`, signing key zeroized

### Testing
- `MockIdentityStore`, `MockFactorStore`, `MockRng`, `MockClock`, `MockPolicyEvaluator`, `MockFido2Provider`
- **78 tests total** (69 passing + 9 Valkey + 2 ignored):
  - 5 unit tests (SessionId, RNG)
  - 4 Valkey crypto unit tests (encrypt/decrypt, key rotation, wrong key)
  - 16 authn integration tests (password, TOTP, HOTP, Email OTP, lockout, replay, fixation, registry)
  - 30 unit tests (authz require/is_permitted/batch_check, session data serialization, scope resolution chain, edge cases, session extractor methods)
  - 8 SQLite session store tests (save/load/delete/cycle, expiry, cleanup, overwrite)
  - 3 HTTP session layer tests (cookie signing, HMAC format, conditional Set-Cookie)
  - 4 macro tests (login_required 401/redirect/custom field, require_partial_authn)
  - 3 OAuth integration tests (CSRF, expiry, unknown provider)
  - 1 ignored Valkey integration test (needs running Valkey)
  - 1 ignored OAuth full-flow test (needs test server ID token fix)

### Examples
- `examples/sqlite/` — authentication (password + TOTP)
- `examples/authz/` — Cedar authorization (RBAC + ReBAC + ABAC)
- `examples/oauth/` — OAuth/OIDC federated login

---

## Planned

### OAuth/OIDC enterprise hardening
**Priority: High**

The current implementation covers the OIDC Authorization Code + PKCE flow. Enterprise environments need richer claim extraction, token lifecycle management, and configuration surface.

Done:
- [x] **`additional_claims` map** — raw ID token claims as `serde_json::Value`, exposing Azure AD `groups`, `roles`, `tid`, `preferred_username`, etc.
- [x] **Group/role extraction** — `OAuthClaims.groups` and `OAuthClaims.roles` extracted from ID token
- [x] **Refresh token storage** — `OAuthClaims.refresh_token` stores the IdP's refresh token (requires `offline_access` scope)
- [x] **Configurable ceremony timeout** — `OAuthProviderConfig::with_ceremony_timeout()`, per-provider
- [x] **`OAuthLoginOptions`** — `prompt` (none/login/consent/select_account), `login_hint`, `extra_scopes` per flow
- [x] **`login_hint` parameter** — passed as OIDC `login_hint` to pre-fill the identifier

Remaining:
- [ ] **`refresh_oauth_token` method** — use stored refresh token to renew access without re-authentication
- [ ] **Full-flow integration test** — `oauth2-test-server` ID token generation needs investigation
- [ ] **`MockOAuthProvider` for DST** — mock OIDC discovery + token exchange without HTTP

Roadmap (medium effort):
- [ ] **UserInfo endpoint** — fetch additional claims beyond the ID token
- [ ] **OIDC Back-Channel Logout** — receive IdP session termination notifications (requires an Axum endpoint)
- [ ] **OIDC Front-Channel Logout** — handle IdP logout redirect
- [ ] **OAuth 2.0 Device Code flow** — for CLI tools and non-browser clients
- [ ] **OAuth 2.0 Client Credentials** — service-to-service authentication

### Test coverage expansion

- [x] **SessionLayer middleware tests** — cookie HMAC signing/verification, conditional `Set-Cookie` (via `tower::ServiceExt::oneshot`)
- [x] **SqliteSessionStore tests** — 8 tests against in-memory SQLite (save/load/delete/cycle, expiry, cleanup, overwrite)
- [x] **Macro tests** — 4 tests for `login_required!()` and `require_partial_authn!()` via Axum `oneshot`

Remaining:
- [ ] **Concurrent session access** — verify `Arc<RwLock<SessionInner>>` under concurrent reads/writes

### FIDO2 remaining work

- [ ] **Integration tests** — requires a real `Webauthn` instance with a software authenticator
- [ ] **Per-ceremony UV/attestation policy** — blocked on webauthn-rs 0.6
- [ ] **FIDO2 example** — standalone example with browser-side JS

### Signup flow
**Priority: Medium**

- [ ] Signup trait methods on `IdentityStore` (`create_user`, `set_initial_factor`)
- [ ] `SignupOrchestrator` driving the `PendingWorkflow` state machine

### crates.io publication
**Priority: Low**

- [ ] Stable public API (target: `v0.1.0`)
- [ ] `CHANGELOG.md`

### Headless management API
**Priority: Speculative**

- [ ] Feature-gated `axess-admin` sub-crate
- [ ] JSON API for user/factor/session management, protected by Cedar policy

---

## Not planned (and why)

| Feature | Reason |
|---|---|
| **SAML 2.0** | Entirely different protocol (XML signatures, assertion consumer service). Very high effort. Enterprise apps needing SAML should use a dedicated SAML crate or IdP proxy (Azure AD supports both OIDC and SAML — use OIDC). |
| **Kerberos / SPNEGO** | Platform-level concern handled by reverse proxy (`nginx auth_gss_module`, Apache `mod_auth_kerb`). The result is a pre-authenticated identity header that the application reads and feeds into Axess as a trusted user ID. Document this pattern. |
| **LDAP bind authentication** | Direct directory operation — use a dedicated LDAP crate (`ldap3`). The application authenticates against LDAP and then calls `session.set_authenticated()`. Axess doesn't need to know about LDAP. |
| JWT-based sessions | Forced logout requires state; session cookies are the right choice. |
| Built-in user management UI | Rendering belongs in the application. |
| Role taxonomy / permission names | Application-specific; Cedar namespace is configurable. |
| Full OAuth Authorization Server | Keycloak/Ory Hydra territory. |
| PostgreSQL backend | Applications implement `SessionStore` against their own pool. |
