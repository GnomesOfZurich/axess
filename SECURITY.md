# Security Policy

## Reporting a Vulnerability

If you discover a security issue in Axess, please report it through GitHub's private vulnerability reporting (the **Report a vulnerability** button under the repository's Security tab) or by emailing security@gnomes.ch. Do not open a public issue.

**Response targets** (best-effort while the project is pre-1.0):

- **Acknowledgement:** within 48 hours of report
- **Triage and severity assessment:** within 7 calendar days
- **Critical / High fix:** patch release within 7 calendar days of confirmation
- **Medium fix:** patch in the next scheduled release (typically within 30 days)
- **Advisory:** published via GitHub Security Advisory once a fix is available

Only the latest 0.x minor receives security patches. If you are on an older version, upgrade to receive fixes.

## Using Axess Securely

Axess is a library for authentication and authorization. Its security depends on correct integration and configuration in your application.

### Production integration checklist

#### Transport and cookies

- [ ] **Terminate TLS** before Axess sees requests. All session cookies default to `Secure; HttpOnly; SameSite=Lax`.
- [ ] **Set an HSTS header** (`Strict-Transport-Security: max-age=63072000; includeSubDomains`) at the reverse-proxy or application layer so browsers never downgrade to HTTP.
- [ ] **Use a cryptographically random 32-byte signing key** loaded from a secrets manager. Never hard-code or re-use the all-zero example key.

#### CSRF

- [ ] **Mount `CsrfLayer`** on state-changing routes. The shipped middleware implements signed double-submit cookie protection; `CsrfConfig::new(signing_key)` is the entry point.
- [ ] `SameSite=Lax` (the cookie default) mitigates the most common vectors, but is not sufficient on older browsers or cross-site `GET`-triggered mutations; keep `CsrfLayer` engaged.
- [ ] For API-only endpoints, validate `Origin` / `Referer` headers or use a custom request header as a CSRF defence in addition.

#### Session binding and hijacking

- [ ] **Enable session binding** (e.g. `UserAgentBinding`) to detect cookie theft from a different browser/client.
- [ ] Understand the trade-off: session binding raises the bar for opportunistic theft but does not protect against an attacker who copies the User-Agent string along with the cookie.
- [ ] Consider combining with IP-subnet or TLS channel binding for higher-security environments.

#### Session registry and forced logout

- [ ] If using a session registry for forced logout, **guard all authenticated routes** with registry validity checks; not just `require_authn!`; so suspended or force-logged-out users cannot continue using stale sessions.
- [ ] Call `suspend_user` (which automatically invalidates registry entries) rather than updating store status manually.

#### Rate limiting

- [ ] **Apply per-IP rate limiting** on login, factor verification, and OAuth callback endpoints using the built-in `RateLimitLayer`. Axess enforces per-user lockout, but distributed brute-force across many usernames requires IP-level throttling.

Recommended configuration for authentication endpoints:

```rust
use axess::{RateLimitLayer, RateLimitConfig, KeyExtractor};
use std::time::Duration;

// Tight limit for login / factor verification (5 attempts per 60 s per IP).
let auth_rate_limit = RateLimitLayer::new(
    RateLimitConfig::builder()
        .max_requests(5)
        .window(Duration::from_secs(60))
        .key(KeyExtractor::ForwardedIp)
        .build(),
);

// Separate, tighter limit for OTP verification (3 attempts per 60 s).
let otp_rate_limit = RateLimitLayer::new(
    RateLimitConfig::builder()
        .max_requests(3)
        .window(Duration::from_secs(60))
        .key(KeyExtractor::ForwardedIp)
        .build(),
);

let app = Router::new()
    .route("/login", post(login_handler))
    .route("/verify-totp", post(totp_handler))
    .layer(auth_rate_limit)
    // Or apply per-route:
    .route("/verify-email-otp", post(otp_handler))
    .route_layer(otp_rate_limit);
```

- [ ] Rate-limit OTP verification endpoints separately; 8-digit email OTPs have 10^8 possibilities but a tighter window reduces feasibility further.

#### Trusted proxy and IP extraction

- [ ] If you rely on `X-Real-IP` or `X-Forwarded-For` for audit trails or rate limiting, ensure your reverse proxy **strips these headers from untrusted client requests** before forwarding. Axess trusts the first entry in `X-Forwarded-For`.

#### Session store selection

- [ ] **In-memory stores** (`MemorySessionStore`, `MemoryRefreshTokenStore`) are for testing only. They use non-constant-time lookups and do not persist across restarts.
- [ ] **SQL stores** (`SqliteSessionStore`, `PostgresSessionStore`, `MysqlSessionStore`) support optional AES-256-GCM encryption at rest via `SqliteSessionStore::new(pool, SessionCrypto::new(key))`; opt out only via the explicit `::plaintext(pool)` constructor (dev/test only).
- [ ] **Valkey store** supports AES-256-GCM encryption via `ValkeySessionStore::new(client, key)`. Plaintext available via `::plaintext(client)` for dev/test.
- [ ] All encryption-capable stores support **key rotation** via `SessionCrypto::with_previous_key(old_key)`; sessions encrypted with the previous key are transparently re-encrypted on the next access.

#### Content Security Policy

- [ ] Set a `Content-Security-Policy` header on all HTML responses to mitigate XSS impact. At minimum: `default-src 'self'; script-src 'self'; style-src 'self'`.
- [ ] Avoid `unsafe-inline` and `unsafe-eval` in CSP directives.

#### OAuth / OIDC

- [ ] Register only **HTTPS** issuer URLs. Axess rejects `http://` issuer URLs in discovery (localhost / `127.0.0.1` / `[::1]` exemption for dev).
- [ ] Request the **minimum scopes** needed; avoid `offline_access` unless refresh tokens are required.
- [ ] Validate that the OAuth redirect URI matches exactly; do not use wildcard patterns.

#### Social login (plain OAuth 2.0)

- [ ] **Prefer OIDC whenever the provider supports it.** Reach for `SocialProvider` only for IdPs that explicitly don't (GitHub user login, Twitter/X, Discord, Reddit, Spotify, …).
- [ ] Understand the weaker security model: identity comes from a userinfo HTTPS GET, not from a signed assertion. A compromised IdP can impersonate any of its users to your service; you accept that blast radius when you adopt the provider.
- [ ] Keep PKCE on (the default). A handful of providers reject the extra parameter; `SocialProvider::without_pkce` is the opt-out and should be used sparingly.
- [ ] Verify `csrf_state` echo on the callback before calling `exchange_code`; `SocialProvider::mint_csrf_state` produces a fresh value routed through the same injectable RNG as PKCE.

#### Workload identity

- [ ] **Pin the trust domain** at resolver construction. Every shipped resolver (`JwtSvidResolver`, `MtlsResolver`, `WorkloadResolver`) accepts an expected `TrustDomain` and rejects tokens / certs whose synthesised `WorkloadId` lives under a different one; defense in depth against a confused-deputy where the JWKS or CA happens to be shared across trust domains.
- [ ] For the generic `WorkloadResolver`, keep adopter-supplied claim mappers **strict** about which `subject` paths the application admits. The recipes in [`examples/workload-identity/`](examples/workload-identity/) are templates, not policy.
- [ ] When fetching SVIDs from a local SPIRE agent, use the `spire-workload` crate today; see [`docs/workload-identity/jwt-svid.md`](docs/workload-identity/jwt-svid.md) for the fetch-side recipe.

#### Dependencies

- [ ] Regularly update Axess and its dependencies (`cargo update`).
- [ ] Run `cargo audit` in CI to catch known vulnerabilities in the dependency tree.

### Trusted proxy configuration (detailed)

Axess extracts client IP addresses from the `X-Real-IP` and `X-Forwarded-For` headers for audit logging and rate limiting. These headers are **only trustworthy if your reverse proxy strips or overwrites them** before forwarding.

**If you don't run behind a trusted reverse proxy**, these headers are user-controlled and any IP-based security decision (rate limiting, geo-blocking, audit trails) can be spoofed.

Configure your reverse proxy to:

1. **Strip incoming `X-Forwarded-For` and `X-Real-IP`** from client requests.
2. **Set `X-Real-IP`** to the immediate client address (TCP peer).
3. **Append `X-Forwarded-For`** with the client address (for multi-hop chains).

Example for nginx:
```nginx
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

Axess reads `X-Real-IP` first; if absent, it takes the first entry from `X-Forwarded-For`. It does **not** walk the forwarded chain or maintain a trusted-proxy allowlist; that is the reverse proxy's responsibility.

## Feature inventory

The shipped security surface, grouped by area. Caveats live in the Notes column.

### Authentication factors

| Feature | Notes |
|---|---|
| Password | Argon2id hashing with workspace-pinned parameters, per-user lockout, password-reuse history, plaintext zeroized after hash. |
| TOTP (RFC 6238) | Constant-time comparison, last-step replay guard, SHA-1 / SHA-256 / SHA-512, 6–8 digit codes. |
| HOTP (RFC 4226) | Counter advancement, zeroized secrets, same algorithm options as TOTP. |
| Email OTP | 8-digit default, Argon2-hashed codes at rest, TTL-bound, single-use. |
| FIDO2 / WebAuthn | Registration + authentication + clone detection + discoverable / passwordless. Per-ceremony UV / attestation policy waits on `webauthn-rs` 0.6 stable; see [ROADMAP.md](ROADMAP.md). |
| LDAP bind | Verifier over `ldap3` with TLS via rustls. Bind only; schema mapping is the application's responsibility. |
| mTLS factor | X.509 certificate verification against a configured trust anchor; SAN URI extraction for SPIFFE / regular identity binding. |
| JWT bearer | Generic JWT verifier with JWKS rotation, `iss` / `aud` / `exp` / `nbf` / `alg` allowlist, clock-injected for DST. |
| Multi-factor chains | Ordered factor pipeline (`FactorStep::AnyOf` for choice steps), session state machine enforces sequencing at compile time. |

### Sessions

| Feature | Notes |
|---|---|
| Session cookies | HMAC-SHA256 signed, `Secure; HttpOnly; SameSite=Lax` by default. Configurable via `SessionLayer::with_secure` / `with_same_site`. |
| Session binding | HMAC-keyed fingerprint (not a plain hash); `UserAgentBinding` + extension points for IP / TLS channel binding. |
| Session registry + forced logout | `SessionRegistry::invalidate_user` is error-observable and fail-closed; cooperates with `suspend_user` for combined identity + session revocation. |
| ID cycling | Automatic on Guest→Authenticated transition (fixation defense) and on logout; explicit `AuthSession::regenerate` for app-defined privilege boundaries (MFA enrollment, password change, role grant). See [`docs/sessions/lifecycle.md`](docs/sessions/lifecycle.md). |
| Refresh tokens | Rotation with family revocation on reuse; integration with device-binding cascade. |
| In-memory store | Testing only; no persistence, no encryption, non-constant-time lookups. |
| SQLite session store | Optional AES-256-GCM via `SqliteSessionStore::new(pool, SessionCrypto::new(key))`. Key rotation via `with_previous_key`. |
| Postgres session store | Same encryption model. Recommended for multi-instance deployments. Validated against CockroachDB via the `cockroach_compat` CI job. |
| MySQL / MariaDB session store | Same encryption model. Tested against MySQL 8.x and MariaDB 10.5+. |
| Valkey session store | AES-256-GCM, key rotation, TTL-managed eviction. |
| Cross-backend `Store<K, V>` trait | All five backends implement it for adopters that want backend-agnostic dispatch via `Arc<dyn Store<…>>`. |

### Device identity

| Feature | Notes |
|---|---|
| Three-stage trust ladder | `Unknown` → `Seen` → `Trusted` (plus terminal `Revoked`); retention sweep demotes idle devices and purges revoked rows past the grace window. |
| Per-tenant fingerprint pepper | Stops cross-tenant fingerprint correlation; `TenantPepperResolver` is adopter-provided. |
| Cascade revocation | Refresh-token family compromise revokes every device that carried that family's binding. |
| `CachedDeviceStore` decorator | LRU + clock-driven TTL eviction; revocation propagates through `set_trust_level`. |
| Five `DeviceStore` backends | `Memory`, `SQLite`, `Postgres`, `MySQL` / MariaDB, `Valkey`; surface-equivalent across SQL dialects + Valkey hash storage, optional AES-256-GCM envelope on the bindings blob (SQL backends). |
| Adopter-supplied store recipe | Documented contracts (tenant scoping, atomic save, hot-path sighting, required sweep) in [`docs/identity/device.md`](docs/identity/device.md) for adopters with non-shipped backends (DynamoDB, MongoDB, …). |
| PII tokenisation | `MemoryDevicePiiStore` reference impl + adopter trait for the GDPR-scoped fields (label, last-seen IP). |

### Workload identity

| Feature | Notes |
|---|---|
| `Principal::{Human, Workload}` unified abstraction | Same `ToCedarEntity` bridge for both shapes; Cedar policies authorise across without branching. |
| `JwtSvidResolver` | SPIFFE JWT-SVID spec adherence; mandatory `spiffe://` URI in `sub`, trust-domain extracted and pinned. |
| `MtlsResolver` | SPIFFE X.509-SVID over mTLS via leaf-cert SAN URI extraction. |
| `WorkloadResolver<C, F, R>` | Generic JWT-bearer workload resolver covering GitHub Actions OIDC, Kubernetes service accounts, GitLab CI, Okta, Azure AD, Auth0, `LocalIdP`, and any other JWT-issuer via an adopter-supplied claim parser + mapping closure. Ready-made recipes for GitHub Actions + k8s SA ship in [`examples/workload-identity/`](examples/workload-identity/). |
| Cloud STS exchange | `aws-sts`, `gcp-wif`, `azure-fic` adapters for exchanging federated workload identity for short-lived cloud credentials. |
| Outbound identity | `outbound-oauth` (axess as OAuth client with `client_credentials` / `private_key_jwt`) and `outbound-mtls` (axess presenting an mTLS identity to downstream services). |

### OAuth / OIDC ceremonies

| Feature | Notes |
|---|---|
| Authorization Code + PKCE | Discovery, token exchange, nonce validation; HTTPS-enforced (localhost / `127.0.0.1` / `[::1]` exemption for dev). |
| Client Credentials | Real HTTP token exchange via `OAuthProviderConfig`. |
| Device Code (RFC 8628) | Real HTTP; device endpoint configured via `with_device_authorization_endpoint`. Nonce-bindable per RFC. |
| Token refresh | Provider-delegated refresh with audit logging. |
| FAPI 2.0 Baseline Profile | Pushed Authorization Requests (PAR, RFC 9126), DPoP (RFC 9449), JARM, RP-initiated logout. Strict `nbf` enforcement on ID tokens with clock-injected validation. |
| Back-Channel Logout | JWT signature verified via cached JWKS; `sid`-based session invalidation. |
| Front-Channel Logout | `GET` handler with `sid` query parameter; shared `SidMap` with back-channel. |
| Plain-OAuth-2.0 social login | `SocialProvider` (gated on `social`, off by default) for IdPs that don't support OIDC (GitHub user login, Twitter/X, Discord, Reddit, Spotify, …). **Weaker security model than OIDC**; identity comes from a TLS-trusted userinfo endpoint, not from a signed assertion. Parallel types (`SocialClaims` vs `IdTokenClaims`) keep the distinction visible at the call site. PKCE on by default. |
| LocalIdpFixture | In-process IdP minting workload JWTs against an in-memory RSA-2048 keypair + matching JWKS endpoint. RS256 + ES256, RFC 8414 discovery, multi-key rotation. |

### On-behalf-of (OBO)

| Feature | Notes |
|---|---|
| `delegated-stored` | RFC 6749 §4.1 Authorization Code + PKCE with persisted refresh token for long-lived offline access. |
| `delegated-exchange` | RFC 8693 Token Exchange for short-lived per-request exchange. |
| `delegated-stored-encrypted` | `EncryptedDelegatedCredentialStore<S, K>` decorator wraps any delegated-credential backend with AES-256-GCM at rest. |

### Authorization

| Feature | Notes |
|---|---|
| Cedar Policy engine | RBAC + ABAC + ReBAC. `AuthzStore` orchestrates evaluation; `ToCedarEntity` bridges principals, resources, and contexts. |
| Layered policy bundle | Base + overlay; adopters drop additional `.cedar` and `.schema.cedar.json` files into an `overlay/` directory. |
| Procedural macros | `require_authn!`, `require_partial_authn!`, `require_authz!` guard handler functions at compile time. |
| Entity caching | `EntityCache` (in-process, default), `MokaEntityCache`, `ValkeyEntityCache` (cross-node). Asymmetric defaults: cache authz, not authn. |

### Middleware

| Feature | Notes |
|---|---|
| CSRF | Signed double-submit cookie; required for state-changing form posts. |
| Rate limiting | Token-bucket via `RateLimitLayer`. `KeyExtractor::{PeerIp, ForwardedIp}` for direct vs trusted-proxy deployments. |
| Request ID | `X-Request-Id` extraction + generation. |
| Trace ID | W3C Trace Context (`traceparent`) propagation. |
| WebSocket | Revocation-aware wrapper that closes connections on session invalidation. |

### Audit and observability

| Feature | Notes |
|---|---|
| `AuthEvent` regulatory audit trail | Six device-identity event variants + the full authn event surface. |
| `AuthnMetrics` | 17-method trait (counters + timers) with no-op defaults. |
| `AuditArchiver` + `AuditRetentionPolicy` | Hot / cold tiering with three-stage retention (90d / 7d / never defaults). `FilesystemAuditArchiver` reference impl behind `audit-archive-fs`. |
| `AuthnAnalyticsSink` + `RichAuthnEvent` | Denormalised analytics path parallel to the regulatory `AuthEvent`. serde + rkyv derives for Apache Iggy / ClickHouse / DuckDB / Snowflake. |
| `TracingCapture` | Test subscriber for asserting on emitted `tracing` events. |

## PII classification

Axess processes personal data as part of authentication. This section documents what the library logs, stores, and never touches; useful for GDPR Data Protection Impact Assessments and SOC2 evidence packages.

### What axess logs (via `tracing` and `AuthEvent`)

| Field | Where | Purpose | PII? |
|---|---|---|---|
| `user_id` | Structured log spans, `AuthEvent` | Correlate events to accounts | **Pseudonymous**; opaque ID, not directly identifying |
| `tenant_id` | Structured log spans, `AuthEvent` | Multi-tenant correlation | No |
| `session_id` | `AuthEvent`, tracing spans | Session correlation | No (random UUID) |
| `IP address` | `AuditContext` (extracted from headers) | Geo/fraud detection, compliance | **Yes**; personal data under GDPR |
| `User-Agent` | `AuditContext`, session binding | Client identification, hijack detection | **Indirect**; device fingerprint |
| `event_type` | `AuthEvent` | Audit trail (login, factor verified, logout) | No |
| `factor_kind` | `AuthEvent` | Which factor was attempted | No |
| `success/failure` | `AuthEvent` | Security monitoring | No |
| `request_id` | `AuditContext` | Request tracing | No |

### What axess stores in session data

| Field | Storage | PII? |
|---|---|---|
| `user_id` / `tenant_id` | Session store (Memory / SQLite / Postgres / MySQL / Valkey) | Pseudonymous |
| `auth_state` | Session store | No |
| `fingerprint` | Session store (HMAC hash) | No (one-way hash) |
| `custom` | Session store (application-defined) | **Depends on application** |

### What axess NEVER logs or stores

- Plaintext passwords (only Argon2id hashes are stored; input is zeroized after hashing)
- TOTP/HOTP secrets in logs (stored encrypted in `FactorConfig`, zeroized on drop)
- Session cookie values
- OAuth tokens (access, refresh, ID tokens); these stay in memory only during the exchange
- PKCE verifiers, CSRF state tokens (cleared from session after use)

### Recommendations

- **Encrypt at rest**: pass a `SessionCrypto::new(key)` to the SQL session-store constructors (`SqliteSessionStore::new(pool, crypto)`, same for Postgres / MySQL) or use `ValkeySessionStore::new(client, key)` so session data (which contains `user_id`) is AES-256-GCM protected. The explicit `::plaintext(pool)` constructor opts out and is dev/test only.
- **Log retention**: configure your log aggregator to retain auth events per your compliance requirements (MiFID II: 5 years; GDPR: minimize).
- **Right to erasure**: deleting a user's sessions (`SessionRegistry::invalidate_user`) and database records satisfies GDPR erasure for axess-managed data. The `custom` session field is the application's responsibility.

## Compliance framework mapping

### GDPR

| Requirement | How Axess addresses it |
|---|---|
| Lawful basis for processing | Application's responsibility. Axess processes only what the app sends. |
| Data minimization | Sessions store only `user_id`, `tenant_id`, `auth_state`, and `fingerprint` (HMAC hash). |
| Right to erasure | `SessionRegistry::invalidate_user()` + database record deletion. |
| Data protection by design | AES-256-GCM encryption at rest, zeroization of secrets in memory. |
| Breach notification | Application responsibility. Axess provides audit trail via `AuthEvent`. |
| DPA (Data Processing Agreement) | Not applicable; Axess is a library, not a service. |

### SOC2

| Trust service criteria | How Axess addresses it |
|---|---|
| CC6.1; Logical access security | MFA, session binding, Cedar policy authorization |
| CC6.3; Access revocation | `SessionRegistry::invalidate_user()`, session TTL |
| CC7.2; Monitoring | `AuthnMetrics` trait (17 hooks), `AuthEvent` audit trail, tracing |
| CC8.1; Change management | Application responsibility (CI/CD, version pinning) |

### PCI-DSS

| Requirement | How Axess addresses it |
|---|---|
| 8.3; MFA for admin access | Multi-factor chain support (password + TOTP/FIDO2) |
| 8.6; Session management | Signed cookies, TTL, session binding, forced logout |
| 3.4; Encryption of cardholder data | AES-256-GCM session encryption (session store, not card data) |
| 10.2; Audit trails | `AuthEvent` records login attempts, factor verifications, logouts |

### HIPAA

| Safeguard | How Axess addresses it |
|---|---|
| Access control (§164.312(a)) | MFA, Cedar RBAC/ABAC, session state machine |
| Audit controls (§164.312(b)) | `AuthEvent` audit trail with timestamps |
| Integrity controls (§164.312(c)) | HMAC-signed session cookies, AES-GCM encryption |
| Transmission security (§164.312(e)) | Application must terminate TLS; Axess sets `Secure` cookie flag |

> These mappings are informational. Compliance certification requires assessment of the complete application stack, not just the authentication library.

## Supported Versions

We recommend using the latest release of Axess and actively maintained branches.

## Disclaimer

Axess is provided as a library. While we strive for secure defaults, the overall security of your application depends on your usage and integration.
