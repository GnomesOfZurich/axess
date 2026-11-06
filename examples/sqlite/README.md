# Axess Example: The Reference Application

A complete reference application showing how Axess handles the full authentication lifecycle. Signup, login, multi-factor authentication, TOTP enrollment with recovery codes, password reset, session management, rate limiting, health checks, and metrics. All backed by SQLite.

This is the example to start with if you want to understand how the pieces fit together.

| Binary | Run with | Shows |
|---|---|---|
| The application (default) | `cargo run -p axess-example-sqlite` | Everything above |
| Device identity | `cargo run -p axess-example-sqlite --bin device` | Fingerprinting, the device trust ladder and its retention sweep, on the same SQLite pool ([below](#device-identity---bin-device)) |

## What it demonstrates

| Flow | Routes | What you see |
|------|--------|-------------|
| Signup | `GET/POST /signup`, `GET /verify-email` | Account creation with password factor and auth method; the account stays a candidate until the mailed link is opened (logged by debug builds, target `dev_mail`) |
| Login | `GET/POST /login` | Password verification, lockout on too many failures |
| MFA (TOTP) | `GET/POST /totp` | Second-factor code entry during login |
| Recovery code | `POST /recovery-code` | A one-time recovery code in place of the TOTP code, offered on the `/totp` page |
| TOTP enrollment | `GET/POST /setup-totp` | Generate secret, verify code, issue ten recovery codes (shown once), upgrade to password then TOTP-or-recovery-code |
| Password reset | `GET/POST /forgot-password`, `GET/POST /reset-password` | Token-based reset (token logged to stdout, would be emailed in production) |
| Logout | `POST /logout` | Session clear (the example runs no session registry; sessions are encrypted with no user column, so `delete_user` erases the user's rows and their sessions expire on their own) |
| Dashboard | `GET /dashboard` | Protected route via `require_authn!` macro |
| Health probe | `GET /healthz` | Auth-component health (SQLite `SELECT 1`). In production, combine with your application's own checks. |
| Metrics | `GET /metrics` | Auth-specific counters (attempts, successes, failures, rate limits). In production, merge into your Prometheus/OTel endpoint. |

## Security features in this example

- **Rate limiting** per client IP via `RateLimitLayer`, on submissions only (reading a form is free): login 10 a minute, forgot-password 5 a minute, each in its own bucket, and one shared bucket of 10 for signup, second factor, reset completion, email verification and TOTP setup
- **Password reset cooldown**: one reset token per account a minute (`with_password_reset_cooldown`)
- **Breached-password check** on every chosen password, at signup and reset (`with_breached_password_check`); a password the check knows is refused by name, and one the check could not screen is refused too, unless the deployment opts out
- **Session encryption at rest** with AES-256-GCM and key rotation (`SessionCrypto::new(key).with_previous_key(old_key)`)
- **HMAC-signed session cookies** with constant-time verification
- **Per-user lockout** after repeated failed attempts

## Running

```sh
cargo run -p axess-example-sqlite
```

The server starts on [http://127.0.0.1:3000](http://127.0.0.1:3000).

### Test accounts (seeded by a debug build)

A debug build seeds two accounts. A release build seeds nothing unless you run it with `EXAMPLE_SEED=1`: the accounts share a published password, so never seed them anywhere real.

| Username | Password | MFA |
|----------|----------|-----|
| alice | Gnomes2+Example | Password only |
| bob | Gnomes2+Example | Password + TOTP (secret printed in the server log at debug level, target `dev_seed`) |

Or sign up at `/signup` to create your own account, then enroll TOTP from the dashboard.

Signup is open to anyone and limited only by the per-IP rate limit. The address is checked by a link that must be opened in the browser that signed up (the pending signup lives in that browser's session); a candidate that never verifies keeps its username until the application purges it. An open signup in production also needs its own abuse controls (a CAPTCHA, an allow-list or an invitation) and a mailer.

### Password reset flow

1. Go to `/forgot-password` and enter a username.
2. Check the server log for the reset link (log target `dev_mail`, written by debug builds only; in production it would be emailed). The token is never logged at info level.
3. Open the link, `/reset-password?user_id=...&tenant_id=...&token=...`, and choose a new password. A password that breaks the tenant's rules is reported as such and the link stays valid.

### Cookies and local HTTP

Session and CSRF cookies are `Secure`. Browsers accept them on `http://localhost`; for a browser or host name that does not, set `AXESS_DEV_INSECURE_COOKIES=1` (a warning banner is logged). Never set it behind a real host name.

## Project structure

```
src/
  main.rs              Startup, migrations, seed data
  models/backend.rs    IdentityStore + FactorStore implementation against SQLite
  web/app.rs           Router, SessionLayer, RateLimitLayer, health/metrics endpoints
  web/auth.rs          Login, signup, TOTP, password reset handlers
  web/protected.rs     Dashboard (require_authn! guard)
migrations/            SQLx migration scripts
templates/             HTML templates
```

## Key patterns

**Backend implementation.** `OurBackend` implements both `IdentityStore` and `FactorStore` on one struct wrapping a `SqlitePool`. This is the typical pattern. See `src/models/backend.rs`.

**Factor storage.** Password hashes and TOTP secrets are stored as JSON-serialized `FactorConfig` values. The `save_factor` method uses SQLite `ON CONFLICT ... DO UPDATE` for upserts.

**TOTP secrets at rest.** The router builds a `FactorSecretCipher` from a key kept in `db/factor-secret.key` (created on first start; in production load it from a secrets manager) and passes it to the service with `with_factor_secret_cipher`. Enrolment seals the secret with `seal_config` before `save_factor`, so the `config_json` column holds ciphertext bound to that user's row. The seed seals Bob's secret through the same cipher, so it is ciphertext from the first start. The cipher still reads a plain secret (`LegacyBlobs::AcceptUntil`) until a fixed date, 2027-01-31 (`plain_secret_cutoff`), so a row written before the cipher existed is sealed by its owner's next login; the date does not move on a restart, and a real deployment sets its own.

**Breached passwords.** The router builds the service with `with_breached_password_check(BreachedPasswordList::new(..))`, a fixed list of six common passwords that meet the default rules, so the refusal can be seen: sign up with `Password1234` and the page says the password is known from a data breach. The signup handler asks `service.check_chosen_password` before `begin_signup` (a refused password creates nothing) and `service.hash_chosen_password` when it stores the factor; the reset flow screens inside `complete_password_reset`. `BreachedPasswordList` lives under axess's `testing` feature because a short list is not protection. A deployment swaps in a range lookup: implement `BreachedPasswordCheck` with one `is_breached` that calls `axess::range_prefix(password)`, fetches `GET https://<range service>/range/<prefix>`, and answers `axess::count_in_range(&body, &suffix).is_some_and(|n| n > 0)`, mapping a transport or status error to `BreachCheckError::new(..)`; then pass it to `with_breached_password_check` in place of the list and drop `testing` from the `axess` features. The book's "Breached passwords" section in `docs/factors/password-totp.md` has the adapter in full.

**Auth method storage.** Each user has an `auth_methods` row holding their `FactorStep`s as JSON: `[{"Required":"Password"}]` after signup, and after TOTP enrollment `[{"Required":"Password"},{"AnyOf":["Totp","RecoveryCode"]}]`, a second step with a choice. `verify_factor` takes either credential for that step and prompts for TOTP first.

**Recovery codes.** Enrollment generates them with `axess::generate_recovery_codes`, stores only the Argon2id hashes as `FactorConfig::RecoveryCodes`, and shows the plaintext once. Each code is spent through the factor store's compare-and-swap, so it works exactly once. `tests/backend_tests.rs` drives the whole flow through the router.

**Metrics hook.** `AppMetrics` implements the metric traits of the concerns it exports (`AuthFlowMetrics`, `FactorMetrics`, `SessionMetrics`, `RotationMetrics`, `ProviderRegistryMetrics`, `RequestGuardMetrics`) and wires itself to every concern with `MetricSinks::all`. Counters are `AtomicU64`, named `axess_<what>_total`. The `/metrics` endpoint lists them. In production you would bridge this to Prometheus or OpenTelemetry.

## License

MIT OR Apache-2.0

## Device identity: `--bin device`

A second binary in this crate: end-to-end device-identity wiring for axess,
run on its own (it listens on the same port as the app, so stop one first).
It exercises:

- One `SqlitePool` shared between `SqliteSessionStore` and
  `SqliteDeviceStore` (the canonical pool-sharing recipe).
- `DefaultFingerprintExtractor` with a per-tenant HMAC pepper.
- `CachedDeviceStore` decorator (axess-cache backed; DST-friendly) on
  the hot path.
- `DeviceLifecycleService::ensure_device` driving the
  Unknown-on-first-sighting upsert and `record_sighting` bump.
- `LifecycleDeviceResolver` as an explicit per-handler resolver.
- A background `tokio` task running the three-stage retention sweep
  (`Trusted` → `Seen` → `Revoked` → purge).

### Running

```bash
cargo run -p axess-example-sqlite --bin device
```

In another terminal, exercise the routes:

```bash
# First sighting: creates an Unknown device, returns its id.
curl -v http://localhost:3000/whoami

# Same User-Agent + IP: finds the existing device, bumps last_seen_at.
curl -v http://localhost:3000/whoami

# Different User-Agent: fingerprint differs, creates a second device.
curl -v -A 'curl/8.0 (different)' http://localhost:3000/whoami

# Note: /devices lists devices owned by the demo user. The example does
# not run an authn flow, so all sighted devices are unowned
# (`user_id = None`) and won't appear here until a real authn flow
# associates them via a login + a follow-up update.
curl -v http://localhost:3000/devices
```

Watch the example's logs for `device-sweep tick` lines from the
background retention task.

### Feature combinations

The crate uses `axess` with `["sqlite"]` and the default-on
`device` feature.

Other useful combinations:

| Combination | Result |
|---|---|
| `["sqlite"]` (this crate) | `SqliteSessionStore` + `SqliteDeviceStore` against one `SqlitePool` |
| `["postgres"]` | Same shape with `PostgresSessionStore` + `PostgresDeviceStore` against one `PgPool` |
| `["mysql"]` | Same shape with `MysqlSessionStore` + `MysqlDeviceStore` against one `MySqlPool` (MySQL 8.x / MariaDB 10.5+) |
| `["valkey"]` | `ValkeySessionStore` + `ValkeyDeviceStore` against one `fred::Client` |
| `["sqlite", "valkey"]` | Sessions in SQLite, devices in Valkey (or any mix) |
| Add `["valkey-cache"]` instead of the in-process cache | Cross-node Valkey-backed device cache (cluster-tier) |

The store traits compose orthogonally; the device subsystem doesn't
care which session store you use, and vice versa.

### What's intentionally NOT in the example

- Real authentication flow. The example demonstrates *device resolution*,
  not factor login. Wire `axess::AuthnService` + an `IdentityStore` to
  drive a real login → `promote_on_authn(device_id, Unknown→Seen)` cascade.
- Cookie-binding records (`DeviceBinding::Cookie`). Issuing a long-lived
  device-binding cookie + recording its HMAC as a `Cookie` binding on the
  device row is the next phase after the basic fingerprint flow.
- WebAuthn binding (`DeviceBinding::WebAuthn`). Lands when the FIDO2
  ceremony emits the binding.
- PII tokenisation. `axess::DevicePiiStore` stores
  display-name / user-agent / IP under tokens, separate from the
  PII-free `Device` row. Add this when your application needs
  GDPR-Art-17-erasable device metadata.
