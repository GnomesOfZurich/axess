# Axess Example: SQLite Backend

A complete reference application showing how Axess handles the full authentication lifecycle. Signup, login, multi-factor authentication, TOTP enrollment, password reset, session management, rate limiting, health checks, and metrics. All backed by SQLite.

This is the example to start with if you want to understand how the pieces fit together.

## What it demonstrates

| Flow | Routes | What you see |
|------|--------|-------------|
| Signup | `GET/POST /signup` | Account creation with password factor and auth method stored automatically |
| Login | `GET/POST /login` | Password verification, lockout on too many failures |
| MFA (TOTP) | `GET/POST /totp` | Second-factor code entry during login |
| TOTP enrollment | `GET/POST /setup-totp` | Generate secret, verify code, upgrade to password+TOTP |
| Password reset | `GET/POST /forgot-password`, `GET/POST /reset-password` | Token-based reset (token logged to stdout, would be emailed in production) |
| Logout | `POST /logout` | Session clear and registry invalidation |
| Dashboard | `GET /dashboard` | Protected route via `require_authn!` macro |
| Health probe | `GET /healthz` | Auth-component health (SQLite `SELECT 1`). In production, combine with your application's own checks. |
| Metrics | `GET /metrics` | Auth-specific counters (attempts, successes, failures, rate limits). In production, merge into your Prometheus/OTel endpoint. |

## Security features in this example

- **Rate limiting** on all auth routes (10 requests/minute per IP via `RateLimitLayer`)
- **Session encryption at rest** with AES-256-GCM and key rotation (`SessionCrypto::new(key).with_previous_key(old_key)`)
- **HMAC-signed session cookies** with constant-time verification
- **Per-user lockout** after repeated failed attempts

## Running

```sh
cargo run -p axess-example-sqlite
```

The server starts on [http://127.0.0.1:3000](http://127.0.0.1:3000).

### Test accounts (seeded automatically)

| Username | Password | MFA |
|----------|----------|-----|
| alice | Gnomes2+ | Password only |
| bob | Gnomes2+ | Password + TOTP (secret printed in server log) |

Or sign up at `/signup` to create your own account, then enroll TOTP from the dashboard.

### Password reset flow

1. Go to `/forgot-password` and enter a username.
2. Check the server log for the reset token (in production this would be emailed).
3. Go to `/reset-password`, enter the user ID, token, and new password.

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

**Auth method storage.** Each user has an `auth_methods` row defining their factor sequence (`["Password"]` or `["Password","Totp"]`). The signup handler creates this. The TOTP enrollment handler upgrades it.

**Metrics hook.** `AppMetrics` implements `AuthnMetrics` via a newtype wrapper (orphan rule). Counters are `AtomicU64`. The `/metrics` endpoint reads them. In production you would bridge this to Prometheus or OpenTelemetry.

## License

MIT OR Apache-2.0
