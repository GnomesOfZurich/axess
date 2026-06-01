# axess-example-device

End-to-end device-identity wiring for axess, exercising:

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

## Running

```bash
cargo run -p axess-example-device
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
# associates them via `set_authenticated` + a follow-up update.
curl -v http://localhost:3000/devices
```

Watch the example's logs for `device-sweep tick` lines from the
background retention task.

## Feature combinations

This example uses `axess` with `["sqlite"]` and the default-on
`device` feature.

Other useful combinations:

| Combination | Result |
|---|---|
| `["sqlite"]` (this example) | `SqliteSessionStore` + `SqliteDeviceStore` against one `SqlitePool` |
| `["postgres"]` | Same shape with `PostgresSessionStore` + `PostgresDeviceStore` against one `PgPool` |
| `["mysql"]` | Same shape with `MysqlSessionStore` + `MysqlDeviceStore` against one `MySqlPool` (MySQL 8.x / MariaDB 10.5+) |
| `["valkey"]` | `ValkeySessionStore` + `ValkeyDeviceStore` against one `fred::Client` |
| `["sqlite", "valkey"]` | Sessions in SQLite, devices in Valkey (or any mix) |
| Add `["valkey-cache"]` instead of the in-process cache | Cross-node Valkey-backed device cache (cluster-tier) |

The store traits compose orthogonally; the device subsystem doesn't
care which session store you use, and vice versa.

## What's intentionally NOT in the example

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
