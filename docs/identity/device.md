# Device identity

A device in axess is a typed aggregate, not a string in a column. A
user has zero or more devices; each device has a stable identifier,
a fingerprint that the session layer can match against, an
assurance level on a three-stage ladder, and a relationship to the
refresh tokens issued against it. The combination is the
machinery behind "this device was lost, revoke its access" and
"this is a new device, require step-up before we trust it." The
mechanism is opt-in but on by default in the `axess` facade
because most adopters benefit from it without specifically asking.

The feature flag is `device` (on by default).

## The three-stage ladder

A device occupies one of four states. The first three form an
assurance ladder; the fourth is terminal.

`Unknown` is the default for a new device. The session layer has
seen this fingerprint for the first time, the user has not yet
confirmed it, and no commitment has been made about trust. An
unknown device can still authenticate (the user enters their
password and second factor as usual), but step-up policies may
require additional friction (a second confirmation email, a
recovery code) before high-sensitivity actions become available.

`Seen` is the second state. The device has authenticated
successfully at least once; the user has implicitly accepted it
by continuing through the login. A seen device retains the
fingerprint binding from the session layer but does not yet carry
explicit trust. It is the right state for a device that the user
might log in from again but has not explicitly registered.

`Trusted` is the third state and the steady state for primary
devices. The user (or the application's administrative flow)
explicitly trusted this device. The device's fingerprint binding
applies; the device is the bound carrier for refresh tokens; the
device can perform high-sensitivity actions without additional
step-up.

`Revoked` is the terminal state. The device was lost, the user
removed it, the security team forced a revocation, or the system
detected compromise. Tokens bound to the device are revoked,
sessions bound to it are deleted, and further authentication
attempts from the fingerprint are blocked until the user
explicitly re-establishes the device.

The transitions move strictly forward through the ladder.
`Unknown` becomes `Seen` on first successful login. `Seen` becomes
`Trusted` on explicit user action or after an
application-configurable trust period. Any state becomes `Revoked`
on revocation. There is no path back from `Revoked`; a device
that was revoked and is later re-encountered registers as a new
`Unknown` device.

## The device record

The `Device` struct carries the per-device state:

```rust,ignore
pub struct Device {
    pub device_id: DeviceId,
    pub user_id: UserId,
    pub tenant_id: TenantId,
    pub trust_level: DeviceTrustLevel,  // Unknown | Seen | Trusted | Revoked
    pub fingerprint_hash: String,        // HMAC against the per-tenant pepper
    pub display_name: Option<String>,   // user-set ("My laptop")
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub trusted_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}
```

The `device_id` is a stable identifier minted at first sight. It
is what refresh tokens bind to (see *Refresh tokens and session
continuity*), what Cedar policies can reference, and what the
admin UI lists when the user inspects their registered devices.

The `fingerprint_hash` is the HMAC of the device's fingerprint
features against a per-tenant pepper. The hash, not the raw
fingerprint, lives in the database; the raw features are computed
per request and matched constant-time. Storing the hash defends
against database breach: an attacker who reads every row of the
device store does not learn the underlying fingerprint features
of any user.

The `display_name` is for the user. When the device transitions
from `Seen` to `Trusted` the application typically asks the user
to name it ("My laptop", "iPhone 15 Pro"); the name appears in the
user's device-management UI. It is not used for authentication.

## The per-tenant pepper

The fingerprint pepper is the secret the HMAC uses. Two design
choices matter.

The pepper is per-tenant, not global. Each tenant has its own
pepper, stored alongside the tenant record. The choice means that
a fingerprint hash from tenant A cannot be matched against tenant
B's hashes; a breach that leaks one tenant's pepper compromises
only that tenant's fingerprint hashes.

The pepper is rotated when the tenant is suspended or when the
deployment chooses to invalidate all device records. Rotation
invalidates every device record under the tenant (their
fingerprint hashes no longer match the new pepper); existing
sessions remain valid (they do not depend on the device record),
but new logins re-register devices from scratch.

The chapter *Operations runbook* covers the rotation sequence and
the staged rollout.

## How devices interact with refresh tokens

The cascade between devices and refresh tokens is bidirectional
and is what makes "revoke this device" actually mean "revoke every
session this device can refresh."

In one direction: when a device is revoked, every refresh token
that carries `device_id = revoked_device` is invalidated. The next
attempt to use any of those tokens fails. The application's
session layer detects this on the next refresh and treats the
session as expired.

In the other direction: when a refresh token family is invalidated
through reuse detection (the family-revoke mechanism covered in
*Refresh tokens*), the cascade marks the bound devices as
compromised. The compromise is the shortcut from `Trusted` (or
`Seen`) to `Revoked` without an intermediate state.

The cascade is what makes the system robust against both
operator-initiated revocation ("the device was lost") and
attack-driven revocation ("a token was stolen"). The two cases
converge on the same revocation primitive; both directions of
cascade fire from the same code path.

## Step-up policies

The trust level becomes interesting at the Cedar policy layer. A
policy that wants to require a `Trusted` device for sensitive
actions reads `principal.device.trust_level == "Trusted"`:

```cedar,ignore
forbid (
    principal,
    action == Action::"transfer-funds",
    resource
) when {
    principal.device.trust_level != "Trusted"
};
```

The rule denies fund transfers from any device that is not
`Trusted`. A user on a new (`Unknown` or `Seen`) device is
prompted to trust the device first, typically by completing an
additional verification step (a second-factor challenge, a
confirmation email, a step-up to FIDO2).

The pattern composes with the other authorisation styles. A policy
that requires both FIDO2 and a Trusted device is the two
constraints together; a policy that allows any of three different
ways to clear the bar is the disjunction in one rule.

## Identifying a device

Each request needs to be associated with a device. The mapping
runs through the `DeviceResolver` trait:

```rust,ignore
#[async_trait]
pub trait DeviceResolver: Send + Sync {
    async fn resolve(
        &self,
        request: &Request,
        user_id: &UserId,
        tenant_id: &TenantId,
    ) -> Result<DeviceMatch, DeviceResolverError>;
}

pub enum DeviceMatch {
    Existing(DeviceId),
    NewDevice(DeviceId),  // freshly minted, written to store
}
```

The default implementation computes the fingerprint from the
request features (user agent, IP, accept-language) and matches it
against existing devices for the user. A match returns the
existing device id; a miss writes a new device row with
`trust_level = Unknown` and returns the new id.

The default works for most deployments. Applications with
stronger device-identity signals (a long-lived hardware key, a
mobile app's persistent installation id, a device certificate)
can provide their own `DeviceResolver` that consults the stronger
signal first and falls back to the fingerprint match.

## Caching

The device record is read on most requests (every authenticated
request that involves a Cedar evaluation reads the device). A
naive lookup against the device store would be the hottest read
in the application.

The `CachedDeviceStore` decorator wraps any `DeviceStore` with an
LRU+TTL cache. The cache key is `(tenant_id, device_id)`; the
cache value is the `Device` record. The TTL is short (a few
seconds) so revocations propagate quickly; the LRU bound
constrains memory under fan-out scenarios.

The cache is invalidated explicitly on revocation. The
`DeviceStore::revoke` call clears the relevant cache entry and
writes the revocation. Subsequent reads see the revoked state
without waiting for the TTL.

The pattern is the same one *Entity providers and request
context* covers for the Cedar entity cache. Cache the data, not
the decision; invalidate eagerly on mutation; let TTLs catch the
cases the invalidation missed.

## PII tokenisation and GDPR

The device record carries personally-identifiable information.
The fingerprint features include the IP address (which is PII
under GDPR), the user agent (which can carry identifying details
about the user's setup), and the timestamps (which together can
identify the user's working patterns).

The defence is twofold.

The first is that the device store holds hashes, not the raw
features. The fingerprint hash is the HMAC against the
per-tenant pepper; an attacker who reads the store sees the
hash, not the IP or user agent.

The second is the retention sweep. The `DeviceStore::retention_sweep`
verb removes device records older than a configured threshold,
along with the refresh tokens that bound to them. The sweep is
the GDPR-shaped lever: data the deployment no longer needs is
removed within a bounded period, and the retention is
documentable.

The retention period is per-tenant. The
`Tenant::device_retention_days` field carries it; the default is
ninety days. Tenants with stricter requirements set it lower
(say, thirty days for an EU tenant subject to strict GDPR
interpretation); tenants with looser ones set it higher (say,
three hundred and sixty-five days for a US tenant where session
continuity matters more).

The chapter *Multi-tenancy* covers the per-tenant configuration
mechanism. *Security posture* covers the GDPR and SOC2
touch-points.

## Storage backends and writing your own

axess ships five `DeviceStore` implementations:

| Backend | Feature | Notes |
|---|---|---|
| `MemoryDeviceStore` | `memory` | `DashMap` + clock-driven sweep. Dev and tests. |
| `SqliteDeviceStore` | `sqlite` | SQLx pool, `INSERT … ON CONFLICT`, schema in `init_schema()`. |
| `PostgresDeviceStore` | `postgres` | SQLx pool, same surface as the sqlite backend with the Postgres dialect. |
| `MysqlDeviceStore` | `mysql` | SQLx pool, MySQL dialect (`?` binds, `ON DUPLICATE KEY UPDATE`, `VARBINARY(32)`). Compatible with MySQL 8.x and MariaDB 10.5+. |
| `ValkeyDeviceStore` | `valkey` | Hash-per-device + per-tenant fingerprint index. Server-side `EXPIRE` handles purge. |

All five SQL/Valkey backends share the same trait surface; switching
between them requires only the `init_schema` call against the new
pool and a different constructor at startup.

### Writing an adopter-supplied store

Any storage technology can back devices as long as it can answer the
ten methods on `axess_core::device::DeviceStore`. The shipped
backends (memory, sqlite, postgres, valkey) are the reference
implementations to read alongside the trait docstring; the recipe
below names the contracts that aren't obvious from method
signatures.

**Type and Error.** Implement the trait on a `Clone + Send + Sync +
'static` struct (typically `Arc<...>` around your connection pool /
client). Pick a single `type Error: std::error::Error + Send + Sync
+ 'static`; the existing backends use a `thiserror` enum that wraps
their driver error + a "missing row" variant. Don't conflate driver
errors with domain errors (a `NotFound` returned by your driver
should not surface as `Some(Device)` in `load`; map it to `Ok(None)`).

**Tenant scoping is mandatory.** Every method that takes a
`TenantId` must filter on it in the query. The peppered
`FingerprintHash` is already keyed per-tenant, but the trait
contract documents the scoping requirement explicitly to prevent
cross-tenant leakage on a backend whose primary index might
otherwise be only by hash. Read the docstring on
`find_by_fingerprint` for the rationale.

**`save` must be atomic.** `save` is documented as idempotent
upsert. Implementations that do `SELECT` + `INSERT` racy-checks
must wrap them in a transaction or use the dialect's native
upsert (`ON CONFLICT`, `ON DUPLICATE KEY UPDATE`, `MERGE`, or
`SETNX` for KV stores). A non-atomic `save` produces lost updates
under concurrent device-promotion calls.

**`record_sighting` is hot-path.** Every authenticated request
touches this. Implement it as a single `UPDATE … SET last_seen_at
= ?` rather than a load-modify-save round trip. The shipped
backends are a guide. The `CachedDeviceStore` decorator (see
caching, above) shields the underlying store from read pressure
but the write path runs through every request.

**`sweep` is required, not defaulted.** A backend that doesn't
implement sweep cannot age devices through the three-stage ladder,
and the documented retention posture (90d trusted / 30d seen / 7d
revoked grace) silently breaks. The trait deliberately omits a
default impl so backends must answer the question, even if the
answer is `Err(_)` with a "sweep not yet implemented" sentinel
during initial development.

**Sighting timestamps come from a `Clock`.** Methods that need
"now" (`record_sighting`, `set_trust_level`, `sweep`) accept
`now: DateTime<Utc>` as a parameter. Callers thread `clock.now()`
through; backends never call `Utc::now()` themselves. This
preserves DST determinism for adopter integration tests.

**Mirror the per-backend test layout.** Each shipped backend has
its own test module exercising the trait surface end-to-end (load
round-trip, fingerprint lookup, refresh-family fan-out, retention
sweep); `device/storage/sqlite/tests.rs` is the most complete
template. Copy that suite, adapt the harness setup to your
backend, and run it to catch the non-obvious contract violations
(tenant-scoping leaks, non-atomic save races, sweep counts off-by-
one).

**Reach for `CachedDeviceStore` over reinventing.** If your gap is
"my backend is slow on `load`", wrap your store in
`CachedDeviceStore` before optimising the implementation. The
decorator gives you bounded-size LRU + clock-driven TTL eviction
for free, with revocation propagating through `set_trust_level`.

## What this enables

Device identity is the connective tissue between the user, the
sessions they hold, the refresh tokens those sessions issue, and
the authorisation decisions the application makes about them. A
user with a known device gets a smoother experience: the
fingerprint binding holds, the refresh tokens roll, the policies
default to trust. A user with an unknown device gets friction
exactly when it makes sense: a step-up before sensitive actions,
a confirmation before high-trust operations. A user with a
revoked device gets nothing, immediately.

The mechanism is small (a handful of types, one ladder, one
cascade) but its reach is wide (every refresh, every policy
evaluation, every audit event). Once you have the device aggregate
in mind, the rest of the security model falls into place around
it.

## Further reading

*Refresh tokens and session continuity* covers the binding between
devices and tokens, including the cascade in both directions.
*Cedar policy fundamentals* covers how policies read the
device's trust level. *Multi-tenancy* covers the per-tenant
fingerprint pepper and retention configuration. *Security
posture* covers the GDPR and SOC2 implications of device data.
