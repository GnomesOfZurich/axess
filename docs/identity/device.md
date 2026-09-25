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

## The model

What a device is to axess, and what makes its identifier unguessable.

### The three-stage ladder

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
on revocation. `Revoked` is terminal; a device
that was revoked and is later re-encountered registers as a new
`Unknown` device.

### The device record

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

### The per-tenant pepper

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

## How devices are used

Refresh tokens, step-up decisions, and recognising a returning device.

### How devices interact with refresh tokens

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

### Step-up policies

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

### Identifying a device

Each request needs to be associated with a device. The mapping runs
through the `DeviceResolver` trait:

```rust,ignore
pub trait DeviceResolver: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    fn resolve(
        &self,
        parts: &Parts,
    ) -> impl Future<Output = Result<Option<DeviceId>, Self::Error>> + Send;
}
```

Three things in that signature decide how device tracking behaves.

It takes `axum::http::request::Parts`, not the whole request, because
`axum::body::Body` is `!Sync` and a `Send` future may not hold it across
an `await`. The session layer splits the request before calling and
reassembles it afterwards, so a resolver sees headers, extensions and
the URI but never the body.

It returns `Option<DeviceId>` rather than a match enum. There is no
"existing versus new" distinction at this seam: whether a device row was
found or minted is the resolver's business, and the layer only wants the
id to attach. `Ok(None)` is the ordinary "no device" answer, not a
failure: a request with no `User-Agent`, or one arriving before the
tenant is known, resolves to nothing at all.

The error type is the implementor's associated `Error`, typically the
`DeviceStore::Error` underneath. Resolution is best-effort: the session
layer logs an `Err(_)` and continues without a device rather than
failing the request. A device store outage degrades device tracking; it
does not take authentication down with it.

Two implementations ship. `NoopDeviceResolver` always answers
`Ok(None)`, and is the default plug when the `device` feature is on but
nothing has been configured. `LifecycleDeviceResolver` is the turn-key
one: it wires a `DeviceFingerprintExtractor` to a
`DeviceLifecycleService`, computing the fingerprint from request
features and either matching an existing device or minting one with
`trust_level = Unknown`.

`LifecycleDeviceResolver` has four hooks, because those are the four
things that differ between deployments:

- `tenant_fn`, defaulting to a `TenantId` in the request extensions.
- `client_ip_fn`, defaulting to `None`, because reading it means
  either `ConnectInfo` or a trusted `X-Forwarded-For`.
- `user_fn`, defaulting to `None`, because the resolver runs before
  authentication.
- `new_id_fn`, defaulting to a v4 UUID, overridden in DST tests for
  determinism.

If `tenant_fn` yields `None` the resolver short-circuits to `Ok(None)`:
there is no meaningful device without a tenant scope, for the
cross-tenant-correlation reason this chapter covers below. A
fingerprint the extractor cannot compute short-circuits the same way.

Applications with a stronger device signal (a long-lived hardware key,
a mobile app's installation id, a device certificate) implement
`DeviceResolver` themselves, consult the stronger signal first, and fall
back to the fingerprint match.

## Performance and privacy

Keeping the lookup cheap without keeping the fingerprint.

### Caching

The device record is read on most requests (every authenticated
request that involves a Cedar evaluation reads the device). A
naive lookup against the device store would be the hottest read
in the application.

The `CachedDeviceStore` decorator wraps any `DeviceStore` with an
LRU+TTL cache. The cache key is `(tenant_id, device_id)`; the
cache value is the `Device` record. The TTL is short (a few
seconds) so revocations propagate quickly; the LRU bound
constrains memory under fan-out scenarios.

Revoking a device is `DeviceStore::set_trust_level(tenant_id, id,
DeviceTrustLevel::Revoked, now)`. There is no `revoke` verb, and there
is no cache invalidation hook: the TTL is the only thing that expires a
cached `Device`, so a revocation is visible to other readers within a
few seconds rather than immediately. Keep the TTL short for that
reason, and call `set_trust_level` on the same instance you read
through if you need the change to be visible to yourself at once.

`delete` is the harder form, removing the record outright. Prefer
`Revoked` where the audit trail matters: a deleted device leaves no
evidence that it was ever trusted.

The pattern is the same one *Entity providers and request
context* covers for the Cedar entity cache. Cache the data, not
the decision; invalidate eagerly on mutation; let TTLs catch the
cases the invalidation missed.

### PII tokenisation and GDPR

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

The second is the sweep. `DeviceStore::sweep(tenant_id, now)` ages
devices down through their trust levels and eventually removes them,
returning a `SweepCounts` of what it did:

```rust,ignore
pub struct SweepCounts {
    pub trusted_to_seen: u64,
    pub seen_to_revoked: u64,
    pub revoked_purged: u64,
}
```

Those three numbers are the three transitions, and they are the shape
of the retention story: a trusted device that has not been seen in a
while drops to `Seen`, a `Seen` device that keeps not being seen is
revoked, and a revoked device is purged after a grace period. Only the
last one deletes anything, so a device does not vanish the moment it
goes quiet.

The thresholds are a `SweepConfig`, not a tenant column: `trusted_idle`
(ninety days by default), `seen_idle` (thirty) and `revoked_grace`. A
deployment that needs different retention per tenant holds its own
config per tenant and passes the right one. Axess does not store that
mapping, and `Tenant` carries no retention field to hold it.

The sweep takes `now` rather than reading a clock, so a test can drive
it to any instant and a scheduled job can run it deterministically.
Nothing calls it for you: wire it to whatever runs your periodic work.

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

## The connective tissue

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
