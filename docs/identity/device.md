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
detected compromise. Revoking through `revoke_device` marks the device
and revokes every refresh token issued to it; a plain
`set_trust_level(Revoked)` marks the device only (see *Revoking a
device*). A revoked row is never reused and never touched by a sighting.
Revocation does not block future logins: the fingerprint is a hint the
client controls, so a request that changes any input of it (the
`User-Agent`, the language, the network range) is a different
fingerprint and registers as a new `Unknown` device. Lock an account out
by rotating its credentials and factors, not by revoking a device.

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
pepper, supplied by the application through a `TenantPepperResolver`
(a function from a tenant id to 32 bytes) that reads it from the
deployment's secrets manager or the tenant record. The choice means that
a fingerprint hash from tenant A cannot be matched against tenant
B's hashes; a breach that leaks one tenant's pepper compromises
only that tenant's fingerprint hashes.

The pepper is rotated when the tenant is suspended or when the
deployment chooses to invalidate all device records. There is no
rotation call in axess: you rotate by changing what the resolver
returns for that tenant. Rotation
invalidates every device record under the tenant (their
fingerprint hashes no longer match the new pepper); existing
sessions remain valid (they do not depend on the device record),
but new logins re-register devices from scratch.

The chapter *Operations runbook* covers the rotation sequence and
the staged rollout.

## How devices are used

Refresh tokens, step-up decisions, and recognising a returning device.

### How devices interact with refresh tokens

A refresh token records the device it was issued to
(`RefreshToken::device_id`), and every token of a rotation family
carries the same device id. The link works in both directions, and
neither direction is implicit: each takes a call you make.

**Revoking a device.** `revoke_device(device_store, refresh_store,
tenant, device_id, now)` marks the device `Revoked` and then revokes every
refresh token issued to it, through `RefreshTokenStore::revoke_device_tokens`
(one statement per backend, scoped by tenant). It attempts both halves
even if one fails, returns the number of tokens revoked, and reports a
store that cannot revoke by device (`RevokeDeviceError::TokensUnsupported`)
instead of skipping it. After it, the next refresh with one of those tokens
fails with `Revoked` and issues nothing, and a token of the same user's
other device still refreshes. Plain `DeviceStore::set_trust_level` changes
the device row and touches no token: a lost device's tokens keep
refreshing until something revokes them.

Sessions that were already issued are not ended by either call. A session
ends at its own expiry or through the session store, and carries
`device_id` for an application that wants to check the device on each
request.

**Checking the device on refresh.** `refresh_session_with_device_check`
is `refresh_session` that first loads the token's device and refuses with
`RefreshError::DeviceRevoked` when it is `Revoked` or no longer exists,
before anything is rotated. A token without a device id is refreshed as
usual, and a device store that cannot answer refuses with
`RefreshError::DeviceStore` instead of letting the refresh through. Use it
as the second line behind `revoke_device`, and as the only line for a
refresh store without revoke-by-device.

**A compromised family.** When a rotated-out token is reused, the family
is revoked and `RefreshTokenStore::on_token_compromise` is called with the
`(tenant, device)` pairs of the family. The default hook only logs,
because a refresh store holds no device store. Wrap the store in
`CascadingRefreshStore::new(refresh_store, device_store, clock)` to have
the hook revoke those devices, with the wrapped store's own hook still
called afterwards.

**The device binding of a token.** The `device_info` string a caller
passes when it issues a token is not stored. The token stores a keyed digest
of it together with the token's device id (`hb1:` and the base64url of an
HMAC-SHA256 under the refresh pepper), so a database dump holds no client
strings, and the stored value matches only the device id on the same row.
Refresh recomputes the digest from the string the caller presents and
compares in constant time; the replacement token inherits the stored value.
Pass the keyed fingerprint (the hex of the `FingerprintHash` the extractor
computed) rather than a raw `User-Agent`: the string is still whatever the
client's request yields, and the device id link above is the strong binding.
Configure `RefreshTokenConfig::hash_pepper` so the digest is keyed; without
one it is an unkeyed hash. A token issued by an earlier release stores the
raw string; it is still honoured, and the token that replaces it carries the
digest.

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

### A fingerprint is a hint, not proof

The default `DefaultFingerprintExtractor` keys a hash on the
`User-Agent`, the first `Accept-Language` entry and the client address
truncated to a /24 (IPv4) or /48 (IPv6) range. Every input is chosen by the
client or shared by anyone on the same network, so anyone who knows a
user's headers produces the same fingerprint and is matched to the same
device row. A match means "this request looks like that device", never
"this is that device".

Consequences for how you use it:

- The default `StepUpPolicy` asks for a factor on a `Trusted` device
  as well as on `Unknown` and `Seen` ones, and on `Revoked` ones (an empty
  `revoked` list means the `unknown` list applies). Setting `trusted` to an
  empty list lets a trusted device skip step-up, which is only safe when a
  second signal the client cannot copy, such as a device certificate or a
  key held by your app, backs the match.
- A request the device layer cannot fingerprint (no `User-Agent`, or an
  unavailable device store) has no device. Neither has a guest that presents
  no valid device cookie: no device row is written for a visitor who never
  signs in. Judge it with
  `decide_step_up_for_optional(None, ..)`, which uses the `unknown` factors,
  not as "no step-up".
- Without `client_ip::layer` the address is left out of the fingerprint
  and clients with the same headers match one device from anywhere. The
  resolver logs a warning once when it finds no layer; install it, as the
  device example does.
- An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is reduced to its IPv4 /24
  before hashing. Deployments upgrading from a release that did not do this
  see new fingerprints for clients that reach them through a dual-stack
  listener, so those clients register as new devices once.

### The device token

Because a fingerprint can be copied, `LifecycleDeviceResolver` does not find a
device by it. A device is found by a token the client holds and cannot guess.

When a request carries an authenticated user and no valid token, the resolver
creates a new `Unknown` device for that user and mints a random 32-byte token.
The row stores only a SHA-256 digest of the token (as a
`DeviceBinding::Cookie`), and the token goes to the browser in a cookie,

```text
__Host-axess_device=<device id>.<token>; Secure; HttpOnly; SameSite=Strict; Path=/
```

valid for 400 days, the longest a browser keeps one. A later request presents
the cookie; the resolver loads the row by the id in it and compares the token's
digest with the row's in constant time. A request without a valid token never
inherits a device by matching headers, whoever the device belongs to and
whatever its trust level: the headers that copy a fingerprint copy nothing
else.

- `DeviceCookieConfig` names the cookie. `DeviceCookieConfig::insecure_for_local_development`
  drops the `__Host-` prefix and `Secure` for a server on plain HTTP, which a
  browser would otherwise reject; never use it behind HTTPS.
- The session layer sends the cookie. It puts a `DeviceCookieSlot` in the
  request extensions, the resolver leaves the `Set-Cookie` value there when it
  issues a token, and the layer appends it to the response. A resolver you
  write yourself does the same, or issues its own cookie.
- `SameSite=Strict` keeps the cookie off cross-site requests, so a visit that
  arrives from another site carries the session cookie and not this one. The
  session layer tells the resolver which device the session was last bound
  to (`SessionDevice`), and the resolver keeps it for an authenticated user
  instead of minting another.
- A guest request that presents a valid cookie is recognised, so step-up can
  judge a returning `Trusted` browser before sign-in; it writes nothing, not
  even a sighting.
- A `Revoked` device is not recognised by its token; the request gets a new
  `Unknown` device.
- Devices created by an earlier release have no token. They are never matched
  by fingerprint again: each browser gets a new device (and a cookie) at its
  next authenticated request, so trust earned on the old row has to be earned
  once more. The old rows age out through the retention sweep.
- Clearing cookies is a new device, as it should be.

`DeviceLifecycleService::ensure_device`, which matches by fingerprint, is
still there for an application that proves the device some other way (a
device certificate, a key held by your app). It carries the limits above.

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
- `client_ip_fn`, defaulting to the address `client_ip::layer` resolved,
  and to `None` (with a one-time warning) when that layer is not installed,
  because reading the address yourself means either `ConnectInfo` or a
  trusted `X-Forwarded-For`.
- `user_fn`, defaulting to the user the session layer found
  authenticated on the session (`SessionUser` in the request
  extensions) and `None` for a guest, so an authenticated request only
  ever reuses a device its user owns.
- `new_id_fn`, unset by default: a new device gets a v4 UUID drawn
  from the resolver's RNG (`with_rng`, default `SystemRng`), so a
  seeded RNG makes device ids reproducible. Set it to replace the id
  scheme.

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

Revoking a device is `revoke_device` (device and refresh tokens), or
`DeviceStore::set_trust_level(tenant_id, id, DeviceTrustLevel::Revoked,
now)` for the row alone. There is no `revoke` verb on the store. Every write
through a `CachedDeviceStore` drops the cached row once the write finishes,
and also when the future running it is dropped after the store has
committed (a cancelled request), so the instance you wrote through never
serves the pre-write row. Other instances and other processes learn of the
change when their cached entry expires, a few seconds later by default: keep
the TTL short for that reason.

`delete` is the harder form, removing the record outright. Prefer
`Revoked` where the audit trail matters: a deleted device leaves no
evidence that it was ever trusted.

The pattern is the same one *Entity providers and request
context* covers for the Cedar entity cache. Cache the data, not
the decision; invalidate eagerly on mutation; let TTLs catch the
cases the invalidation missed.

### Sighting writes and the per-user lookup

`DeviceLifecycleService::ensure_device` runs on the request path, so it
avoids a store write per request. A known device whose `last_seen_at` is
less than the sighting granularity before `now` (five minutes by default,
`with_sighting_granularity`) is returned without a write; a granularity
of zero records every sighting. `last_seen_at` therefore lags real use by
up to the granularity, which the retention sweep's windows (days) absorb.

`DeviceStore::record_sighting` returns the trust level the row had when the
sighting was applied. `DeviceLifecycleService::promote_on_authn` reports that
level, so a device revoked between its load and its sighting comes back as
`Revoked`, with `last_seen_at` unchanged. `ensure_device` never reuses or
touches a revoked device (a request that matches one gets a new `Unknown`
device), and two first sightings of one fingerprint that race settle on one
device: the one that sorts later removes itself.

For an identified user `ensure_device` looks for the caller's own device
first, with `DeviceStore::find_by_fingerprint_for_user`, and only then at the
newest device that carries the fingerprint, which may belong to another user
(two people behind one office address with the same browser). The
SQL stores answer it from the `idx_devices_user_fingerprint` index on
`(tenant_id, user_id, fingerprint_hash, last_seen_at)`, so a user with
any number of devices finds the right one. SQLite and Postgres create the
index in `init_schema`. A MySQL deployment created earlier adds it once:

```sql
ALTER TABLE devices ADD INDEX idx_devices_user_fingerprint
    (tenant_id, user_id, fingerprint_hash, last_seen_at);
```

A store that does not override the method falls back to scanning the
user's 100 most recently seen devices. The Valkey store keeps a set per
(tenant, fingerprint, user), so the lookup reads only the devices that can
match; devices written by an earlier release are found through the user's
index once and added to the set.

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
`Seen` row is revoked `seen_idle` after the later of its last sighting
and the moment it was demoted from `Trusted` (`Device::demoted_at`). A
`Seen` device that was never trusted is therefore revoked 30 days after
its last sighting, and a Trusted device that goes quiet is demoted at 90
days and revoked 30 days after that (120 days from the last sighting) and
is never revoked in the sweep that demotes it. A sighting after the
demotion restarts the Seen window. Every window is compared in whole
seconds, which is how the SQL backends store timestamps, so all
backends take the same decision for the same row;
`SweepConfigBuilder::build` returns an error for a window with a
fractional second. A `Revoked` row that has no `revoked_at` is stamped
by the sweep and purged one grace period later. The stamp is set on every move from
`Trusted` to `Seen` and cleared by a move to any level but `Seen`, so promoting a
device again starts a fresh ladder. A
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
| `ValkeyDeviceStore` | `valkey` | Key-per-device + per-tenant fingerprint index (a set of the ids that carry each fingerprint, so devices sharing one all stay findable). Server-side `EXPIRE` handles purge. |

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
upsert. It never changes a stored `Revoked` row (a `Device` loaded
before a revocation and saved after it leaves the revoked row alone,
and a save of a revoked copy does not rewrite its `revoked_at` or
bindings; reinstating is an explicit `set_trust_level`), and a
`Revoked` row saved for the first time without `revoked_at` is stamped
with the write time so the sweep can purge it. Setting `Revoked` on a
row that already is keeps its first `revoked_at`. Implementations that do `SELECT` + `INSERT` racy-checks
must wrap them in a transaction or use the dialect's native
upsert (`ON CONFLICT`, `ON DUPLICATE KEY UPDATE`, `MERGE`, or
`SETNX` for KV stores). A non-atomic `save` produces lost updates
under concurrent device-promotion calls.

**`record_sighting` is hot-path.** Every authenticated request
touches this. Implement it as a single `UPDATE … SET last_seen_at
= ?` rather than a load-modify-save round trip. It is monotonic
(`last_seen_at` becomes the later of the stored time and the new one,
so a late request never moves it back) and it leaves a `Revoked` row
alone while still succeeding. It returns the trust level the row has
(`Revoked` for a revoked one), which callers report instead of the level
they loaded earlier. The shipped
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
