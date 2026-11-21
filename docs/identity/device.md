# Device identity

A device in axess is a typed aggregate, not a string in a column. A
user has zero or more devices; each device has a stable identifier,
a secret token its browser holds as proof, a fingerprint
recorded as a hint, an assurance level on a three-stage ladder, and a
relationship to the refresh tokens issued against it. The combination is the
machinery behind "this device was lost, revoke its access" and
"this is a new device, require step-up before we trust it."

The feature flag is `device` (on by default in the `axess` facade,
because most adopters benefit from it).

## The model

What a device is to axess, and what makes its identifier unguessable.

### The three-stage ladder

A device occupies one of four states. The first three form an
assurance ladder; the fourth is terminal.

`Unknown` is the state of a new device: an authenticated request
arrived without a valid device token, a device was created for its
user, and nothing is yet assumed about its trust. An
unknown device can still authenticate (the user enters their
password and second factor as usual), but step-up policies may
require additional friction (a second confirmation email, a
recovery code) before high-sensitivity actions become available.

`Seen` is the second state. The device has authenticated
successfully at least once; the user has implicitly accepted it
by continuing through the login. A seen device is recognised by its
token on every later visit but does not yet carry explicit trust. It
is the right state for a device that the user might log in from again
but has not explicitly registered.

`Trusted` is the third state and the steady state for primary
devices. The user explicitly trusted this device, through a
`DeviceLifecycleService::grant_trust` call the application makes, or the
application's administrative flow set the level with
`DeviceStore::set_trust_level`. What the level buys is the policy's decision: a
Cedar rule can require it, and a `StepUpPolicy` can ask a trusted
device for less. The default `StepUpPolicy` asks a trusted device
for a factor all the same (see *A fingerprint is a hint, not proof*).

`Revoked` is the terminal state. The device was lost, the user
removed it, the security team forced a revocation, or the system
detected compromise. Revoking through `revoke_device` marks the device
and revokes every refresh token issued to it; a plain
`set_trust_level(Revoked)` marks the device only (see *Revoking a
device*). A revoked row is never reused and never touched by a sighting.
Revocation does not block future logins: a revoked device is not
recognised by its token, so the next authenticated request from that
browser is given a new `Unknown` device and a new token. Lock an account
out by rotating its credentials and factors, not by revoking a device.

`Unknown` becomes `Seen` on the first successful login
(`DeviceLifecycleService::promote_on_authn`). `Seen` becomes `Trusted`
when the application says so, with `grant_trust` (see *Trust is written
onto a proven device of the session's user*): axess promotes nothing to
`Trusted` by itself and has no trust period. `DeviceStore::set_trust_level`
is the store's own write, which sets any level and checks neither the
proof nor the owner. Any state
becomes `Revoked` on revocation. The retention sweep moves the other
way: a `Trusted` device that goes unseen drops to `Seen`, and a `Seen`
one that stays unseen is revoked (see *PII tokenisation and GDPR*).
`Revoked` is terminal for the request path; only an explicit
`set_trust_level` reinstates a revoked row.

### The device record

The `Device` struct carries the per-device state:

```rust,ignore
pub struct Device {
    pub id: DeviceId,
    pub tenant_id: TenantId,
    pub user_id: Option<UserId>,          // None until an owner claims it
    pub trust_level: DeviceTrustLevel,    // Unknown | Seen | Trusted | Revoked
    pub fingerprint_hash: FingerprintHash, // HMAC against the per-tenant pepper
    pub first_seen_at: Timestamp,
    pub last_seen_at: Timestamp,
    pub revoked_at: Option<Timestamp>,
    pub demoted_at: Option<Timestamp>,    // set by a move from Trusted to Seen
    pub bindings: Vec<DeviceBinding>,     // Cookie | WebAuthn | Refresh | Key
}
```

The `id` is a stable identifier minted when the device is created. It
is what refresh tokens bind to (see *Refresh tokens and session
continuity*), what the session carries as `device_id`, and what the
admin UI lists when the user inspects their registered devices. A
session's `device_id` holds for the person it was resolved for: the
person at the browser when the request began (the administrator during an
impersonation, otherwise the signed-in user). A device resolved on a
guest's request or inside a login is resolved for nobody and holds for
whoever signs in.

The `fingerprint_hash` is the HMAC of the fingerprint features of the
request the device was created on, against a per-tenant pepper. The
hash, not the raw features, lives in the database, so an attacker who
reads every row of the device store does not learn the underlying
features of any user. The stock resolver stores the hash but never looks a
device up by it (see *The device token*).

The `bindings` tie the row to authentication artefacts: a
`Cookie` binding holds the SHA-256 digest of the device token, a
`WebAuthn` binding a passkey registered on the device, a `Refresh`
binding a refresh-token family the device takes part in, and a `Key`
binding the public half of the device's key (see *Device keys*).

The record carries no name, no address and no user agent. A display
name the user gives a device ("My laptop"), like any other identifying
detail, belongs in the separate, deletable `DevicePiiMapping` (see *PII
tokenisation and GDPR*); it is not used for authentication.

### The per-tenant pepper

The fingerprint pepper is the secret the HMAC uses. Two design
choices matter.

The pepper is per-tenant, not global. The application supplies it
through a `TenantPepperResolver`
(a function from a tenant id to 32 bytes) that reads it from the
deployment's secrets manager or the tenant record. As a result,
a fingerprint hash from tenant A cannot be matched against tenant
B's hashes; a breach that leaks one tenant's pepper compromises
only that tenant's fingerprint hashes.

There is no rotation call in axess: you rotate by changing what the
resolver returns for that tenant. What a rotation does depends on how
devices are found. Under `LifecycleDeviceResolver` a device is found by
its token, so existing devices and sessions go on as before and only
the hash stored on devices created from then on differs. Under
`ensure_device`, which looks a device up by its fingerprint, the stored
hashes no longer match and every client registers as a new device. In
either case a refresh token issued with the fingerprint as its
`device_info` no longer matches the fingerprint its client presents.

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
request. The exception is a session bound to a key of the device (see
[Device keys](#device-keys)): a revoked device is refused a fresh proof, so
such a session stops being served when its last proof runs out.

**Checking the device on refresh.** Every refresh must state how it treats the device a token names; there is
no default. A `Refresh` that was given neither the device store nor the
named opt-out has no `run` and does not compile.

`Refresh::device_store` makes a refresh first load the token's device and
refuse with `RefreshError::DeviceRevoked` when it is `Revoked` or no longer
exists, and with `RefreshError::DeviceMismatch` when another user owns it,
before anything is rotated. A token without a device id is refreshed as
usual, and a device store that cannot answer refuses with
`RefreshError::DeviceStore` instead of letting the refresh through. Use it
as the second line behind `revoke_device`, and as the only line for a
refresh store without revoke-by-device. It composes with the other checks
of the one refresh entry point:

```rust,ignore
let (session, rotated) = Refresh::new(&plaintext, &tenant, status_check)
    .device_info(Some(fingerprint))
    .device_store(&devices)
    .run(&refresh_store, &config, &rng, now)
    .await?;
```

`Refresh::without_device_check` is the opt-out, for a deployment whose
tokens name no device or that has no device store to ask. It says at the
call site what is given up for a token that does name a device: the device
is not loaded, so a revoked or purged device still refreshes and so does a
device another user owns.

A device that holds a key (see [Device keys](#device-keys)) adds one rule.
`Refresh::device_key(&keys, proof)` holds its token to a proof by that key.
A refresh that was given the device store and not the key service refuses
such a token with `RefreshError::KeyCheckMissing`, with nothing rotated or
revoked. Omitting the key service by mistake therefore never refreshes a
keyed device's token into a session not bound to the key; that takes the
explicit `without_device_check` with no key service.

The checks run in the order tenant, revoked, expired, account status,
device, device binding, device key, rotation; a token of another tenant
answers `RefreshError::NotFound` before the device is loaded.

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
Refresh recomputes the digest from the string the caller presents, under
the pepper the token was found under, and compares in constant time. The
replacement token carries the digest under the current pepper, so a
bound token survives a pepper rotation (`previous_hash_pepper`) and keeps
working once the previous pepper is dropped. Pass the keyed fingerprint (the
hex of the `FingerprintHash` the extractor computed) rather than a raw
`User-Agent`: the string is still whatever the client's request yields, and
the device id link above is the strong binding. Configure
`RefreshTokenConfig::hash_pepper` so the digest is keyed; without one the
config refuses a `device_info` (`InvalidConfig`) unless it calls
`allow_unkeyed_hashes()`, because an unkeyed hash lets a reader of the store
confirm a guessed device string against it (it never lets a caller pass with
the wrong string).

A token issued by an earlier release stores the raw string; it is still honoured, and
the token that replaces it on its first refresh carries the digest. With
rotation off nothing replaces the token, so the raw string stays until the
token expires; turn rotation on or revoke the user's tokens to retire it
sooner.

The device-checked refreshes also match the owner: a token whose device now
belongs to another user (a guest device claimed by someone else first) is
refused with `RefreshError::DeviceMismatch` and nothing is rotated; an
unowned device passes. The check and the rotation are two store operations,
so a device revoked between them is rotated once more; `revoke_device`
revokes the replacement token when its insert landed first, and the next device-checked
refresh refuses it otherwise.

### Step-up policies

The trust level takes effect at the Cedar policy layer. Axess
builds no device entity of its own: your `AuthzEntityProvider` loads
the session's device and puts what a policy needs on the principal. With
the device as a `device` record there, a policy that wants to require a
`Trusted` device for sensitive actions reads
`principal.device.trust_level == "Trusted"`:

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
`Trusted`. A user on an `Unknown` or `Seen` device is
prompted to trust it first, typically by completing an
additional verification step (a second-factor challenge, a
confirmation email, a step-up to FIDO2).

The pattern composes with other policy conditions: requiring both FIDO2
and a `Trusted` device is the conjunction of the two constraints, and
allowing any of three ways to clear the bar is a disjunction in one rule.

### A fingerprint is a hint, not proof

The default `DefaultFingerprintExtractor` keys a hash on the
`User-Agent`, the first `Accept-Language` entry and the client address
truncated to a /24 (IPv4) or /48 (IPv6) range. Every input is chosen by the
client or shared by anyone on the same network, so anyone who knows a
user's headers produces the same fingerprint, and a lookup by fingerprint
(`ensure_device`) matches them to the same device row. A match means "this
request looks like that device", never "this is that device".

Consequences for how you use it:

- The default `StepUpPolicy` asks for a factor on a `Trusted` device
  as well as on `Unknown` and `Seen` ones, and on `Revoked` ones (an empty
  `revoked` list means the `unknown` list applies). Setting `trusted` to an
  empty list lets a trusted device skip step-up, which is only safe when a
  second signal the client cannot copy, such as a device certificate or a
  key held by your app, backs the match.
- A request the device layer cannot fingerprint (no `User-Agent`) is
  given no new device, and a guest's has none. A signed-in session's is
  found by its device token, its key or the device the session keeps, as
  any other request; with none of them it has no device, so a client that
  never sends a `User-Agent` never has one. A request whose device store
  does not answer proves no device: a guest's has none, and a signed-in
  session keeps the device it had, unproven. Nor does a guest that
  presents no valid device cookie have a device: no device row is written
  for a visitor who never signs in. Judge a request with no device with
  `decide_step_up_for_optional(None, ..)`, which applies the `unknown`
  factors; no device does not mean no step-up.
- Without `client_ip::layer` the address is left out of the fingerprint
  and clients with the same headers share one fingerprint from anywhere.
  The resolver logs a warning once when it finds no layer; install it, as
  the device example does.
- An IPv6 address that carries an IPv4 client (IPv4-mapped `::ffff:a.b.c.d`,
  IPv4-translated, IPv4-compatible, NAT64 `64:ff9b::/96`, 6to4 or Teredo) is
  reduced to the /24 of that client before hashing, as the login throttle
  and the rate limiter key it; an address under the locally used NAT64
  prefix (`64:ff9b:1::/48`) keeps its /120. Deployments upgrading from a
  release that did not do this see new fingerprints for clients that reach
  them through a dual-stack listener, a translator or a relay: a lookup by
  fingerprint (`ensure_device`) registers those clients as new devices
  once, and a device found by its token is not affected.

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
  drops the `__Host-` prefix and `Secure` for a server on plain HTTP, where a
  browser would otherwise reject the cookie; never use it behind HTTPS.
- The session layer sends the cookie. It puts a `DeviceCookieSlot` in the
  request extensions, the resolver leaves the `Set-Cookie` value there when it
  issues a token, and the layer appends it to the response. A resolver you
  write yourself does the same, or issues its own cookie.
- `SameSite=Strict` keeps the cookie off cross-site requests, so a visit that
  arrives from another site carries the session cookie and not this one. The
  session layer tells the resolver which device the session was last bound
  to (`SessionDevice`), and the resolver keeps it for an authenticated user
  instead of minting another. It keeps it as recognised
  (`BoundDevice::Unproven`), not as proven: that request presented no token,
  so `AuthSession::proven_device` answers `None` for it and the lockout does
  not exempt it. The next request that sends the cookie is proven again, and
  neither answer is stored, so the session is not rewritten between them.
- A guest request that presents a valid cookie is recognised, so step-up can
  judge a returning `Trusted` browser before sign-in; it writes nothing, not
  even a sighting.
- A `Revoked` device is not recognised by its token; the request gets a new
  `Unknown` device.
- Devices created by an earlier release have no token. They are never matched
  by fingerprint again: each browser gets a new device (and a cookie) at its
  next authenticated request, so trust earned on the old row has to be earned
  once more. The old rows age out through the retention sweep.
- Clearing cookies makes the browser a new device.
- A device row has one owner, so a browser profile several accounts sign in
  on holds one device per account. The cookie holds one entry per device,
  newest first, joined by `~` (`<id>.<token>~<id>.<token>`), at most
  `MAX_DEVICE_COOKIE_ENTRIES`. A request is resolved to the first entry that
  proves a device its user may use, so an account switch finds the account's
  own device again instead of minting a new one, and a device minted for one
  account keeps the other accounts' entries. A guest is recognised only when
  the cookie proves one device: on a shared profile nothing says which
  account is signing in. A cookie of one entry, as earlier releases wrote
  it, reads as before.

`DeviceLifecycleService::ensure_device`, which matches by fingerprint, is
still there for an application that proves the device some other way (a
device certificate, a key held by your app). It carries the limits above.

### Identifying a device

The `DeviceResolver` trait maps a request to its device, if it has one:

```rust,ignore
pub trait DeviceResolver: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    fn resolve(
        &self,
        parts: &Parts,
    ) -> impl Future<Output = Result<Option<BoundDevice>, Self::Error>> + Send;
}

pub enum BoundDevice {
    Proven(ProvenDevice), // the request presented the device's token
    Unproven(DeviceId),   // found by other means: a label, not a proof
}
```

Three things in that signature decide how device tracking behaves.

It takes `axum::http::request::Parts`, not the whole request, because
`axum::body::Body` is `!Sync` and a `Send` future may not hold it across
an `await`. The session layer splits the request before calling and
reassembles it afterwards, so a resolver sees headers, extensions and
the URI but never the body.

It returns `Option<BoundDevice>`: the device, and whether the request
proved it. There is no "existing versus new" distinction at this seam:
whether a device row was found or minted is the resolver's business. What
the layer does need is the difference between a device the client proved
it holds and one found some other way, because `AuthSession::proven_device`
and the lockout exemption answer only for the first. A `ProvenDevice`
cannot be built by hand: only a resolution by `resolve_or_keep` or
`resolve_proven` yields one, so a resolver cannot claim a proof it does not
hold, and a bare `DeviceId` converts to `Unproven`. The layer stores the id
on the session and nothing else; whether it was proven is asked again on
every request. `Ok(None)` is the ordinary "no device" answer, not a
failure: a guest's request with no `User-Agent`, or one arriving before
the tenant is known, resolves to nothing at all, and the session's
`device_id` is cleared. A signed-in session's request with no tenant says
nothing about its device, so `LifecycleDeviceResolver` fails it instead
(`LifecycleResolveError::TenantMissing`) and the session keeps its
`device_id`; one with no `User-Agent` is resolved as any other and given
no new device.

A request resolves its device for the person at the browser when the
request begins. The device holds for the session only while that person
is still the one at the browser or, while nobody is signed in, is the
user a login in progress names (a person who begins a new login on their
own session keeps their device for it, its lockout exemption included).
A session that becomes another
person's within a request (a sign-in by another account on a signed-in
session) names no device for the rest of that request:
`AuthSession::device_id`, `AuthSession::proven_device` and
`AuthSession::user_device` answer `None`, and the row is written without
the device. The next request resolves a device for the new person. A
step-up and the start of an impersonation keep the person at the browser,
and with them the device. A device resolved for nobody (a guest's request,
or one inside a login) holds for whoever signs in; that is how a login
takes the browser's device as the person's own. `AuthSession::data` and
`AuthSession::with_data` show the row as the request holds it, before
that judgement.

The error type is the implementor's associated `Error`, typically the
`DeviceStore::Error` underneath. Resolution is best-effort: the session
layer logs an `Err(_)` and leaves a signed-in session's `device_id` as it
was rather than failing the request, so a fault in the device store neither
takes authentication down nor strips a session of its device. A session
with nobody signed in keeps no device on a request that resolved nothing
(the resolver failed, or none is installed): its device was resolved on an
earlier request, and the login this request completes may be another
person's.

Two implementations ship. `NoopDeviceResolver` always answers
`Ok(None)`, and is the default plug when the `device` feature is on but
nothing has been configured. `LifecycleDeviceResolver` is the turn-key
one: it wires a `DeviceFingerprintExtractor` to a
`DeviceLifecycleService`, finding the device by the token on its cookie
(or keeping the one the session is bound to) and otherwise minting one
with `trust_level = Unknown` for an authenticated user and storing the
fingerprint computed from the request features on the new row.

`LifecycleDeviceResolver` has four hooks, one for each thing that differs
between deployments:

- `tenant_fn`, defaulting to a `TenantId` in the request extensions and,
  when there is none, to the tenant the session authenticated into
  (`SessionTenant` in the request extensions, filled by the session layer).
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

If `tenant_fn` yields `None` for a guest the resolver short-circuits to
`Ok(None)`: there is no meaningful device without a tenant scope, for the
cross-tenant-correlation reason *The per-tenant pepper* gives. For an
authenticated request the same answer is a fault and fails with
`LifecycleResolveError::TenantMissing` (see *A resolver with no tenant*). A
fingerprint the extractor cannot compute short-circuits to `Ok(None)` for a
guest; an authenticated request without one is resolved by its token, its
key or its session's device and given no new device (see *A request with
no fingerprint*).

Where the tenant comes from decides whether a device is ever issued, so
pick the form that matches the application:

```rust,ignore
// One tenant for the whole deployment: a constant.
let resolver = LifecycleDeviceResolver::new(extractor, lifecycle, SystemClock)
    .with_tenant_fn(|_| Some(tenant));

// The tenant is a property of the signed-in user: set nothing. The tenant
// stored by the login service reaches the resolver
// as `SessionTenant`, and the first authenticated request gets a device
// cookie.
let resolver = LifecycleDeviceResolver::new(extractor, lifecycle, SystemClock);

// The tenant comes from the host name: an outer layer inserts a `TenantId`
// extension, which is read before the session's.
```

A guest, and a session part-way through a login, carry no `SessionTenant`,
so they still get no device. Without a `TenantId` extension and without a
tenant in the session the resolver returns `Ok(None)` and no device is ever
issued, so a deployment that never sees a device should check this first.

Applications with a stronger device signal (a long-lived hardware key,
a mobile app's installation id, a device certificate) implement
`DeviceResolver` themselves, consult the stronger signal first, and fall
back to the fingerprint match.

## Performance and privacy

Keeping the lookup cheap without keeping the fingerprint.

### Caching

The device record is read on most requests: the resolver loads the
device a request's cookie names, or the one its session is bound to,
and an entity provider that shows the device to Cedar reads it again.
A naive lookup against the device store would be the hottest read
in the application.

The `CachedDeviceStore` decorator wraps any `DeviceStore` with an
LRU+TTL cache. The cache key is `(tenant_id, device_id)`; the
cache value is the `Device` record. The default TTL is 60 seconds and
`with_ttl` sets it; the LRU bound caps memory under fan-out. The refresh device check (`Refresh::device_store`) does not
read the cache: it calls `DeviceStore::load_fresh`, which
`CachedDeviceStore` answers from the backing store, so a revocation made
on another instance stops the next refresh whatever the TTL is.

Revoking a device is `revoke_device` (device and refresh tokens), or
`DeviceStore::set_trust_level(tenant_id, id, DeviceTrustLevel::Revoked,
now)` for the row alone. There is no `revoke` verb on the store. Every write
through a `CachedDeviceStore` drops the cached row once the write finishes,
and also when the future running it is dropped after the store has
committed (a cancelled request), so the instance you wrote through never
serves the pre-write row. Other instances and other processes learn of the
change in a cached `load` when their entry expires, 60 seconds later by
default: keep the TTL short for that reason.

`delete` removes the record outright. Prefer
`Revoked` where the audit trail matters: a deleted device leaves no
evidence that it was ever trusted.

The pattern is the same one *Entity providers and request
context* covers for the Cedar entity cache. Cache the data, not
the decision; invalidate eagerly on mutation; let TTLs catch the
cases the invalidation missed.

### Sighting writes and the per-user lookup

`DeviceLifecycleService::resolve_or_keep` and `ensure_device` run on the
request path, so they avoid a store write per request. A known device
whose `last_seen_at` is
less than the sighting granularity before `now` (five minutes by default,
`with_sighting_granularity`) is returned without a write; a granularity
of zero records every sighting. `last_seen_at` therefore lags real use by
up to the granularity, which the retention sweep's windows (days) absorb.

`DeviceStore::record_sighting` returns the trust level the row had when the
sighting was applied. `DeviceLifecycleService::promote_on_authn` reports that
level, and `ensure_device` and `resolve_proven` act on it: a device revoked
between its load and its sighting is never served (the request gets a new
`Unknown` device) and its `last_seen_at` is unchanged. `ensure_device` never
reuses or touches a revoked device. Two first sightings of one
fingerprint that race end on one device: the create goes through
`DeviceStore::create_or_find`, which inserts the new row only while no live
device of the same tenant, fingerprint and owner exists and otherwise returns
the one that does.

The memory store serialises creates of one key on a
per-key lock, SQLite runs the read and the insert in an immediate
transaction, Postgres under a transaction-scoped advisory lock and MySQL
under a named lock (`GET_LOCK`, taken on the connection that runs the
create and released on it only after the transaction has committed or rolled
back; a create that is dropped part-way closes its connection, which frees the
lock). The Valkey store inserts the row in one script that runs only while
the key's create guard still holds what the caller read, so of two
concurrent creates one inserts and the other returns the first one's
device. The trait provides no implementation: a save followed by a re-read
cannot give that guarantee.

For an identified user `ensure_device` looks for the caller's own device
first, with `DeviceStore::find_by_fingerprint_for_user`, and only then at the
newest device that carries the fingerprint, which may belong to another user
(two people behind one office address with the same browser). The
SQL stores answer it from the `idx_devices_user_fingerprint` index on
`(tenant_id, user_id, fingerprint_hash, last_seen_at DESC, id ASC)`, so a user
with any number of devices finds the right one (MySQL 8 reads the newest
sighting from the descending key parts; MariaDB before 10.8 ignores the
direction and sorts). SQLite and Postgres create the
index in `init_schema`. A MySQL deployment created earlier adds it once:

```sql
ALTER TABLE devices ADD INDEX idx_devices_user_fingerprint
    (tenant_id, user_id, fingerprint_hash, last_seen_at DESC, id ASC);
```

A store that does not override the method falls back to scanning the
user's 100 most recently seen devices. The Valkey store keeps a set per
(tenant, fingerprint, user), so the lookup reads only the devices that can
match; devices written by an earlier release are found through the user's
index once and added to the set.

### PII tokenisation and GDPR

The device record carries personally identifiable information.
The fingerprint features include the IP address (which is PII
under GDPR), the user agent (which can carry identifying details
about the user's setup), and the timestamps (which together can
identify the user's working patterns).

The defence is twofold.

First, the device store holds hashes, not the raw
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
    pub skipped: u64,
}
```

The first three counts are the three transitions of the retention
ladder: a trusted device that has not been seen in a
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
days and revoked 30 days after that (120 days from the last sighting); it
is never revoked in the sweep that demotes it. A sighting after the
demotion restarts the Seen window. Every window is compared in whole
seconds, which is how the SQL backends store timestamps, so all
backends take the same decision for the same row;
`SweepConfigBuilder::build` returns an error for a window with a
fractional second. A `Revoked` row that has no `revoked_at` is stamped
by the sweep and purged one grace period later. `Device::demoted_at` is set on every move from
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

axess ships five `DeviceStore` backends, and `CachedDeviceStore`, a
decorator over any of them:

| Backend | Feature | Notes |
|---|---|---|
| `MemoryDeviceStore` | `device` | `Mutex<HashMap>` + clock-driven sweep. Dev and tests. |
| `SqliteDeviceStore` | `sqlite` | SQLx pool, `INSERT … ON CONFLICT`, schema in `init_schema()`. |
| `PostgresDeviceStore` | `postgres` | SQLx pool, same surface as the sqlite backend with the Postgres dialect. |
| `MysqlDeviceStore` | `mysql` | SQLx pool, MySQL dialect (`?` binds, `ON DUPLICATE KEY UPDATE`, `VARBINARY(32)`). Compatible with MySQL 8.x and MariaDB 10.5+. |
| `ValkeyDeviceStore` | `valkey` | Key-per-device + per-tenant fingerprint index (a sorted set of the ids that carry each fingerprint, scored by last sighting, so devices sharing one all stay findable). Server-side `EXPIRE` handles purge. On a cluster the prefix needs a hash tag (`{axess}`): every write is one script over several keys, so `with_prefix` refuses a prefix without one there (`try_with_prefix` returns `ValkeyDeviceStoreError::PrefixWithoutHashTag`), and a store left on the default prefix refuses its writes with the same error, which its health check reports too. |

All five backends share the same trait surface; switching between them
requires only a different constructor at startup and, for a SQL
backend, the `init_schema` call against the new pool.

### Writing an adopter-supplied store

Any storage technology can back devices as long as it can answer the
required methods of `axess_core::device::DeviceStore` (`load`,
`load_fresh`, the three finders, `save`, `create_or_find`,
`record_sighting`, `set_trust_level`, `set_trust_level_if`,
`replace_bindings`, `claim_owner`, `delete` and `sweep`). The shipped backends (memory, sqlite, postgres, mysql, valkey)
are the reference implementations to read alongside the trait documentation;
the recipe below names the contracts that are not obvious from method
signatures.

**Type and Error.** Implement the trait on a `Clone + Send + Sync +
'static` struct (typically `Arc<...>` around your connection pool /
client). Pick a single `type Error: std::error::Error + Send + Sync
+ 'static`; the existing backends use a `thiserror` enum that wraps
their driver error and a "missing row" variant. Do not conflate driver
errors with domain errors (a `NotFound` returned by your driver
should not surface as an `Err` from `load`; map it to `Ok(None)`).

**Tenant scoping is mandatory.** Every method that takes a
`TenantId` must filter on it in the query. The peppered
`FingerprintHash` is already keyed per tenant, but the trait
contract states the scoping requirement explicitly, to prevent
cross-tenant leakage on a backend whose primary index is by hash alone. Read the docstring on
`find_by_fingerprint` for the rationale.

**`save` must be atomic.** `save` is documented as an idempotent
upsert. It never changes a stored `Revoked` row (a `Device` loaded
before a revocation and saved after it leaves the revoked row alone,
and a save of a revoked copy does not rewrite its `revoked_at` or
bindings; reinstating is an explicit `set_trust_level`), and a
`Revoked` row saved for the first time without `revoked_at` is stamped
with the write time so the sweep can purge it. Setting `Revoked` on a
row that already is keeps its first `revoked_at`. An implementation that runs a `SELECT` and then an `INSERT`
must wrap them in a transaction or use the dialect's native
upsert (`ON CONFLICT`, `ON DUPLICATE KEY UPDATE`, `MERGE`, or
`SETNX` for KV stores). A non-atomic `save` produces lost updates
under concurrent device-promotion calls.

**`record_sighting` is hot-path.** The lifecycle calls it for a known
device at most once per sighting granularity (five minutes by default),
which for a busy deployment is still the most frequent device write.
Implement it as a single `UPDATE … SET last_seen_at
= ?` rather than a load-modify-save round trip. It is monotonic
(`last_seen_at` becomes the later of the stored time and the new one,
so a late request never moves it back) and it leaves a `Revoked` row
alone while still succeeding. It returns the trust level the row has
(`Revoked` for a revoked one), which callers report instead of the level
they loaded earlier. The `CachedDeviceStore` decorator (see
*Caching* above) shields the underlying store from read pressure;
writes go through to it.

**`replace_bindings`, `set_trust_level_if`, `claim_owner` and
`create_or_find` are single steps.** All four are required, with no
provided body, because a body built from the other methods would be a read
followed by a write. `replace_bindings` writes the bindings alone, only
while they are still the ones the caller read, and never on a `Revoked`
row; `set_trust_level_if` writes the level only while the row is at the
level the caller expected, so a promotion decided before a revocation
cannot undo it; `claim_owner` sets the owner only while the device has none
and is not revoked; `create_or_find` inserts only while no live device of
the same tenant, fingerprint and owner exists. Two concurrent callers of
any of them have one winner.

**`sweep` is required, not defaulted.** A backend that does not
implement sweep cannot age devices through the three-stage ladder,
and the documented retention posture (90d trusted / 30d seen / 7d
revoked grace) silently breaks. The trait deliberately omits a
default impl, and every backend implements the sweep: one call moves
a row one level at most, counts the rows it wrote, reads only the
tenant it was given and leaves an `Unknown` row alone. An `Err` is a
store failure, never a stand-in for a sweep that was not written. A
row the call met and could neither decide nor move (one that does not
decode, or a due one whose write another writer kept winning in the
Valkey store) is counted in `skipped` and met again by the next
sweep, so `Ok` with every count zero says that nothing was due. Each
shipped backend runs one shared test of the ladder.

**Sighting timestamps come from a `Clock`.** Methods that need
"now" (`record_sighting`, `set_trust_level`, `sweep`) accept
`now: Timestamp` as a parameter. Callers thread `clock.now()`
through; backends never read the system clock themselves. This
preserves DST determinism for adopter integration tests.

**Mirror the per-backend test layout.** Each shipped backend has
its own test module exercising the trait surface end-to-end (load
round-trip, fingerprint lookup, refresh-family fan-out, retention
sweep); `device/storage/sqlite/tests.rs` is the most complete
template. Copy that suite, adapt the harness setup to your
backend, and run it to catch the non-obvious contract violations
(tenant-scoping leaks, non-atomic save races, off-by-one sweep
counts).

**Reach for `CachedDeviceStore` over reinventing.** If `load` is slow on your backend, wrap your store in
`CachedDeviceStore` before optimising the implementation. The
decorator provides bounded-size LRU and clock-driven TTL eviction. A
revocation through `set_trust_level` drops the cached row on the instance
it was written through; other instances see it when their entry expires,
and `load_fresh` reads through (see *Caching*).

## Device keys

The device token is a bearer value: it sits in the same cookie store as the
session cookie, so whoever copies one copies the other, and on the copy's
machine the device reads as proven. With the `device-keys` feature a device
can hold a key instead: a P-256 key pair whose private half the client can
use and cannot read. The device row keeps the public half as a `Key` entry
in its `bindings`, beside the `Cookie` entry, and three things change:

- **A device that has a key is proven only by it**, under a session layer
  that enforces keys. A request proves the key with a short-lived proof
  cookie, which the server mints only against a signature by the key over a
  challenge it chose, or, for an app, with a signature over the request
  itself. The device's token alone then proves nothing: a guest that
  presents it has no device, a session that names the device keeps it as
  recognised (`BoundDevice::Unproven`), and any other authenticated request
  is given a new `Unknown` device. `ProvenDevice::proof` says which of the
  two a request made, `Token` or `Key`, so an application can ask for the
  key before it lets a `Trusted` device skip a step-up.
- **A session can be bound to the key.** It then runs only for a request
  that proves the same key, and any other request of it runs as a guest. A
  sign-in binds a session only to a device its user owns, or to one with no
  owner, which is claimed for the user first. A bound session's request that
  proved its key has its device proven by key whether or not it presented
  the device token, so `AuthSession::proven_device` answers for an arrival
  from another site too.
- **Revoking the device ends those sessions**, within one proof cookie's
  life, because a revoked device is refused a fresh proof. A session served
  by request proofs ends at its next request.

`DeviceKeyService` registers and proves keys, `DeviceKeyConfig` sets the
lifetimes and the policy, and `SessionLayer::with_device_keys` turns the
enforcement on. Give the key service to every layer that shares the session
store: a layer without it cannot check a key and runs a bound session's
request as a guest. An app that signs every request with its key
(`DeviceKeyService::with_request_proofs`) needs no proof cookie, and a
Cedar policy can ask for a session held to a key with `context.key_bound`
(`StandardRequestContext::with_key_bound`). A deployment that requires keys
builds its authentication service with
`AuthnServiceBuilder::with_key_proven_device_store`, so the lockout exempts
a device only when it was proven by its key. The protocol, the policies and
what the binding does not answer are in
[Design: device-bound sessions](../sessions/device-bound-sessions.md).

A resolver of your own builds its `DeviceRequest` with
`keys: KeyEnforcement::of(&parts)`. The field is required, and it is what
holds `resolve_or_keep` and `resolve_proven` to the key of a keyed device
under a layer that enforces keys. Its `fingerprint` is `None` for a request
the resolver cannot fingerprint, for which neither creates a device.

### Trust is written onto a proven device of the session's user

`DeviceLifecycleService::promote_on_authn`, `promote_if_authenticated` and
`grant_trust` take a `UserDevice`: the device a request proved, paired with
the user and the tenant its session is authenticated as.
`AuthSession::user_device` answers one, and only for an authenticated
session on a request that proved a device, so ask it after the handler has
authenticated the session:

```rust,ignore
let outcome = authn.verify_factor(&credential, &session).await?;
if let Some(device) = session.user_device().await {
    lifecycle.promote_if_authenticated(&outcome, &device, now).await?;
}
```

A device found by fingerprint through `ensure_device`, and a device a
session only kept, yield no `UserDevice`, so neither can be promoted or trusted: the
trust lands on the device the cookie (or the key) proves, never on a row
that merely looks like it.

Nothing is written to another user's device. The request that completes a
login proved its device before anyone was signed in, so on a browser profile
two accounts share it may be the other account's. A row another user owns is
left as it was and the answer is `Ok(None)`; a row with no owner is first
claimed for the user by `DeviceStore::claim_owner`.

`grant_trust` is the write behind "trust this device". It moves an `Unknown`
or `Seen` device to `Trusted` by one conditional write, leaves a `Revoked`
one revoked, and writes the `DeviceTrustGranted` row.

### An impersonated session's device

During an impersonation the browser is the administrator's, and nothing
the impersonation does creates, claims, promotes or trusts a device for the
user the session runs as.

- **The request's device is the administrator's own.** The session layer
  hands the device resolver the administrator as the request's user
  (`SessionUser`), so the device is found among the administrator's or
  created as the administrator's, in the tenant the session runs in. No
  device of the user is added, displaced or sighted.
- **No trust write.** `AuthSession::user_device` answers none under
  impersonation, so `promote_on_authn`, `promote_if_authenticated` and
  `grant_trust` have nothing to take, for the user or for the administrator.
- **No lockout exemption.** The per-account lockout lets through a device the
  account owns, and the user owns none on the administrator's browser.
- **A key is the administrator's.** With device keys, a registration under
  impersonation puts the key on the administrator's device, and a session is
  bound at sign-in only to a device the administrator owns.
- **A refresh token names no device.** A deployment that allows credential
  changes under impersonation
  (`with_impersonated_credential_changes_allowed`) can issue a refresh token
  from an impersonated session; it carries no device, whatever the caller
  passes. A session refreshed from it is the user's own and is no
  impersonation: it is given a device on whatever client presents the token.

The audit rows name the administrator as actor, as every row of an
impersonated request does. `axess-core/tests/device_impersonation.rs` holds
the tests.

The start of an impersonation keeps the administrator at the browser, within
the administrator's tenant and across tenants, so the session keeps the
device the request resolved for the administrator; its end
(`AuthSession::clear`) leaves no device. A sign-in by another person on a
signed-in session is the opposite case: the device was resolved for the
first person and holds for nobody else, so the session names none until the
next request resolves one. `axess-core/tests/session_device_person.rs` holds
those tests (`another_persons_sign_in_leaves_the_session_without_the_first_persons_device`,
`a_login_on_a_guests_request_takes_the_browsers_device`,
`a_step_up_keeps_the_device` and
`an_impersonation_keeps_the_administrators_device`), the three-way merge's tests
in `axess-core/src/session/data/merge/tests.rs`
(`a_device_stamped_for_the_first_person_is_not_carried_to_another`,
`a_device_stamped_meanwhile_stays_while_the_person_does`), and the property
`a_device_holds_exactly_for_the_person_it_was_resolved_for` in
`axess-core/src/session/data/device/tests.rs`.

### A resolver with no tenant

`LifecycleDeviceResolver` creates a device only inside a tenant. Its default
`tenant_fn` reads a `TenantId` request extension and falls back to the tenant
the session authenticated into, so an authenticated request always has one.
A `tenant_fn` of your own that answers nothing for an authenticated request
is a fault, and the resolver reports it as one
(`LifecycleResolveError::TenantMissing`): the resolution fails, the session
keeps the device it has, no device is created and no device cookie issued.
The resolver explains the first such request at `error`, and the session
layer logs each failed resolution at `warn`. A guest without a tenant is not
a fault and is not reported.

### A request with no fingerprint

The fingerprint has no part in finding a device: it is stored on a new row
and nothing else. An authenticated request the extractor cannot fingerprint
(the default extractor needs a `User-Agent`) is therefore not a failure.
`LifecycleDeviceResolver` finds its device by the device token it presents,
the key it proved or the device its session keeps, as for any other
request, so a session keeps its device and a request that proves it is
answered as proven. Only no device is created for it, since there is no
fingerprint to store, and nothing is deleted to make room. Such a request
that finds no device has no device; the resolver explains the first one at
`warn`, since a client that sends no `User-Agent` makes it. A client that
never sends one therefore never has a device: it is offered no device key,
and under `KeyBindingPolicy::Require` its session ends when the
registration window closes.
A guest's request without a fingerprint has no device, whatever it
presents, and is not reported.

## The connective tissue

Device identity is the connective tissue between the user, the
sessions they hold, the refresh tokens those sessions issue, and
the authorisation decisions the application makes about them. A
user on a known device gets a smoother experience where the
application's policies say so: the device is recognised by its token,
the refresh tokens roll, a step-up can be waived. A user on an unknown
device meets friction where the policies ask for it: a step-up before
sensitive actions, a confirmation before high-trust operations. A
revoked device's refresh tokens stop at once (`revoke_device`), and
its browser starts over as a new `Unknown` device; a session already
issued runs to its own end unless the application ends it.

The mechanism is small (a handful of types, one ladder, one
cascade) but its reach is wide (every refresh, every policy
evaluation, every audit event).

## Further reading

*Refresh tokens and session continuity* covers the binding between
devices and tokens, including the cascade in both directions.
*Cedar policy fundamentals* covers how policies read the
device's trust level. *Multi-tenancy* covers the per-tenant
fingerprint pepper and retention configuration. *Security
posture* covers the GDPR and SOC2 implications of device data.
