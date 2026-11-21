# Session lifecycle and crypto envelope

A session in axess is a server-side record that holds the
authentication state, the bound principal, and any application data
the session carries. The cookie that travels between the browser
and the server identifies the session, but the cookie itself does
not contain the session data. The separation lets the session shape change between deployments
without invalidating existing cookies, and lets the data be encrypted
at rest under keys the client never sees.

This chapter walks through the lifecycle of a single session from
its creation through its expiry, the cookie shape and signing, the
AES-256-GCM envelope that encrypts the data at rest, the
fingerprint binding that catches cookie replay, and the dirty-flag
and write-back machinery that makes the lifecycle invisible to
application code.

## What a session is made of

Four pieces: one in the browser, three on your side.

### The cookie

The session cookie is small. By default it carries an opaque
session id (the `SessionId` newtype, sixteen bytes of cryptographic
randomness from `SecureRng`, base64-encoded for transport) plus an
HMAC signature computed from the id under a key derived from the
deployment's signing key. The whole cookie is well under two hundred
bytes.

```text
__Host-axess.sid=<base64(session_id)>.<base64(hmac_sha256(cookie_key, session_id))>
```

The signature defeats forgery. An attacker who guesses or
brute-forces a session id cannot use it without also producing the
HMAC, which requires the signing key. The signing key is the
operational secret covered in the *Getting started* chapter: a
32-byte value loaded from a secrets manager, stable across process
restarts, rotated on a schedule.

The default cookie name is `__Host-axess.sid`. The `__Host-` prefix makes
browsers refuse the cookie unless it is `Secure`, has `Path=/` and carries
no `Domain`, which stops a sibling subdomain from planting a cookie of the
same name ("cookie tossing"). When no name was chosen and the layer is built with `Secure` off or a
path other than `/`, the default falls back to `axess.sid`, because a
prefixed cookie would be dropped. A name you choose
is used as given and checked: a prefix that the other settings cannot honour
panics at startup.

If a request carries the cookie name twice with different
values, the session layer treats it as no cookie rather than picking one.
The refusal allows a denial of service wherever a cookie can be planted:
a sibling subdomain, or a man in the middle on plain HTTP, sets a second
cookie of the same name and the user reads as logged out until it expires.
Only the `__Host-` prefix (`Secure`, `Path=/`, no `Domain`) stops a browser
from accepting such a cookie, which is why a non-root `with_path`,
`with_secure(false)` or an unprefixed `with_cookie_name` leaves it open.

Responses that set the session cookie carry `Cache-Control: no-store`
and `Vary: Cookie`. A handler's own `Cache-Control` stays only when it
already names `no-store` or `private`; a cacheable policy such as
`public, max-age=600` is replaced.

The cookie attributes are conservative by default: `HttpOnly`
(client-side JavaScript cannot read it), `SameSite=Lax` (it is sent
on top-level cross-site navigations but not on cross-site
sub-requests), `Path=/` (it applies to the whole application), and
`Secure` (it is only sent over HTTPS; `with_secure(false)` turns it off
for development over plain HTTP). `SessionLayer::with_ttl` sets the session lifetime; the default is
twenty-four hours.

The cookie is opaque. It carries the session id and a signature, and
nothing of the user's identity, the factors completed, or any other
session state. The server does not keep the id: the layer hashes it to
the session's key (`SessionKey`, the SHA-256 of a fixed tag and the id),
and the key names the row in the session store, the entry in the
registry and the session in audit records and logs. A read of any of
those yields no value a cookie could carry.

### The session store

The session store is the persistence layer for the data the cookie
identifies. Each row in the store carries:

- The session's key (the primary key): 64 hexadecimal characters, a
  digest of the session id, never the id.
- The serialised `SessionData` (covered below), sealed when the store
  encrypts.
- The expiry timestamp (a column in SQL, the key's TTL in Valkey).

Nothing else is a column. The fingerprint binding, the write revision
and the time of the last write are inside the serialised data, and no
row carries a created-at or an updated-at of its own.

`SessionData` is the application's view of the session:

```rust,ignore
pub struct SessionData {
    pub version: u8,                   // see Schema migration
    pub auth_state: AuthState,         // see Part II
    pub fingerprint: Option<String>,   // HMAC of the binding material
    pub device_id: Option<DeviceId>,   // set by the DeviceResolver, if any
    pub device_proven: bool,           // this request's answer; never stored
    pub custom: serde_json::Value,     // application data
    pub revision: u64,                 // raised by every write
    pub touched_at: Option<Timestamp>, // when the row was last written
    pub ending: Option<EndingClaim>,   // the layer's claim to end it
}
```

`ending` is the layer's own. The layer sets it on the stored row between deciding to end a session
and removing it, so that only one of several requests carrying the same
cookie records the ending. The load hands a handler `None`. An `EndingClaim` holds when the claim was made and
the reason the session ends. A row that carries a claim younger than thirty
seconds (`ENDING_CLAIM_LEASE`) is refused and left to the request that
claimed it. A row that carries an older one is ended by the request that
meets it, for the reason the claim holds: a claimed session is never served
again. A request that was already running when the claim was made, and
writes the session afterwards, writes onto the claimed row and leaves the
claim in place; the layer does not rotate the id of a claimed
session, and discards the rotating request's changes with a warning in the log.

`custom` is a single `serde_json::Value` that axess keeps as a JSON
object and edits by key: `set_custom`, `get_custom` and `take_custom`
address one key each, a concurrent write is merged key by key, a login
clears every key but the ones named with `with_preserved_custom_keys`,
and one key (`axess.login.flow`) is the library's own. The values under
your keys are yours, including their versioning.

The `auth_state` carries the state-machine variant (`Guest`,
`Identifying`, `Authenticating`, `Authenticated`,
`PendingWorkflow`). The `fingerprint` is the HMAC of whatever the
configured `SessionBinding` extracted, set at the first transition out
of `Guest` and compared on every later request. The `device_id` is
whatever the `DeviceResolver` returned, if one is configured. The
`custom` value carries application-defined data, capped by
`SessionLayer::with_max_custom_bytes`. The `version` is the field that
lets the data shape evolve.

There is no cached principal on the session. The resolver runs per
request against the `auth_state`, which is what keeps a revoked session
from serving a stale identity.

The serialisation format is MessagePack, written by `rmp-serde` with
each field under its name: faster than JSON, more compact, and a fixed
wire format, so the bytes do not depend on the version of `serde`. Every backend
stores the bytes as they are: the SQL stores in a binary column, Valkey
as the value. Base64 text is only read, from rows an earlier release
wrote. The format is the same in every backend, so switching backends
needs no re-serialisation.

### The AES-256-GCM envelope

The serialised session bytes are encrypted before storage. The
envelope is AES-256-GCM, a standard authenticated-encryption scheme
that seals the bytes under a key and a nonce into a ciphertext and a
tag. The encryption key
is a 32-byte value loaded from a secrets manager at process start.

The shape of one envelope:

```text
marker (4 bytes) | salt (16 bytes) | ciphertext (variable) | tag (16 bytes)
```

Each write draws a fresh salt through `SecureRng` and seals under a
key derived for that one record from the configured key, the salt and
the AAD. AES-GCM is sensitive to nonce reuse: a reused nonce under the same key
catastrophically compromises confidentiality and authenticity, and a
random nonce under one key has a budget of about 2^32 seals. A derived
key encrypts exactly one message, so the nonce is fixed and no budget
applies. A session blob is read in this form
and in no other: a blob in an earlier layout, or with no binding, is
refused whatever `LegacyBlobs` policy the `SessionCrypto` carries (the
policy applies to device rows and factor secrets).

The additional authenticated data (AAD) carries the session's key:
the label `axess.session.v2`, a zero byte and the 32 bytes of the key.
The binding means that an encrypted blob from one session cannot be
swapped into another session's row even if an attacker can write
to the database. The key is the row's own name, so this adds no
confidentiality, but it adds integrity: the database is
not the source of truth for "which session is this blob from."

Key rotation is the operational lever. `SessionCrypto::new(key)`
constructs an envelope with one current key. `.with_previous_key(old_key)`
keeps the old key available for reads, so sessions encrypted with
the old key continue to decrypt while new writes use the new key.
A store that opens a row under the previous key writes it back under
the current one, so a session moves to the new key when it is next read
or written. Remove the previous key once every existing session has
been rewritten.

The chapter *Operations runbook* covers the rotation sequence and
the staged rollout for both the signing key and the envelope key.

### The fingerprint binding

A session id alone is not enough to defend against cookie theft. An
attacker who captures a session cookie can replay it from a
different browser, IP, and operating system, and the session
machinery on the server cannot tell the difference without
additional signal.

The fingerprint binding is the additional signal, and it is opt-in:
a layer binds nothing until it is given a `SessionBinding`
(`with_binding`). At the session's first step out of `Guest`, the
layer takes the material the binding reads from the request (the
stock `UserAgentBinding` reads the `User-Agent` header; nothing
reads the IP address), HMACs it under a key derived from the signing
key, and stores the digest in the session data. On every subsequent
request, it recomputes the digest from the incoming request and
compares it (constant-time) against the stored value.

The match has two outcomes:

- Match: the session is allowed to proceed.
- Mismatch: the request is refused the session and runs as a guest
  under a new id, with a `warn` line and a count on the session
  metrics. The stored session stays for the client it is bound to.

There is no tolerance and no policy to choose: the comparison is
exact, which is why the material should be something that does not
change under a legitimate user. A binding of your own that wants to
tolerate change (an address reduced to its network, a user agent
reduced to its major version) reduces the material itself before
returning it.

The chapter *Cookies, fingerprinting, hijack detection* covers the
binding and the trade-offs in detail.

## How it runs

What the layer does per request, and what decides a write.

### The Tower layer

The `SessionLayer` is the Tower middleware that threads the
session through every request. Its `call` method sequences the
lifecycle.

The pseudocode of one request:

```rust,ignore
async fn call(&self, req: Request) -> Response {
    // 1. Extract the cookie (or skip if absent → Guest).
    let cookie = extract_session_cookie(&req);

    // 2. Verify the HMAC (current key, then the previous one during a
    //    rotation), decode the session id and hash it to the session's
    //    key. A failure at this step or any of the next three is not an
    //    error: the request goes on as a guest under a freshly minted id.
    let session = verify_cookie(&cookie, &self.signing_keys);

    // 3. Load the session by its key. The store opens the envelope and
    //    decodes the data; the layer holds no encryption key.
    let data: SessionData = self.store.load(session.key()).await;

    // 4. For an authenticated session: the absolute age caps, then the
    //    registry. A session past a cap or gone from the registry is
    //    ended: claimed, recorded through the audit sink, then deleted.
    enforce_age_and_registry(&data, &self.config, &self.registry);

    // 5. Verify the fingerprint binding, when one is configured.
    check_binding(&data, &req);

    // 6. Resolve the device, when a resolver is configured, then wrap
    //    into a SessionHandle and insert it into the request extensions.
    let handle = SessionHandle::new(session, data);
    req.extensions_mut().insert(handle.clone());

    // 7. Run the handler.
    let response = self.inner.call(req).await?;

    // 8. If the session changed, write it back, by the verb that fits:
    //    - a rotated id: `cycle_if_revision` for a session the request
    //      loaded, `cycle` for one that was never stored;
    //    - a changed stored session: `update_if_revision`, merged with a
    //      concurrent write and tried again when the revision moved;
    //    - a fresh guest's first write: `save`.
    //    Then reissue the cookie when the session was created or changed.
    if handle.is_dirty() {
        write_back(&self.store, &handle).await;
        response.headers_mut().append("Set-Cookie", construct_cookie(...));
    }

    response
}
```

Three of the eight steps are worth dwelling on.

Step 5 (the fingerprint check) is the gate that catches replay. A
mismatched fingerprint does not stop the request. The stored session
is not used for it (the row stays for the client it is bound to), the
`session_binding_mismatch` metric fires, and the
handler runs as a `Guest` under a freshly minted session id, so the
attacker-planted id never reaches it. A route that needs a signed-in
user then refuses the request in the usual way (a redirect to login
or a 401, whatever the route's guard does).

Step 7 runs the handler. The handler receives a `SessionHandle`
through the `AuthSession` extractor and reads or mutates it; the dirty
flag tracks the mutations.

A request that arrives without a trusted session cookie runs as a guest
that exists only in memory. It is stored, and a cookie is set, only when
something needs it: a handler modified it or read its id, or a handler used
the CSRF token (`CsrfToken` or `CsrfIssuer`). Set
`CsrfConfig::mint_on_every_request` for a single-page app that reads the
CSRF cookie without any handler touching the token.

Step 8 is the write-back. The session is saved only when it is
dirty, which means a read-only request (the dashboard, a metric
endpoint, an idle-page poll) does not write to the session store.
The store sees writes in proportion to the rate of state changes,
not the rate of requests.

### The dirty flag

The dirty flag is the optimisation that makes the session store
viable at the read rates a real application produces. The flag is
on `SessionHandle` and is set by any method that mutates the
session: `set_authenticated`, `clear`, `set_custom`, and so on.

The flag is checked at step 8 in the lifecycle above. A clean
handle is dropped silently; a dirty handle triggers the
serialisation, encryption, store-write, and cookie-reissue path.

A read through the typed accessors (`is_authenticated`, `user_id`,
`get_custom`) needs no mutable borrow and does not mark the handle dirty. Mutating accessors (`clear`, `set_custom`, the orchestrated
`begin_login` and `verify_factor` paths) all set the flag.

A `Set-Cookie` header is sent whenever the session was created or
modified in the request, not only when the id rotates; an unmodified
request sends none, which keeps responses cacheable. The library
rotates the identifier at every transition of the session's state:
the start of a login (`Guest` to `Identifying` or `Authenticating`, to
defeat fixation), the completion of a factor chain (a login, and a
step-up through `verify_factor`), a workflow step, the OAuth callback,
the beginning and the end of an impersonation, logout (so the new
`Guest` session doesn't share an id with the old), and a request that
failed the fingerprint binding. Explicit re-issuance is
`AuthSession::regenerate`. The routine read-write-read cycle does not
rotate.

`regenerate` exists for the cases the library can't infer on its
own: any handler that crosses a **privilege boundary** should call
it before responding.

The canonical list is drawn from OWASP ASVS V3, the OWASP Session
Management Cheat Sheet, and NIST SP 800-63B on transitions between
authenticator assurance levels. An AAL is that standard's measure of
how strongly a session's authentication is evidenced: AAL1 is a single
factor, AAL2 adds a second, AAL3 requires a hardware authenticator.

| Boundary | Rotate session id? | Also revoke sibling sessions? |
|---|---|---|
| Primary login | automatic | optional |
| Logout | automatic (id invalidated) | depends |
| MFA factor added (TOTP, WebAuthn, recovery codes, …) | yes | optional |
| MFA factor removed or disabled (AAL drops) | yes | recommended |
| Password / primary credential change | yes | **strongly recommended** |
| Step-up to a higher assurance level | automatic through `verify_factor`; yes for a path of your own | no |
| Account recovery flow completion | yes | yes |
| Impersonation start / stop | automatic | no |
| Role grant / revoke, scope change | yes | depends on direction |
| Tenant switch in a multi-tenant deployment | yes | no |
| Profile edit, theme change, factor *config* tuning | no | no |

Rotating does two things at once: it defeats fixation (any
pre-existing id, including one an attacker planted before the
boundary, becomes useless), and it caps the blast radius of a
captured pre-elevation cookie: one stolen while the session was at
AAL1 cannot ride the new AAL2 binding. Sibling-session revocation is
a strictly stronger statement that matters most on credential
changes, where any other device holding a stale password-derived
session must be cut off. `RequestAuthnService::invalidate_other_sessions`
does it. Change the credential, then call it with the key the registry
holds the session under, `session.registered_key().await`
(`AuthSession::registered_key`):

- It ends every other session the registry holds for the user, in one
  step of the registry, so a session that registers or moves to a new key
  while the call runs is ended with the rest or came after the step. A
  sign-in that began against the old credential and registers after the
  step is refused by its own check of the credentials it began against.
- It revokes every refresh token of the user, on every device, the
  caller's own included, when the service was built with
  `with_refresh_store`: a refresh token mints a session, so one issued
  before the change would outlive it. Issue the caller a new one after
  the call. `invalidate_other_sessions_keeping_refresh_tokens` ends the
  sessions only, for a deployment that revokes tokens by a rule of its
  own; without `with_refresh_store` the service cannot reach the tokens
  at all.
- It writes one audit row, and its `OtherSessionsError` says when the
  registry did not confirm the sessions ended, when the tokens could not
  be revoked, when the row could not be written, or, with
  `OtherSessionsError::CallerEnded`, that the caller's own session was
  ended with the rest.

It does not touch the kept session, the user's device records, or
tokens an identity provider issued.

`AuthSession::registered_key` names the key the registry holds, before
or after `regenerate` or `RequestAuthnService::rotate_session` in the same
handler. The registry
holds the key the request arrived with (or the key a login in the request
registered) until the response is written, and the session layer moves the
entry then; `AuthSession::session_key` after a rotation names a key the
registry does not hold yet, and the call is refused with nothing ended. The
caller is kept when its own request holds the key the registry holds the
session under. When another request of the same session had rotated it
to a new key before the step ran, the session to keep cannot be told
from a copy of its cookie, and a credential change must not leave a
copied cookie's session as the one that survives: every session of the
user is ended, the caller's included, the call answers
`OtherSessionsError::CallerEnded`, and the person signs in again. A
rotation moves only a session the registry still holds, so a session that
was ended is not brought back by rotating it. `SessionRegistry::invalidate_user` ends the
caller's session with the rest.

A library hook on `FactorStore::save_factor` would catch some of
the rows above and miss the rest (un-enrolment, password change,
role grants), and would misfire on factor-config tuning that is
not a privilege change. The boundary decision belongs to the
application: call `regenerate` in the handler that knows.

## Ending a session

Expiry from the inside, and sweeping what is left.

### When the session expires

The session has two expiry mechanisms. The first is the cookie's
own `Max-Age` attribute, which the browser enforces: after the
configured TTL, the browser stops sending the cookie. The second
is the session store's expiry timestamp, which the server
enforces: after the timestamp passes, the store returns the row
as expired (or the cleanup sweep removes it altogether).

Both are needed. The cookie expiry handles the browser-side case
(the user closes the browser, the cookie is forgotten); the
server-side expiry handles the case where the cookie outlives the
session's intended lifetime (an attacker captures a cookie and
replays it after the user's session would have expired).

The expiry is sliding by default: every dirty write updates the
expiry timestamp, so an actively used session keeps refreshing.
The maximum lifetime is the configured TTL from the most recent
write. A session that goes idle for the TTL expires; a session
written at least once per TTL window does not expire by the TTL (the
absolute cap below still ends a signed-in session).

A request that only reads keeps the session alive too, without a write on
every request. Each write stamps the session with the time it re-armed the
row (`SessionData::touched_at`). A stored session whose stamp is older than
half the TTL is re-armed by the next request, read-only or not: the row's
expiry moves out by a full TTL and the response re-issues the cookie with a
fresh `Max-Age`. A session within half its TTL costs no write and sets no
cookie. The re-arm is a compare-and-swap on the session's revision, so it
never overwrites what a concurrent request wrote; when it loses the race the
other request's write has already re-armed the row. A session stored before
the stamp existed is re-armed once, on its next request.

A session also expires absolutely at a fixed time after its login,
regardless of activity: 7 days by default. Change it with
`SessionLayer::with_max_session_age(Some(age))` (or `max_authenticated_age`
on the config builder), or lift it with `with_max_session_age(None)`, which
leaves the sliding TTL as the only bound. On the next request after the cap,
the session is deleted and the request runs as a new guest. The age is
measured from the session's login (`signed_in_at` in the stored state),
using the layer's clock (`with_clock`); a step-up and an id rotation leave
it as it is, so stepping up now and then never extends the session's life.
The step-up's own time (`authn_time`) is what recency checks read. An impersonated session is capped at 1 hour
from when the impersonation began, set with `with_max_impersonation_age`
(`None` lifts it). A session in the middle of a step-up is still the
signed-in session it began from, and is held to the same two caps.

### Revocation

Revoking a session (suspending the user, a completed password reset,
`invalidate_user_sessions`, the per-user session cap, an administrator
kick, log out everywhere) removes it from the **session registry**. On its
own that does not touch the stored session row or the cookie. Whether a
request notices depends on what guards the route:

- `require_authn!` checks only the session's own state. A revoked
  session still passes it.
- `require_valid_session` consults the registry and answers 401. It also
  clears the stored session and rotates its id, so the row stops saying
  `Authenticated`.
- A `SessionLayer` consults the registry it was built with
  (`SessionLayer::new(store, key, registry, audit)`) for every authenticated
  session on every request, whatever guards the route, and for every
  session in the middle of a step-up, which is still the signed-in session
  it began from; a login in progress is not registered yet and is not
  checked. A session the registry no longer holds is recorded through the
  audit sink, deleted from the store, and the request runs as a new guest
  with a replacement cookie. When the registry cannot answer,
  `with_unknown_liveness` decides: the default treats the request as a
  guest without touching the row, and `Accept` trusts the stored session.
  The check costs one registry call per
  authenticated request. `SessionLayer::without_registry_insecure` builds a
  layer with no registry and logs an error: revocation then reaches only the
  routes behind a validator.

The layer leaves an audit row for every session it ends this way, at an
absolute age cap, or because a rotation of its id could not be kept. It
writes the row through the sink it is built with: the fourth
argument of `SessionLayer::new`, for which the service's
`authn.session_end_audit()` is the stock choice. The row is written before
the session is removed: while the sink fails, the session is refused and
stays stored, and the next request that presents it tries again. *Audit
events* lists the rows. `UnrecordedSessionEnds::insecure()` is the sink
that records nothing, for a deployment that says so on purpose.

When a handler rotates an authenticated session, or one in a step-up, with
`regenerate`, a layer built with a registry moves the registry entry to the
new key by itself, in one step, after the row has moved.
`RequestAuthnService::rotate_session` asks for the rotation: under a layer
with a registry the layer moves the entry, and without one (a layer built
with `SessionLayer::without_registry_insecure`, or a session no layer stands
behind) the method moves it in one call. A session the registry no longer
holds is ended through the ending protocol, with its audit row, wherever the
move finds it gone. A WebSocket a `RevocationAwareSocket` supervises follows
the move: a rotation another request makes does not close it, and it closes
when the rotated session ends.

A session the layer ends, whatever the reason, also leaves the registry:
it is no longer listed by `AuthnService::active_sessions` or counted by the
session limit, and a socket that watches it is told. The entry of a session that a request signs out, or signs in as another
person, leaves the registry too.

Becoming authenticated clears the session's `custom` data, whichever way the
login completes (a password, a factor chain, a passkey, an OAuth callback,
an impersonation), so state an anonymous visitor could plant does not ride
into the signed-in session. The key the login service owns for the flow in
flight survives its own transition. An application that stashes something on
purpose before the login (a post-login destination, a chosen locale) names
the keys with `AuthnServiceBuilder::with_preserved_custom_keys`; names match
exactly and nothing is preserved by default.

Ending sessions through the authentication service
(`RequestAuthnService::invalidate_user_sessions`, `invalidate_session`,
suspension, a password reset) removes the registry entries and, when the
service was given the session store with `with_session_store`, deletes the
stored rows as well. Every kick names who acted with an `Actor`, and
a registry that cannot carry the revocation out is an error to the caller;
no audit row claims otherwise. `AuthnServiceBuilder::build` logs a warning
when no registry is attached, because without one none of these end an
existing session.

`require_authn!` takes a validator for a layer built without a registry:
`require_authn!(url = "/login", validator = authn.session_validator())`
consults the registry and ends a revoked session like `require_valid_session`.
`require_authz!` always takes one, as its fourth argument.

### Single-use values

`AuthSession::take_custom` hands a value to exactly one request. The removal
is written to the store as a compare-and-swap on the session's revision
before the value is returned, so of any number of requests (on this node or
others) holding the same stored session, one gets the value and the rest get
`None`. A store that cannot answer gives `None` as well: a one-shot ceremony
is started again, never run twice. Every other write of a stored session is
a compare-and-swap on the revision too, merged key by key with the write it
lost to, so an unrelated request that loaded the session before the value
was taken and saves it afterwards does not put the value back: a key a
concurrent request took stays taken unless this request set it anew.

### Cancelled requests

The layer finalises the session in a task of its own. A request dropped
mid-handler (the client went away, a timeout layer fired) still has the
session state the handler had reached written to the store, so a logout that
cleared the session and then lost its connection does not leave the stored
row `Authenticated`.

### Session cleanup

The application removes expired sessions from the store; axess starts
no background task on its own.

The SQL backends expose a `cleanup_expired` method that deletes
rows whose expiry timestamp has passed. The
[`examples/sqlite/`](https://github.com/GnomesOfZurich/axess/tree/main/examples/sqlite)
reference application writes the loop out in its `main.rs`, on a
`tokio::time::interval` of one hour. Each SQL store's
`spawn_cleanup_task(interval)` runs the same loop at the interval you
pass.

The Valkey backend uses Valkey's native TTL: each row is written
with an expiry, and Valkey removes it automatically. There is no
cleanup task to write because the database does the work.

For deployments with millions of sessions, the cleanup pattern
matters operationally. A daily delete-by-range is fine for tens of
thousands; for millions, the delete needs to be incremental (a
limit clause, looping through batches) to avoid long-running
transactions that lock the table.

## Invisible to application code

Session handling is invisible to application code. The handler
reads `AuthSession`, mutates it (or does not), and axess handles
the cookie, the
serialisation, the encryption, the fingerprint check, the
write-back, and the expiry. The application's surface area for
session bugs is small: most session-related issues are policy
choices (rotate too aggressively, lockout too strict, fingerprint
material that changes under a legitimate user), not bugs in the lifecycle itself.

## Further reading

*Backends: SQLite, Postgres, MySQL, Valkey* covers the four
first-party session stores and their feature-flag and dialect
notes. *Cookies, fingerprinting, hijack detection* covers the
configuration knobs for the fingerprint and the trusted-proxy
configuration that determines how IP is read. *Schema migration*
covers the `SessionData::version` field. *Operations
runbook* covers signing-key and envelope-key rotation.
