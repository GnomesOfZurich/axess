# Session lifecycle and crypto envelope

A session in axess is a server-side record that holds the
authentication state, the bound principal, and any application data
the session carries. The cookie that travels between the browser
and the server identifies the session, but the cookie itself does
not contain the session data. This separation is what lets the
session shape evolve across deployments without invalidating
existing cookies, and what lets the data be encrypted at rest with
keys the client never sees.

This chapter walks through the lifecycle of a single session from
its creation through its expiry, the cookie shape and signing, the
AES-256-GCM envelope that encrypts the data at rest, the
fingerprint binding that catches cookie replay, and the dirty-flag
and write-back machinery that makes the lifecycle invisible to
application code.

## The cookie

The session cookie is small. By default it carries an opaque
session id (the `SessionId` newtype, sixteen bytes of cryptographic
randomness from `SecureRng`, base64-encoded for transport) plus an
HMAC signature computed from the id and the deployment's signing
key. The whole cookie is well under two hundred bytes.

```text
session=<base64(session_id)>.<base64(hmac_sha256(signing_key, session_id))>
```

The signature defeats forgery. An attacker who guesses or
brute-forces a session id cannot use it without also producing the
HMAC, which requires the signing key. The signing key is the
operational secret covered in the *Getting started* chapter: a
32-byte value loaded from a secrets manager, stable across process
restarts, rotated on a schedule.

The cookie attributes are conservative by default: `HttpOnly`
(client-side JavaScript cannot read it), `SameSite=Lax` (it is sent
on top-level cross-site navigations but not on cross-site
sub-requests), `Path=/` (it applies to the whole application), and
`Secure` when configured (it is only sent over HTTPS). The default
session lifetime is a function of `SessionLayer::with_ttl`; the
default in the constructor is twenty-four hours.

The cookie is opaque. The session id maps to a row in the session
store, and the row carries the actual data. A user who copies the
cookie has the session id and the signature, both of which the
server already has; nothing on the cookie carries the user's
identity, the factors completed, or any other session state.

## The session store

The session store is the persistence layer for the data the cookie
identifies. Each row in the store carries:

- The session id (the primary key).
- The serialised `SessionData` (covered below).
- The created-at and updated-at timestamps.
- The expiry timestamp.
- The optional fingerprint binding (covered below).

`SessionData` is the application's view of the session:

```rust,ignore
pub struct SessionData {
    pub auth_state: AuthState,                  // see Part II
    pub principal_hint: Option<PrincipalHint>,  // cache of recent extractor outputs
    pub custom: HashMap<String, serde_json::Value>,  // application data
    pub schema_version: u32,                    // see Schema migration
}
```

The `auth_state` carries the state-machine variant (`Guest`,
`Authenticating`, `Authenticated`, `PendingWorkflow`,
`Identifying`). The `principal_hint` is an optional cache of the
principal extracted during this session's authentication, kept on
the session so the `PrincipalResolver` does not have to recompute
it on every request. The `custom` map carries application-defined
data with a sixty-four kilobyte cap. The `schema_version` is the
field that lets the data shape evolve.

The serialisation format is MessagePack: faster than JSON, more
compact, and stable across versions of `serde`. Backends that
support binary blobs persist the bytes directly; backends that
require text (some configurations of MySQL, for instance) encode
the bytes as base64 first. The format is the same across all
backends; switching backends does not require re-serialisation.

## The AES-256-GCM envelope

The serialised session bytes are encrypted before storage. The
envelope is AES-256-GCM, a standard authenticated-encryption scheme
that produces a ciphertext, a tag, and a nonce. The encryption key
is a 32-byte value loaded from a secrets manager at process start.

The shape of one envelope:

```text
nonce (12 bytes) | ciphertext (variable) | tag (16 bytes)
```

The nonce is generated fresh per write through `SecureRng`. AES-GCM
is sensitive to nonce reuse (a reused nonce against the same key
catastrophically compromises confidentiality and authenticity); the
twelve-byte random nonce gives a collision probability of about
one in 2^48 per encryption, which is comfortably safe for any
realistic session volume.

The additional authenticated data (AAD) carries the session id. The
binding means that an encrypted blob from one session cannot be
swapped into another session's row even if an attacker can write
to the database. The session id is plaintext in the cookie, so this
adds no confidentiality, but it adds integrity: the database is
not the source of truth for "which session is this blob from."

Key rotation is the operational lever. `SessionCrypto::new(key)`
constructs an envelope with one current key. `.with_previous_key(old_key)`
keeps the old key available for reads, so sessions encrypted with
the old key continue to decrypt while new writes use the new key.
After a transition window long enough for every existing session
to be rewritten (which happens naturally over the next session
write, or can be forced through a background scan), the previous
key can be removed.

The chapter *Operations runbook* covers the rotation sequence and
the staged rollout for both the signing key and the envelope key.

## The fingerprint binding

A session id alone is not enough to defend against cookie theft. An
attacker who captures a session cookie can replay it from a
different browser, IP, and operating system, and the session
machinery on the server cannot tell the difference without
additional signal.

The fingerprint binding is the additional signal. At session
creation (typically at first login), the server computes a
fingerprint from the user agent header, the IP address (read
through the trusted-proxy configuration), and any other coarse
features the deployment chooses to include. The fingerprint is
HMAC-signed and stored alongside the session id. On every
subsequent request, the server recomputes the fingerprint from the
incoming request and compares it (constant-time) against the
stored value.

The match has three outcomes:

- Match exactly: the session is allowed to proceed.
- Match within a tolerance: the session is allowed to proceed, but
  the divergence is logged.
- Mismatch beyond tolerance: the session is treated as compromised
  and one of three responses fires (warn, re-authenticate, full
  logout), depending on the configured policy.

The tolerance accommodates legitimate change: a user's IP can
change when they switch from wifi to cellular; their user agent
can update overnight when the browser auto-updates. Strict matching
on either signal produces too many false positives. The default is
coarse: the IP must remain within the same /24 (for IPv4) or /64
(for IPv6), and the user agent must share its major version.

The chapter *Cookies, fingerprinting, hijack detection* covers the
configuration knobs and the trade-offs in detail.

## The Tower layer

The `SessionLayer` is the Tower middleware that threads the
session through every request. The layer's `call` method is the
sequencing centre of the session lifecycle.

The pseudocode of one request:

```rust,ignore
async fn call(&self, req: Request) -> Response {
    // 1. Extract the cookie (or skip if absent → Guest).
    let cookie = extract_session_cookie(&req);

    // 2. Verify the HMAC, decode the session id.
    let session_id = verify_cookie(&cookie, self.signing_key)
        .map_err(|_| ();  // fall through to a guest session

    // 3. Load the row from the session store.
    let row = self.store.load(&session_id).await;

    // 4. Decrypt the envelope, deserialise the data.
    let data = decrypt_and_deserialize(&row, &self.crypto)?;

    // 5. Verify the fingerprint binding.
    enforce_fingerprint(&data, &req, self.fingerprint_policy)?;

    // 6. Wrap into a SessionHandle, insert into request extensions.
    let handle = SessionHandle::new(session_id, data);
    req.extensions_mut().insert(handle.clone());

    // 7. Run the handler.
    let response = self.inner.call(req).await?;

    // 8. If the handle is dirty, write back.
    if handle.is_dirty() {
        let new_data = handle.into_data();
        let new_envelope = encrypt(&new_data, &self.crypto, &new_session_id);
        self.store.save(&session_id, &new_envelope).await?;
        // Reissue the cookie (with a fresh id if rotation was triggered).
        response.headers_mut().append("Set-Cookie", construct_cookie(...));
    }

    response
}
```

Three of the eight steps are worth dwelling on.

Step 5 (the fingerprint check) is the gate that catches replay. A
mismatched fingerprint causes the handler not to run at all; the
session-layer returns a 401 (or the configured response). The
choice of response depends on the policy: warn-only deployments
log and continue; strict deployments deny.

Step 7 is where the handler actually runs. The handler receives a
`SessionHandle` via `AuthSession` (the extractor), reads or
mutates it, and the mutations are tracked via the dirty flag.

Step 8 is the write-back. The session is saved only when it is
dirty, which means a read-only request (the dashboard, a metric
endpoint, an idle-page poll) does not write to the session store.
The store sees writes proportional to the rate of state changes,
not the rate of requests, which is the difference between a
manageable database load and a saturated one.

## The dirty flag

The dirty flag is the optimisation that makes the session store
viable at the read rates a real application produces. The flag is
on `SessionHandle` and is set by any method that mutates the
session: `set_authenticated`, `clear`, `set_custom`, and so on.

The flag is checked at step 8 in the lifecycle above. A clean
handle is dropped silently; a dirty handle triggers the
serialisation, encryption, store-write, and cookie-reissue path.

The trade-off is that a read of mutable state through an immutable
borrow does not mark dirty, but the application's pattern for that
case is to use the typed accessors (`is_authenticated`,
`current_user_id`, `custom_get`) that do not need a mutable
borrow. Mutating accessors (`clear`, `set_custom`, the orchestrated
`begin_login` and `verify_factor` paths) all set the flag.

The cookie is reissued only when the session id rotates, not on
every write. Identifier rotation happens at two automatic moments
(`Guest` → authenticated to defeat fixation; logout so the new
`Guest` session doesn't share an id with the old) plus explicit
re-issuance through `AuthSession::regenerate`. The routine
read-write-read cycle does not rotate.

`regenerate` exists for the cases the library can't infer on its
own: any handler that crosses a **privilege boundary** should call
it before responding. The canonical list (drawn from OWASP ASVS
V3, the OWASP Session Management Cheat Sheet, and NIST SP 800-63B
on AAL transitions):

| Boundary | Rotate session id? | Also revoke sibling sessions? |
|---|---|---|
| Primary login | automatic | optional |
| Logout | automatic (id invalidated) | depends |
| MFA factor added (TOTP, WebAuthn, recovery codes, …) | yes | optional |
| MFA factor removed or disabled (AAL drops) | yes | recommended |
| Password / primary credential change | yes | **strongly recommended** |
| Step-up to a higher assurance level | yes |; |
| Account recovery flow completion | yes | yes |
| Impersonation start / stop | yes |; |
| Role grant / revoke, scope change | yes | depends on direction |
| Tenant switch in a multi-tenant deployment | yes |; |
| Profile edit, theme change, factor *config* tuning | no |; |

Rotating does two things at once: it defeats fixation (any
pre-existing id, including one an attacker planted before the
boundary, becomes useless), and it caps the blast radius of a
captured pre-elevation cookie (a cookie stolen at AAL1 cannot ride
the new AAL2 binding). Sibling-session revocation
(`SessionRegistry::revoke_user_sessions`) is a strictly stronger
statement that matters most on credential changes, where any other
device holding a stale password-derived session must be cut off.

A library hook on `FactorStore::save_factor` would catch some of
the rows above and miss the rest (un-enrolment, password change,
role grants), and would misfire on factor-config tuning that is
not a privilege change. The boundary decision is necessarily
app-level. Call `regenerate` at the handler that knows.

## When the session expires

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
expiry timestamp, so an actively-used session keeps refreshing.
The maximum lifetime is the configured TTL from the most recent
write. A session that goes idle for the TTL expires; a session
that gets a single dirty write per TTL window never expires
(through ordinary use).

Some deployments want a hard cap: a session expires absolutely at
a fixed time after creation, regardless of activity. The
`SessionLayer::with_absolute_ttl` option enables this; the
absolute expiry is stored at session creation and is not refreshed.
The two TTLs (sliding and absolute) compose: the session expires
at the earlier of the two.

## Session cleanup

Expired sessions need to be removed from the store. The cleanup
is the application's responsibility (axess does not run a
background task on its own), but the patterns are uniform across
backends.

The SQL backends expose a `cleanup_expired` method that deletes
rows whose expiry timestamp has passed. The
[`examples/sqlite/`](https://github.com/GnomesOfZurich/axess/tree/main/examples/sqlite)
reference application runs this on a `tokio::interval` once per
hour; the interval is tunable.

The Valkey backend uses Valkey's native TTL: each row is written
with an expiry, and Valkey removes it automatically. There is no
cleanup task to write because the database does the work.

For deployments with millions of sessions, the cleanup pattern
matters operationally. A daily delete-by-range is fine for tens of
thousands; for millions, the delete needs to be incremental (a
limit clause, looping through batches) to avoid long-running
transactions that lock the table.

## What this enables

The lifecycle as designed makes session handling invisible to
application code. The handler reads `AuthSession`, mutates it (or
does not), and the framework handles the cookie, the
serialisation, the encryption, the fingerprint check, the
write-back, and the expiry. The application's surface area for
session bugs is small: most session-related issues are policy
choices (rotate too aggressively, lockout too strict, fingerprint
tolerance too tight), not bugs in the lifecycle itself.

The chapter *Backends* covers the storage backends in detail; the
chapter *Cookies, fingerprinting, hijack detection* covers the
fingerprint binding in detail; the chapter *Schema migration*
covers the `SessionData::schema_version` field and what happens
when the data shape changes between deployments.

## Further reading

*Backends: SQLite, Postgres, MySQL, Valkey* covers the four
first-party session stores and their feature-flag and dialect
notes. *Cookies, fingerprinting, hijack detection* covers the
configuration knobs for the fingerprint and the trusted-proxy
configuration that determines how IP is read. *Schema migration*
covers the `SessionData::schema_version` field. *Operations
runbook* covers signing-key and envelope-key rotation.
