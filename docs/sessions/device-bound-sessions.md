# Design: device-bound sessions

Status: built in part, behind the `device-keys` feature.
[What is built and what is not](#what-is-built-and-what-is-not) lists both
halves, and the page describes the whole design. The browser protocol's wire
details were compared with the W3C editor's draft of 9 November 2026, and no
browser has run against the implementation:
[The browser front-end and the draft](#the-browser-front-end-and-the-draft)
says what matched, what the comparison changed and what stays open.

## The gap

A session is a bearer cookie. `__Host-axess.sid` carries the session id and
an HMAC over it, and whoever presents the pair is the session. A session that
is not bound to a device key has four protections against a copy of that
cookie taken off the device (malware that reads the browser's cookie store,
a stolen backup, a proxy log that kept the `Cookie` header):

- **The fingerprint binding**, when the adopter configured one with
  `SessionLayer::with_binding`; none is configured by default. The one that
  ships, `UserAgentBinding`, compares a header the thief copies together with
  the cookie.
- **The lifetime.** 24 hours sliding and 7 days from authentication by
  default. The thief's own requests keep the sliding half alive.
- **Revocation** through the registry, once somebody knows there is
  something to revoke.
- **Recency gates.** A policy that asks for a recent factor, the
  passkey-change rule and every step-up still stop the thief, who has no
  factor.

So a copied cookie is the user's session, on every route that asks for no
fresh factor, for up to seven days.

The device token is the same kind of secret. `__Host-axess_device` holds a
random token whose digest is on the device row (`DeviceBinding::Cookie`), and
a request that presents it is answered `BoundDevice::Proven`. It sits in the
same cookie store as the session cookie, so whoever copied one copied the
other. On the thief's machine `AuthSession::proven_device` answers the
victim's device, and the per-account lockout exempts it when the row is
`Seen` or `Trusted`. For a device without a key, "proven" means "holds the
token"; it does not mean "is the machine".

A refresh token is single-use and its family is revoked when a rotated-out
token comes back, so theft is detected at the owner's next refresh. Until
then the thief who refreshed first holds a working session, and the
`device_info` string that binds the token is a value the thief copied too.

## What binding answers, and what it does not

The client generates a P-256 key pair where the private half can be used and
cannot be read: a TPM, a Secure Enclave, a platform key store. The server
keeps the public half on the device row. From then on the long-lived cookies
are not enough. A session bound to the key is served, and the device counted
as proven, only for a request that also proves the key. A browser proves it
with a short-lived proof cookie, which is minted only against a signature by
that key over a challenge the server chose. An app that signs every request
proves it with a signature over that request.

It answers:

- **A copied cookie store replayed from another machine.** Without an
  unexpired proof cookie the session cookie is worth nothing. With one, it is
  worth the rest of that cookie's life: at most `proof_ttl` plus
  `acceptance_grace`, 10 minutes 30 seconds by default, in place of seven
  days.
- **A copied device token.** Where keys are enforced, a device that has a key
  is never proven by its token, so the copy earns no lockout exemption and no
  shortcut past a step-up.
- **A copied refresh token.** A refresh given the key service
  (`Refresh::device_key`) refreshes the token of a keyed device only with a
  proof by the key, and presenting the token without one revokes its family.
  A refresh given the device store and no key service refuses such a token
  (`RefreshError::KeyCheckMissing`). See
  [With refresh tokens and the family cascade](#with-refresh-tokens-and-the-family-cascade)
  for the one call that refreshes it unchecked.
- **Slow revocation of a device.** Revoking a device stops its proofs, so its
  bound sessions stop being served within the same window. A session that is
  not bound outlives `revoke_device`.

It does not answer:

- **Malware that stays on the device.** The key cannot be exported, and it
  can be asked to sign by anything that runs as the user. Binding turns
  "copy once, use anywhere, for days" into "stay on the machine", and no
  further.
- **Malware present when the key is registered.** Registration is trust on
  first use. The browser protocol carries no attestation, so the server
  cannot tell a hardware key from a software key an attacker generated.
  [Registering a key](#registering-a-key) narrows the opening and does not
  close it.
- **The window.** A proof cookie is a bearer value for its own lifetime. A
  request proof is one for the single request it names, from the moment it
  is made until it is used or its lifetime ends.
- **Script in the page, cross-site requests, fixation.** Unchanged; each has
  its own layer.
- **A party that can write the stores.** It can replace the public key on a
  device row, as it can rewrite `auth_state` on a session row. The
  sealed stores refuse a row they did not seal; an unsealed one trusts it.
- **Long-lived connections.** A WebSocket or an event stream is checked at
  the upgrade, as the fingerprint binding is, and not again.
- **A client with no support, under the `Prefer` policy.** It keeps a bearer
  session and a device proven by its token.

## The model

A **device key** is the client's key pair; the server holds only its public
half. A **proof** is a compact JWS the key signs over a server **challenge**.
The **proof cookie** is the short-lived cookie a verified proof buys. A
session is **bound** when its row names a device, that device's key and the
person the binding was made for (`SessionKeyBinding::owner`), and that
person is the one at the session's browser: the signed-in user, or the
administrator while the session is an impersonation
(`SessionKeyBinding::in_force_for`). A binding made for another person binds
nothing. Every reader asks for the binding in force
(`SessionData::key_binding_in_force`), and the layer drops a binding that is
not in force from the row at the next write.

The key belongs to the device row, not to the session. A browser registers
once, and a later sign-in on it needs no registration round trip and has no
first-use opening. If the request that completes the sign-in proved the device by its key and
the device is the signed-in user's, that request binds the new session.
Otherwise the first later request that proves the user's own device by key
binds it. The alternative, a key per session, is the first
of the [Decisions](#decisions).

A layer **enforces keys** when it was given a key service whose policy is not
`Off`.

The invariants:

1. The private key never reaches the server, and nothing the server stores
   lets anyone mint a proof.
2. A proof cookie is minted only in the response to a request that carried a
   valid signature by the device's registered key over that device's current
   challenge (at registration: by the key being registered, over the offer).
3. A challenge is accepted once.
4. Under a layer that enforces keys, a device that has a key is never proven
   by its token alone.
5. A layer that enforces keys serves a bound session only to a request that
   proves the session's device and key: by a valid proof cookie or, where
   request proofs are taken, by a proof made for that request. A layer that
   cannot check a key (one given no key service, or a build without the
   feature) runs such a request as a guest. The policy `Off` is the one way
   to serve a bound session as a bearer session. A bound session is never
   unbound; it ends.
6. A key is registered only against an offer, and an offer is made only to a
   signed-in session whose login is no older than `registration_window`, for
   the device that request proved by its token, on one response per login.
7. No decision about an offer, a challenge or a proof cookie reads the
   client's clock. A request proof is the exception: its `iat` is the
   client's clock, held to the injected clock.
8. Every time comparison reads the injected `Clock`, and every random value
   comes from the injected `SecureRng`.

## The protocol

Two front-ends carry the same three steps (register, prove, present). The
browser front-end is the W3C Device Bound Session Credentials draft, in which
the browser does the work unprompted. The app front-end is a proof in the
shape of RFC 9449 (DPoP) that an app sends itself. They differ in the headers
and in the claims of the proof, and in nothing the server stores.

The exchanges below show the browser front-end, as the editor's draft of
9 November 2026 lays it out. The names, the status codes and the header-value functions are in
`axess_factors::key_proof::browser_draft`; the `<tenant>.<device>`
identifier and the composition of the description are written in the
session layer.
The draft defines the two request headers as structured-field strings, the
text in double quotes, and its own algorithm appends the bare value; both
forms are read, and the exchanges show the quoted one.

### Registering a key

```text
POST /login                                   (the request that completes a factor)
  <- 303
     Set-Cookie: __Host-axess.sid=...

GET /                                         (the first request of the signed-in session)
     Cookie: __Host-axess.sid=...
  <- 200
     Set-Cookie: __Host-axess_device=...
     Secure-Session-Registration: (ES256);path="/axess/device-key";challenge="<offer>"
     Cache-Control: no-store

POST /axess/device-key                        (sent by the browser itself)
     Cookie: __Host-axess.sid=...; __Host-axess_device=...
     Secure-Session-Response: "<proof: ES256, public key as a JWK, jti=<offer>>"
  <- 200
     Set-Cookie: __Host-axess_device_proof_1a2b3c4d5e6f7a8b=...; Max-Age=600
     Secure-Session-Challenge: "<first challenge>";id="<tenant>.<device>"
     { "session_identifier": "<tenant>.<device>",
       "refresh_url": "/axess/device-key/refresh",
       "scope": { "origin": "https://app.example", "include_site": false },
       "credentials": [ { "type": "cookie",
                          "name": "__Host-axess_device_proof_1a2b3c4d5e6f7a8b",
                          "attributes": "Path=/; Secure; HttpOnly; SameSite=Lax" } ] }
```

**The offer.** After the handler has run, the layer adds the registration
header when all of these hold:

- the policy is not `Off`;
- the session is signed in (`Authenticated`, or in a step-up of that
  session) and its `signed_in_at` (when its login completed, which a
  step-up, an impersonation and an id rotation keep) is no older than
  `registration_window`;
- the request's device was proven by its token and has no key;
- this is the request on which the session came to hold both its login and
  that device.

The device condition covers the device the resolver created on this request
and a device from before the upgrade alike.

The offer therefore rides on one response per login. A step-up, begun or
finished, keeps the login's time and is offered nothing: its window is the
login's, which has had its offer. A new browser has no device while it is a
guest, so the offer rides on the response to the first request of the
signed-in session, the request that creates the device, as the exchange
above shows. Where the
request that verifies the factor already proved a keyless device by its
token (a returning browser, under a resolver that has a tenant for a guest),
the offer rides on that request's response. Every later response inside the
window carries none, so presenting the session and device cookies again does
not fetch it. The response that carries it is kept out of shared caches: it
is marked `Cache-Control: no-store`, unless the handler already marked it
`no-store` or `private`, and `Vary: Cookie`.

The offer's challenge is not stored. It is `v1.<expires>.<mac>`. The MAC is
HMAC-SHA256 under a sub-key of the session signing key over four values: the
session's key (the 32 bytes of the digest that names it in the store, never
the id its cookie carries), the tenant, the device id and the expiry. The
expiry is `signed_in_at` plus `registration_window`. It is good for one session and one device until the
window closes, and making an offer writes nothing.

**The registration.** The registration path is one of two routes
`DeviceKeyService::router` supplies, merged into the application's router
inside the session layer. The layer marks a `POST` to either path, and a
CSRF layer between the session layer and the routes lets a marked request
through without a token:
the signature over the offer is what authenticates it. The registration
refuses unless all of these hold: the session cookie verifies and loads a
trusted, signed-in row (`Authenticated`, or in a step-up of that session)
whose `signed_in_at` is inside the window; the session's device is the one
the offer was made for; and the offer's MAC and expiry hold. Then it verifies the proof: size bound, `alg` exactly `ES256`,
the expected `typ`, a P-256 public key with no private member, the signature
under that key, and the challenge claim equal to the offer in constant time.
An app's proof must also name the method and the URL (`htm`, `htu`). The
browser's is bound to its endpoint by the offer alone, because the later
draft's proof carries no audience claim; the constant
`PROOF_AUDIENCE_CLAIM` is where that is decided. Last, it reads the
device row: a device another user owns is refused, and one with no owner is
claimed for the session's user by `DeviceStore::claim_owner` before it takes
the key.

On success it makes two writes, in this order:

1. The device row gains the key through `DeviceStore::replace_bindings`,
   with the bindings it read as the expected value. Two registrations that
   race cannot both land, a `Revoked` row gains nothing, and a device that
   already has a key refuses a second.
2. The session row gains its binding if it has none, as a compare-and-swap
   on its revision merged like any other session write. A session that is
   already bound (to another device's key) keeps its binding.

If the second write fails, the device has a key and the session is not
bound: under `Prefer` the session carries on as it was, and under `Require`
it ends when the window closes. If the response is lost after both writes,
the session is bound and the browser holds no proof, so it is signed out.
Either way the browser never learned of the key its device row now requires,
and that row is not proven from this browser again. Its next sign-in is given
a new `Unknown` device, as a sign-in without a valid token is, and the offer
with it; the orphaned row ages out through the retention sweep and the cap on
`Unknown` devices.

Three things narrow the first-use opening: an offer exists only for the
registration window after a login; it is delivered on one response, in a
header and never in the cookie jar; and it is bound to the session it was
made for. A thief who copies the cookie store after that response holds no offer,
is handed none by presenting the copied cookies, even inside the window, and
so cannot register a key of their own on the victim's device or bind a
stolen session to one.

### The proof cookie

```text
__Host-axess_device_proof_<16 hex of SHA-256("<tenant>.<device>")> =
    v1.<tenant>.<device>.<base64url(thumbprint)>.<expires>.<base64url(mac)>
```

The MAC is HMAC-SHA256 under the sub-key of the session signing key that
also signs offers, over a domain label of its own followed by the tenant id,
the device id, the key's thumbprint and `expires`, each of the four
length-prefixed. An offer's MAC starts with another label, so neither value
passes for the other. Verifying a proof cookie is a MAC and a comparison
with the clock: no store is read. The sub-key is derived for the current and
the previous signing key, as the cookie and fingerprint sub-keys are, so a
signing-key rotation does not cost every browser a failed request.

- `Max-Age` is `proof_ttl`. The server accepts the value until `expires`
  plus `acceptance_grace`, which covers a request in flight when the
  browser's timer fires. `Max-Age` is a duration, so the two clocks need not
  agree on the time of day.
- `Secure`, `HttpOnly`, `Path=/`, and the `SameSite` value of the session
  cookie. It must travel wherever the session cookie travels: a proof cookie
  stricter than the session cookie would make every arrival from another
  site look like a stripped binding.
- The expiry is inside the MAC, so a copy does not outlive its own expiry
  however often the owner's browser refreshes. The session cookie cannot be
  the short-lived credential because its value does not change.
- The name carries the first 16 hexadecimal digits of the SHA-256 digest of
  the tenant and the device id, so that two devices registered in one
  browser profile keep separate proofs whatever shape the ids have (see
  [A browser shared by several accounts](#a-browser-shared-by-several-accounts)).
  Nothing in the name reads back as the id.
- Where request proofs are taken, a registration in the app shape sets no
  proof cookie (see [The app front-end](#the-app-front-end)).

### Refreshing the proof

```text
POST /axess/device-key/refresh                (browser: the proof cookie ran out)
     Sec-Secure-Session-Id: "<tenant>.<device>"
     Secure-Session-Response: "<proof: ES256, jti=<challenge>>"
  <- 200
     Set-Cookie: __Host-axess_device_proof_1a2b3c4d5e6f7a8b=...; Max-Age=600
     Secure-Session-Challenge: "<next challenge>";id="<tenant>.<device>"

  or, when the proof is absent or its challenge is not the current one:
  <- 403
     Secure-Session-Challenge: "<current challenge>";id="<tenant>.<device>"
```

The refresh names a device, not a session, and needs no session cookie: a
signed-out browser keeps its proof fresh, so the request that signs the user
in is already proven.

1. The identifier gives the tenant and the device; a request without one is
   refused with 400 (`REFRESH_REFUSED_STATUS`). A final refusal at this path
   is never 403: the draft has a browser answer a 403 by sending the same
   refresh again with the challenge it holds, and end its session on any
   other status from 400 to 499 except 407 and 429. The row is read with `DeviceStore::load_fresh`, past any
   cache. A missing row, a `Revoked` row and a row with no key get one and
   the same answer: the session has ended, and the proof cookie is expired.
2. With no proof, or a challenge claim that is not the row's current
   challenge, the answer is the current challenge. Nothing is written,
   unless the current challenge is older than `challenge_ttl`: then it is
   replaced first, by the same compare-and-swap.
3. Otherwise the signature is checked under the stored key. The structure,
   `alg` and `typ` were checked before the row was read, and a value that
   fails them is answered 400 with no row read. The key in the proof, if it
   carries one, is ignored.
4. A valid proof rotates the challenge with `DeviceStore::replace_bindings`
   (a new random challenge, the time of the proof) and only then mints the
   cookie. `BindingsUpdate::Conflict` means another writer changed the row:
   the service reads it again and, if the challenge moved, answers with
   the new one.
5. A proof that names the current challenge and whose signature does not
   verify, or that an app made for another method or URL, is refused with
   400, recorded as `Suspicious` and counted. Nothing is revoked: the caller has
   gained nothing, and the device row belongs to the victim.

The session row is not touched by a refresh. The cost is one device-row
write per `proof_ttl` of activity per device, the same order as the sighting
write the lifecycle already makes every five minutes.

### What each request is checked for

Under a layer that enforces keys, the request path is:

1. Load the session (cookie, row, registry, age caps, fingerprint).
2. Verify the request's proof cookies, at most eight of them. Each valid one
   is a key the request proved: tenant, device and thumbprint. Where request
   proofs are taken, a proof in the `DPoP` header of a request off the two
   key paths is verified too (see [The app front-end](#the-app-front-end)).
   What a request proved is its own answer and is never stored, like
   `SessionData::device_proven`.
3. If the row is bound by a binding in force for the person at its browser
   and none of the proven keys is exactly its tenant, device and thumbprint,
   the request does not run as that session. It runs
   as a fresh guest, the row is left alone and the client's cookie is not
   cleared.
4. Under `Require`, a signed-in row (`Authenticated`, or in a step-up of
   that session) that is not bound (a binding made for another person
   counts as none) and whose `signed_in_at` is older than
   `registration_window` is ended as a row past its age cap is: claimed
   with a compare-and-swap on its revision, recorded through the layer's
   `SessionEndAudit` (reason `key_binding_required`, the administrator as
   actor for an impersonation), then deleted, in a task of its own. Of
   several requests that carry the cookie one ends it; a sink that fails
   leaves the row stored, and the next request tries again. The request
   runs as a fresh guest either way.
5. Resolve the device. The resolver is handed the proven keys. A device with
   a key is answered `Proven` only when one of them is its own. With a valid
   token and no such proof, the answer depends on the request: for a
   signed-in session whose row already names the device, the kept device
   (`ResolvedOrKept::Kept`, recognised and not proven); for a guest, no
   device at all; for any other signed-in request, a new `Unknown` device. A session in a step-up is
   handed to the resolver as the signed-in session it is (its person, its
   tenant and its device), so its device and a bound key's proof of it
   carry through the step.
6. Run the handler. When a signed-in session has no binding in force, is
   inside its registration window, and the request proved the session
   user's device by its key, the write that follows binds the session to
   that device and key; the binding names that person (the
   administrator under impersonation) as its owner. The layer reads the device row past any cache
   first: the row must be live, still hold that key, and be owned by the
   user the session is signed in as, or have no owner, in which case it
   is claimed for that user (`DeviceStore::claim_owner`). The binding's
   tenant is the proven key's, and a proven key of another tenant than the
   session's binds nothing.
7. Finalize: a binding that is not in force for the person at the
   browser now is dropped before the row is written. Then add the offer
   when its conditions hold and, once the write that stores a binding this
   request made has landed, write its `SessionKeyBound` row.

In the layer a session therefore becomes bound in exactly two ways, both
inside the registration window after its login: a request proves
by key a device its user owns, or a registration succeeds. Outside the layer
there is a third: the session a refresh token builds after a proof by the
key (see
[With refresh tokens and the family cascade](#with-refresh-tokens-and-the-family-cascade)).

The request that completes a sign-in resolved its device before anyone was
signed in, so the device it proved may be another account's. Such a sign-in
binds nothing: the session stays unbound, and its next request resolves the
user's own device and binds to it or is offered a registration.

### Replay

- **An offer** is single-use by state: a device takes one key, and the write
  that adds it is a compare-and-swap.
- **A challenge** is single-use by state: accepting it replaces it in the
  same compare-and-swap. Two refreshes with one proof cannot both win; the
  loser is answered with the new challenge and signs again.
- **A proof** kept from an earlier refresh names a challenge that is gone. A
  proof made for one device names another's challenge. A registration proof
  answers an offer, which is no device's challenge, so it is no refresh.
- **A challenge outlives no more than `challenge_ttl`.** Without that bound,
  something that could ask the key for one signature while the laptop was
  idle would hold a proof good until the owner's next refresh, which may be
  days away.
- **The proof cookie** is replayable for its lifetime. That is the residual
  window of a client that holds one.
- **A request proof** is single-use by its `jti`, which the replay store
  records for as long as the proof is accepted.

The two key paths need no replay cache. Their replay state is two fields on
a row every node already shares, which keeps the default build free of
infrastructure and makes a fleet correct without a second store. Request
proofs are the one part that needs a replay store, and
`DeviceKeyService::with_request_proofs` refuses a store that records
nothing.

### Clocks

In a proof that answers an offer or a challenge, `iat` is not read.
Its freshness comes from the challenge, which the server minted and whose
age the server measures. The four time comparisons of the two key paths and
the layer (the offer's expiry, the challenge's age, the proof cookie's expiry
plus grace, the registration window against `signed_in_at`) all read the
injected `Clock`, so a `MockClock` drives every one of them to the tick on
either side of its boundary. A client whose clock is wrong registers and
refreshes like any other. One whose timer runs slow by more than
`acceptance_grace` in `proof_ttl` has its requests run as a guest from the
server's expiry until its own timer fires and it refreshes.

A request proof adds a fifth comparison, and it is the one that reads the
client's clock: the proof's `iat` against the injected `Clock`. An app whose
clock is more than `max_age` behind the server's, or more than five seconds
ahead of it, has every request proof refused, and the requests of its bound
session run as a guest.

### A client with no support

The browser ignores a header it does not know, so nothing arrives at the
registration path and the offer lapses. The server cannot tell "no support"
from "the user's hardware has no key store" from "a proxy removed the
header"; it sees only that no key was registered.

- `Prefer`: the session stays a bearer session and the device stays proven
  by its token.
- `Require`: the session ends when `registration_window` has passed since
  its login, whether or not it is in a step-up: a step-up neither pauses
  nor restarts the window. The application reads the session's binding
  state to tell the user why. `Require` is for a fleet of managed browsers,
  not for the open web: the browser protocol ships in Chromium
  only.

### The app front-end

A native app holds the same kind of key in the platform key store and drives
the steps itself. Its proof is a DPoP proof (`typ` of `dpop+jwt`, the public
key in the `jwk` header, `htm`, `htu`) with the challenge in the `nonce`
claim. It sends the proof in a `DPoP` header to the same two paths, and reads
the challenge from `DPoP-Nonce`, as RFC 9449 section 8 describes for a
server-chosen nonce; every answer that carries a challenge carries it in
that header and in the browser's. The offer reaches it in the same
registration header. On the two key paths `iat` and `jti` are not read, for
the reason above: the nonce is single-use.

The app front-end exists because the browser draft is still moving and an
app's proof format should not move with it, and because mobile platforms
already have DPoP libraries.

An app that holds refresh tokens is bound at the token: see
[With refresh tokens and the family cascade](#with-refresh-tokens-and-the-family-cascade).

An app can also sign every request and need no proof cookie. With
`DeviceKeyService::with_request_proofs(replay, max_age)`, a request off the
two key paths that carries a `DPoP` proof by the device key over that
request is proven by it:

- `htm` and `htu` name the request. The URL is the origin the server serves
  the request's host at, followed by the path.
- `iat` is no more than `max_age` before the server's clock and no more than
  five seconds after it (`REQUEST_PROOF_CLOCK_ALLOWANCE`). `max_age` is
  between one second and five minutes (`MAX_REQUEST_PROOF_AGE`). A proof
  cannot be made after it is used, so one dated further ahead is refused.
- `jti` is new to the replay store. It is recorded for `max_age` plus six
  seconds, the whole span over which the proof is accepted, as
  `axess.device-key.request:<tenant>:<thumbprint>:<jti>`, so a proof is
  accepted once and one device's `jti` never refuses another's.

A request of a bound session names its device by the binding. Any other
request (a guest's, the one that signs a user in) names it in the identifier
header the refresh path reads, `Sec-Secure-Session-Id: <tenant>.<device>`.
A proof that stands recognises the device, so a sign-in on it binds the new
session with no registration and no proof cookie.

No store is read for a request that has shown no secret and no valid
signature. The proof carries its public key in the `jwk` header, as RFC 9449
lays it out, and its signature is checked first, under that key, with the
request it names, its `iat` and its `jti`: a value that is no proof, or a
proof that does not verify, costs no read. Only then is the device row read,
and the key the proof carries must be the key on the row.

How the row is read depends on what the request has already shown
(`RequestProofSender`). A request that presented a session cookie whose row
is bound to the device has it read past any cache, so revoking the device or
forgetting its key ends the session on every node at its next request; one
device-store read per signed request of a bound session is the price. A
request that holds no session bound to the device and names it in the
identifier header has shown no secret: its row is read through the store's
own `load`, which `CachedDeviceStore` answers from its cache. Such a request
costs one signature check and at most one cached read, and gains
recognition alone: the step that binds a session at a
sign-in reads the row again, past the cache, so a device recognised from a
cached row is never bound after it was revoked or its key replaced.

A proof that does not stand leaves the request to be judged without it, so a
bound session's request then runs as a guest. A refused proof is counted
separately for the two kinds of sender, so what anybody can send beside a device
identifier never hides a refusal under a bound session
(`request_proof_refused` for a request that held a session bound to the
device, `unbound_request_proof_refused` for any other). Two refusals also
write a `Suspicious`
`DeviceKeyProofRefused` row: a proof by the device's key that comes a second
time, and a proof that is not the key's on a request that held a session
bound to the device, which is the session cookie held without the key. A
proof by another key beside nothing but a device identifier writes no row,
since anybody can post one. A proof that could not be judged because the
device store or the replay store did not answer is not a refusal: it is
logged at `warn` and counted separately (`request_proof_unanswered`).

The replay store must record what it is handed: `with_request_proofs`
refuses `NoReplay`. A fleet shares one (`ValkeyJtiReplayStore`), since a
store in one process (`MemoryJtiReplayStore`) lets a proof be accepted once
per node. A store that cannot answer, or one that is full, leaves the proof
unaccepted.

What a copy of everything such an app holds is worth: where request proofs
are taken, a registration in the app shape sets no proof cookie, and an app
that never calls the refresh path never holds one, so it holds no bearer
value that outlives a request. A proof it has made names one request and is
accepted once, until `max_age` after its `iat`. An app that does call the
refresh path is handed a proof cookie as every client is, a bearer value for
`proof_ttl` plus `acceptance_grace`, and the layer serves a bound session to
a valid proof cookie whether or not it takes request proofs.

### A browser shared by several accounts

A device row has one owner, so a second account that signs in on the same
browser profile gets a device of its own. The device cookie holds one entry
per device, newest first, and a request is resolved to the first entry that
proves a device its user may use, so each account switch finds the
account's own device again. With keys, each of those devices registers
separately, and the registrations live side by side in the browser:

- The proof cookie's name carries a digest of the tenant and the device id,
  so one registration's refresh does not overwrite another's proof, under
  the default random ids and under an id scheme of the deployment's own
  (`LifecycleDeviceResolver::with_new_id_fn`) alike.
- At most eight of a request's proof cookies are read, as the device cookie
  holds at most eight entries. A profile shared by more accounts proves only the
  first eight.
- Before sign-in nothing says which account is signing in, so a request
  whose cookie proves several devices is recognised as none. The session is
  then bound at the first request inside its registration window that
  proves the session's own device by key, which is the request after the
  sign-in.
- A request whose cookie proves exactly one device proves it whoever owns
  it. A sign-in on it by another account binds nothing: a session is bound
  only to a device its own user owns, or to one with no owner, which is
  claimed for the user first.
- Each account's device takes a key at that account's first sign-in, from
  the offer every keyless device gets, and its later sign-ins bind to it.
- Revoking either device ends the sessions bound to its key.

The cost is one refresh per registered device per `proof_ttl` while the
profile is in use.

## How it composes

### With the device token

The token stays. It names the device, it is all a device without a key has,
and it is what a new browser is first recognised by. A `Cookie` entry and a
`Key` entry sit side by side in the row's `bindings`. What changes is what
the token is worth on a device that has a key: nothing by itself (invariant
4). The request-local answer `SessionData::device_proven` is joined by two
more: `SessionData::device_key`, the key the request proved its device by,
and `SessionData::key_proven`, the layer's verdict that the request proved
the key the session is bound to. `ProvenDevice::proof` says whether the
device was proven by token or by key.

### With the lockout exemption and step-up

The per-account lockout exempts the session's device only as a
`ProvenDevice` (`AuthSession::proven_device`). That call does not change; what
it answers does. On a keyed device it answers only for a request that proved
the key, and because the refresh works signed out, the owner's sign-in
request carries a valid proof cookie and the thief's copy does not. A bound
session's request that proved its key has its device proven by key whether
or not it also presented the device token. That holds while a step-up is
open too: the session in a step-up is handed to the device resolver as the
signed-in session it is, so the step-up's own `verify_factor`, on a request
after the one that began it, still finds the key-proven device and its
exemption. A deployment that requires keys
builds its service with `AuthnServiceBuilder::with_key_proven_device_store`
in place of `with_device_store`: a device without a key is then never
exempt.

The device chapter says that letting a `Trusted` device skip step-up
(`StepUpPolicy` with an empty `trusted` list) is safe only when a signal the
client cannot copy backs the match. A key proof is that signal, and an
application can ask `ProvenDevice` for it before it skips.

The trust ladder does not move. A key proves that this is the machine that
registered, not that the machine is to be trusted, so registering one
promotes nothing.

A trust write is made for the session's own user.
`DeviceLifecycleService::promote_on_authn`, `promote_if_authenticated` and
`grant_trust` take the `UserDevice` that `AuthSession::user_device` answers:
the device the request proved, with the user and tenant the session is
authenticated as. They write nothing to a row another user owns, and claim a
row with no owner for the user first, so one account's login never promotes
another account's device.

### With session rotation, login and logout

- **Rotation.** The binding is a field of the row, and `SessionStore::cycle`
  and `SessionStore::cycle_if_revision` carry the row to its new id. The
  proof cookie names the device, not the session, so a rotation reissues
  nothing, and a refresh never rotates the session id, so the CSRF tokens
  bound to that id are left alone.
- **Concurrent writes.** The three-way merge of a session keeps the stored
  value of every field a request did not change, so a request that loaded
  the row before the registration cannot write the binding away. The
  binding the merge picks stays only while it is in force for the merged state: a
  sign-out that raced a bind leaves a guest's row, and another person's
  sign-in leaves that person's, and neither keeps the binding; a step-up
  that raced a registration is still the owner's session and keeps it.
- **Login.** A transition into `Authenticated` on a request that proved by
  its key a device the signed-in user owns binds the session in the same
  write, which is the write that rotates its id. On any other request it
  leaves the session unbound: the next request binds it when it proves the
  user's own device by key, and a device without a key is offered one.
- **A second sign-in.** A login begun on a bound session, by another person
  or by the binding's owner again, ends the binding's force at the
  transition: nobody is signed in while the login is open, and another
  person is not the owner once it completes. `AuthSession::key_bound`
  answers false from then on in that request, the row is written without
  the binding, and a later request that proves the first person's key is
  not key-bound. The new login is bound as any login is, inside its own
  window; under `Require` an unbound session of the second person is held
  to the window counted from that person's login.
- **Step-up.** A step-up completes on a request of a bound session, which
  had to prove the key to be served at all; the binding stands.
- **Logout.** `AuthSession::clear` resets the row, binding included. The
  device keeps its key and the browser its proof, so the next sign-in needs
  no registration. It is bound by the request that completes it when the
  resolver has a tenant for a guest (a `TenantId` request extension, or a
  `tenant_fn` of the deployment's own), and by the first request after it
  otherwise: the default resolver gives a guest no device.
- **Impersonation.** The binding is to the browser, not to the user, and
  stays: it names the administrator as its owner, and only the owner is
  compared, not the tenant, so it holds within the administrator's tenant
  and across tenants (`begin_impersonation_across_tenants`), where the
  session's tenant is the user's and the device's is the
  administrator's. `AuthSession::clear` at its end leaves no binding. The
  browser is the administrator's, so everything about its device
  is the administrator's own: the device an impersonated session's request
  resolves or creates, the key registered on it, and the owner a sign-in
  binding asks the device to have. The user the session runs as gains no
  device, no key and no binding from it. See
  [An impersonated session's device](../identity/device.md#an-impersonated-sessions-device).

### With refresh tokens and the family cascade

A refresh token already names its device (`RefreshToken::device_id`). A
refresh says what it does about that device before it can run:
`Refresh::device_store` loads the device before anything is rotated, and
`Refresh::without_device_check` is the named opt-out. A `Refresh` that says
neither has no `run` and does not compile. The key rides on that link; the
token row gains nothing.

```rust,ignore
let (session, rotated) = Refresh::new(&plaintext, &tenant, status_check)
    .device_store(&devices)
    .device_key(&keys, proof)
    .run(&refresh_store, &config, &rng, now)
    .await?;
```

A refresh given the key service (`Refresh::device_key`) requires, for a token
whose device has a key, a proof by that key. `proof` is what the client sent
with the token, with the method and URL of the refresh request as the server
knows them:

- a valid signature over the current challenge: the challenge rotates, then
  the token rotates, and the session the refresh builds is bound to the
  token's device and key;
- a valid signature over a stale challenge: nothing is rotated, and
  `RefreshError::KeyProofRequired` carries the current challenge to sign;
- no proof, or a proof that is not the device key's: the token is in hands
  that do not hold the key. The family is revoked and
  `RefreshTokenStore::on_token_compromise` runs, exactly as for a rotated-out
  token that comes back, so `CascadingRefreshStore` revokes the family's
  devices. The answer is `RefreshError::KeyProofInvalid`, and a `Suspicious`
  `DeviceKeyProofRefused` row is written.

A client therefore holds the device's current challenge before it refreshes
a token: the registration and every refresh of the proof hand out the next
one, and the refresh path answers a request without a proof with the current
one.

The device row decides, not the token, and it is read before anything the
client sent. A token issued before its device had a key is held to the key
from the moment the key is registered. A token whose device has no key
refreshes whatever header comes with it (a proof in another algorithm, bytes
that are no proof, a sound proof, none): nothing is revoked and no row is
written for it.

A refresh that cannot check a key does not refresh a keyed device's token.
One given the device store and not the key service refuses it with
`RefreshError::KeyCheckMissing`, with nothing rotated or revoked, and so does
a build with `device` and without `device-keys`. `Refresh::without_device_check`
with no key service is the one call that refreshes such a token unchecked,
into a session that is not bound. It loads no device, so a revoked device's
token and a token of a device another user owns refresh too.

### With revocation, the sweep and the cache

- `revoke_device` marks the row `Revoked`. The next refresh reads the row
  fresh and is answered as ended, and `DeviceStore::replace_bindings` refuses
  a `Revoked` row, so a refresh that races the revocation cannot win. The
  device's bound sessions stop within `proof_ttl` plus `acceptance_grace`.
  A request proof reads the row past any cache, so a session served by
  request proofs alone stops at its next request, on every node.
- A device the retention sweep purged, or one evicted by the cap on `Unknown`
  devices, ends its bound sessions the same way.
- `CachedDeviceStore` serves the resolver's reads, so a node may see a device
  as keyless for one cache lifetime after another node registered its key,
  and answer its token as proof for that long. The session check (invariant
  5) reads no cache and has no such delay: a proof cookie is verified with no
  store read, and a bound session's request proof and the binding at a
  sign-in read the device row past the cache. A request proof on a request
  that holds no bound session is read through the cache; it recognises a
  device and binds nothing by itself.

### With Cedar

`StandardRequestContext::with_key_bound` emits a `key_bound` Boolean, from
`AuthSession::key_bound`: the session is bound by a binding in force for
the person at its browser, and the layer verified a proof by exactly the
bound key on this request, a proof cookie or a request proof. An action that reads it declares `key_bound: Bool`; a single Boolean
needs no schema fragment. A deployment on `Prefer` can then require a bound
session for the actions that warrant it, in one rule, without locking every
other browser out of the rest.

The answer is the layer's own and does not depend on the device token: a
request that arrives from another site carries the session and proof cookies
and not the `SameSite=Strict` device cookie, is served as the bound session,
and reads `key_bound` true; its device is proven by key too. `key_bound` is
false for a session that is not bound, for one whose binding was made for
a person other than the one now at its browser, for a bound session that
`Off` serves without a proof, and on the request that registers the key:
that request makes the binding, and the next one proves it.

## What the server stores

| Where | What | Bytes | Secret |
|---|---|---|---|
| Device row, one `Key` entry in `bindings` | thumbprint, public key, proof shape, when bound, when last proven, the current challenge and when it was issued | about 500 | no; the challenge is unpredictable before it is issued and worthless without the key |
| Session row, `key_binding` | the owner's user id, tenant id, device id, thumbprint, when bound | under 250 | no |
| Replay store, only where request proofs are taken | one record per accepted request proof, kept for `max_age` plus six seconds | under 100 a record | no |
| Nowhere | the private key, proofs, proof cookies, offers, a list of used challenges | | |

One more sub-key is derived from the session signing key. It signs the proof
cookie and the offer, each under a domain label of its own. There is no new
secret to provision or rotate.

## The public API

What follows is the surface as built. The verifier is in `axess-factors`,
everything else in `axess-core`. The facade re-exports the module as
`axess::device_key` and the verifier as `axess::device_key::key_proof`.

### Feature gating

```toml
# axess-core, passed through by the facade. Not in `default`.
device-keys = ["device", "axess-factors/key-proof"]

# axess-factors. Verifies through `jsonwebtoken`, like the DPoP verifier.
key-proof = ["jwt", "dep:p256", "dep:sha2", "dep:subtle"]
```

A build that turns it on also picks a verification backend, `jwt-aws-lc` or
`jwt-rust-crypto`, as every user of `jwt` does. `p256` checks that the
coordinates of a key a proof carries are a point of the curve, and is what
the software key of the test fixtures signs with. With the feature on and
the in-memory stores, the whole protocol runs in one process with no
database, cache or network call.

A deployment that holds no bound session and no keyed device sees no change
from the feature being off, or from it being on with no key service given to
the layer. A row that is bound to a key is another matter: a build without
the feature, and a layer given no key service, cannot check the key and run
that row's requests as a guest (see
[Failure and downgrade](#failure-and-downgrade)).

The stored values are compiled whatever the features: the `Key` variant of
`DeviceBinding`, the `key_binding` field of `SessionData`, `KeyThumbprint`,
`P256PublicKey`, `KeyChallenge`, `SessionKeyBinding`. A device row and a
session row therefore have one shape in every build.

### The verifier

`axess_factors::key_proof` reads no clock and no store.

- `parse_key_proof` checks size, structure, `alg` and `typ`, refuses a
  header that carries `crit`, and yields a `ParsedKeyProof` whose challenge
  is still the sender's claim.
- `ParsedKeyProof::answers` compares that claim with a challenge in constant
  time, and `ParsedKeyProof::verify` checks the target (`ProofTarget`) and
  the signature under a `ProofKey`: the key the proof carries for a
  registration, the stored key for every later proof.
- `verify_key_proof` does all of it, challenge first.
- `ParsedKeyProof::verify_request` checks a proof that rides on an ordinary
  request against a `RequestProofCheck`: the target, an `iat` no more than
  `max_age` before and `max_ahead` after the time the caller hands
  it, a `jti`, and the signature under the stored key. The caller records
  the `jti`.
- `KeyProofError` has one variant per check and carries none of the
  sender's text.
- `key_proof::browser_draft` holds the browser draft's wire names, and
  `SoftwareKey` in `key_proof::testing` signs both shapes for tests.

### The service

```rust,ignore
let keys = DeviceKeyService::new(devices.clone(), DeviceKeyConfig::new("https://app.example"))?
    .with_event_sink(audit_sink);

let app = Router::new()
    .merge(application_routes)
    .merge(keys.router())
    .layer(
        SessionLayer::new(store, signing_key, registry, audit)
            .with_device_resolver(LifecycleDeviceResolver::new(extractor, lifecycle, SystemClock))
            .with_device_keys(keys),
    );
```

`DeviceKeyService::new` refuses a configuration `DeviceKeyConfig::validate`
refuses. `DeviceKeyService::router` supplies the two routes; they read what
they need from the request, where the layer put it, and answer 404 when the
layer enforces no keys. A rate limit that should cover them sits outside the
session layer; without one, a caller with no credentials costs one
device-row read per refresh attempt, past any cache.

Keys are registered on, and sessions bound to, the device the resolver
proves. A layer given a key service and no device resolver proves no device,
so it offers no key and binds no session, and under `Require` it ends every
session at the end of its registration window; it logs that at `error` when
it is built.

Registration is not a public operation. The layer's registration path is its
one caller, because only the layer can check that the offer was made to this
session for this device. The public operations:

- `DeviceKeyService::prove_device_key` verifies a proof over the current
  challenge under the stored key and replaces the challenge, as one
  compare-and-swap on the device's bindings. The challenge is judged before
  the signature.
- `DeviceKeyService::prove_key_of_secret_holder` is the same for a caller
  that presented a secret of the device, such as a refresh token. It reads
  the device row first, so a device with no key is `Keyless` whatever came
  with the secret. For a device that has a key the signature is judged
  before the challenge, and a refusal of the proof is the theft signal the
  caller acts on.
- `DeviceKeyService::prove_request` verifies a proof that rides on an
  ordinary request for a device of a tenant, records its `jti`, and answers
  the key the signature held under; a caller that serves a bound session
  compares it with the binding (`SessionKeyBinding::is_met_by`).
- `DeviceKeyService::current_key_challenge`,
  `DeviceKeyService::key_thumbprint` and
  `DeviceKeyService::forget_device_key`.

`DeviceKeyError` says why an operation refused: the proof itself (`Proof`),
a device that already has a key (`Registered`), a device of another user
(`NotOwner`), a device with no key (`Keyless`), a device that is revoked or
gone (`Ended`), a stale challenge with the challenge to sign (`Stale`), a
row that kept changing (`Contended`), a request proof presented before
(`Replayed`), a replay store that could not answer (`ReplayStore`), a
request proof where none are taken (`RequestProofsOff`), or the device store
(`Store`).

A resolver of the deployment's own builds its `DeviceRequest` with
`keys: KeyEnforcement::of(&parts)`, which reads what the layer left in the
request. The field is required and `KeyEnforcement::of` is its one
constructor outside tests, so `DeviceLifecycleService::resolve_or_keep` and
`resolve_proven` hold a keyed device to its key under a layer that enforces
keys, whichever resolver asks. `KeyCheck`, the value the layer leaves, is
made only by the layer; `LifecycleDeviceResolver` reads it the same way.

### Configuration and defaults

`DeviceKeyConfig::new` takes the origin; everything else has a default.

| Setting | Default | Accepted | Meaning |
|---|---|---|---|
| origin | none, required | `https` and a host with no path; `http` only from `DeviceKeyConfig::insecure_for_local_development` | the scheme and host an app's proof must name in `htu`, and the origin of the session description; a browser's proof names no origin and is bound by its challenge. `DeviceKeyConfig::with_origins` lists one per host and holds each request to its host's, and `DeviceKeyConfig::with_origin_fn` answers it from the request's head (`RequestHead`); a request to a host with no origin is answered 404 at both paths |
| `DeviceKeyConfig::with_policy` | `Prefer` | | see [Failure and downgrade](#failure-and-downgrade) |
| `DeviceKeyConfig::with_proof_ttl` | 10 minutes | 1 minute to 1 hour | the proof cookie's `Max-Age` |
| `DeviceKeyConfig::with_acceptance_grace` | 30 seconds | 0 to 5 minutes | how long past its expiry the server still accepts a proof cookie |
| `DeviceKeyConfig::with_challenge_ttl` | 20 minutes | more than the proof lifetime plus the grace, at most 24 hours | the oldest challenge a proof may answer; below the lower bound every routine refresh would take two round trips |
| `DeviceKeyConfig::with_registration_window` | 2 minutes | 10 seconds to 15 minutes | how long after a login (`signed_in_at`) an offer stands and a registration or a binding is accepted, and how long `Require` serves an unbound session, in a step-up too |
| `DeviceKeyConfig::with_registration_path` | `/axess/device-key` | an absolute path of visible ASCII with no `?`, `#`, double quote or backslash | a route of the router; sent to the browser inside a quoted string |
| `DeviceKeyConfig::with_refresh_path` | `/axess/device-key/refresh` | another such path | a route of the router |
| `DeviceKeyConfig::with_proof_cookie_name` | `__Host-axess_device_proof` | a cookie name; `__Host-` needs `Secure` | the device suffix is appended |

The algorithm is not an option: `ES256`, and a proof that names another is
refused. Both proof shapes are accepted on both paths.

Request proofs are a setting of the service, not of the configuration:
`DeviceKeyService::with_request_proofs(replay, max_age)`, with `max_age` from
one second to five minutes. There is no default; without the call no request
proof is read.

### What the two paths answer

| Case | Registration path | Refresh path |
|---|---|---|
| key registered, or proof accepted | 200, the session description, the first challenge, and the proof cookie unless the key is an app's and request proofs are taken | 200, the proof cookie, the next challenge |
| no proof | 403 | the challenge status with the current challenge |
| a proof for an offer that does not hold, or for a challenge that is not the current one | 403 | the challenge status with the current challenge |
| a value that is no proof in structure, or a signature that does not verify | 403 | 400, with no challenge |
| a session that may not register (not signed in, outside its window, without a device), a device another user owns, a device that already has a key | 403 | does not apply |
| no identifier header, or one that names no device | does not apply | 400, with no challenge |
| device revoked or gone | 403 | the session-ended answer, and the proof cookie expired |
| device without a key | registers it | the session-ended answer, and the proof cookie expired |
| the device store cannot answer | 503; nothing is ended | 503; nothing is ended |
| the row kept changing under the write | 503; nothing is ended | 503; nothing is ended |
| the layer enforces no keys (no service, or `Off`), or the request's host has no origin | 404 | 404 |

Every answer is marked `Cache-Control: no-store`,
`Cross-Origin-Resource-Policy: same-origin` and `X-Frame-Options: DENY` (the
draft recommends that the refresh endpoint refuse to be embedded, since its
timing says whether a session exists), and none says which check failed. At
the registration path a refusal stays 403: the draft has a browser that
holds no session yet end the registration attempt on a 403, with no retry.
The challenge is handed out in the browser draft's header and in
`DPoP-Nonce`, so either front-end reads it.

### Audit rows

| Variant | Wire string | Status | Written when |
|---|---|---|---|
| `DeviceKeyRegistered` | `device_key_registered` | `Success`, or `Failure` with the reason (`proof_refused`, `not_owner`, `already_registered`) | a device takes a key, or a registration whose offer held is refused for its proof, for the device's owner or for a key the device already has |
| `SessionKeyBound` | `session_key_bound` | `Success`, with the administrator as actor for an impersonated session | the layer binds a session, at a registration or on a request that proved by key a device the session's user owns (the administrator, under impersonation); written once the write that stores the binding has landed, and not at all when it did not |
| `DeviceKeyProofRefused` | `device_key_proof_refused` | `Suspicious` | at the refresh path, the current challenge came back with a signature that is not the key's or in a proof made for another request; at a refresh of a refresh token, a keyed device's token came with no proof or with one that is not the key's; on an ordinary request, a request proof by the key came a second time, or a request that held a session bound to the device carried a request proof that is not the key's |

These three are written through the key service's `DeviceEventSink`,
also when the session layer causes them. `DeviceKeyProofRefused` is the one
`Suspicious` row the library writes itself. At the two key paths a
structurally broken proof writes no row: anyone can post bytes, and a row
per attempt would be an audit log anyone can fill. For the same reason a
request proof by another key beside nothing but a device identifier writes
none. When a refresh token builds a bound session, no `SessionKeyBound` row is
written.

Ending a session under `Require` writes no device-key row. The session
layer makes that ending by itself and records it as it records its other
endings, through the `SessionEndAudit` every `SessionLayer` constructor
takes, before the row is removed. With `AuthnService::session_end_audit`,
the record is a `SessionInvalidated` row with the status `Success` and
`key_binding_required` as its reason; it names the user, the tenant and the
session, and the administrator as actor for an impersonation (see
[Audit events](../production/audit-events.md)). A sink
that fails leaves the session stored and refused, and of several requests
that carry its cookie one records it.

## Stores

### Device stores

| Store | Schema or key change | Where the key contract runs |
|---|---|---|
| `MemoryDeviceStore` | none; it keeps the value | its unit tests |
| `SqliteDeviceStore` | none: no column, no index, no statement to run | its unit tests |
| `PostgresDeviceStore` | none | its suite on a live server |
| `MysqlDeviceStore` | none | its suite on a live server |
| `ValkeyDeviceStore` | none: no new key, the same row blob, the same compare-and-swap script | its suite on a live server |
| `ValkeyDeviceStore` on a cluster | none: the scripts address the keys they addressed before, under the one hash slot the store already asks for | its suite on a live cluster |
| `CachedDeviceStore` | none | forwards `load_fresh` and `replace_bindings` to the store it wraps |

The key lives in the `bindings` list every device store already persists as
one encoded value, so the new variant is a new value in an existing column.
Nothing looks a device up by its key (the refresh names the device), so no
index or side table is needed; `device_bindings_refresh` is untouched.

No trait method is added, and one existing method must be implemented:
`DeviceStore::replace_bindings` has no provided body, because a
load followed by a save lets two writers both win. It is what makes a
challenge single-use, lets a device take exactly one key and keeps a revoked
row from gaining anything, so a store of the deployment's own implements it as one
conditional write: compare the whole list, write only on a match, never
write a `Revoked` row.

### Session stores

| Store | Schema or key change |
|---|---|
| `MemorySessionStore` | none |
| `SqliteSessionStore` | none |
| `PostgresSessionStore` | none |
| `MysqlSessionStore` | none |
| `ValkeySessionStore` | none |
| `ValkeySessionStore` on a cluster | none: one key per session, as before |

`key_binding` is a field of `SessionData`, which the encrypted stores write
as MessagePack with field names inside the sealed blob and the in-memory
store keeps as a value. It is skipped when empty. `SESSION_DATA_VERSION`
becomes 3. No row an earlier release wrote is read: the upgrade signs every
session out once, and a row below version 3 is not served, so there is no
step from 2 to 3 to describe. No store method is added. `cycle` and `cycle_if_revision` carry the binding because they carry
the row, and `update_if_revision` is the compare-and-swap the registration
uses.

### Refresh-token stores

None. The token's device decides whether a proof is required, so an adopter's
`RefreshTokenStore` and its table do not change, and neither does the token
store of the SQLite example. The token has no thumbprint column, because a store that did not persist
the column would turn every bound token into an unbound one without a sign.

### Sessions and devices that exist at the upgrade

- **Sessions** from an earlier release are not carried over: the upgrade
  signs every one of them out once, and each user signs in again. That
  login makes the offer or, on a device that has a key by then, binds the
  new session. Switching `Require` on signs
  out every session that is not bound: a session signed in under 0.20.0
  before the switch is older than the window at its first request after
  it, unless its login was in the last few minutes, and it ends there.
- **Devices** read as keyless and are proven by their token as before. Each
  is offered a key at its user's next login and keeps its row and its trust
  level when it takes one.
- There is no backfill, no statement to run and no job to schedule.

### Upgrade and rollback

All nodes are upgraded together. A 0.19.0 node names a session by its id and
a 0.20.0 node by its key, so neither finds a session row the other stored.
Device rows are shared, and a 0.19.0 node cannot decode a `bindings` list
that holds the `Key` variant. So 0.20.0 is deployed to every node before any
layer is given a key service, and no offer is made while a 0.19.0 node still
reads the device store.

Every layer that shares the session store is then given the key service, or
one whose policy is `Off`. A layer that was given none, and a build
without the `device-keys` feature, cannot check a key: it runs a request
whose row is bound as a guest and leaves the row for a layer that can check
it, logging the first such request at `error` with what is missing. Every
refresh of a refresh token is likewise given the device store and the key
service; one given the store alone refuses a keyed device's token.

Rolling back to 0.19.0 after keys exist: a 0.19.0 node finds no session row
this release stored, so every session, bound or not, is signed out again.
Device rows with a key do not decode. Before such a rollback, set the policy
to `Off` and remove the keys with the maintenance call (`forget_device_key`
over each tenant's devices).

## Failure and downgrade

What an attacker gains by removing the binding from the exchange:

| The attacker | Holding | Gains |
|---|---|---|
| sends a bound session's cookie without a proof cookie | the session cookie | nothing: the request runs as a guest and the row is untouched |
| sends it with an expired or altered proof cookie | both cookies, late | nothing |
| sends both in time | both cookies, inside the window | the session until the proof cookie expires, plus the grace |
| asks the refresh path for a challenge and answers it | cookies, no key | nothing; a `Suspicious` row is written |
| replays a captured proof | an old proof | nothing: its challenge is gone |
| replays a captured request proof | a proof the app already sent | nothing: its `jti` is recorded |
| sends a request proof the app made and never sent | cookies and one unused proof | that one request, with its method and URL, until `max_age` after the proof's `iat` |
| presents the device token of a keyed device | the device cookie | a recognised device at most, never a proven one |
| registers a key of their own on the victim's device | cookies copied after the response that carried the offer | nothing: no later response carries an offer |
| removes the registration header in transit | a position inside the TLS connection: the device itself, or a proxy the operator runs | an unbound session under `Prefer`, a session that ends at the window under `Require` |
| presents a keyed device's refresh token to a refresh given the key service | the token | nothing, and the family is revoked |
| presents it to a refresh given the device store and no key service | the token | nothing: the refresh is refused and nothing is rotated |
| sends a bound session's cookie to another service on the same session store that was given no key service | the session cookie | nothing: the request runs as a guest |
| withholds or blocks refreshes | the network | a signed-out user; no access |

The policies:

| | `Off` | `Prefer` (default) | `Require` |
|---|---|---|---|
| Offers a key | no | yes | yes |
| Answers the two paths | no (404) | yes | yes |
| A bound session without proof | served, as a bearer session | not served | not served |
| A keyed device with only its token | proven by its token | not proven | not proven |
| A signed-in session that is not bound, in a step-up too | served | served | served for `registration_window` from its login, then ended and recorded through the layer's audit sink |
| A device without a key | proven by token | proven by token | proven by token; never exempt from the lockout when the service is built with `with_key_proven_device_store` |

`Off` is the operator's switch and it is total: every session is a bearer
session and every device is proven by its token, bound or keyed or not, and
what is stored stays in place so that switching back resumes where it
stopped. It exists because the browser protocol ships in one engine and is
still changing; a regression there must be answerable in configuration. It
is not reachable by a client.

A layer that was given no key service is not `Off`. It offers nothing,
answers neither path and proves a device by its token, as `Off` does, but it
runs a request whose row is bound as a guest: nothing told it to serve bound
rows without proof, so a service that shares the session store and was not
given the key service is no way around the key. It logs the first such
request at `error`, naming what is missing, and leaves the row for a layer
that can check it. A build without the `device-keys` feature does the same.

`Prefer` never lets a client choose for a session that is already bound.
What it leaves open is the session that never bound, which is what every
session is without the feature.

Operational failures:

- **The device store is down.** Refreshes are answered 503 and nothing is
  ended, but once the proof cookies in circulation run out, bound sessions
  run as guests until the store is back. A request proof reads the store on
  every request, so a session served by request proofs runs as a guest from
  the first request of the outage. Without device keys a device-store outage
  degrades device tracking and does not touch authentication. There is no
  setting that serves a bound session without proof during an outage,
  because that setting would be the downgrade.
- **The replay store is down, or full.** Request proofs are not accepted,
  and the requests that relied on them run as a guest, until it answers
  again. A proof cookie is not affected.
- **The signing key is rotated.** Proof cookies verify under the previous
  key for the rotation window, like session cookies.
- **The signing key is replaced without a window.** Every proof cookie fails
  once. Each browser refreshes, which needs only its device key, and is
  proven again.
- **The device loses its key** (a cleared TPM, a profile moved to another
  machine). The cookies arrive without a proof, the bound sessions are not
  served, and the user signs in to a new `Unknown` device. Trust earned on
  the old row is not carried over; that is the point of the key.

## Test plan

The tests named below are in the tree. They run on
a `MockClock` and a seeded `MockRng`, against a software key: a P-256 key
drawn from a seed that signs both proof shapes, shipped behind the `testing`
feature of `axess-factors` (`key_proof::testing::SoftwareKey`).

**The verifier** (`axess-factors/src/key_proof/tests.rs`)

- A test per refusal: `each_structural_fault_is_refused_by_name`,
  `the_size_bound_is_inclusive`, `every_algorithm_but_es256_is_refused`,
  `the_typ_must_be_the_shapes_own`, `a_header_with_crit_is_refused`,
  `a_key_that_is_not_a_p256_public_key_is_refused`,
  `a_point_off_the_curve_is_refused`,
  `a_proof_for_another_request_is_refused`,
  `a_proof_for_another_challenge_or_none_is_refused_before_its_signature`
  and `an_altered_payload_or_signature_fails_the_signature_check`.
- `the_stored_key_is_used_when_the_proof_carries_another`.
- Request proofs: `a_request_proof_verifies_and_hands_back_its_jti`,
  `a_request_proofs_iat_window_is_inclusive` and
  `a_request_proof_is_refused_for_each_fault`.
- `no_refusal_carries_the_senders_text`.
- The thumbprint, in `axess-factors/src/jwk_p256.rs`:
  `the_thumbprint_is_the_rfc_7638_digest_for_every_key`, over a sweep of
  coordinates.
- Each constant of `key_proof::browser_draft` is pinned by a test in that
  module.

**The proof cookie and the offer** (`axess-core/src/device_key/cookie/`)

- `a_proof_ends_exactly_at_its_expiry_plus_the_grace`,
  `changing_any_field_of_a_proof_makes_it_fail`,
  `a_rotation_reads_the_previous_keys_proofs`,
  `the_cookie_name_gives_each_device_a_slot_of_its_own`,
  `at_most_the_bound_of_proof_cookies_is_read`,
  `an_offer_holds_for_its_session_tenant_and_device_until_it_expires` and
  `the_two_domains_do_not_verify_each_others_tags`.
- Property tests: `a_proof_is_accepted_exactly_inside_its_window`,
  `a_changed_proof_never_proves_another_key`,
  `an_offer_holds_only_for_what_it_was_made_for` and
  `arbitrary_text_proves_nothing`.

**The key service** (`axess-core/src/device_key/service/`)

- Registration:
  `a_registration_adds_the_key_and_hands_out_the_first_challenge`,
  `a_registration_is_refused_for_a_wrong_offer_a_second_key_or_another_owner`
  and `a_registration_claims_an_unowned_device_for_its_user`.
- Proofs: `a_proof_rotates_the_challenge_and_is_not_accepted_twice`,
  `the_current_challenge_signed_by_another_key_is_refused_and_recorded`,
  `a_challenge_ends_exactly_at_its_lifetime` and
  `a_revoked_or_missing_device_registers_and_proves_nothing`.
- A caller that holds a secret of the device:
  `a_secret_holder_is_judged_by_signature_before_challenge` and
  `a_keyless_device_is_keyless_whatever_its_secret_holder_sends`.
- Request proofs:
  `request_proofs_take_a_lifetime_within_its_bounds_and_a_store_that_records`,
  `a_request_proof_stands_once_for_the_devices_key`,
  `a_revocation_on_another_node_ends_request_proofs_at_once` and
  `a_wrong_key_under_a_bound_session_is_recorded`.
- A property test over sequences of refreshes, stale proofs, replays,
  foreign keys and clock steps:
  `a_proof_is_accepted_exactly_once_and_only_over_the_current_challenge`.
- Races, against a store double that loses compare-and-swaps and lets a
  rival at the row between the read and the write (`tests/contention.rs`):
  `a_lost_swap_is_made_again_on_the_fresh_row`,
  `a_row_that_keeps_changing_is_contended`,
  `of_two_registrations_one_key_is_left`,
  `of_two_refreshes_with_one_proof_one_is_accepted` and
  `a_refresh_that_races_a_revocation_proves_nothing`.

**The layer, end to end on the in-memory stores**
(`axess-core/tests/device_keys.rs`)

- What a bound session is served for:
  `a_bound_session_is_served_only_with_its_proof` (both proof shapes),
  `a_proof_cookie_ends_at_its_lifetime_and_a_refresh_restores_it` and
  `a_bound_request_without_the_device_token_is_still_key_bound`.
- The two paths: `a_registration_needs_its_offer_and_its_window`,
  `the_registration_offer_is_delivered_once`,
  `the_refresh_path_hands_out_challenges_and_accepts_each_once`,
  `revoking_the_device_ends_its_proofs`,
  `the_refresh_path_answers_alike_for_a_device_gone_revoked_or_keyless`,
  `a_failing_store_or_a_contended_row_is_answered_503`,
  `the_csrf_exemption_covers_the_two_key_paths_and_nothing_else` and
  `each_host_holds_proofs_to_its_own_origin` (two tenants on two hosts, both
  paths, both proof shapes).
- The identifier header, in the layer's unit tests
  (`axess-core/src/session/layer/device_keys/paths/tests.rs`):
  `the_identifier_names_one_tenant_and_one_device` and the property tests
  `arbitrary_text_without_a_dot_names_no_device` and
  `arbitrary_text_never_panics`. The property that text names a device only as a
  tenant id and a device id is stated by the fuzz target
  `device_identifier_header` (see Fuzzing below) and by no deterministic
  test.
- The registration window, in the same file:
  `the_registration_window_runs_from_the_login`,
  `a_session_in_a_step_up_registers_as_the_signed_in_one`,
  `the_offer_expires_with_the_logins_window` and
  `a_step_up_carries_no_offer`.
- Sign-in: `a_sign_in_on_a_proven_key_is_bound_at_once` and
  `a_sign_in_is_not_bound_to_another_accounts_device`.
- A binding holds for the person it was made for:
  `a_second_person_signing_in_on_a_bound_session_is_not_key_bound`,
  `a_new_login_of_the_owner_unbinds_until_it_completes_and_binds_again`,
  `an_impersonation_keeps_the_administrators_binding_within_and_across_tenants`
  and `require_holds_a_second_person_to_their_own_window`; in the layer's
  unit tests, `a_binding_made_for_another_person_does_not_stop_a_bind`;
  and over every kind of state, the property
  `a_binding_is_in_force_exactly_for_the_signed_in_person_at_the_browser`
  (`axess-core/src/session/data/device/tests.rs`).
- Policies and layers: `require_ends_an_unbound_session_after_the_window`,
  `require_ends_an_unbound_session_in_a_step_up_after_the_window`,
  `a_finished_step_up_does_not_restart_the_window`,
  `a_bound_session_in_a_step_up_outlives_the_window`,
  `off_offers_nothing_and_answers_neither_path`,
  `off_serves_a_bound_session_and_proves_a_keyed_device_by_its_token`,
  `prefer_leaves_a_client_without_a_key_as_it_was` and
  `a_layer_without_the_key_service_does_not_serve_a_bound_session`.
- Refresh tokens: `a_refresh_token_of_a_keyed_device_needs_the_key`,
  `a_refresh_without_the_key_service_refuses_a_keyed_devices_token` and
  `a_keyless_devices_token_refreshes_whatever_comes_with_it`.
- Request proofs: `an_app_proves_its_key_on_every_request`,
  `an_app_is_recognised_by_its_request_proof_at_the_next_sign_in` and
  `a_request_proof_counts_for_nothing_where_none_are_taken`.
- Metrics: `the_layer_reports_to_the_device_key_concern`.
- The ending `Require` makes, through the layer's audit sink:
  `two_concurrent_requests_end_an_unbound_session_once`,
  `the_ending_of_an_impersonation_names_the_administrator` and
  `a_failing_audit_sink_keeps_the_unbound_session`.
- The window counted from the login at the other readers:
  `a_step_up_is_offered_no_registration` and
  `a_key_proven_past_the_window_binds_nothing`; a step-up over two requests
  keeps the device its key proves, and the lockout exemption with it:
  `a_step_up_over_two_requests_keeps_the_key_proven_device`.
- The `SessionKeyBound` row follows the write:
  `the_bound_row_follows_the_write_that_stores_the_binding` and
  `a_binding_whose_write_fails_has_no_row`.

**What the feature touches elsewhere**

- Trust writes and the rule for a keyed device
  (`axess-core/src/device/lifecycle/tests/trust.rs`):
  `a_login_writes_no_trust_onto_another_accounts_device`,
  `a_trust_write_claims_an_unowned_device_for_its_user` and
  `a_keyed_device_is_proven_only_by_its_own_key_for_its_own_tenant`.
- The lockout exemption, at the check itself
  (`axess-core/src/authn/service/known_device.rs`):
  `a_token_proven_device_is_known_only_where_keys_are_not_required`.
- The three-way merge (`axess-core/src/session/data/merge/tests.rs`):
  `a_binding_is_never_dropped_or_restored_by_a_request_that_did_not_change_it`,
  `the_binding_follows_the_field_rule_in_every_combination`,
  `a_sign_out_that_races_a_bind_leaves_no_binding`,
  `another_persons_sign_in_that_races_a_bind_leaves_no_binding` and
  `a_step_up_that_races_a_registration_keeps_the_binding`.
- The store kit carries the binding's owner through a rotation:
  `a_store_that_rebuilds_the_binding_for_another_person_is_caught`.
- A session row from before the field, planted as raw bytes and refused
  (`axess-core/src/session/layer/lifecycle/planted_row_tests.rs`):
  `a_row_below_the_version_under_the_key_is_counted_and_left_as_it_lies`.
- The Cedar attribute: `the_standard_context_carries_key_bound_only_when_asked`.
- The replay stores: `a_jti_is_recorded_once_until_its_ttl_ends` and
  `a_full_store_refuses_as_a_fault_and_forgets_nothing_live` for the store in
  the process, `only_a_server_that_never_evicts_passes_the_policy_check` for
  the Valkey store, and
  `the_record_names_the_verifier_and_the_key_and_lasts_the_window` for the
  DPoP verifier.
- What does not compile (`axess/tests/ui/`): a `DeviceStore` without
  `replace_bindings` (`device_store_without_replace_bindings.rs`) and a
  `Refresh` that says nothing about the token's device
  (`refresh_without_device_choice.rs`).
- The example (`examples/sqlite/tests/device_keys.rs`):
  `a_copied_session_cookie_without_the_key_opens_nothing` and
  `a_browser_without_a_key_store_still_signs_in`.

**Store contract checks**

- Device stores (`axess-core/src/device/store/key_contract.rs`), run in the
  unit tests of the memory and SQLite stores and in the live suites of
  Postgres, MySQL, Valkey and a Valkey cluster. `a_key_binding_round_trips`:
  a `Key` entry reads back equal through `load` and `load_fresh`.
  `a_challenge_is_replaced_by_one_compare_and_swap`: a replacement through
  `replace_bindings` writes on a match and conflicts on a list that moved,
  of two replacements from one read exactly one writes, a `Revoked` row
  takes nothing and a missing one says so.
- Session stores: `assert_key_binding_contract`, which
  `assert_update_if_revision_contract` runs. A bound row round-trips;
  `cycle` and `cycle_if_revision` deliver the binding under the new id and
  leave nothing under the old; `update_if_revision` on a stale revision
  leaves the stored binding as it was.

**The invariants, end to end** (`axess-core/tests/device_keys.rs`). One
test is named for each invariant of [The model](#the-model), `invariant_1`
to `invariant_8`: no private key and nothing stored that mints a proof; a
proof cookie minted only for a valid signature; a challenge accepted once; a
keyed device never proven by its token alone; a bound session served only
with its key and never unbound; a key registered only against its offer;
only a request proof reading the client's clock; and two worlds built alike
on one clock handing out the same bytes. The same file holds a step-up and
an impersonation on a bound session, a key registered under impersonation
landing on the administrator's device, the lockout exemption through a
login, the family revocation reaching the device cascade and a signing-key
rotation through the layer.

**Fuzzing.** Four targets. `key_proof_parse`: the parser of the proof
against an independent statement of what parses, and every proof that
parses through the three verifications (under the key it carries, under a
stored key, as a request proof). `device_proof_cookie` and
`device_key_offer`: arbitrary text proves nothing and is no offer, a genuine
value stands exactly until it ends, and with one byte changed it does not.
`device_identifier_header`: the reader of the identifier header against an
independent statement of it. The last three reach parsers that are private
to the crate through `axess_core::testing::device_key_parsers`.

**One thing no deterministic test covers** is a real browser. A walk with a
browser that implements the draft, against the SQLite example built with
`device-keys`, is where the wire details listed below are confirmed. It has
not been made.

## The browser front-end and the draft

The browser front-end's wire details were compared, detail by detail, with
the W3C editor's draft of Device Bound Session Credentials dated 9 November
2026, which calls itself an early draft. No browser has run against the
implementation. The app front-end follows RFC 9449 and RFC 7638, as
`dpop_verify.rs` implements them, and does not depend on the draft.

What the draft and the code agree on:

- The header names: `Secure-Session-Registration`,
  `Secure-Session-Challenge`, `Secure-Session-Response` and
  `Sec-Secure-Session-Id`.
- The registration header: a structured-field list of algorithms with
  `path` and `challenge` parameters. The challenge header: the challenge as
  a string with an `id` parameter.
- The proof: a JWS with the `typ` `dbsc+jwt`, the challenge in `jti`, the
  public key as a JWK in the `jwk` header, and no audience claim, so the
  browser's proof is bound to its endpoint by the challenge alone.
- The JSON a registration answers with: `session_identifier`,
  `refresh_url`, `scope` with `origin` and `include_site`, and `credentials`
  naming the cookie with the attributes it is set with.
- The refresh exchange: the identifier header, 403 with a challenge for a
  proof still to be made, a fresh cookie and the next challenge for one that
  stands, and a registration answer that carries the first challenge.
- Ending a session: a JSON body with `continue` set to false.

What the comparison changed in the code:

- **The two request headers are read quoted or bare.** The draft defines
  `Secure-Session-Response` and `Sec-Secure-Session-Id` as structured-field
  strings and shows them in double quotes, while its own algorithm appends
  the bare value. A browser that quoted them would have registered nothing
  and refreshed nothing. `browser_draft::request_header_string` reads both
  forms and ignores parameters.
- **A final refusal at the refresh path is 400, not 403.** The draft gives
  403 one meaning there (sign again with the cached challenge) and states no
  limit on the repeats; any other status from 400 to 499 except 407 and 429
  ends the browser's session (`REFRESH_REFUSED_STATUS`).
- **The two paths hold only characters a quoted string carries unescaped.**
  The registration path is sent inside a structured-field string, so a
  configured path with a double quote, a backslash or a byte outside visible
  ASCII is refused when the configuration is validated.
- **The answers of the two paths refuse to be embedded**, as the draft
  recommends for the refresh endpoint
  (`Cross-Origin-Resource-Policy: same-origin`, `X-Frame-Options: DENY`).

Parts of the draft the front-end does not use, each optional there:

- The `authorization` parameter of the registration header and the claim a
  browser copies it into. A registration is tied to its sign-in by the
  session cookie and the offer's MAC.
- Sessions shared with another site (`provider_key`, `provider_session_id`,
  `provider_url`) and the `/.well-known/device-bound-sessions` document,
  which a browser fetches only for a session whose scope includes the site.
  The description always says `include_site` false.
- `allowed_refresh_initiators`. Without it the draft lets only a request
  whose origin is the session's own start a refresh, so a request started
  from another origin after the proof cookie ran out arrives without it and
  runs as a guest until a same-origin request has refreshed.
- `Secure-Session-Skipped`, the request header a browser adds when it sends
  a request without the bound cookie on purpose (the refresh endpoint was
  unreachable, answered an error, or the browser's quota was spent). It is
  not read, so such a request is told apart from a copied session cookie by
  nothing: both run as a guest and count as `bound_session_unproven`.
- `Clear-Site-Data`. The draft has a browser delete its sessions and keys
  when a site clears its storage or its cookies. An application that sends
  that header leaves a device row whose key the browser no longer holds;
  the device's token then proves nothing, and the browser's next sign-in is
  given a new device and offered a key for it.

The draft leaves the following to the browser; where the design depends on an
item, the item says so:

- whether a registration outlives a sign-in, which keying the device rather
  than the session assumes;
- what a browser does with a registration whose key it can no longer use;
- how often a browser registers or refreshes before its own quota stops it:
  the draft asks for backoff and names no number, so a request without the
  bound cookie can arrive at any time;
- whether a shipping browser writes the two request headers quoted or bare,
  which reading both forms makes immaterial;
- which browsers ship it, and on which platforms.

Not compared, because the texts were not at hand: the structured-fields
specification the draft's header syntax rests on (the rule that a double
quote and a backslash are escaped inside a string is stated from that
specification's known text), the cookie specification's rules for when a
cookie is set and attached, and the Fetch rules for the credentials mode and
the origin of the browser's own registration and refresh requests.

Where the wire format lives: the header and parameter names, the status
codes, the body that ends a session, the `typ`, the challenge claim, the
absent audience claim, the place of the key and the member names of the
session description are constants in
`axess_factors::key_proof::browser_draft`; the two response header values
(`registration_header_value`, `challenge_header_value`) and the reading of
the two request header values (`request_header_string`) are functions
there, each pinned by a test in that module. Three things are written
outside it: the `<tenant>.<device>` identifier and the composition of the
session description (its members, `include_site` set to false, the
attributes of the credential), in the session layer
(`axess-core/src/session/layer/device_keys.rs`), and which claims the
verifier compares, in `axess-factors/src/key_proof.rs`.

The walk with a
browser that implements the draft, against the SQLite example built with
`device-keys`, is not done: the deterministic tests hold the server to the
draft's text as compared, not to what a browser sends.

## Decisions

The twelve questions this design raised were decided as it recommended:

1. **The key lives on the device row**, not on each session. If a browser
   turns out to end a registration at sign-out, the same design registers
   again at each sign-in and loses only the binding from the first request.
2. **Built now**, not when the draft settles: only the browser front-end
   depends on the draft.
3. **The feature stays out of `default`**; a layer given a key service runs
   `Prefer`; `Require` is chosen by name and never by a profile.
4. **`ES256` only.**
5. **A refresh token of a keyed device presented without the key revokes
   its family** and runs the cascade, at a refresh that was given the key
   service.
6. **A wrong signature at the refresh path revokes nothing** and writes a
   `Suspicious` row: the identifier a caller presents there is no secret.
7. **Challenges expire**, after 20 minutes by default.
8. **The window is 10 minutes and 30 seconds of grace**, and 5 minutes
   and the same grace under the strict profile.
9. **`Require` ends sessions from before the upgrade**; the migration page
   says to run `Prefer` first.
10. **A proof on every request, for apps, belongs to the same release**,
    with a replay store every node shares.
11. **A device row keeps one owner.** A device's owner is what scopes its
    trust level, the lockout exemption and its revocation, and a row shared
    by two accounts would let one account's trust ceremony or revocation
    act on the other. A browser profile used by several accounts therefore
    holds one device per account, each with its own key, side by side. The
    device cookie holds one entry per device, and the resolver chooses the
    first presented device its user may use. A sign-in binds a session, and
    a trust write lands, only on a device the signed-in user owns.
12. **A device-store outage signs bound sessions out** once their proofs
    run out, and that is documented, not softened.

## What is built and what is not

Built, with tests on the in-memory stores and SQLite:

- the proof verifier, both shapes, and the software key for tests;
- the `Key` variant, its value types and the device-store key contract, run
  for memory and SQLite and in the live suites of Postgres, MySQL, Valkey
  and a Valkey cluster, with `DeviceStore::replace_bindings` a required
  method;
- the key service: registration through the layer's path, prove and forget,
  with its audit rows;
- how a device was proven, and the rule for a keyed device, which every
  resolver is held to through `DeviceRequest::keys`;
- the session field, version 3 and the merge;
- the proof cookie and the offer, with the previous-key fallback, and the
  offer on one response per login;
- enforcement in the session layer under the three policies, and the refusal
  of a bound row by a layer that cannot check its key;
- binding at a sign-in only to a device the signed-in user owns, and trust
  writes that take a `UserDevice`;
- the two paths, in the browser shape and the app shape;
- refresh tokens held to the key, with the family revocation, and the
  required choice about a token's device (`Refresh::device_store` or
  `Refresh::without_device_check`);
- the lockout exempting only a key-proven device where the service asks
  for it, and the `key_bound` Cedar attribute;
- property tests of the proof cookie, the offer and the identifier header,
  a test of the merge rule of the binding in every combination, and the
  session-store contract check of a bound row
  (`assert_key_binding_contract`);
- a property test over sequences of refreshes, stale proofs, replays,
  foreign keys and clock steps, and tests of the three races above the
  store contract;
- property tests of the proof cookie's and the offer's parsers, held to the
  property that arbitrary text proves nothing;
- the metrics concern `DeviceKeyMetrics`, fed through
  `DeviceKeyService::with_metrics`;
- the strict profile's device-key lifetimes,
  `ProfileValues::device_key_config`;
- origins per host: `DeviceKeyConfig::with_origins` and
  `DeviceKeyConfig::with_origin_fn`, so a deployment with a host per tenant
  holds each request's app-shaped proofs to its own host's origin, and a
  host it does not serve has no key paths;
- a proof on every request for apps (decision 10):
  `DeviceKeyService::with_request_proofs` takes a replay store that records
  and a lifetime. A request that carries an RFC 9449 proof by the device key
  (`htm`, `htu`, `iat`, `jti`) is proven by it, a bound session's request is
  served without a proof cookie, and a sign-in is bound by it. The
  signature is checked under the key the proof carries before any store
  read; a bound session's device row is then read past any cache, so a
  revocation ends the session at its next request on every node, and the
  `jti` is recorded once under the tenant and the key;
- the replay stores (decision 10): `MemoryJtiReplayStore` for one process,
  `ValkeyJtiReplayStore` for a fleet, with its check that the server never
  evicts, `verify_dpop_proof_with_store`, and `MemoryJtiCache` as a
  `JtiReplayStore`;
- the example: the SQLite example built with `device-keys` offers a key on
  the first signed-in page under `Prefer`, and its test shows a copied
  session cookie, with the device cookie beside it but not the proof
  cookie, served as a guest and redirected to the login from a page that
  needs a sign-in, while the owner keeps the session;
- the tests the design calls for: one named for each invariant; a step-up
  and an impersonation on a bound session; the family revocation of a
  refresh token presented without its key reaching the device cascade; a
  signing-key rotation through the layer; the lockout exemption through a
  login; the device-store contract check of a registration beside a
  sighting, run by every backend's suite; and fuzz targets for the proof
  parser and verifier, the proof cookie, the offer and the identifier
  header (`key_proof_parse`, `device_proof_cookie`, `device_key_offer`,
  `device_identifier_header`), the last three through entry points the
  crate keeps under its `testing` feature.

Not built:

- **The walk with a real browser**, which
  [The browser front-end and the draft](#the-browser-front-end-and-the-draft)
  waits on.
- **The mutation sweep** of the files where one changed operator is a
  bypass: the proof verifier; the proof cookie (the expiry comparison, the
  grace addition, the fields under the MAC); the bound-session check (the
  equality on tenant, device and thumbprint, the policy match); the rule for
  a keyed device; the offer's conditions; the challenge comparison and its
  age check; the refresh-token branch that revokes; the merge's handling of
  the binding.
