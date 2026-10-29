# Refresh tokens and session continuity

A session cookie keeps a user logged in until it expires or is cleared.
A refresh token is the mechanism that extends that lifetime past the
cookie's short window, without exposing a long-lived bearer credential
to the client. The choice between a long cookie and a short cookie plus
a refresh token is the choice between a stolen cookie that is valid for
a day and one that is valid for an hour and then shows up as theft the
next time the legitimate user refreshes.

The code is in
[`axess-core/src/session/refresh.rs`](https://github.com/GnomesOfZurich/axess/blob/main/axess-core/src/session/refresh.rs).

## Why refresh tokens at all

A naive long-lived session is one cookie that lives for a month. If
the cookie is stolen, the attacker has a month of access. The
legitimate user has no way to know the cookie was stolen unless they
notice the attacker's actions in their account.

A short-lived session with a refresh token is two credentials. The
session cookie lives for an hour and grants access. The refresh token
lives for a month and grants only the right to mint a new session
cookie. The refresh exchange happens server-side, typically when the
session cookie expires; the client sends the refresh token, the server
checks it, and the server issues a fresh session cookie (and
optionally a fresh refresh token).

The cost is one extra round-trip per hour. The benefit is twofold.
First, a stolen session cookie expires within the hour. Second, and
more importantly, a stolen refresh token gets caught the next time
either the attacker or the legitimate user attempts to refresh,
because the system detects that a token has been used twice and
revokes the entire token family.

## The stored shape

`RefreshToken` is the row that lives in the refresh token store:

```rust,ignore
pub struct RefreshToken {
    pub id: RefreshTokenId,
    pub user_id: UserId,
    pub tenant_id: TenantId,
    pub token_hash: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    pub device_info: Option<String>,
    pub family_id: Option<TokenFamilyId>,
    pub device_id: Option<DeviceId>,
    pub authn_time: Option<DateTime<Utc>>,
    pub revoked_reason: Option<RevocationReason>,
    pub revoked_at: Option<DateTime<Utc>>,
}
```

Six fields are worth dwelling on.

`authn_time` is when the user last proved who they are. Rotation mints
a new token on every refresh, so `issued_at` keeps moving forward while
the person has not signed in again. The session a refresh produces
carries `authn_time` (or `issued_at` when it is `None`, as it is for a
token issued at login), so a 29-day-old refresh chain does not pass a
"recent login" or step-up freshness check. Rotation copies the value from
parent to child; a store must persist it.

`revoked_reason` and `revoked_at` record why and when a token was
revoked. Only the reuse of a token that was rotated out is a theft
signal; a token the user logged out, one the per-user cap evicted and
one a family revocation already killed were revoked on purpose, and a
stale client presenting one of them is not an attacker. The reasons are
`Rotated` (replaced by its child), `Explicit` (a logout or a user-wide
revocation), `Evicted` (made room under `max_per_user`) and `Compromise`
(swept by a family revocation). A store persists both fields next to
`revoked`; a revocation never overwrites the reason of a token that is
already revoked. The SQL adapters add them as two nullable columns
(`revoked_reason`, `revoked_at`), which is an additive migration: a row
revoked before the columns existed reads as `Rotated`, the strictest
reading, so reuse of such a token still revokes the family.

`device_info` is a keyed digest of the device string the caller passed at
issue, together with `device_id` (`hb1:` and the base64url of an
HMAC-SHA256 under the pepper). The client string itself is not stored.
Refresh recomputes the digest from the string presented and compares in
constant time, and the child token inherits the stored value. A token of an
earlier release stores the raw string; it is still honoured and its child
carries the digest. *Device identity* has the detail.

`token_hash` is the SHA-256 hash of the token string (HMAC-SHA256
under the configured pepper when there is one), not the string
itself. The plaintext token is generated when the token is issued
(through `SecureRng` for DST), returned to the client once, and never
stored. The hash is what lives in the database. A database breach that
leaks every row of the refresh token store does not leak any usable
token, because the hash is one-way. The verification path hashes the
client-supplied plaintext and compares it constant-time against the
stored hash.

The hashing uses an optional pepper, configured through
`RefreshTokenConfig::hash_pepper`. When set, the hash is
HMAC-SHA256(pepper, plaintext); when unset, the hash is plain
SHA-256(plaintext). The pepper is a deployment-level secret stored
outside the database (in the secrets manager that holds the session
signing key, typically) and adds defence in depth: an attacker who
breaches the database alone cannot mount an offline brute-force attack
against the hashes.

`family_id` is the link to the token's lineage. Every refresh token
issued in a single authentication chain shares a `TokenFamilyId`. The
first token issued at login starts a family; each subsequent token
issued by rotation extends the same family. When the system detects
that a token from a family has been used after rotation (which is
what theft looks like), it revokes the entire family.

`device_id` is the link to the device identity ladder, and it is what
makes revocation travel in both directions between the two stores. The
section on the cascade below has the detail; *Device identity* covers
the ladder itself.

## How families catch theft

Alice logs in. The server issues refresh token A, in family F. A is
delivered to her browser; the hash of A is stored in the database
with `family_id = F`.

An hour later, Alice's session cookie expires. Her browser sends A
back to refresh. The server hashes the plaintext, finds the row,
verifies it is not revoked, marks A as revoked (rotation), and issues
a new refresh token B in the same family F. B is delivered to the
browser.

Meanwhile, an attacker has stolen the cookie and copied A. The
attacker now sends A to refresh. The server hashes the plaintext,
finds the row, and sees that A is already marked revoked.

The clean refresh-after-rotation invariant says that a revoked token
should never be presented again. If it is, either Alice's browser is
broken (unlikely), or the network retried (rare and recoverable), or
the token has been stolen and the attacker is racing the legitimate
user. The conservative response is to assume the worst: revoke the
entire family F. Token B (which Alice's browser holds and has not yet
used) is now revoked. The next time Alice's browser refreshes, it
fails. The user has to log in again, but during the brief window
between detection and re-login the attacker has no access either.

The detection-and-revoke pattern is implemented in the
`refresh_session` function: when a token that was rotated out is
presented, the function calls `revoke_family(user_id, family_id)` and then
`on_token_compromise` on the store. The hook runs even when the family
revocation itself failed (the failure is logged and the caller still sees
`Revoked`), so a store fault cannot skip the device cascade. The refresh path
writes no audit event of its own; override `on_token_compromise` to record
one (an auth event with status `Suspicious`, carrying the user and family) and to take
application-specific action (logging Alice out of related sessions, alerting
her by email, escalating to fraud review).

A token that was revoked for another reason is refused as `Revoked` and
nothing else happens: a client that logs out and then replays its old token,
or one whose token the per-user cap evicted, does not take the user's other
sessions with it.

Two refreshes by one client can race: the browser retries, or two tabs
refresh at once. The second presentation of the rotated-out token looks like
reuse. `reuse_grace` (default zero, so every reuse is treated as theft) names a
short window after a rotation in which the second presentation answers
`ConcurrentRefresh` instead, revokes nothing, and lets the client retry with
the token the first refresh returned. Keep it to a few seconds: a thief who
replays the token just after the victim used it gets the same grace.

A token stored without a family (a row from before families existed) gives
its child a family named after the token's own id, so reuse of that token can
still find and revoke what descends from it.

What a long-lived session cannot do is notice. An attacker who avoids
every other alert still cannot avoid this one, because it is the
legitimate user's next refresh that fires it, and the cost is a single
re-login per detection.

## Device-binding cascade

When the `device` feature is enabled, refresh tokens are bound to the
device that received them. A refresh token issued from a browser on
Alice's laptop carries `device_id = Some(laptop)`. A refresh token
issued from her phone carries `device_id = Some(phone)`. Family
revocation cascades to the device store, marking the relevant device
as `Revoked`; device revocation cascades back to the token store,
revoking every token bound to the device.

The cascade is the mechanism behind "log out everywhere on this
device" and "this device was lost, revoke all access from it". The
operator marks the device revoked in the device store; the cascade
revokes every refresh token bound to it; the next refresh from that
device fails. The user is logged out of every session that ran
through the device, including any session that was idle but still
holding a refresh token.

The opposite direction matters too. When a family-revoke triggers
from a token-reuse detection, the cascade marks the relevant device
as compromised. The device's three-stage trust ladder
(Unknown to Seen to Trusted, covered in *Device identity*) is
short-circuited to the terminal `Revoked` state. Subsequent logins
from the same device fingerprint surface as a fresh `Unknown` device,
which the user re-establishes trust on with whatever step-up the
application requires.

The `collect_family_device_targets` helper gathers
`(TenantId, DeviceId)` pairs from a family for the cascade. The
helper exists because the device store and the refresh-token store
are independent persistence layers, and the cascade is the place
where they coordinate. The application's `on_token_compromise`
callback receives the list and decides which cascade to apply (some
applications mark devices `Revoked` directly; others write an
intermediate audit event and let an operator confirm).

## Configuration

`RefreshTokenConfig` is the operator's tuning surface:

```rust,ignore
pub struct RefreshTokenConfig {
    pub ttl: Duration,
    pub max_per_user: usize,
    pub rotation: bool,
    pub hash_pepper: Option<Zeroizing<Vec<u8>>>,
    pub previous_hash_pepper: Option<Zeroizing<Vec<u8>>>,
    pub max_lifetime: Option<Duration>,
    pub reuse_grace: Duration,
}
```

The defaults are conservative for most applications: a thirty-day TTL,
ten concurrent tokens per user, rotation enabled, no pepper, no absolute
lifetime and no reuse grace.

`ttl` is how long a refresh token is valid before it expires without
being used. Thirty days is enough that most users do not feel the
expiry in normal use, and short enough that an abandoned device's
tokens become unusable in a bounded time. Applications with stricter
posture set this lower; applications with weak step-up at re-login
set this higher.

`max_lifetime` is the absolute lifetime of a family, counted from the
authentication it descends from (the `authn_time` carried through rotation).
Without it expiry is sliding: a token refreshed at least once per `ttl` never
expires, so a stolen family that is rotated faster than the owner can notice
lives for ever. With it, a refresh at or after `authn_time + max_lifetime`
returns `Expired` on both refresh paths, and every token's `expires_at` is
clamped to that instant at issue and at rotation, so the stored expiry is the
truth. It must be positive and at least `ttl`; `validate` refuses anything
else. Ninety days is a reasonable hardening value. The default is `None`
because forcing re-authentication is a product decision.

`reuse_grace` is the window described above for racing refreshes. It must not
be negative.

`max_per_user` is the cap on how many refresh tokens a user can have
active at once. The cap exists to prevent a runaway "log in from
every device the user owns" pattern from filling the token store.
Issuing a new token past the cap evicts the oldest one. Ten is
generous for most users (a phone, a laptop, a tablet, plus a few
spares); applications with operators who routinely log in from
ephemeral machines push this higher.

`rotation` controls whether a refresh issues a new token (true) or
extends the existing one (false). Rotation enabled is the default and
is what makes family-based theft detection work. Rotation disabled
is faster (one less write per refresh) but defeats the family
detection mechanism, because a token never moves to revoked under
normal use. The recommendation is to leave rotation on; the
performance cost is negligible.

`hash_pepper` is the optional shared secret used to HMAC the token
hash, held in `zeroize::Zeroizing` so each copy of the config wipes it
when dropped. Adding a pepper is a defence-in-depth measure that helps when
the database is breached but the secrets manager is not. The pepper
must be stable across the deployment (otherwise existing tokens
become unverifiable).

To rotate it, set `hash_pepper` to the new secret and move the old one to
`previous_hash_pepper`. A presented token that is not found under the
current hash is looked up under the previous pepper; one found there is
refreshed by force, even when `rotation` is off, so the token the client
receives is stored under the new pepper. Reuse detection is unchanged: the
rotated-out record keeps its old hash and is still found by the retry. After
one `ttl` (or `max_lifetime`, for tokens nobody uses) set
`previous_hash_pepper` back to `None`. Only a keyed previous pepper can be
named, so moving from no pepper to a pepper still invalidates the tokens.

## Refreshing for one tenant

`refresh_session` finds a token by its hash alone, so a token issued for one
tenant can be presented to an endpoint that serves another. When the tenant
comes from the request (a host name, a path segment), use
`refresh_session_in_tenant` or `refresh_session_with_status_check_in_tenant`:
a token of any other tenant answers `NotFound`, exactly as an unknown token
does, and is not rotated, revoked or checked against the status predicate.

## Atomicity contracts

The `RefreshTokenStore` trait documents that production backends
must implement three methods atomically. The atomicity is what makes
the family-based theft detection sound; a non-atomic implementation
opens a time-of-check-to-time-of-use window, where an attacker could
race the legitimate user past the detection between the moment the
token is checked and the moment it is spent.

Each of these records the revocation reason described above: `Rotated`
(stamped with the child's issue time) for the parent in `rotate_token`,
`Evicted` for the tokens `issue_capped` removes, `Compromise` for
`revoke_family`, `Explicit` for the single-token and user-wide revocations.

`rotate_token` must atomically mark the current token revoked and
issue a new token in the same family. Two requests racing each other
must result in one rotation and one detected reuse, not two
rotations.

`issue_capped` must atomically issue a new token and evict the oldest
until the user has at most `max_per_user` active tokens, counting inside
the same transaction as the insert. An implementation that counts first
and writes after lets two concurrent issues for one user both pass the
cap, and can evict the wrong token under contention, which logs a
legitimate session out for no reason.

`revoke_family` must atomically revoke every token in a family.
Partial revocation defeats the detection mechanism: an attacker
holding a token from a half-revoked family can still refresh.

The first-party SQL adapters use transactions to satisfy these
contracts. Custom adapters need to do the same; the contract is
documented on the trait so reviewers can check it explicitly.

## Choosing a point on the continuum

Refresh tokens and session cookies are the two ends of a continuum
between "convenience" and "security". A session cookie alone is the
convenience end. A refresh token with family-based theft detection
and device-binding cascade is what lets axess sit much closer to the
security end without compromising user experience: sessions feel
permanent because they refresh transparently, and theft gets caught
the next time anyone attempts a refresh.

The mechanism is the same one that lets axess support
"log out of everything" at the user-account level and
"this device was lost" at the device level, because the cascade
between tokens, families, and devices is the same in both directions.
A session that has lived its whole life behind axess can be revoked
through any of the three handles, and the others follow.

## Further reading

*Device identity* covers the three-stage device assurance ladder,
the per-tenant fingerprint pepper, and the retention sweep. *Session
lifecycle and crypto envelope* covers the session cookie itself, the
AES-256-GCM envelope, and the orchestration that issues and reads
cookies. *Operations runbook* covers key rotation for the session
signing key, the refresh-token pepper, and the device fingerprint
pepper.
