# Refresh tokens and session continuity

A session cookie keeps a user logged in until it expires or is cleared.
A refresh token is the mechanism that extends that lifetime past the
cookie's short window, without exposing a long-lived bearer credential
to the client. The shape of the mechanism matters more than most
adopters initially realise, because the choice between "long cookie"
and "short cookie plus refresh token" is the choice between "stolen
cookie is valid for a day" and "stolen cookie is valid for an hour
and then detectable as theft when the legitimate user next refreshes".

This chapter covers the refresh token shape in axess: hash-only
storage, token families for reuse detection, device binding and
cascade revocation, and the configuration surface adopters tune. The
relevant code lives in
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
}
```

Three fields are worth dwelling on.

`token_hash` is the SHA-256 hash of the token string, not the string
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

`device_id` is the link to the device identity ladder. When a refresh
token is bound to a device, revoking the token can cascade to revoke
the device, and revoking the device cascades to revoke every token
bound to it. The cascade is bidirectional and is the mechanism that
makes "log out everywhere on this device" work in practice. *Device
identity* covers the device ladder in detail.

## How families catch theft

The interesting part of the design is the family. The mechanism is
worth walking through with a concrete sequence.

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
`refresh_session` function: when a revoked token is presented, the
function calls `revoke_family(user_id, family_id)` and emits an
audit event noting the suspected compromise. The application can
also wire an `on_token_compromise` callback to receive the event
synchronously and take application-specific action (logging Alice
out of related sessions, alerting her by email, escalating to
fraud review).

The pattern catches a class of attacks that long-lived sessions
cannot detect at all. Even a sophisticated attacker who avoids
generating alerts cannot avoid the family revoke, because the
legitimate user's next refresh inevitably triggers it. The trade-off
is one re-login per detected compromise; given the alternative is
silent access, the trade-off is worth it.

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
    pub hash_pepper: Option<Vec<u8>>,
}
```

The defaults are conservative for most applications: a thirty-day TTL,
ten concurrent tokens per user, rotation enabled, and no pepper. Each
field is worth a few words of guidance.

`ttl` is how long a refresh token is valid before it expires without
being used. Thirty days is enough that most users do not feel the
expiry in normal use, and short enough that an abandoned device's
tokens become unusable in a bounded time. Applications with stricter
posture set this lower; applications with weak step-up at re-login
set this higher.

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
hash. Adding a pepper is a defence-in-depth measure that helps when
the database is breached but the secrets manager is not. The pepper
must be stable across the deployment (otherwise existing tokens
become unverifiable); rotation is supported through the same pattern
as the session signing key, covered in *Operations runbook*.

## Atomicity contracts

The `RefreshTokenStore` trait documents that production backends
must implement three methods atomically. The atomicity is what makes
the family-based theft detection sound; a non-atomic implementation
opens a TOCTOU window where an attacker could race the legitimate
user past the detection.

`rotate_token` must atomically mark the current token revoked and
issue a new token in the same family. Two requests racing each other
must result in one rotation and one detected reuse, not two
rotations.

`issue_with_eviction` must atomically issue a new token and evict the
oldest if the user is at the `max_per_user` cap. A non-atomic
implementation can leave a user with eleven active tokens
momentarily, which is harmless, or evict the wrong token under
contention, which can log a legitimate session out for no reason.

`revoke_family` must atomically revoke every token in a family.
Partial revocation defeats the detection mechanism: an attacker
holding a token from a half-revoked family can still refresh.

The first-party SQL adapters use transactions to satisfy these
contracts. Custom adapters need to do the same; the contract is
documented on the trait so reviewers can check it explicitly.

## What this enables

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
