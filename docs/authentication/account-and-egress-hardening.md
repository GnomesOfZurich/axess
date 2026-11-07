# Impersonation standing, tenant egress and candidate expiry

This page is the design of the hardening in 0.18.0 that touches who may act,
what the server may fetch for a tenant, and what an unverified signup may hold.
For each: what holds, the API, the invariants, how it fails, and what an
adopter changes. The steps to take are in
[0.17.0 to 0.18.0](../production/migrating/0.17.0-to-0.18.0.md).

## An impersonation ends with its administrator

**What holds.** An impersonation session lasts only while the administrator
who began it is in good standing: suspending them, deleting them or ending
their sessions ends it on its next request.

**How.** The session is registered under the target, as before, so the
target's own revocations still reach it. `begin_impersonation` also registers
an entry under the *administrator*, whose id is derived from the administrator,
the target and the start time (`Impersonation::registry_anchor`). The id does
not change when the session id rotates. The session layer, for a session that
carries an impersonation, asks the registry about both entries on every
request and ends the session when either is gone. `suspend_user`,
`delete_user` and `invalidate_user_sessions` already end every entry under the
administrator, and the anchor is one of them. `end_impersonation` removes it.

**Why not check the administrator's account on each request.** The layer has
the registry and no identity store, so that check would add a store read to
every request of every impersonation and a dependency the layer does not have.
Every revocation path already writes to the registry.

**Failure modes.** A registry that cannot answer is `unknown`, and the layer's
`UnknownLiveness` policy decides, as for any session. A registry that holds
sessions for a bounded time keeps the anchor alive while the impersonation is
in use. The anchor counts as one of the administrator's registered sessions for
`with_max_sessions_per_user`; evicting it ends the impersonation.

**Also fixed here.** When a handler changes who a session is, the layer used to
read the old id as the new user's revoked one and end the session. A rotation
in which the user changed is now treated like a login's.

## Tenant-supplied provider URLs are screened

**What holds.** The issuer URL a tenant writes, and every URL its discovery
document names, are checked before they are fetched, and every connection is
checked again at the address it resolves to. A destination in a loopback,
private, link-local, unique-local, shared-address, metadata, unspecified or
multicast range is refused by name, and so is plain HTTP.

**The API.** `axess_factors::egress::EgressPolicy`:

| Policy | What it allows |
|--------|----------------|
| `screened()` (default) | HTTPS to public addresses |
| `screened_allowing_loopback_http()` | the same, and plain HTTP to loopback; for tests and local development |
| `unscreened()` | any address, HTTPS or loopback HTTP; the named opt-out for an identity provider on the deployment's own network |

`StoredTenantOAuthProviders` applies `screened()` unless
`with_egress_policy` says otherwise; `upsert` refuses a record whose issuer the
policy refuses, and a record written past `upsert` is refused when its provider
is built. `OAuthProviderConfig::discover_screened` and
`discover_screened_with_private_key_jwt` take the policy for an adopter that
builds tenant providers itself. `OAuthProviderConfig::discover` is for an
issuer the operator wrote and keeps the transport rule alone.

**How the connect-time check works.** The policy builds the HTTP client with a
DNS resolver that drops every reserved address from the answer and fails when
none is left, so a name that points at a reserved address, or changes its
answer after the URL check, is refused at connect time. A URL whose host is an
address needs no lookup and is refused by the URL check. The document is checked
for `jwks_uri`, `authorization_endpoint`, `token_endpoint`,
`userinfo_endpoint`, `end_session_endpoint`, `revocation_endpoint`,
`pushed_authorization_request_endpoint`, `device_authorization_endpoint` and
every `mtls_endpoint_aliases` entry. Redirects are off.

**Failure modes.** A refusal is an `OAuthError::Config` that names the setting
and the range, never the URL. A client behind an egress proxy that resolves
names itself sees the proxy's address, not the destination's: put such a
deployment on `unscreened()` and filter at the proxy.

## An unverified candidate holds its identifier for a bounded time

**What holds.** `begin_signup` creates the account before anyone has shown
control of the identifier. A `Candidate` older than `candidate_ttl` (default
`DEFAULT_CANDIDATE_TTL`, 24 hours, `with_candidate_ttl` on the builder, never
shorter than the verification secret's life) no longer reserves its
identifier: the next `begin_signup` for it deletes the row, writes an
`AccountDeleted` row and goes on as for a free identifier. The session that
began the signup can still resume it.

**Why on read.** The identifier matters only when someone asks for it, and
a check at that moment needs no store method and no scheduler. The age is the
service's clock at creation, stamped by `begin_signup`, not the time on the
record the caller built.

**The sweep.** A candidate nobody asks for again would stay as a row.
`purge_expired_candidates(limit)` deletes those past the lifetime through
`IdentityAdmin::delete_candidates_created_before`, one `AccountDeleted` audit
row per deletion, at most `limit` per call. Run it from a timer and call it
again while it returns `limit`.

## A device exempts a lockout only when the client proved it

The per-account lockout lets an account's own `Seen` or `Trusted` device
through. The session records the device a resolver bound, and now also whether
the client proved it (`SessionData::device_proven`). A `DeviceResolver` returns
a `BoundDevice`: `Proven` only from a `ProvenDevice`, which only
`resolve_proven` yields (the secret cookie token), or `Unproven` for a bare id.
`AuthSession::proven_device` answers only for a proven binding and is what the
lockout reads, so a device found by fingerprint cannot lift a lock.

## A reset request never invalidates a live link

An account holds up to `DEFAULT_MAX_LIVE_RESET_TOKENS` (3) live reset tokens.
`store_reset_token` adds one unless the account is full, and a request beyond
that is audited as `live_tokens_full` and answered `None`, as an unknown
identifier is, so the answer says nothing about the account. Using any one
token deletes all of the account's tokens.
