# Impersonation standing, tenant egress and candidate expiry

This page describes the hardening that touches who may act,
what the server may fetch for a tenant, and what an unverified signup may hold.
For each of these three, it states what holds, the API, the invariants, how it
fails and what an adopter changes. Two shorter sections follow: when a device
lifts a lockout, and how many live reset links an account keeps. The steps to
take are in
[0.17.0 to 0.18.0](../production/migrating/0.17.0-to-0.18.0.md).

## An impersonation ends with its administrator

**What holds.** An impersonation session lasts only while the administrator
who began it is in good standing: suspending them, deleting them or ending
their sessions ends it on its next request.

**How.** The session is registered under the target, as before, so the
target's own revocations still reach it. `begin_impersonation` also registers
an entry under the *administrator*, named by its own key: the SHA-256 of
a dedicated tag, the administrator, the target and the start time
(`Impersonation::registry_anchor`). The key does not change when the session
rotates, and it names no session's row: a session's key is a digest under
another tag. For a session that carries an impersonation, the session layer
asks the registry about both entries on every request and ends the session
when either is gone. `suspend_user`,
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

**Who may begin one.** An administrator cannot impersonate themselves
(refused with `NoFlow` and a failed row whose reason is `self_impersonation`).
`AuthnServiceBuilder::with_impersonation_max_authn_age(window)` makes
`begin_impersonation` refuse an administrator session whose authentication is
older than `window` (`NoFlow`, reason `authn_too_old`); the administrator
steps up and retries. The default is no limit. An impersonation that fails
after the administrator's entry was registered ends that entry too, so it is
not left counting against the administrator's sessions.

**Also fixed here.** When a handler changes who a session is, the layer used to
ask the registry for the session's old id under the new user, find it missing
and end the session as revoked while its id rotated. A rotation in which the
user changed is now treated like a login's: the handler registered the new id
for the new user, and the layer checks that id.

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
is built. `OAuthProviderConfig::discover` and `discover_with_private_key_jwt`
run under `screened()` too; `discover_screened` and
`discover_screened_with_private_key_jwt` take the policy as an argument, for a tenant
provider an adopter builds itself, an identity provider on the deployment's
own network (`unscreened()`) or a mock on loopback in development
(`screened_allowing_loopback_http()`). The social-login provider and the
outbound OAuth client build their HTTP client through a policy too:
`SocialProvider::new_screened` and `OutboundOAuthClient::new_screened` take
it as an argument, check their endpoints against it and connect through a client
it built; `new` names `screened()`. The policy lives in its own `egress`
feature, which `oidc`, `social` and `outbound-oauth` turn on.

**How the connect-time check works.** The policy builds the HTTP client with a
DNS resolver that drops every reserved address from the answer and fails when
none is left, so a name that points at a reserved address, or changes its
answer after the URL check, is refused at connect time. A URL whose host is an
address needs no lookup and is refused by the URL check. The document is checked
for `jwks_uri`, `authorization_endpoint`, `token_endpoint`,
`userinfo_endpoint`, `end_session_endpoint`, `revocation_endpoint`,
`pushed_authorization_request_endpoint`, `device_authorization_endpoint` and
every `mtls_endpoint_aliases` entry. Redirects are off.

**The client carries its policy.** `EgressPolicy::build_client` returns a
`ScreenedClient`: a client the policy built, with the caller's own settings
applied first and the policy's last. The caller's settings are a
`ClientSettings` value that offers a timeout and a client certificate and
nothing else. A raw `reqwest` builder would also offer a pinned answer for a
host name, which the resolver screen is never asked about. So nothing the
caller sets can turn redirects or the environment proxy back on, turn the
resolver screen off, or route a name around it. The discovery and key-set
fetches take that client and no other: `DiscoveryDocument::fetch`,
`Discovery::fetch`, `JwksCache::fetch` and
`JwksCache::from_parts` screen their URLs under the policy the
client carries. No fetch takes a client the caller built. Each of them, and
every refresh, refuses an answer that is a redirect or that came from
a URL other than the one requested. The provider keeps the policy discovery ran under
and builds every later client from it: under the FAPI profile with mTLS, the
client that presents the certificate is built the same way, and each
advertised `mtls_endpoint_aliases` entry is checked against the policy before
a token, PAR, userinfo or revocation request can go to it.

**Failure modes.** A refusal is an `OAuthError::Config` that names the setting
and the range, never the URL. A client behind an egress proxy that resolves
names itself would hide the destination from the screen, so a screened client
never follows `HTTP_PROXY`, `HTTPS_PROXY` or `ALL_PROXY` from the environment:
put such a deployment on `unscreened()`, which follows them as a plain client
does, and filter at the proxy.

## An unverified candidate holds its identifier for a bounded time

**What holds.** `begin_signup` creates the account before anyone has shown
control of the identifier. A `Candidate` older than `candidate_ttl` no longer reserves its
identifier: the next `begin_signup` for it deletes the row, writes an
`AccountDeleted` row and goes on as for a free identifier. `candidate_ttl`
defaults to `DEFAULT_CANDIDATE_TTL` (24 hours), is set with
`with_candidate_ttl` on the builder, and is never shorter than the
verification secret's life. The session that
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
through. The session records the device a resolver bound, and each request
notes whether it proved that device (`SessionData::device_proven`, the
request's own answer, never stored). A `DeviceResolver` returns a
`BoundDevice`: `Proven` only from a `ProvenDevice`, which only
`resolve_or_keep` and `resolve_proven` yield, or `Unproven` for a bare id. Both
yield one for a request that presents the secret cookie token, and for the
device they create for an authenticated user on that request. Under a session
layer that enforces device keys, a device that has a key is proven only by a
proof of that key, and its token alone proves nothing. A request of an
authenticated session that presents no token (a visit from another site does
not send the strict cookie, and neither does whoever holds a copy of the
session cookie alone) keeps the device the session is bound to as `Unproven`:
the session cookie is not proof of the device.
The lockout reads `AuthSession::proven_device`, which answers only on a
request that proved the device, so neither a device found by fingerprint nor
one a session merely kept can lift a lock.

## A reset request never invalidates a live link

An account holds up to `DEFAULT_MAX_LIVE_RESET_TOKENS` (3) live reset tokens.
`store_reset_token` adds one unless the account is full. A request beyond
that is audited as `live_tokens_full` and answered `None`, as an unknown
identifier is, so the answer says nothing about the account. Using any one
token deletes all of the account's tokens.
