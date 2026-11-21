# Delegated and OBO access

An application often needs to act on behalf of the user against
a downstream service. A user signs in, grants
your application the right to read their inbox or post on their
behalf, and from then on your application can make
calls that the downstream service sees as
coming from the user. The mechanism is on-behalf-of (OBO) access,
and axess covers two shapes through the `delegated/` module under
`axess-core`.

The feature flag is `delegated` (off by default), with three
narrower ones: `delegated-stored` and `delegated-exchange` turn on
each shape independently, and `delegated-stored-encrypted` (which
pulls `delegated-stored`) adds the encrypting store wrapper. The
module lives inside
`axess-core` rather than as a separate crate because the
encryption envelope it needs already ships with the SQL session
backends, so a separate crate would
have isolated nothing. Adopters who do not turn on the feature
pay zero compile cost.

## The two shapes

OBO comes in two architectural shapes, which differ in
operation: where credentials live,
how often they refresh, what happens when the user revokes
consent.

The first shape is stored OBO. The user grants consent once
through an OAuth flow; you receive a refresh token
with the initial access token and persist it; each later call mints
a fresh access token from the refresh token and calls the downstream
with it. Most "connect your Google account" or "connect your Slack
account" flows work this way.

The second shape is token exchange (RFC 8693). The user's session
in your application carries a credential (a session cookie, a JWT
session, a workload identity token). When you need
to call a downstream service on the user's behalf, you present
the credential to a Security Token Service (STS) and receive a
short-lived access token bound to the call. Nothing is stored for the downstream; the exchange happens
per call (or once per short cache window).

The two shapes solve different problems. Stored OBO is right when
you need to act on the user's behalf while the user
is not present (a scheduled report that pulls from
Gmail at 6am, a background sync that runs while the user is
offline). Token exchange is right when you need to
act on the user's behalf only while the user has an active
session, and where the user's session credential can be exchanged
for a downstream credential at low cost.

## The two mechanisms

One keeps a refresh token on your side; the other keeps nothing.

### Stored OBO

Stored OBO uses the `delegated-stored` feature. It has three
parts: an OAuth flow that grants
initial consent, a credential store that persists the refresh
token, and a refresh path that mints fresh access tokens for
calls.

The initial grant is an OAuth authorization code flow where the
scopes include the downstream's access scope (`https://mail.google.com/`,
`channels:read`, whatever the downstream's vocabulary is) and the
flow includes `offline_access` (the OAuth scope that asks for a
refresh token). A successful flow returns an access token
(usable at once) and a refresh token (to store for later).

The three URLs a `DelegatedProvider` carries (the authorization endpoint,
the token endpoint and the `redirect_uri`) must be HTTPS, or HTTP to a
loopback host for development, and carry no userinfo. `begin_grant` and
`complete_grant` refuse any other with `DelegatedError::Transport` (the
`redirect_uri` refusal names the setting; an endpoint's says what an
endpoint must be): the first two receive the client credentials and the
code, and the IdP sends the code and the `state` back to the third.

`begin_grant` records the registration it was called with in the
`GrantContext` (`registration`: the provider's name and a digest of its
name, client id, authorization endpoint, token endpoint and
`redirect_uri`). Persist it with the state and the verifier.
`complete_grant` refuses any other provider, one of the same name
included, with `DelegatedError::RegistrationMismatch` before a request is
made, so a code issued to one tenant's client is never posted to another
provider's token endpoint. The exchange is sent with a client the library
builds, `grant_client(|settings| settings)`, which follows no redirect:
the request carries the code, the verifier and the client credentials.

The persistence runs through the `DelegatedCredentialStore`
trait, keyed by the `(tenant, user, provider)` triple:

```rust,ignore
use axess_core::delegated::stored::{DelegatedCredentialStore, StoredDelegation};

pub trait DelegatedCredentialStore: Send + Sync + 'static {
    fn load(
        &self,
        tenant: &TenantId,
        user: &UserId,
        provider: &str,
    ) -> impl Future<Output = Result<Option<StoredDelegation>, String>> + Send;

    fn save(
        &self,
        tenant: &TenantId,
        user: &UserId,
        credential: StoredDelegation,
    ) -> impl Future<Output = Result<(), String>> + Send;

    /// Replace the row only if it still equals `expected`, atomically.
    /// A store that cannot answers `Ok(CredentialSwap::Unsupported)`.
    fn save_if_unchanged(
        &self,
        tenant: &TenantId,
        user: &UserId,
        expected: &StoredDelegation,
        replacement: StoredDelegation,
    ) -> impl Future<Output = Result<CredentialSwap, String>> + Send;

    fn revoke(
        &self,
        tenant: &TenantId,
        user: &UserId,
        provider: &str,
    ) -> impl Future<Output = Result<(), String>> + Send;
}

pub struct StoredDelegation {
    pub provider: String,
    pub registration: Option<GrantRegistration>,
    pub access_token: ZeroizedString,
    pub refresh_token: Option<ZeroizedString>,
    pub expires_at: Option<Timestamp>,
    pub scopes: Vec<String>,
    pub token_type: String,
}
```

Two details in that signature matter. The futures are
native `impl Future` rather than `#[async_trait]` boxes, so an
implementation costs no allocation per call. And the error is a plain
`String`: the trait does not constrain the implementor's concrete error
type, which keeps a store backed by sqlx, by Dynamo, or by a bespoke
vault from having to convert into an axess error enum. Format the
detail you want to see in your logs into that string.

There is no owner type. The triple is passed positionally, so the same
(tenant, user) pair holds independent credentials for `"google"`,
`"slack"` and `"github"` side by side, and `provider` matches the
`DelegatedProvider::name` of the grant it came from.

The name is only a label, so the credential also carries the
`registration` it was granted through, the `GrantRegistration` the grant
recorded, and every refresh keeps it. A store of your own persists it with
the other fields and gives it back on `load`.

`save` overwrites, and the store treats the whole credential as the unit
of write. The first grant is written with it; a refresh goes through the
conditional `save_if_unchanged` below and falls back to `save` only for
a store that cannot compare.

`save_if_unchanged` has no default: a refresh writes its result through it,
so a row the user disconnected (in this process or another) while the IdP
was being asked is not written back, and a re-seal under a new key cannot
overwrite a token another request rotated. For a SQL store it is one
conditional `UPDATE ... WHERE` on the columns of `expected`, answering
`Saved` when a row changed and `Changed` when none did. A store that cannot
compare says so with `Ok(CredentialSwap::Unsupported)`; a refresh then falls back to
`save` and logs a warning naming the store type once.

Both token fields are `ZeroizedString`, so the in-memory copy zeroes on
drop. That says nothing about storage: **encryption at rest is the
implementor's responsibility**, and the plaintext reaches your `save`
unless you wrap the store. `MemoryDelegatedCredentialStore` ships for
dev and test and holds plaintext; it is not a production store.

The wrapper is `EncryptedDelegatedCredentialStore<S, K>`, a decorator
over any store `S` and a `KeyProvider` `K`, compiled under the
`delegated-stored-encrypted` feature. It encrypts each token field with
AES-256-GCM under a random 12-byte nonce of its own, and the key provider carries
historical keys, so after a key rotation the store still reads what
the previous key wrote. The trait surface is unchanged; the encryption happens inside
the decorator.

The refresh path is `StoredDelegationSession`. It wraps a store and a
provider, and its `get_access_token` loads the credential, returns the
access token if it is still fresh against the configured skew, and
otherwise runs the refresh exchange and saves the result before
returning. The refresh is single-flight: refreshes of one
`(tenant, user, provider)` credential are serialised across the process,
so a rotating refresh token is redeemed once and the callers that waited
read the stored result. Do not read `StoredDelegation::access_token` directly; the
session owns refresh-before-expiry. The session uses a credential
only with the registration it was granted through: one stored from another
registration of the same name (another tenant's client, a shared one) or
from none is refused with `DelegatedError::RegistrationMismatch` before its
access token is handed out or its refresh token is sent anywhere, and the
user grants again. `EncryptedDelegatedCredentialStore` seals the
registration into each token's associated data, so a row moved under
another registration's label does not open. `StoredDelegationSession::revoke`
is the matching teardown on your side: it removes the stored row. It does
not tell the provider, and a `DelegatedProvider` has no revocation
endpoint to tell: where the provider should forget the grant as well,
post to its revocation endpoint yourself before you call it.

### Token exchange

Token exchange uses the `delegated-exchange` feature.
It is much smaller because nothing is stored: the exchange runs
per call.

The exchange is an RFC 8693 token exchange. The application
presents:

- A subject token: the credential identifying the user. This
  might be the user's session ID, a JWT session token, or a
  workload identity token that names the user.
- A subject token type: an identifier for the kind of subject
  token (`urn:ietf:params:oauth:token-type:access_token`,
  `urn:ietf:params:oauth:token-type:jwt`, an application-specific
  string).
- The audience: the downstream service the token will be used
  against.
- Optional: the scopes of the requested token (`with_scopes`).
  Without them the request carries no `scope`, and the STS decides
  what the token grants.

The STS validates the subject token, determines the user's
identity, applies whatever policy its operator has configured (which
downstreams the user may reach, which scopes it grants), and returns
an access token bound to the audience. Axess evaluates none of that
policy: `TokenExchangeClient` posts the request and reads the answer.

```rust,ignore
use axess_core::ZeroizedString;
use axess_core::delegated::exchange::{TokenExchangeClient, TokenExchangeRequest};

let client = TokenExchangeClient::new(
    token_endpoint,
    client_id,
    Some(ZeroizedString::new(client_secret)),
)?;

let downstream_token = client
    .exchange(
        &TokenExchangeRequest::new(session_credential, token_types::ACCESS_TOKEN)
            .with_audience("https://api.downstream.example")
            .with_scopes(["read:data"]),
    )
    .await?;

let response = http_client
    .get("https://api.downstream.example/data")
    .bearer_auth(&*downstream_token.access_token)
    .send()
    .await?;
```

The exchange runs in the request path. It adds one round-trip to the STS
before the downstream call. The
exchanged token is short-lived (typically minutes), so the
application either re-exchanges per call (the simple shape) or
caches the exchanged token while it is valid (worth the complexity
only at high call rates).

### Which to use

If you need to act on the user's behalf while the
user is offline (a background job, a scheduled report, a
notification that runs hours after the user has gone home), use
stored OBO. Token exchange cannot serve it: the user's
session no longer exists when the call is made.

If you call the downstream only while the user is
actively signed in, and the downstream service supports RFC 8693
token exchange (Google Cloud's Security Token Service, for one), use
token exchange. The credential never reaches your database, so a
breach exposes less. Microsoft Entra ID's on-behalf-of flow uses the
JWT bearer grant instead, which `TokenExchangeClient` does not send.

If you need both shapes, turn on both feature flags: they are two
modules of one crate and work side by side.

The most common arrangement in practice is hybrid: token exchange for
the foreground synchronous calls (the user clicks "fetch latest
data from Gmail"), stored OBO for the background asynchronous
calls (the nightly sync that pulls all new mail since the last
run).

## Operating it

Recording consent, and taking it back.

### Audit and consent

Both shapes need an audit trail. The user granted consent at a
specific moment; the record of that moment defends against later
disputes ("this application made calls I did not authorise").

**Axess emits no delegated audit events.** Both shapes are primitives you call directly:
`complete_grant` returns a `StoredDelegation` for you to store, and
`TokenExchangeClient::exchange` returns a response. Neither has an audit
sink on its call path, and the event vocabulary has no name reserved for
a consent grant, a credential use or a token exchange.

So the trail is yours to write. Record the
grant with what the user agreed to (which scopes, which downstream) and
each use with when, against which downstream, and for which operation
if you surface that. Write it where you perform the operation, into the
same store your `IdentityAuthnLog` implementation writes to, so the
delegated trail and the authentication trail line up.

Delegated events are typically kept longer than ordinary
authentication events, because they defend against disputes that
may surface months or years later. The retention configuration is in *Audit pipeline*.

### Revocation

Both shapes need a revocation path. The user (or an
administrator) decides you should no longer act on
their behalf; the next call should fail.

Stored OBO revocation runs through `DelegatedCredentialStore::revoke`,
which `StoredDelegationSession::revoke` calls for you. The trait's
contract is removal: `MemoryDelegatedCredentialStore` deletes the row,
`EncryptedDelegatedCredentialStore` passes the call to the store it
wraps, and a store of your own that keeps revoked rows for audit must
not return them from `load`. Subsequent loads return `None`, and
`get_access_token` answers `DelegatedError::NotConnected`; your call
path either treats this as "user has not granted consent" or as
"consent was revoked, ask again". Telling the provider is a call of
your own, covered at the end of this section.

Token exchange revocation runs through the user's session
revocation. Logging the user out invalidates the session
credential, which means subsequent exchanges fail; in-flight
calls that have already exchanged the token continue until the
exchanged token expires (typically minutes). The granularity is
coarser than stored OBO's; the trade-off is operational simplicity.

Either shape benefits from the downstream's own revocation
mechanism. Most OAuth providers support RFC 7009 token
revocation; calling it on logout invalidates the access and
refresh tokens at the IdP, so even a stolen credential cannot be
used. Stored OBO with downstream revocation gives the
strongest revocation guarantee.

## Threat model

The threat surface for OBO is unusual. The application acts as
the user, which means a compromise of your application is a
compromise of the user's downstream account. The defences:

**Minimise the scope of the OAuth grant.** Request
the narrowest scopes you need (`channels:read` not
`channels:*`, the specific calendar not "all calendars"). An attacker who compromises you can act only within the
granted scopes.

**Encrypt the stored credentials at rest.** The
`EncryptedDelegatedCredentialStore` decorator covers this. An
attacker who breaches the database without the encryption key
cannot use the stored credentials.

**Monitor the trail you wrote above.** A spike in
delegated-credential use for one user, especially against operations
they do not normally perform, is a strong signal of compromise. Axess
supplies no rule for this because it supplies no event; the shape of
the query follows whatever you recorded.

**Bound consent in time.** Some downstreams support
explicit consent expiry; for those that do not, you
can require the user to re-consent on a schedule (every ninety
days, every year). The friction is the price of defending against long-lived stale
grants.

## The applications this opens up

OBO serves applications that do more than authenticate users for
themselves: a unified inbox that
pulls from Gmail and Outlook, a CI pipeline that posts to Slack
on the user's behalf, a calendar integration that books meetings.
The mechanism is opt-in (the feature flag), the two shapes cover
the architectural choices, and encryption at rest plus the audit trail you write
let the deployment defend its decisions.

## Further reading

*Refresh tokens and session continuity* covers the session's own
refresh tokens and their family detection, which is a separate
mechanism: a stored OBO credential has no families, only the
single-flight refresh described above. *OAuth 2.0 and OIDC* covers the OAuth flow that
grants the initial consent. *Workload identity overview* covers
the subject-token side of token exchange when the subject is a
workload rather than a human. *Audit pipeline* covers the sink the
delegated trail you write should share with the authentication trail.
