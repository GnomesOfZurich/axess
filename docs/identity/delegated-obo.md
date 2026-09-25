# Delegated and OBO access

The scenario is common: your application needs to act on behalf
of the user against a downstream service. A user signs in, grants
your application the right to read their inbox or post on their
behalf, and from that moment forward your application can make
calls to the downstream service that the downstream sees as
coming from the user. The mechanism is on-behalf-of (OBO) access,
and axess covers two shapes through the `delegated/` module under
`axess-core`.

The feature flag is `delegated` (off by default), with two
narrower variants (`delegated-stored`, `delegated-exchange`) that
turn on each shape independently. The module lives inside
`axess-core` rather than as a separate crate because the
encryption envelope it needs already ships with the SQL session
backends, so the isolation benefit a separate crate would have
provided was illusory. Adopters who do not turn on the feature
pay zero compile cost.

## The two shapes

OBO comes in two architectural shapes. The shape matters because
the operational characteristics differ: where credentials live,
how often they refresh, what happens when the user revokes
consent.

The first shape is stored OBO. The user grants consent once
through an OAuth flow; you receive a refresh token
along with the initial access token; you persist the
refresh token; future calls to the downstream service use the
refresh token to mint a fresh access token, then use the access
token to make the actual call. The pattern is what most "connect
your Google account" or "connect your Slack account" flows do.

The second shape is token exchange (RFC 8693). The user's session
in your application carries a credential (a session cookie, a JWT
session, a workload identity token). When you need
to call a downstream service on the user's behalf, it presents
the credential to a Security Token Service (STS) and receives a
short-lived access token bound to the call. There is no persistent
storage of credentials for the downstream; the exchange happens
per call (or per a short cache window).

The two shapes solve different problems. Stored OBO is right when
you need to act on the user's behalf when the user
is not actively present (a scheduled report that pulls from
Gmail at 6am, a background sync that runs while the user is
offline). Token exchange is right when you need to
act on the user's behalf only while the user has an active
session, and where the user's session credential can be exchanged
for a downstream credential at low cost.

## The two mechanisms

One keeps a refresh token on your side; the other keeps nothing.

### Stored OBO

The stored OBO shape uses the `delegated-stored` feature. The
machinery has three moving parts: an OAuth flow that grants
initial consent, a credential store that persists the refresh
token, and a refresh path that mints fresh access tokens for
calls.

The initial grant is an OAuth authorization code flow where the
scopes include the downstream's access scope (`https://mail.google.com/`,
`channels:read`, whatever the downstream's vocabulary is) and the
flow includes `offline_access` (the OAuth scope that asks for a
refresh token). The flow's success returns both an access token
(usable immediately) and a refresh token (storable for later use).

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

    fn revoke(
        &self,
        tenant: &TenantId,
        user: &UserId,
        provider: &str,
    ) -> impl Future<Output = Result<(), String>> + Send;
}

pub struct StoredDelegation {
    pub provider: String,
    pub access_token: ZeroizedString,
    pub refresh_token: Option<ZeroizedString>,
    pub expires_at: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
    pub token_type: String,
}
```

Two details in that signature are worth reading twice. The futures are
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

`save` overwrites. Refresh-token rotation lands there rather than on a
separate update path, because the store treats the whole credential as
the unit of write.

Both token fields are `ZeroizedString`, so the in-memory copy zeroes on
drop. That says nothing about storage: **encryption at rest is the
implementor's responsibility**, and the plaintext reaches your `save`
unless you wrap the store. `MemoryDelegatedCredentialStore` ships for
dev and test and holds plaintext; it is not a production store.

The wrapper is `EncryptedDelegatedCredentialStore<S, K>`, a decorator
over any store `S` and a `KeyProvider` `K`. It encrypts with AES-256-GCM
under a random 12-byte nonce per row, and the key provider carries
historical keys so a rotation can still read what the previous key
wrote. The trait surface is unchanged; the encryption happens inside
the decorator.

The refresh path is `StoredDelegationSession`. It wraps a store and a
provider, and its `get_access_token` loads the credential, returns the
access token if it is still fresh against the configured skew, and
otherwise runs the refresh exchange and saves the result before
returning. Do not read `StoredDelegation::access_token` directly; the
session is what owns refresh-before-expiry. `StoredDelegationSession::revoke`
is the matching teardown: it calls the provider's revocation endpoint
where one is configured and removes the stored row.

### Token exchange

The token exchange shape uses the `delegated-exchange` feature.
The machinery is much smaller because there is no persistent
storage: the exchange runs per call.

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
- Optional: the scope of the requested token (defaults to "all
  scopes the user has").

The STS validates the subject token, determines the user's
identity, applies whatever policy decisions the deployment has
configured (Cedar policies that govern the exchange, the user's
allowed downstreams), and returns an access token bound to the
audience.

```rust,ignore
use axess_core::ZeroizedString;
use axess_core::delegated::exchange::{TokenExchangeClient, TokenExchangeRequest};

let client = TokenExchangeClient::new(
    token_endpoint,
    client_id,
    Some(ZeroizedString::new(client_secret)),
);

let downstream_token = client
    .exchange(
        &TokenExchangeRequest::new(session_credential, ACCESS_TOKEN_TYPE)
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

The exchange runs in the request path. The latency cost is one
round-trip to the STS plus the actual downstream call. The
exchanged token is short-lived (typically minutes), so the
application either re-exchanges per call (the simple shape) or
caches the exchanged token for the duration of its validity (the
optimisation, which is worth the complexity only at high call
rates).

### Which to use

The decision tree is short.

If you need to act on the user's behalf while the
user is offline (a background job, a scheduled report, a
notification that runs hours after the user has gone home), use
stored OBO. Token exchange does not work because the user's
session does not exist when the call needs to happen.

If you call the downstream only while the user is
actively signed in, and the downstream service supports token
exchange (Azure AD, Google Cloud, most enterprise SaaS that
supports RFC 8693), use token exchange. The credential never
hits your database, so the breach impact is smaller.

If you need both shapes, both work side by side. The
two crates compose without conflict; turn on both feature flags.

The most common shape in practice is hybrid: token exchange for
the foreground synchronous calls (the user clicks "fetch latest
data from Gmail"), stored OBO for the background asynchronous
calls (the nightly sync that pulls all new mail since the last
run). The two flows handle the two needs.

## Operating it

Recording consent, and taking it back.

### Audit and consent

Both shapes need an audit trail. The user granted consent at a
specific moment; that moment is what defends against later
disputes ("this application made calls I did not authorise").

**Axess emits neither.** Both shapes are primitives you call directly:
`complete_grant` returns a `StoredDelegation` for you to store, and
`TokenExchangeClient::exchange` returns a response. Neither has an audit
sink on its call path, and the event vocabulary has no name reserved for
a consent grant, a credential use or a token exchange.

So the trail is yours to write, and it is worth writing. Record the
grant with what the user agreed to (which scopes, which downstream) and
each use with when, against which downstream, and for which operation
if you surface that. Write it where you perform the operation, into the
same store your `IdentityAuthnLog` implementation writes to, so the
delegated trail and the authentication trail line up.

The audit retention for delegated events is typically longer
than for ordinary authentication events because the events
defend against future disputes that may surface months or years
later. The retention configuration is in *Audit pipeline*.

### Revocation

Both shapes need a revocation path. The user (or an
administrator) decides you should no longer act on
their behalf; the next call should fail.

Stored OBO revocation runs through `DelegatedCredentialStore::revoke`,
which `StoredDelegationSession::revoke` calls for you after it has
told the provider.
The credential is removed from the store (or marked revoked, if
the store retains for audit). Subsequent loads return `None`;
your call path either treats this as "user has not
granted consent" or as "consent was revoked, ask again."

Token exchange revocation runs through the user's session
revocation. Logging the user out invalidates the session
credential, which means subsequent exchanges fail; in-flight
calls that have already exchanged the token continue until the
exchanged token expires (typically minutes). The granularity is
coarser than stored OBO but the operational simplicity is the
trade-off.

Either shape benefits from the downstream's own revocation
mechanism. Most OAuth providers support RFC 7009 token
revocation; calling it on logout invalidates the access and
refresh tokens at the IdP, so even a stolen credential cannot be
used. Stored OBO with downstream revocation gives the
strongest possible revocation guarantee.

## Threat model

The threat surface for OBO is unusual. The application acts as
the user, which means a compromise of your application is a
compromise of the user's downstream account. The defences:

**Minimise the scope of the OAuth grant.** Request
the narrowest scopes you need (`channels:read` not
`channels:*`, the specific calendar not "all calendars"). The
an attacker who compromises you can act only within the
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

The fourth is to time-bound consent. Some downstreams support
explicit consent expiry; for those that do not, you
can require the user to re-consent on a schedule (every ninety
days, every year). The friction is real; the defence against
long-lived stale grants is also real.

## The applications this opens up

OBO is what lets axess fit into the kind of application that does
more than authenticate users for itself: a unified inbox that
pulls from Gmail and Outlook, a CI pipeline that posts to Slack
on the user's behalf, a calendar integration that books meetings.
The mechanism is opt-in (the feature flag), the two shapes cover
the architectural choices, and the encryption-at-rest plus the
audit trail let the deployment defend its decisions.

## Further reading

*Refresh tokens and session continuity* covers the refresh-token
family-detection mechanism that also applies to stored OBO
credentials. *OAuth 2.0 and OIDC* covers the OAuth flow that
grants the initial consent. *Workload identity overview* covers
the subject-token side of token exchange when the subject is a
workload rather than a human. *Audit pipeline* covers the sink the
delegated trail you write should share with the authentication trail.
