# Delegated and OBO access

The scenario is common: your application needs to act on behalf
of the user against a downstream service. A user signs in, grants
your application the right to read their inbox or post on their
behalf, and from that moment forward the application can make
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
through an OAuth flow; the application receives a refresh token
along with the initial access token; the application persists the
refresh token; future calls to the downstream service use the
refresh token to mint a fresh access token, then use the access
token to make the actual call. The pattern is what most "connect
your Google account" or "connect your Slack account" flows do.

The second shape is token exchange (RFC 8693). The user's session
in the application carries a credential (a session cookie, a JWT
session, a workload identity token). When the application needs
to call a downstream service on the user's behalf, it presents
the credential to a Security Token Service (STS) and receives a
short-lived access token bound to the call. There is no persistent
storage of credentials for the downstream; the exchange happens
per call (or per a short cache window).

The two shapes solve different problems. Stored OBO is right when
the application needs to act on the user's behalf when the user
is not actively present (a scheduled report that pulls from
Gmail at 6am, a background sync that runs while the user is
offline). Token exchange is right when the application needs to
act on the user's behalf only while the user has an active
session, and where the user's session credential can be exchanged
for a downstream credential at low cost.

## Stored OBO

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
trait:

```rust,ignore
#[async_trait]
pub trait DelegatedCredentialStore: Send + Sync {
    async fn save_credential(
        &self,
        owner: &CredentialOwner,
        credential: StoredCredential,
    ) -> Result<(), StoreError>;

    async fn load_credential(
        &self,
        owner: &CredentialOwner,
        downstream: &str,
    ) -> Result<Option<StoredCredential>, StoreError>;

    async fn revoke_credential(
        &self,
        owner: &CredentialOwner,
        downstream: &str,
    ) -> Result<(), StoreError>;
}

pub struct StoredCredential {
    pub access_token: ZeroizedString,
    pub refresh_token: ZeroizedString,
    pub expires_at: DateTime<Utc>,
    pub scopes: Vec<String>,
    pub downstream: String,
}
```

The owner is typically the user, identified by `UserId` and
`TenantId`. The downstream is named by a string (`"google.com"`,
`"slack"`, `"github"`), letting one user have multiple stored
credentials for different downstreams.

The encrypted variant is `EncryptedDelegatedCredentialStore<S, K>`,
a decorator that wraps any store with AES-256-GCM at-rest
encryption using a key the deployment provides. The trait surface
is the same; the encryption happens transparently inside the
decorator. Production deployments use the encrypted variant.

The refresh path runs on demand. When the application needs to
call the downstream, it loads the stored credential, checks
whether the access token is still valid, and either uses it
directly or runs the refresh exchange to mint a fresh access
token. The fresh token replaces the stored one if rotation is
configured (most downstreams rotate the refresh token on each
refresh, which is the same defence the session refresh-token
mechanism uses; *Refresh tokens and session continuity* covers
the family-based theft detection in detail).

## Token exchange

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
use axess::delegated::{ExchangeRequest, TokenExchanger};

let exchange = TokenExchanger::new(sts_config);

let downstream_token = exchange
    .exchange(ExchangeRequest {
        subject_token: session_credential,
        audience: "https://api.downstream.example",
        scopes: vec!["read:data".to_string()],
    })
    .await?;

let response = http_client
    .get("https://api.downstream.example/data")
    .header("Authorization", format!("Bearer {}", downstream_token.access_token))
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

## Which to use

The decision tree is short.

If the application needs to act on the user's behalf while the
user is offline (a background job, a scheduled report, a
notification that runs hours after the user has gone home), use
stored OBO. Token exchange does not work because the user's
session does not exist when the call needs to happen.

If the application calls the downstream only while the user is
actively signed in, and the downstream service supports token
exchange (Azure AD, Google Cloud, most enterprise SaaS that
supports RFC 8693), use token exchange. The credential never
hits your database, so the breach impact is smaller.

If the application needs both shapes, both work side by side. The
two crates compose without conflict; turn on both feature flags.

The most common shape in practice is hybrid: token exchange for
the foreground synchronous calls (the user clicks "fetch latest
data from Gmail"), stored OBO for the background asynchronous
calls (the nightly sync that pulls all new mail since the last
run). The two flows handle the two needs.

## Audit and consent

Both shapes need an audit trail. The user granted consent at a
specific moment; that moment is what defends against later
disputes ("the application made calls I did not authorise").

The stored OBO shape emits a `DelegatedConsentGranted` audit
event at the initial OAuth flow and a `DelegatedCredentialUsed`
event on each refresh. The first event records what the user
agreed to (which scopes, which downstream); the second records
each use (when, against which downstream, for which operation if
the application surfaces that).

The token exchange shape emits a `DelegatedTokenExchanged` event
on each exchange. The event records the subject token's source,
the audience, the scopes, and the timestamp.

The audit retention for delegated events is typically longer
than for ordinary authentication events because the events
defend against future disputes that may surface months or years
later. The retention configuration is in *Audit pipeline*.

## Revocation

Both shapes need a revocation path. The user (or an
administrator) decides the application should no longer act on
their behalf; the next call should fail.

Stored OBO revocation runs through `DelegatedCredentialStore::revoke_credential`.
The credential is removed from the store (or marked revoked, if
the store retains for audit). Subsequent loads return `None`;
the application's call path either treats this as "user has not
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
the user, which means a compromise of the application is a
compromise of the user's downstream account. The defences:

The first is to minimise the scope of the OAuth grant. Request
the narrowest scopes the application needs (`channels:read` not
`channels:*`, the specific calendar not "all calendars"). The
attacker who compromises the application can act only within the
granted scopes.

The second is to encrypt the stored credentials at rest. The
`EncryptedDelegatedCredentialStore` decorator covers this. An
attacker who breaches the database without the encryption key
cannot use the stored credentials.

The third is to monitor the audit events. A spike in
`DelegatedCredentialUsed` events for a user, especially for
operations the user does not typically perform, is a strong
signal of compromise. The SIEM rules in *Audit events* name the
patterns.

The fourth is to time-bound consent. Some downstreams support
explicit consent expiry; for those that do not, the application
can require the user to re-consent on a schedule (every ninety
days, every year). The friction is real; the defence against
long-lived stale grants is also real.

## What this enables

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
workload rather than a human. *Audit pipeline* covers the
retention configuration for `Delegated*` audit events.
