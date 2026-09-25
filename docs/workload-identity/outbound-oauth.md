# Outbound: OAuth

Your application authenticates itself as a workload against a
downstream OAuth-protected service.
The application is the OAuth client; the downstream is the resource
server. The credential is an access token you acquire
through one of the OAuth client flows (client credentials, token
exchange, or refresh of a stored token).

The chapter pairs with *Inbound: federation* and *Cloud STS
exchange*: those cover the inbound case where you
accepts workload tokens; this covers the outbound case where the
application presents them.

The feature flag is `outbound-oauth` (off by default).

## When to use it

Three patterns lead to outbound OAuth.

**A service-to-service call** between two services your
deployment owns, where the receiving service authenticates
inbound OAuth (typically through the generic `WorkloadResolver`
from *Inbound: federation*). The application's outbound
configuration mints a fresh token through the client-credentials
grant, sends it on the request, and the receiving service
validates it.

**A call to a SaaS service** that requires OAuth (Slack,
Stripe, Twilio, an enterprise CRM). The application is registered
as an OAuth client at the SaaS, holds a client id and secret, and
mints tokens to call the SaaS's API.

**A call on a user's behalf** to a downstream service,
where the credential is a token exchanged from the user's session
or from a stored refresh token. This is the OBO case, covered in
*Delegated and OBO access*; the outbound-oauth machinery in this
chapter is what `delegated-stored` and `delegated-exchange` use
under the hood.

## Configuration

`OutboundOAuthClient` fetches tokens through the client-credentials
grant. The configuration:

```rust,ignore
use axess_core::ZeroizedString;
use axess_core::workload::outbound::oauth_client::{
    ClientAuthMethod, OutboundOAuthClient,
};

let client = OutboundOAuthClient::new(
    "https://idp.example.com/oauth/token".parse()?,
    ClientAuthMethod::ClientSecretBasic {
        client_id: "billing-api-prod".into(),
        client_secret: ZeroizedString::new(secret),
    },
)
.with_scopes(["https://api.downstream.example/.default"]);
```

The first argument is the OAuth server's token endpoint. It typically
comes from the server's discovery document; the configuration is the
resolved URL.

The client authenticates to that endpoint with a `ClientAuthMethod`:

```rust,ignore
pub enum ClientAuthMethod {
    ClientSecretBasic { client_id: String, client_secret: ZeroizedString },
    ClientSecretPost  { client_id: String, client_secret: ZeroizedString },
    PrivateKeyJwt {
        client_id: String,
        signing_key: EncodingKey,
        algorithm: Algorithm,
        key_id: Option<String>,
        audience: String,
        assertion_ttl: Duration,
    },
}
```

`ClientSecretBasic` puts `client_id` and `client_secret` in an
`Authorization: Basic` header, which is what most off-the-shelf IdPs
expect (Okta, Auth0, Entra). `ClientSecretPost` sends the same pair as
form fields, which some older IdPs require instead; check their
documentation rather than guessing. Both secrets are zeroized on drop.

`PrivateKeyJwt` is RFC 7523, and it is the one to reach for in a
FAPI-grade integration: axess signs a short-lived assertion with its
private key and the IdP validates it against the published JWKS, so
there is no shared secret to rotate. Its `audience` is the assertion
JWT's own `aud` claim: per RFC 7523 §3 a value the IdP recognises as
naming itself, usually the token endpoint URL, though some IdPs want
their `issuer` URL instead. It does not name the downstream API. The
`signing_key` is validated when the client is constructed, so a
malformed key fails at startup rather than on the first call.

mTLS is not a variant here. Outbound client-certificate
authentication is a property of the connection rather than of the token
request; see *Outbound mTLS*.

The rest of the builder is small: `with_scopes` sets the requested
scopes, `with_refresh_threshold` moves the cache's refresh point
(default 30 seconds before expiry), and `with_clock`, `with_rng` and
`with_http_client` substitute the ambient dependencies, the first two
for deterministic tests, the third for proxy, timeout or outbound-mTLS
configuration.

The narrowest possible scope list is the recommendation; over-broad
scopes leak privilege if the resulting token is compromised.

There is no audience parameter. Token endpoints that bind a token to a
specific resource through a non-standard `audience` form field (Auth0,
some Azure AD configurations) are not covered by the builder; where the
IdP accepts a resource-shaped scope instead (`.default` for Entra, for
example), express it through `with_scopes`.

## Getting a token

`get_access_token` returns the current token as a `String`, fetching
one if the cache has nothing fresh:

```rust,ignore
async fn call_downstream(
    client: &OutboundOAuthClient,
    http: &reqwest::Client,
) -> Result<(), Error> {
    let token = client.get_access_token().await?;

    let response = http
        .get("https://api.downstream.example/data")
        .bearer_auth(&token)
        .send()
        .await?;
    Ok(())
}
```

`OutboundOAuthClient` always caches, and there is no wrapper to reach
for: it holds the token itself. The first call
fetches and stores the response under a write lock, later calls inside
the validity window read it under a read lock, and the window ends
`refresh_threshold` before `expires_in` so a token does not expire
mid-flight. Call it per request rather than holding the returned
`String`, and the refresh is handled for you.

`force_refresh` bypasses the cache and replaces its contents, which is
what to call when the downstream rejects an apparently-fresh token,
since the IdP may have revoked it early.

## Token exchange (RFC 8693)

The token-exchange flow is the alternative to client-credentials
when the outbound call is on behalf of an inbound principal
(human or workload). The application presents the inbound
credential to a token-exchange-capable IdP and receives a token
bound to the downstream audience.

```rust,ignore
use axess_core::ZeroizedString;
use axess_core::delegated::exchange::{TokenExchangeClient, TokenExchangeRequest};

let client = TokenExchangeClient::new(
    token_endpoint,
    "billing-api-prod",
    Some(ZeroizedString::new(client_secret)),
);

let token = client
    .exchange(
        &TokenExchangeRequest::new(
            inbound_token,
            "urn:ietf:params:oauth:token-type:jwt",
        )
        .with_audience("https://api.downstream.example")
        .with_scopes(["read:data"]),
    )
    .await?;
```

The client secret is optional. Pass `None` where the authorization
server authenticates axess through mTLS at the transport layer
instead, and configure the certificate on a `reqwest::Client` handed
to `with_http_client`.

The exchange runs through the IdP's token endpoint with the
RFC 8693 parameters; the IdP validates the subject token,
applies whatever exchange policy it has, and returns a
`TokenExchangeResponse`. Its `access_token` is a `ZeroizedString`
rather than a `String`, so the in-memory copy zeroes on drop; deref it
where the HTTP client wants a `&str`. The pattern is what most
enterprise IdPs support today (Azure AD, Okta, Auth0); the OBO chapter
covers it in detail from your side.

## Sender-constrained tokens

The FAPI 2.0 chapter (*FAPI 2.0*) covers DPoP and mTLS as ways to bind
an access token to a key the client controls. That machinery is
inbound: `SenderConstraint` is a field of `FapiConfig`, which applies
to an `OAuthProviderConfig` axess authenticates users against.

The outbound client does not generate DPoP proofs. Sender-constraining
an outbound call means one of two things instead. Either authenticate
to the token endpoint with `ClientAuthMethod::PrivateKeyJwt`, which
proves possession of a private key on every token request and removes
the shared secret a thief could replay; or present a client
certificate on the connection, which is *Outbound mTLS*, and ask the
IdP to bind the issued token to that certificate under RFC 8705.

Whether the second is available is the IdP's decision, not axess's:
the binding is recorded in the token's `cnf` claim by the issuer. Axess
presents the certificate; it does not verify that the issuer acted on
it.

## Threat model

The outbound OAuth flows have a smaller threat surface than the
inbound flows because you control both ends of the
trust relationship.

Against client credential theft: the credential lives in the
application's secrets store. Theft requires application-level
compromise, which has bigger problems than just the OAuth
credential.

Against access token theft in transit: TLS protects the wire. A
stolen token from a TLS-protected call requires breaking TLS,
which is not the OAuth client's defence to provide.

Against access token theft at rest: tokens are short-lived
(typically minutes) and held in process memory. A long-lived
refresh token (in the stored OBO case) is what carries longer
exposure; the encrypted credential store decorator covers that.

Against scope creep: the scopes parameter restricts what the
token can do. The discipline is to request the narrowest scopes
you need, so a compromised token has limited blast
radius.

## Troubleshooting

If the token endpoint returns `invalid_client`, the client
credentials are not what the IdP expects. The most common cause
is using `ClientSecretBasic` against an endpoint that wants the
credentials as form fields (`ClientSecretPost`), or a shared secret
where the IdP expects `PrivateKeyJwt`.

If the token endpoint returns `invalid_scope`, the requested
scopes are not authorised for this client. Check the client's
registration at the IdP to see which scopes are permitted.

If the downstream returns 401 on an apparently-fresh token, the
audience does not match what the downstream expects. Some IdPs
default a client-credentials token's audience to the client id
rather than to a resource URL. The builder exposes nothing to
override it, so the fix is at the IdP, either by registering the downstream as
a resource and requesting its scope (`.../.default` and similar) or
by configuring the default audience on the client registration.

If a call fails on a token that worked moments earlier, the IdP
revoked it before its stated expiry. The cache has no way to learn
this, so call `force_refresh` on a 401 and retry once before
surfacing the error.

## Further reading

*OAuth 2.0 and OIDC* covers the inbound OAuth machinery and the
shared OIDC primitives. *FAPI 2.0* covers DPoP and the
sender-constrained-token pattern. *Delegated and OBO access*
covers the higher-level OBO machinery that uses outbound OAuth
under the hood. *Operations runbook* covers client-credential
rotation and the DPoP key lifecycle.
