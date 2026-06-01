# Outbound: OAuth

This chapter covers the case where the application authenticates
itself as a workload against a downstream OAuth-protected service.
The application is the OAuth client; the downstream is the resource
server. The credential is an access token the application acquires
through one of the OAuth client flows (client credentials, token
exchange, or refresh of a stored token).

The chapter pairs with *Inbound: federation* and *Cloud STS
exchange*: those cover the inbound case where the application
accepts workload tokens; this covers the outbound case where the
application presents them.

The feature flag is `outbound-oauth` (off by default).

## When to use it

Three patterns lead to outbound OAuth.

The first is a service-to-service call between two services your
deployment owns, where the receiving service authenticates
inbound OAuth (typically through the generic `WorkloadResolver`
from *Inbound: federation*). The application's outbound
configuration mints a fresh token through the client-credentials
grant, sends it on the request, and the receiving service
validates it.

The second is a call to a SaaS service that requires OAuth (Slack,
Stripe, Twilio, an enterprise CRM). The application is registered
as an OAuth client at the SaaS, holds a client id and secret, and
mints tokens to call the SaaS's API.

The third is a call to a downstream service on a user's behalf,
where the credential is a token exchanged from the user's session
or from a stored refresh token. This is the OBO case, covered in
*Delegated and OBO access*; the outbound-oauth machinery in this
chapter is what `delegated-stored` and `delegated-exchange` use
under the hood.

## Configuration

`OutboundOAuthClient` is the type that mints tokens. The
configuration:

```rust,ignore
use axess::workload::outbound::{OutboundOAuthClient, OutboundOAuthConfig};

let client = OutboundOAuthClient::new(OutboundOAuthConfig {
    token_endpoint: "https://idp.example.com/oauth/token".parse().unwrap(),
    client_id: "billing-api-prod".into(),
    client_credential: ClientCredential::Secret("...".into()),
    scopes: vec!["https://api.downstream.example/.default".into()],
    audience: Some("https://api.downstream.example".into()),
});
```

`token_endpoint` is the OAuth server's token endpoint. The
endpoint typically comes from the OAuth server's discovery
document; the configuration is the resolved URL.

`client_credential` carries how the application authenticates to
the token endpoint. The variants are:

```rust,ignore
pub enum ClientCredential {
    Secret(ZeroizedString),
    JwtAssertion { signing_key: SigningKey, kid: String },
    Mtls,                         // client cert from outbound TLS
    SignedJwt { /* ... */ },
}
```

The `Secret` variant is the classic OAuth client secret. The
`JwtAssertion` variant is RFC 7523 (private_key_jwt
authentication), which is what FAPI-grade integrations use; the
application signs a short-lived assertion JWT with its private
key, and the token endpoint validates it against the registered
public key. The `Mtls` variant uses the outbound TLS connection's
client certificate as the authentication. The `SignedJwt` variant
covers cases where the JWT structure differs from RFC 7523.

`scopes` is the list of scopes requested. The narrowest possible
list is the recommendation; over-broad scopes leak privilege if
the resulting token is compromised.

`audience` is the optional audience parameter, used by some token
endpoints (Azure AD, Auth0, others that follow the same pattern)
to bind the resulting token to a specific resource.

## Minting tokens

The simple shape calls `mint_token` directly:

```rust,ignore
async fn call_downstream(
    client: &OutboundOAuthClient,
) -> Result<(), Error> {
    let token = client.mint_token().await?;

    let response = http_client
        .get("https://api.downstream.example/data")
        .header("Authorization", format!("Bearer {}", token.access_token))
        .send()
        .await?;
    Ok(())
}
```

Each `mint_token` call hits the token endpoint, exchanges the
client credentials, and returns the access token. The cost is one
round-trip per call.

The optimised shape caches the token for the duration of its
validity:

```rust,ignore
async fn call_downstream_cached(
    client: &CachedOutboundOAuthClient,
) -> Result<(), Error> {
    let token = client.get_cached().await?;
    // token is fresh or freshly-minted; cache handles the expiry.
    // ... use it
}
```

`CachedOutboundOAuthClient` is the cache wrapper. The cache uses
the same `ClockTtlCache` machinery the rest of axess uses; the
TTL is the token's `expires_in` value, minus a small buffer so a
token that expires mid-call is refreshed proactively.

The right shape depends on the call rate. Below a few calls per
minute, the simple shape works. Above that, the cache is worth
the complexity.

## Token exchange (RFC 8693)

The token-exchange flow is the alternative to client-credentials
when the outbound call is on behalf of an inbound principal
(human or workload). The application presents the inbound
credential to a token-exchange-capable IdP and receives a token
bound to the downstream audience.

```rust,ignore
use axess::workload::outbound::{TokenExchanger, ExchangeRequest};

let exchanger = TokenExchanger::new(/* ... */);

let token = exchanger.exchange(ExchangeRequest {
    subject_token: inbound_token,
    subject_token_type: "urn:ietf:params:oauth:token-type:jwt".into(),
    audience: "https://api.downstream.example".into(),
    scopes: vec!["read:data".into()],
}).await?;
```

The exchange runs through the IdP's token endpoint with the
RFC 8693 parameters; the IdP validates the subject token,
applies whatever exchange policy it has, and returns a token for
the requested audience. The pattern is what most enterprise IdPs
support today (Azure AD, Okta, Auth0); the OBO chapter covers it
in detail from the application's side.

## DPoP and sender-constrained tokens

The FAPI 2.0 chapter (*FAPI 2.0*) covers DPoP as a way to bind
access tokens to a key the client controls. The
outbound-oauth machinery supports DPoP through an opt-in
configuration:

```rust,ignore
let config = OutboundOAuthConfig {
    // ... standard configuration ...
    sender_constraint: Some(SenderConstraint::DPoP {
        key_provider: Box::new(my_dpop_key_provider()),
    }),
};
```

When `sender_constraint` is set, the client generates a DPoP
proof on each call, signed with the configured key, and attaches
it to the request along with the access token. The downstream
validates the proof, matches the key thumbprint against the
token's binding, and serves the request.

The cost is one extra HTTP header per call plus a signature. The
benefit is that a stolen access token is unusable without the
DPoP key, which the client never transmits.

## Threat model

The outbound OAuth flows have a smaller threat surface than the
inbound flows because the application controls both ends of the
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
the application needs, so a compromised token has limited blast
radius.

## Troubleshooting

If the token endpoint returns `invalid_client`, the client
credentials are not what the IdP expects. The most common cause
is using `Secret` against an endpoint that requires
`JwtAssertion`, or vice versa.

If the token endpoint returns `invalid_scope`, the requested
scopes are not authorised for this client. Check the client's
registration at the IdP to see which scopes are permitted.

If the downstream returns 401 on the apparently-fresh token, the
audience does not match the downstream's expected audience. Some
IdPs default the audience to the client id rather than to a
resource URL; set the `audience` parameter explicitly.

## Further reading

*OAuth 2.0 and OIDC* covers the inbound OAuth machinery and the
shared OIDC primitives. *FAPI 2.0* covers DPoP and the
sender-constrained-token pattern. *Delegated and OBO access*
covers the higher-level OBO machinery that uses outbound OAuth
under the hood. *Operations runbook* covers client-credential
rotation and the DPoP key lifecycle.
