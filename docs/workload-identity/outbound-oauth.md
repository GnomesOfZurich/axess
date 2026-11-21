# Outbound: OAuth

Your application authenticates as a workload to a
downstream OAuth-protected service.
The application is the OAuth client; the downstream is the resource
server. The credential is an access token you acquire
through one of the OAuth client flows (client credentials, token
exchange, or refresh of a stored token).

The chapter pairs with *Inbound: federation*, which covers the
inbound case where the application accepts workload tokens, and with
*Cloud STS exchange*, which trades a workload identity for cloud
provider credentials. This chapter covers the outbound case where the
application presents a token to an OAuth-protected service.

The feature flag is `outbound-oauth` (off by default).

## When to use it

Three patterns lead to outbound OAuth.

**A service-to-service call** between two services your
deployment owns, where the receiving service authenticates
inbound OAuth (typically through the generic `WorkloadResolver`
from *Inbound: federation*). The application fetches a token through the client-credentials
grant and sends it on the request; the receiving service validates it.

**A call to a SaaS service** that requires OAuth (Slack,
Stripe, Twilio, an enterprise CRM). The application is registered
as an OAuth client at the SaaS, holds a client id and secret, and
fetches tokens to call the SaaS's API.

**A call on a user's behalf** to a downstream service,
where the credential is a token exchanged from the user's session
or from a stored refresh token. This is the OBO case, covered in
*Delegated and OBO access*; the outbound-oauth machinery in this
chapter is what `delegated-stored` and `delegated-exchange` build
on.

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
)?
.with_scopes(["https://api.downstream.example/.default"]);
```

`new` returns an error for a token URL that is not HTTPS, since the
request carries the client secret. The default HTTP client is built by an
`EgressPolicy`: it follows no redirects and has connect and request
timeouts. `new` uses `EgressPolicy::screened()`: the token URL may not be a
reserved address (`localhost` included), and the token request follows no
proxy from the environment and connects to no reserved address.
`new_screened(url, method, policy)` names another policy:
`EgressPolicy::unscreened()` for a token endpoint on the deployment's own
network, `EgressPolicy::screened_allowing_loopback_http()` for a mock on
loopback in tests. Plain HTTP is accepted only under these two, and only
to a loopback host (`localhost`, or a loopback address such as
`127.0.0.1` or `[::1]`). `OutboundOAuthClient` accepts no HTTP client the caller built:
`with_client_settings` adds a `User-Agent`, a trusted root certificate, a
client certificate or timeouts to the client the policy builds, and
nothing it offers can undo the redirect rule, the proxy rule or the
connect-time screen. A token
fetch times out after `with_request_timeout` (30 seconds by default), holds
no lock on the cache, and is shared between callers that arrive together.

The first argument is the OAuth server's token endpoint. It typically
comes from the server's discovery document; pass the resolved URL.

The client authenticates to that endpoint with a `ClientAuthMethod`:

```rust,ignore
pub enum ClientAuthMethod {
    ClientSecretBasic { client_id: String, client_secret: ZeroizedString },
    ClientSecretPost  { client_id: String, client_secret: ZeroizedString },
    PrivateKeyJwt(Box<ClientAssertionSigner>),
}
```

`ClientSecretBasic` puts `client_id` and `client_secret` in an
`Authorization: Basic` header, which is what most off-the-shelf IdPs
expect (Okta, Auth0, Entra). `ClientSecretPost` sends the same pair as
form fields, which some older IdPs require instead; check the IdP's
documentation. Both secrets are zeroized on drop.

`PrivateKeyJwt` (RFC 7523) is the method for a FAPI-grade
integration: axess signs a short-lived assertion with its
private key and the IdP validates it against the published JWKS, so
there is no shared secret to rotate. It takes the same
`ClientAssertionSigner` the user login uses, with its `kid`, `x5t` and
`x5t#S256` headers (Microsoft Entra finds a certificate credential by the
thumbprint). The assertion's `aud` is the token URL unless the signer sets
another with `with_audience`. Per RFC 7523 §3 it is a value the IdP recognises
as naming itself: usually the token endpoint URL, though some IdPs want their
`issuer` URL instead. It does not name the downstream API. The signer signs
one assertion when it is built, so a key that does not suit its algorithm
fails at startup rather than on the first call.

```rust,ignore
let signer = ClientAssertionSigner::from_pem(client_id, &private_key_pem, Algorithm::PS256)?
    .with_x5t_s256(certificate_thumbprint);
let client = OutboundOAuthClient::new(token_url, ClientAuthMethod::PrivateKeyJwt(Box::new(signer)))?;
```

An RSA key (`RS*`, `PS*`) signs on the `jwt-aws-lc` backend, where axess
installs `jsonwebtoken`'s aws-lc crypto provider. Anywhere else its
signature may run in `rsa` 0.9, whose private-key operations leak timing
(RUSTSEC-2023-0071): on `jwt-rust-crypto` alone, and in a build that
compiles both backends when the application or another crate installed a
provider before axess did. With both compiled, that provider may be
RustCrypto's, and `jsonwebtoken` cannot report which one is in place. In
those builds `from_pem`, `from_spec` and `new` refuse an RSA algorithm with
`ClientAssertionError::RsaNotChosen` before the key is read, unless the build
opts in with the `client-assertion-rsa` feature. To sign RSA in aws-lc-rs,
build with `jwt-aws-lc` and leave installing the provider to axess. An
ES256, ES384 or EdDSA key needs neither feature.

mTLS is not a variant here. Outbound client-certificate
authentication is a property of the connection rather than of the token
request; see *Outbound mTLS*.

The rest of the builder is small: `with_scopes` sets the requested
scopes, `with_refresh_threshold` moves the cache's refresh point
(default 30 seconds before expiry), `with_clock` and `with_rng`
substitute the ambient dependencies for deterministic tests, and
`with_client_settings` names a `User-Agent`, a private root, timeouts or
an outbound-mTLS certificate for the HTTP client.

Request the narrowest scopes that work; over-broad scopes leak
privilege if the token is compromised.

There is no audience parameter. The builder does not cover token endpoints that bind a token to a
specific resource through a non-standard `audience` form field (Auth0,
some Azure AD configurations); where the
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

`OutboundOAuthClient` always caches the token itself; there is no wrapper to
add. The first call
fetches and stores the response under a write lock, later calls inside
the validity window read it under a read lock, and the window ends
`refresh_threshold` before `expires_in` so a token does not expire
mid-flight. Call it per request rather than holding the returned
`String`; the client then handles the refresh.

A refresh that fails while the cached token is still unexpired is not
an error: the token is returned until it expires and each later call
tries the endpoint again, so a short outage at the IdP does not fail
every outbound call at once. Callers that waited for one fetch share
its outcome rather than fetching in turn.

`force_refresh` condemns the cached token and fetches its replacement.
Call it when the downstream rejects a token it accepted before, since the
IdP may have revoked it early. From that call on, no caller receives the
condemned token, either during the fetch or after a failed one. `force_refresh_of(&token)` condemns only the token the
401 was about, so a rejection reported after another caller already
replaced the token keeps the replacement instead of fetching again.

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
)?;

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
instead, and name the certificate with
`with_client_settings(|settings| settings.client_certificate(identity))`.

The exchange runs through the IdP's token endpoint with the
RFC 8693 parameters; the IdP validates the subject token,
applies whatever exchange policy it has, and returns a
`TokenExchangeResponse`. Its `access_token` is a `ZeroizedString`
rather than a `String`, so the in-memory copy zeroes on drop; deref it
where the HTTP client wants a `&str`. Most enterprise IdPs
support it (Azure AD, Okta, Auth0); *Delegated and OBO access* covers it
in detail.

## Sender-constrained tokens

*FAPI 2.0* covers DPoP and mTLS as ways to bind
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
the issuer records the binding in the token's `cnf` claim. Axess
presents the certificate; it does not verify that the issuer acted on
it.

## Threat model

For a service-to-service call, the outbound OAuth flows have a smaller
threat surface than the inbound flows because your deployment controls
both ends of the trust relationship. A SaaS downstream and its IdP are
outside your control; the threats below concern your end in either case.

Against client credential theft: the credential lives in the
application's secrets store. Theft requires compromising the application, at which point the
OAuth credential is the lesser problem.

Against access token theft in transit: TLS protects the wire. Stealing
a token from a TLS-protected call requires breaking TLS, which is
not the OAuth client's defence to provide.

Against access token theft at rest: tokens are short-lived
(typically minutes) and held in process memory. A long-lived
refresh token (in the stored OBO case) is what carries longer
exposure; the encrypted credential store decorator covers that.

Against scope creep: the scopes parameter restricts what the
token can do. Request the narrowest scopes
you need, so a compromised token has a limited blast radius.

## Troubleshooting

If the token endpoint returns `invalid_client`, the client
credentials are not what the IdP expects. The most common cause
is using `ClientSecretBasic` against an endpoint that wants the
credentials as form fields (`ClientSecretPost`), or a shared secret
where the IdP expects `PrivateKeyJwt`.

If the token endpoint returns `invalid_scope`, the requested
scopes are not authorised for this client. Check the client's
registration at the IdP to see which scopes are permitted.

If the downstream returns 401 on every fresh token, from the first
call on, the audience does not match what the downstream expects. Some IdPs
default a client-credentials token's audience to the client id
rather than to a resource URL. The builder cannot override it, so fix it at
the IdP: register the downstream as a resource and request its scope
(`.../.default` and similar), or configure the default audience on the
client registration.

If a call fails on a token that worked moments earlier, the IdP
revoked it before its stated expiry. The cache has no way to learn
this, so call `force_refresh_of` with the rejected token on a 401 and
retry once before surfacing the error.

## Further reading

*OAuth 2.0 and OIDC* covers the inbound OAuth machinery and the
shared OIDC primitives. *FAPI 2.0* covers DPoP and the
sender-constrained-token pattern. *Delegated and OBO access*
covers the higher-level OBO machinery built on outbound OAuth. *Operations runbook* covers client-credential
rotation and the DPoP key lifecycle.
