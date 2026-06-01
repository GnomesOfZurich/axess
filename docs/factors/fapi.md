# FAPI 2.0

FAPI is the OpenID Foundation's Financial-grade API profile, a set
of additional requirements on top of OAuth 2.0 and OIDC that address
the threat model of regulated financial APIs. The headline
differences from baseline OAuth are mandatory Pushed Authorization
Requests (PAR), mandatory sender-constrained tokens through DPoP or
mTLS, optional JWT Authorization Response Mode (JARM), and stricter
ID token lifetime bounds. This chapter walks through what FAPI adds,
how axess exposes it, and when to reach for it.

The feature flag is `fapi` (off by default), which implies `oauth`.
The base OAuth chapter (*OAuth 2.0 and OIDC*) covers everything that
remains true under FAPI; this chapter covers only what changes.

## Axess is the Relying Party, not the OP

A FAPI deployment has two parties. The **OpenID Provider** (OP, also
called the IdP) owns user identity, runs the login UI, and issues
tokens; in open-banking this is typically the bank's own SSO or a
hosted Keycloak / Ory Hydra / Curity instance. The **Relying Party**
(RP) is the application that delegates identity to the OP, accepts
the resulting tokens, and runs a session on top. Axess fills the RP
role. PAR, DPoP, JARM, and RP-Initiated Logout are all RP-side
protocols that exist to talk to an external OP; without an OP to talk
to, none of them make sense.

This is a deliberate architectural choice. Building a FAPI-conformant
OP is a multi-year project (Keycloak, Hydra, Curity, and the
commercial vendors are the established options) and is largely
disjoint from the RP-side machinery axess provides (sessions, MFA
verifiers, Cedar authorization). The verifier-vs-orchestrator split
in the workspace (covered in *Architecture at a glance*) is the
internal expression of the same boundary; axess does not become the
OP, and adopters are expected to point at one. The
[`examples/fapi/`](https://github.com/GnomesOfZurich/axess/tree/main/examples/fapi)
crate ships a pre-configured Keycloak realm in a podman container as
a quick way to get an OP locally for the demo, but in production the
issuer URL would point at whatever OP your organisation already runs.

The `local-idp` feature is the one place axess does issuance, but
that is on-host workload-identity issuance (service-to-service flows
where a sidecar mints JWTs for its own workloads), not a
user-facing OP. *Local IdP* covers that surface.

## What FAPI changes

The four headline mechanisms address four specific gaps in baseline
OAuth.

Pushed Authorization Requests (PAR, RFC 9126) move the authorization
parameters off the redirect URL. Instead of the application
constructing a query-string-laden authorize URL and redirecting the
user to it, the application makes a direct POST to the IdP's PAR
endpoint containing the parameters, receives an opaque `request_uri`
in return, and constructs a much shorter authorize URL containing
only the client id and the request URI. The defence is twofold: the
authorization parameters never appear in browser history or referer
headers, and the parameters cannot be tampered with in transit
because the user only carries a reference to them.

DPoP (Demonstration of Proof of Possession, RFC 9449) binds the
access token to a key pair the client controls. Each request the
client makes to a protected resource carries a JWT signed with the
client's DPoP key, and the token validator at the resource server
checks that the access token was issued for a thumbprint of that
key. The defence is against bearer-token theft: an attacker who
captures the access token (from logs, a misconfigured proxy, a
debugging surface) cannot use it without also having the DPoP
private key, which never leaves the client.

JARM (JWT Authorization Response Mode) is the optional FAPI 2.0
recommendation that the IdP return the authorization response as a
signed JWT instead of as query parameters. The defence is integrity:
the response cannot be tampered with after the IdP issues it. JARM
is optional in FAPI 2.0; some implementations use it, others do not.

Stricter ID token bounds: FAPI 2.0 requires the ID token's `nbf`
(not-before) claim to be enforced and the lifetime to be no longer
than a short window (axess defaults to five minutes, and refuses
ID tokens with `nbf` in the future or `exp` more than five minutes
out). The defence is against replay through stale tokens.

## When to reach for FAPI

The honest answer is: when a regulator requires it. FAPI 2.0 was
designed for the open-banking ecosystem and similar regulated
financial APIs, and adopting it imposes operational complexity
(every client needs DPoP key management, every authorize call goes
through PAR, every IdP must support the PAR endpoint) that is
substantial relative to the security benefit for non-regulated
deployments. A consumer-facing SaaS that takes credit card payments
through Stripe does not need FAPI; an open-banking application that
acts as an account-information service provider does.

The decision is binary: either you need FAPI because someone is
asking you for compliance evidence, or you do not. If you do, the
mechanisms below are non-negotiable, and axess implements them. If
you do not, the baseline OAuth chapter covers what you need.

## Configuration

FAPI is enabled per-provider by attaching a `FapiConfig` to an
`OAuthProviderConfig`:

```rust,ignore
use axess::factors::oauth::{FapiConfig, SenderConstraint, OAuthProviderConfig};

let fapi_config = FapiConfig {
    sender_constraint: SenderConstraint::DPoP,
    require_jarm: false,
    max_id_token_lifetime_secs: 300,
};

let provider = OAuthProviderConfig::discover(
    "https://idp.example.com/.well-known/openid-configuration",
    client_id,
    client_secret,
    redirect_uri,
)
.await?
.with_fapi(fapi_config);
```

`sender_constraint` chooses between DPoP and mTLS for the
sender-constrained-tokens requirement. DPoP is the right choice for
applications that already manage HTTPS in software; mTLS is the
right choice for applications that already manage X.509 certificates
for service-to-service authentication. The two cannot be combined
on a single provider, but different providers in the same
application can use different constraints.

`require_jarm` toggles JARM enforcement. When true, the authorization
response from the IdP must arrive as a signed JWT; the
configuration's `oidc.discovery.jwks_uri` is used to verify the
signature. When false, the IdP may return the response as query
parameters as in baseline OAuth.

`max_id_token_lifetime_secs` is the upper bound on ID token validity.
The FAPI default is three hundred seconds (five minutes), which is
short enough that a captured token expires before most replay attacks
can succeed and long enough that clock skew does not cause spurious
rejections.

## The PAR flow

With FAPI enabled, the application starts a federated login through
the PAR-enhanced auth URL rather than the query-parameter auth URL:

```rust,ignore
let auth_url = service
    .begin_oauth_login(&session, "fapi-provider", OAuthLoginOptions::default())
    .await?;
// auth_url looks like:
//   https://idp.example.com/authorize?client_id=...&request_uri=urn:ietf:params:oauth:request_uri:...
```

Internally, `begin_oauth_login` detects the FAPI configuration and
takes the PAR branch. The branch performs a POST to the IdP's PAR
endpoint with the full set of authorization parameters (client id,
redirect URI, scopes, PKCE challenge, CSRF state, nonce), receives
the `request_uri` and its `expires_in`, and constructs the
shorter authorize URL the user is redirected to.

The PAR exchange happens server-to-server and is authenticated. The
authentication is whatever the IdP requires (client secret POST,
client secret basic, mTLS, or signed JWT assertion); axess passes
through the credential that `OAuthProviderConfig` was constructed
with.

The callback flow on the application side is unchanged. The IdP
redirects the user back to the application's callback URL with a
code; the application calls `finish_oauth_login` with the code and
state; axess performs the token exchange and ID token validation.

## DPoP key management

DPoP binds each access token to a public key the client controls.
The application generates a key pair at session start (or at
application start, for some deployments), uses the private key to
sign a DPoP proof JWT on each request to a protected resource, and
the resource server verifies the proof and matches the JWK
thumbprint against the access token's binding.

Axess exposes the proof-generation primitive through
`OAuthProvider::generate_dpop_proof`:

```rust,ignore
let proof: DpopProof = provider.generate_dpop_proof(
    "GET",                                         // HTTP method
    "https://resource.example.com/data",           // target URL
    Some(&access_token),                           // bind to this access token
    &dpop_key,                                     // the application's key
)?;

let response = http_client
    .get("https://resource.example.com/data")
    .header("Authorization", format!("DPoP {}", access_token))
    .header("DPoP", &proof.proof_jwt)
    .send()
    .await?;
```

The proof JWT contains the HTTP method, the target URL, a nonce, a
timestamp, and the thumbprint of the binding key. The resource
server checks all of these against the access token's `cnf`
(confirmation) claim, which carries the thumbprint at token
issuance.

Key lifecycle is the operational concern. A DPoP key pair generated
per session is the safest choice (a compromised session is bounded
to one key); a key pair generated per application instance is the
easiest choice (one key to manage). The trade-off is between blast
radius and operational complexity. Most deployments choose
per-session keys for high-sensitivity flows and per-instance keys
for routine flows.

## Token revocation

FAPI 2.0 expects that compromised tokens can be revoked through the
IdP's revocation endpoint (RFC 7009). The application calls
revocation when the user logs out, when a session is administratively
ended, or when token theft is detected. Axess exposes revocation
through `OAuthProvider::revoke_token`:

```rust,ignore
provider.revoke_token(&access_token, Some(TokenTypeHint::AccessToken)).await?;
provider.revoke_token(&refresh_token, Some(TokenTypeHint::RefreshToken)).await?;
```

The revocation endpoint, when present in the discovery document, is
called with the token to revoke and an optional type hint. The IdP
responds with a 200 regardless of whether the token was actually
revoked (intentionally, to defeat token-existence enumeration).

Revoking the refresh token is the more important call. The access
token typically has a short lifetime (matching the FAPI ID token
bound) and expires on its own; the refresh token has a longer life
and an unrevoked one allows continued access through new access
tokens. A logout that revokes only the access token leaves the
refresh token active, which is rarely what the application wants.

## Testing FAPI flows

There are three useful test modes, picked by what you want to
exercise.

For Rust unit and integration tests, the FAPI feature pairs with the
`local-idp` feature. The `LocalIdpFixture` in `axess-core::testing::local_idp`
mints FAPI-grade tokens with the right `nbf`/`exp` bounds and exposes
a shared `JwkSet` handle that a `JwtVerifier` borrows for signature
verification. The fixture is an in-process value, not an HTTP service:
PAR and discovery endpoints are not part of its surface. For FAPI
flows that need a real PAR exchange, use Keycloak or another OP (see
the end-to-end walkthrough below). The pattern for unit tests is to
write against an `OAuthProvider` trait object, parameterise it over
fixture and live, and run both in CI. *Local IdP* covers the fixture
in detail.

For an end-to-end browser walkthrough, the [`examples/fapi/`](https://github.com/GnomesOfZurich/axess/tree/main/examples/fapi)
crate ships with a pre-configured Keycloak realm under
`examples/fapi/keycloak/`. One `podman compose up -d` brings up
Keycloak with PAR required, PKCE S256 required, DPoP-bound tokens
enabled, the `axess-fapi-client` client registered, and a seeded
user (`alice`/`alice`) ready to log in. The example's
`OAuthProviderConfig::discover(...)` call points at the local
Keycloak issuer through env vars, and the same code talks to a real
production IdP when those env vars point elsewhere. Docker users can
substitute `docker compose` for `podman compose`; podman is the
documented path.

For compliance certification, the OpenID Foundation runs a free
hosted conformance suite at <https://www.certification.openid.net/>.
It acts as a scripted OP that drives an RP through the full FAPI 2.0
test matrix including adversarial cases (missing PAR, bad DPoP,
replay, wrong audience). Point it at the example's `/auth/callback`
to produce a certifiable artifact; use Keycloak for everyday
development.

## Threat model

FAPI 2.0 closes the attacks baseline OAuth leaves open in regulated
contexts.

Against authorization-parameter tampering: PAR moves the parameters
off the URL, so they cannot be modified by an intermediary.

Against bearer-token theft: DPoP (or mTLS) binds tokens to keys the
attacker does not have, so a captured token is unusable.

Against ID token replay through stale tokens: the strict lifetime
bound shrinks the replay window to minutes.

The attacks FAPI does not close are the same ones baseline OAuth
does not close: a compromised IdP issues compromised tokens
regardless of the profile, and a compromised client device gives
the attacker access to the DPoP private key alongside everything
else.

## Troubleshooting

If the PAR exchange fails with `invalid_client`, the application's
PAR endpoint authentication does not match what the IdP expects.
Some IdPs require mTLS authentication on PAR even when the rest of
the flow uses client secrets; check the IdP's PAR documentation.

If DPoP verification fails at the resource server, the most common
cause is a clock-skew issue between the client and the resource
server. The DPoP proof's timestamp is checked within a small window
(a few seconds typically); larger skew triggers spurious failures.
Synchronise both sides against the same NTP source.

If JARM verification fails, the signing key the IdP uses for JARM
may differ from the key used for ID token signing. Some IdPs
publish separate JWKS for the two; the discovery document should
indicate this, but configurations occasionally miss it. Inspect the
discovery document.

## Further reading

*OAuth 2.0 and OIDC* covers the base OAuth machinery this chapter
extends. *Workload identity overview* covers the resolver side of
OAuth, where axess is the resource server rather than the client.
*Local IdP* covers the test fixture for FAPI-grade
integration testing.
