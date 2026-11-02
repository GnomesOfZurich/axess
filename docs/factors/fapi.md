# FAPI 2.0

FAPI is the OpenID Foundation's Financial-grade API profile, a set
of additional requirements on top of OAuth 2.0 and OIDC that address
the threat model of regulated financial APIs. The headline
differences from baseline OAuth are mandatory Pushed Authorization
Requests (PAR), mandatory sender-constrained tokens through DPoP or
mTLS, optional JWT Authorization Response Mode (JARM), and stricter
ID token lifetime bounds.

> **Scope.** Axess is the relying party. `OAuthProviderBuilder::with_fapi`
> switches the profile on for a provider: the token request is
> sender-constrained (a DPoP proof, or a client certificate), the client
> authenticates by `private_key_jwt` or mTLS and never by a secret, the ID
> token is held to the profile's lifetime, `nbf` and algorithm rules, and the
> authorization response can be required to arrive as a signed JWT (JARM).

The `oauth` feature carries the whole client side of the profile and the
resource-server side of DPoP, `verify_dpop_proof`. The `fapi` feature is an
alias for it.
The base OAuth chapter (*OAuth 2.0 and OIDC*) covers everything that
remains true under FAPI; this chapter covers only what changes.

## Whether FAPI applies to you

What the profile is, what it demands, and who needs it.

### Axess is the Relying Party, not the OP

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

### What FAPI changes

Four mechanisms, each closing a specific gap in baseline OAuth.

#### PAR: parameters off the redirect URL

Pushed Authorization Requests ([RFC 9126]) POST the authorization
parameters straight to the IdP, which returns an opaque `request_uri`.
The authorize URL then carries only the client id and that reference.

Two gaps close at once: the parameters never reach browser history or a
referer header, and the user cannot tamper with what they are only
holding a reference to.

#### DPoP: tokens bound to a key

DPoP ([RFC 9449]) binds the access token to a key pair the client holds.
Every request carries a JWT signed with that key, and the resource server
checks the access token was issued for its thumbprint.

That defeats bearer-token theft. An attacker who lifts the token from
logs, a misconfigured proxy or a debugging surface cannot use it without
the private key, which never leaves the client.

DPoP is not FAPI-only. Outside the profile a provider binds its tokens to
a DPoP key by default whenever the IdP advertises DPoP, whatever the client
authenticates with; [OAuth 2.0 and OIDC](oauth.md#binding-tokens-to-a-key-dpop)
covers that. FAPI builds on the same binding and makes it unconditional: on
whether or not the IdP advertises it, with the code bound too through PAR,
and with no way to switch it off.

#### JARM: signed authorization responses

The IdP returns the authorization response as a signed JWT rather than
query parameters, so it cannot be tampered with after issuance. Optional
in FAPI 2.0; some implementations use it, some do not.

#### Short ID token windows

Axess refuses an ID token whose `exp` is more than five minutes after its
`iat` (the default of `max_id_token_lifetime_secs`), which narrows replay
through stale tokens, and one whose `nbf` is more than 60 seconds in the
future, the rule FAPI 2.0 (section 5.3.2.1) sets for every JWT. `nbf` is
optional: neither OpenID Connect nor FAPI 2.0 requires it in an ID token,
and Keycloak issues none.

[RFC 9126]: https://www.rfc-editor.org/rfc/rfc9126
[RFC 9449]: https://www.rfc-editor.org/rfc/rfc9449

### When to reach for FAPI

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

## The mechanisms

The four things FAPI adds over ordinary OAuth.

### Configuration

`FapiConfig` describes the profile and `OAuthProviderBuilder::with_fapi`
attaches it to the builder `discover` returns. It is the only way to turn the
profile on, and `build` either returns a provider that keeps all of it or an
`OAuthError::Config` naming what is missing, whatever order the settings
came in.

```rust,ignore
use axess::federation::oauth::{FapiConfig, SenderConstraint};

let provider = builder
    .with_par_endpoint("https://idp.example.com/par") // if discovery did not find it
    .with_fapi(FapiConfig {
        sender_constraint: SenderConstraint::DPoP,
        require_jarm: true,
        ..FapiConfig::default()
    })
    .build()?;
```

* `sender_constraint` chooses DPoP or mTLS, below.
* `require_jarm` makes the authorization request ask for `response_mode=jwt`
  and the callback finish through `finish_oauth_login_jarm`, below. A plain
  `finish_oauth_login` for such a provider is refused and ends the ceremony.
* `max_id_token_lifetime_secs` bounds `exp - iat` of the ID token (300 by
  default), and an `nbf`, when present, must not be more than 60 seconds in
  the future.
* `allowed_id_token_algs` lists the JOSE names an ID token may be signed
  with: `PS256`, `ES256` and `EdDSA` by default, whatever the IdP advertises
  in `id_token_signing_alg_values_supported`. An IdP that cannot sign with
  those is a deployment decision to widen this list, knowingly: the profile
  does not accept `RS256`. Symmetric names and `none` are refused, and so is an
  empty list. With `with_id_token_signing_algs` as well, the provider accepts
  the algorithms both lists name, and `build` refuses a pin the profile shares
  nothing with.
* A PAR endpoint is required. `begin_oauth_login` then pushes the
  authorization request there.
* The client authenticates by `private_key_jwt` or mTLS, never by a
  client secret, below.

### Client authentication

FAPI 2.0 (Security Profile section 5.3.1.1) allows two ways for the
client to prove its identity to the authorization server:
`private_key_jwt` (RFC 7523) and mTLS (`tls_client_auth` or
`self_signed_tls_client_auth`, RFC 8705). A shared secret, sent in the
form or in a Basic header, is not one of them. `build` therefore
refuses, with an `OAuthError::Config` naming both methods, a provider
that holds neither a `private_key_jwt` signer nor an mTLS sender
constraint, and drops any secret the provider was discovered with. No
request a FAPI provider makes (the pushed authorization request, the
code exchange, the refresh, `client_credentials`, the device grant,
revocation) carries a secret; userinfo never did.

**`private_key_jwt`.** Give the provider its signer: discover it with
`discover_with_private_key_jwt`, or call `with_private_key_jwt` on the
builder `discover` returns, before or after `with_fapi`. Each
request then carries a fresh `client_assertion` signed for the issuer as
audience (section 5.3.2.1), unless the signer fixed another with
`ClientAssertionSigner::with_audience`. Sign with `PS256`, `ES256` or
`EdDSA`. The [OAuth chapter](oauth.md) covers the signer, its key
formats and the `kid` and thumbprint headers.

```rust,ignore
use axess::federation::oauth::{ClientAssertionSigner, FapiConfig, OAuthProviderConfig};

let signer = ClientAssertionSigner::from_pem(client_id, &private_key_pem, jsonwebtoken::Algorithm::ES256)?
    .with_key_id("2026-11");
let provider = OAuthProviderConfig::discover_with_private_key_jwt(
    "bank", issuer, signer, "https://app.example.com/auth/callback",
)
.await?
.with_fapi(FapiConfig::default()) // DPoP-bound tokens, assertion-authenticated client
.build()?;
```

**mTLS.** Choose `SenderConstraint::Mtls` with the certificate and key
paths. The certificate both authenticates the client and binds its
tokens, so no signer is needed; the requests carry `client_id` and the
handshake carries the proof. A signer added as well authenticates by
assertion over the same TLS connection.

The order of the builder calls never matters: nothing brings a secret back
under the profile, and a provider that would authenticate by its secret is
refused by `build`.

### Sender-constrained token requests

**DPoP.** The profile turns on the provider's one DPoP switch, the one
discovery turns on for an IdP that advertises DPoP, so everything below is
also what a provider outside the profile does when it binds its tokens.
Under the profile it is on whatever the discovery document says, and
`build` refuses `without_dpop()`. For each login the service makes a `DpopKey` from its `SecureRng` and
the token request carries a `DPoP` header: a proof with `htm` POST, `htu` the
token endpoint, a fresh `jti` and `iat` from the provider's clock. When the
server answers `use_dpop_nonce` with a `DPoP-Nonce` header the request is sent
once more with a proof that echoes the nonce. The response must say
`token_type` `DPoP`; a `Bearer` answer is refused, and so is an access token
that is a JWT with a `cnf.jkt` other than the key's thumbprint. The key comes
back as `OAuthClaims::dpop_key`.

Refresh and userinfo calls are bound to the same key:
`refresh_oauth_token` and `fetch_userinfo` take it as `dpop_key`, sign their
requests with it, and send the access token under the `DPoP` authorization
scheme with a proof that carries the token's hash. A provider configured for
DPoP refuses them given no key (`OAuthError::DpopKeyRequired`), since they
would send the token unbound.

The key is the caller's to keep: axess does not store it. Store
`DpopKey::to_seed_bytes` beside the refresh token and restore it with
`DpopKey::from_seed` in the process that refreshes; see
[DPoP key management](#dpop-key-management).

**mTLS.** `build` reads the certificate and key (PEM) from the configured
paths into the HTTP client every request goes through, so a TLS server that
asks for a client certificate gets one. The client authenticates with the
certificate (`tls_client_auth`), so the configured client secret is no longer
sent. When the discovery document has `mtls_endpoint_aliases`, the token,
userinfo, revocation and PAR requests go to the aliases it lists, including
an endpoint named with `with_par_endpoint` or `with_revocation_endpoint`.
Missing or unreadable files, a bad PEM, or an alias that is not an HTTPS URL
fail `build`, not the first login. The tokens are certificate-bound but say
`Bearer`, as RFC 8705 has it. Under mTLS DPoP is off, even where the IdP
advertises it, and `build` refuses `with_dpop()`: the certificate is the binding.

### JARM

With `require_jarm` the authorization response is a signed JWT in the
`response` parameter of the callback. Finish the login with
`finish_oauth_login_jarm(response, &session)`. The JWT is verified against the
provider's key set with the profile's algorithms (never `none`, never a
symmetric one): `iss` must be the provider's issuer, `aud` this client, and
`exp` is required and enforced. A stale key set is refreshed once. The `code`,
`state` and `iss` inside then go through the same checks as
`finish_oauth_login_with_iss`, with `iss` required; a response carrying
`error` ends the ceremony.

### The PAR flow

With FAPI enabled, you start a federated login through
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

With DPoP as the sender constraint, the login's key is made at begin:
the pushed request names it in `dpop_jkt` and carries a DPoP proof
signed by it (RFC 9449 sections 10 and 10.1), so the authorization
server binds the code to the key before the token request presents it,
and a PAR endpoint that answers `use_dpop_nonce` is retried once with
its nonce. The key travels in the session's ceremony state, beside the
PKCE verifier, and the token request at `finish_oauth_login` presents
it; `OAuthClaims::dpop_key` carries it back as before. On the trait,
`build_auth_url_par` and `push_authorization_request` take the signer in
their `dpop` argument; without one they push no `dpop_jkt` and no proof,
which the RFC leaves optional since the token request binds the code.

The PAR exchange happens server-to-server and is authenticated the way
every request of a FAPI provider is: by a `private_key_jwt` assertion
(audience the issuer) or by the mTLS client certificate, never by a
client secret (see Client authentication above).

The callback flow on your side is unchanged. The IdP
redirects the user back to your callback URL with a
code; you call `finish_oauth_login` with the code and
state; axess performs the token exchange and ID token validation.

### DPoP key management

DPoP binds each access token to a public key the client controls
(`cnf.jkt` in the token). RFC 9449 requires every proof presented with that
token to be signed by that one key: a proof from any other key does not match
the binding.

`DpopKey` is that key. A login against a DPoP provider makes it for you and
returns it in `OAuthClaims::dpop_key`; keep it for as long as the token lives
(`to_seed_bytes` exports the scalar for storage next to the token, and
`from_seed` restores it), and pass it by reference to every proof and to the
refresh and userinfo calls. `AuthnService::new_dpop_key` draws one from the
service's `SecureRng` for the cases where you make the key yourself.
`thumbprint` returns the RFC 7638 thumbprint, which is the `jkt` the
authorization server binds the token to. `Debug` prints the thumbprint only,
never the scalar.

`AuthnService::generate_dpop_proof` builds a proof with the key. It draws the
`jti` from the service's `SecureRng` and stamps `iat` from the service's
`Clock`, so a seeded RNG and a mock clock reproduce the proof exactly. The
provider trait method it calls, `OAuthProvider::generate_dpop_proof`, takes the
key, `iat` and `jti_bytes` as arguments and reads neither a clock nor a random
source itself.

```rust,ignore
let key = claims.dpop_key.expect("a DPoP login returns its key"); // kept for the token's life

let proof: DpopProof = authn.generate_dpop_proof(
    "bank",                                        // provider name
    &key,                                          // the token's key
    "GET",                                         // HTTP method
    "https://resource.example.com/data",           // target URL
    Some(&access_token),                           // bind to this access token
)?;

let response = http_client
    .get("https://resource.example.com/data")
    .header("Authorization", format!("DPoP {}", access_token))
    .header("DPoP", &proof.proof_jwt)
    .send()
    .await?;
```

The proof JWT contains the HTTP method, the target URL, a unique `jti`, an
`iat` timestamp, the hash of the access token (`ath`) when one is passed, and
the public key in its header. Two proofs from one key for different URLs
carry the same thumbprint. The resource server checks all of these against the
access token's `cnf` (confirmation) claim.

Key lifecycle is the operational concern. A key per session bounds a
compromised session to one key; a key per application instance is easier to
manage but makes one key the binding of every token. Keep the exported scalar
with the same care as the refresh token.

### Token revocation

FAPI 2.0 expects that compromised tokens can be revoked through the
IdP's revocation endpoint (RFC 7009). The application calls
revocation when the user logs out, when a session is administratively
ended, or when token theft is detected. Axess exposes revocation
through `OAuthProvider::revoke_token`:

```rust,ignore
provider.revoke_token(&access_token, Some("access_token")).await?;
provider.revoke_token(&refresh_token, Some("refresh_token")).await?;
```

The hint is the RFC 7009 string, passed through verbatim rather than
through an enum, because an IdP may accept hints the RFC does not list.
Passing `None` is legal and makes the IdP search both token types.
Providers with no revocation endpoint return `OAuthError::Config`
rather than silently succeeding, so a deployment cannot believe it is
revoking when it is not.

The revocation endpoint, when present in the discovery document, is
called with the token to revoke and an optional type hint. The IdP
responds with a 200 regardless of whether the token was actually
revoked (intentionally, to defeat token-existence enumeration).

Revoking the refresh token is the more important call. The access
token typically has a short lifetime (matching the FAPI ID token
bound) and expires on its own; the refresh token has a longer life
and an unrevoked one allows continued access through new access
tokens. A logout that revokes only the access token leaves the
refresh token active, which is rarely what you want.

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
enabled, ID tokens signed `ES256` (Keycloak's default `RS256` is outside
the profile), the `axess-fapi-client` client registered for
`private_key_jwt` with a development key, and a seeded user
(`alice`/`alice`) ready to log in. The example's
`OAuthProviderConfig::discover_with_private_key_jwt(...)` call points
at the local Keycloak issuer through env vars and signs with that
development key unless `FAPI_PRIVATE_KEY_FILE` names another; the same
code talks to a real production IdP when those env vars point
elsewhere. Docker users can substitute `docker compose` for
`podman compose`; podman is the documented path.

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

If `build` fails with "FAPI 2.0 does not allow a client secret",
the provider has no `private_key_jwt` signer and no mTLS constraint:
call `with_private_key_jwt` on the builder (or discover with
`discover_with_private_key_jwt`), or choose `SenderConstraint::Mtls`.

If the PAR exchange fails with `invalid_client`, your client
authentication does not match what the IdP registered for the client:
the method (`private_key_jwt` or `tls_client_auth`), the public key or
certificate, the `kid`, or the assertion's audience. Some IdPs accept
only the token endpoint as audience; fix it with
`ClientAssertionSigner::with_audience`.

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
