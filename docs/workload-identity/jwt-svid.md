# Inbound: SPIFFE JWT-SVID

A JWT-SVID is a JWT carrying a SPIFFE identity. It is the
right credential for service-to-service authentication where mTLS
is impractical (the network path crosses a load balancer that does
not preserve client certificates, the calling service speaks a
protocol that does not support TLS client auth, the deployment
favours the simplicity of bearer tokens). `JwtSvidResolver`
validates these tokens and produces a
`Principal::Workload`.

The feature flag is `jwt-svid` (off by default).

## The credential shape

A SPIFFE JWT-SVID is an ordinary JWT with two specific claim
requirements. The subject (`sub`) claim is the SPIFFE ID, formatted
as `spiffe://<trust_domain>/<path>`. The audience (`aud`) claim
names the intended recipient: when your application validates the
token, the audience must match a configured value.

```json
{
  "iss": "https://spire.prod.example.com",
  "sub": "spiffe://prod.example.com/billing/acme",
  "aud": ["https://api.example.com"],
  "exp": 1735689600,
  "iat": 1735686000,
  "jti": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "tid": "3b9d2c1e-7f4a-4c8e-9a2b-5d6e7f8a9b0c"
}
```

The signature covers the JWT header and payload, under keys the
trust domain's issuing authority publishes through a JWKS endpoint.
Production deployments sign with RS256 or ES256. The JWT-SVID standard admits the RSA
PKCS#1 v1.5, ECDSA and RSA-PSS families (RS256 to PS512, section
2.1) and has a validator reject any other; the resolver refuses a
token signed with anything else, whatever its verifier allows.

## Wiring it up

The resolver takes a verifier, a trust domain and a token, and then a
tenant lookup or a named waiver of the tenant cross-check.

### Configuration

For example:

```rust,ignore
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axess_factors::jwt::{svid::JwtSvidResolver, verifier::JwtVerifier};
use axess_identity::TrustDomain;

let verifier = Arc::new(
    JwtVerifier::new(Arc::new(RwLock::new(jwks)))
        .with_issuer("https://spire.prod.example.com")
        .with_audience("https://api.example.com")
        .with_clock_skew(Duration::from_secs(30)),
);
let resolver = JwtSvidResolver::new(
    verifier,
    TrustDomain::new("prod.example.com")?,
    token,
)
// Maps the SPIFFE tenant slug to the tenant you registered for it.
.with_tenant_lookup(|slug| tenants.id_of(slug));
let principal = resolver.resolve().await?;
```

Everything about *how* a token is validated (issuer, audience,
clock skew, which algorithms, whether a `jti` may be replayed)
belongs to the [`JwtVerifier`](../../axess-factors/src/jwt/verifier.rs)
you hand it, and is configured there. The resolver adds the SPIFFE
rules on top: the trust domain, and the shape of the identity.

Where the key set comes from is likewise yours: a `JwkSet` read from
a file the deployment mirrors, or `JwksCache` (feature `oidc`) if you
want axess to fetch it. The resolver never fetches.

`trust_domain` is the trust domain the resolver accepts SVIDs
from. A token whose `sub` SPIFFE ID names a different trust domain
is rejected. This enforces the trust-domain isolation that SPIFFE
is built around.

`expected_audiences` and the clock skew are configured on the verifier
with `with_audience` and `with_clock_skew`, not here. The skew is at most
`axess_factors::jwt::validation::MAX_LEEWAY`, 300 s, in whole seconds; above
that, or with a fraction of a second, the verifier refuses every token by
name. The verifier rejects a token whose
`aud` does not match before the resolver sees it.

**There is no `max_token_age`.** An `iat` upper bound is not implemented: a
token is accepted until its `exp`, and bounding issuance age is the issuer's
to do through a short lifetime. If you need it, check `VerifiedClaims::iat`
yourself after `verify`.

### Wiring the resolver

**There is no `JwtSvidLayer`.** Axess ships no Tower middleware for SVIDs;
the resolver is a plain call you make where you like, so a daemon with no
Axum router can use it too:

```rust,ignore
use axess_identity::PrincipalResolver;

// `bearer_from` and its error are yours; axess has no opinion on how a
// request without a credential is refused.
let token = bearer_from(&headers).ok_or(MyError::NoCredential)?;
let resolver = JwtSvidResolver::new(verifier.clone(), trust_domain.clone(), token)
    .with_tenant_lookup(|slug| tenants.id_of(slug));
let principal = resolver.resolve().await?;   // Principal::Workload
```

In an Axum application, call it in a middleware of your own and insert the
`Principal` into the request extensions; the `bearer` feature's
`BearerTokenLayer` is the shipped example of that shape, for plain bearers
rather than SVIDs.

## What it checks, and what you get

Almost every rejection returns the same error, deliberately. The
exception is a `sub` that is not a SPIFFE ID of the expected shape, or
one under another trust domain.

### Validation details

The verifier runs six checks in order, and the resolver then checks the
identity in `sub`. Cheaper checks come first: a token over the size bound
is refused before its header is read, and a token that is not three
segments or whose header does not parse is refused before any key is
looked up. The time claims are checked only once the
signature verifies.

`resolve` reports every one of these failures as `IdentityError`, because
that is what `PrincipalResolver` returns. A `sub` that is not a valid SPIFFE
ID, one whose path is not `<service>/<tenant_slug>`, and a trust-domain
mismatch surface as `IdentityError::InvalidSpiffeId` with a message naming
the problem; everything else collapses to
`IdentityError::NotAuthenticated`, with the underlying JWT error logged at
`debug` for operators. `JwtSvidError` does not exist. The collapse is
deliberate: a caller presenting a bad token learns only that it was
refused.

The first check is parsing. The token must be a well-formed JWT
with header, payload, and signature segments. Malformed input is
rejected without further work.

The second check is the header, read once the token is known to be
no longer than the size bound. The `alg` field must be one of the
configured allowed algorithms (RS256, RS384, RS512, ES256 and ES384 by
default; deployments
that need others configure them explicitly) and one the JWT-SVID
standard lists. The `kid` field is optional, as the standard
(section 2.2) leaves it: a token with one is verified with that key
alone, and a token without one against each key of the trust
domain's set. Every other JWT path of axess still requires a `kid`.

The third check is the signature. With a `kid`, the verifier looks
up the key matching it in the key set, and a `kid` the set does
not hold is refused without trying the other keys. Without one, the
verifier tries in turn each key that could have made the signature. It
passes over a key marked for another use, one whose `alg` member names
another algorithm, and one whose type or curve does not sign under the
header's `alg`. The first key under which the signature verifies wins. A
set of more than 32 keys is refused before any is tried. A signature
failure is final: the verifier does not refresh the key set and retry.
With the signature verified, a pinned `iss` must be present and match,
and the `aud` claim must contain the configured audience.

The fourth check is `exp`. It must be present (unless the verifier is
built with `require_exp(false)`), and a token is refused once `exp` plus
the clock skew has passed. `iat` is not checked. Which claim failed
appears in the debug log, not in the returned error.

The fifth check is the `nbf` (not-before) claim when present. A
token whose `nbf` is later than now plus the clock skew is refused,
the same tolerance `exp` gets.

The sixth check is the duplicate-`jti` check, when configured.
SPIFFE recommends a `jti` on each token so a receiver can detect
replay; a deployment that wants it hands a `JtiReplayStore` to the
verifier with `with_replay_store`. Two ship in `axess_core::replay`:
`MemoryJtiReplayStore` for one process, and `ValkeyJtiReplayStore`
(with `valkey`) for a fleet, where a `jti` recorded by one node is
refused by every other; `NoReplay`, the default, records nothing.
`MemoryJtiCache`, the DPoP verifier's cache (with the `oauth` feature),
implements the trait too. The in-process stores are bounded: a full
one refuses, as a store that cannot answer does, and never forgets a live
record. The Valkey server must run `maxmemory-policy noeviction`, since
under any other policy it may drop a live record;
`ValkeyJtiReplayStore::checked` asks the server at start and refuses any
other policy. With a store configured, a token carrying
no `jti` is rejected rather than admitted unchecked, and entries
expire with the token's own `exp`. Give each verifier a key prefix of
its own (`ValkeyJtiReplayStore::with_prefix`), so two kinds of token
never refuse each other's `jti` values.

Once the verifier accepts the token, the resolver checks the identity.
The `sub` claim must be present (`NotAuthenticated` otherwise), must be a
valid SPIFFE ID whose path is exactly `<service>/<tenant_slug>`, and must
name the configured trust domain (`InvalidSpiffeId` otherwise). Last, the
tenant slug and the `tid` claim must name the same tenant, as *Cross-checking
the tenant claim* below describes.

### What the principal looks like

A successful validation produces a `Principal::Workload`:

```rust,ignore
Principal::Workload(WorkloadPrincipal {
    workload_id: WorkloadId::parse("spiffe://prod.example.com/billing/acme")?,
    trust_domain: TrustDomain::new("prod.example.com")?,
    issuer: Issuer::JwtSvid,
    tenant_id: tid,                      // the token's `tid` claim
    tenant_slug: "acme".to_string(),
    service_name: "billing".to_string(),
    attributes: BTreeMap::new(),
})
```

The `workload_id` is the parsed SPIFFE URI. The `trust_domain`
mirrors the configured trust domain. The `issuer` records that
the principal came through the JWT-SVID path. The service name and
the tenant slug are the two segments of the SPIFFE path, which must
be exactly `<service>/<tenant_slug>`; the path shape is fixed, and a
SPIFFE ID of any other shape is refused. The tenant id is the token's
`tid` claim, cross-checked against the slug through your tenant lookup
unless you waive the check.

The `attributes` map is empty: the resolver copies no other claims
onto the principal, so a Cedar policy cannot match on them.

## Threat model

The JWT-SVID flow is robust against the standard attacks when the
validation is complete.

Against token forgery: the signature check defeats it. An attacker
without the issuing authority's signing key cannot mint a valid
SVID.

Against token theft: the audience check defeats most of it. A
token stolen from one service cannot be used against another
service whose audience does not match.

Against token replay: no issuance-age bound is implemented here, so the
token's own lifetime is the window and a short `exp` at the issuer is the
control. With a `JtiReplayStore` configured,
replay is detected explicitly rather than merely bounded.

Against trust-domain confusion: the trust-domain match defeats
cross-domain attacks. A token from a different trust domain is
rejected without further consideration.

The remaining attack surface is the issuing authority itself. A
compromised SPIRE control plane can mint compromised SVIDs, and no
client-side check catches that. The defence is operational:
secure the SPIRE control plane, monitor its audit log, rotate keys
on a schedule.

## Troubleshooting

**Almost every rejection looks the same to the caller.** `resolve` returns
`IdentityError::NotAuthenticated` for a bad signature, an unknown key, a
wrong audience, an expired token, a replayed `jti`, a missing `sub` and a
`tid` that does not match the slug alike. That is deliberate,
and it mirrors the user-enumeration discipline the Authn surface
follows: a caller learns that it was refused, not what to change
to get past. Do not branch on the variant. The one exception is the
SPIFFE ID itself: a `sub` that is not a valid SPIFFE ID, whose path is
not `<service>/<tenant_slug>`, or that names another trust domain
returns `IdentityError::InvalidSpiffeId` with a message naming the
problem.

The cause goes to the log instead, at `debug` on the
`axess_factors::jwt` target. Turn that on and the rejected
verification prints the underlying `JwtError`:

```text
RUST_LOG=axess_factors::jwt=debug
```

A key the JWKS does not advertise is the common cause during SPIRE
rotation, where the cache debounce can hide a fresh key briefly;
force a refresh or wait out the TTL. An audience rejection means
the issuer mints a different `aud` than `expected_audiences`
lists. The token payload is base64 and readable, so decode it and
compare rather than guessing.

If `InvalidSpiffeId` names a trust domain mismatch, a
workload from a different domain is calling your service. If this is intentional,
configure federation (*Inbound: federation* covers the mechanism). If it is not intentional, the workload is
misconfigured.

## Fetching SVIDs from a local SPIRE agent

`JwtSvidResolver` is the verifying side: it takes an SVID presented
in a request and validates it against the trust domain's keys. The
other two sides of a SPIRE deployment are the `spire` feature's:
`SpireClient` talks to the local agent's socket, and *SPIRE Workload
API client* is its chapter.

The `spire` feature meets this chapter in three places.

**Where the keys come from.** `JwtBundleSource::key_set` gives the
agent's JWT signing keys for a trust domain as the shared key set a
`JwtVerifier` is built on, rewritten whenever the agent rotates them:

```rust,ignore
let bundles = client.watch_jwt_bundles()?;
bundles.ready().await;

let verifier = Arc::new(
    JwtVerifier::new(bundles.key_set(&trust_domain))
        .with_issuer("https://spire.prod.example.com")
        .with_audience("https://api.example.com"),
);
```

The resolver above is then built on that verifier, unchanged. The
resolver takes a verifier that pins the issuer or waives it by name:
the JWT-SVID standard defines no `iss` claim, so on a trust domain's
own keys `allow_any_issuer()` stands in for `with_issuer(..)` where
the issuing server sets none. The key
set is emptied when the agent has not confirmed its keys within the
client's maximum bundle age, so a verifier that has lost its agent
refuses tokens instead of trusting keys that may have been withdrawn.

**Validation by the agent.** `AgentJwtSvidResolver` has the agent
validate the token through the Workload API and resolves the same
`Principal::Workload`, with no key set in the process and no `iss`
needed in the token.

**The calling side.** A service that presents a JWT SVID to another
takes it from a `JwtSvidSource`, which fetches one for an audience and
replaces it before it expires:

```rust,ignore
let partner = client.watch_jwt_svid(["https://api.partner.example"])?;
partner.ready().await;
let token = partner.token()?;          // current, never expired
```

## Further reading

*Workload identity overview* covers the SPIFFE model and the
unified `Principal` type this resolver produces. *Inbound:
mTLS-SVID* covers the X.509 variant for deployments where mTLS is
practical. *SPIRE Workload API client* covers fetching SVIDs and
bundles from a local agent. *Inbound: federation* covers the cross-trust-domain
patterns. *Cedar policy fundamentals* covers how policies match on
workload principals.

## Cross-checking the tenant claim

The SPIFFE path carries the tenant slug and the `tid` claim carries the
tenant UUID. Both are written by the issuer, and nothing ties them together
unless you do. Give the resolver a lookup with
`JwtSvidResolver::with_tenant_lookup`: it maps the slug to the tenant you
registered for it, and the token is refused when the slug is unknown or maps
to a different tenant than `tid`. A resolver with no lookup refuses every
token. Where you have no registry and trust the issuer to have kept the two
claims consistent, say so with `JwtSvidResolver::without_tenant_cross_check()`,
a waiver by name in line with the verifier's `allow_any_*` ones.
