# Inbound: SPIFFE JWT-SVID

A JWT-SVID is a JWT carrying a SPIFFE identity. It is the
right credential for service-to-service authentication where mTLS
is impractical (the network path crosses a load balancer that does
not preserve client certificates, the calling service speaks a
protocol that does not support TLS client auth, the deployment
favours the simplicity of bearer tokens). The `JwtSvidResolver` is
the axess resolver that validates these tokens and produces a
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
  "sub": "spiffe://prod.example.com/svc/billing",
  "aud": ["https://api.example.com"],
  "exp": 1735689600,
  "iat": 1735686000,
  "jti": "f47ac10b-58cc-4372-a567-0e02b2c3d479"
}
```

The signature is over the standard JWT body plus header, using
keys published by the trust domain's issuing authority through a
JWKS endpoint. The signing algorithm is RS256 or ES256 in
production deployments; SPIFFE does not standardise the algorithm,
but the keys advertised in the JWKS specify it.

## Wiring it up

The resolver takes a verifier, a trust domain and a token, and nothing else.

### Configuration

The resolver takes a verifier, the trust domain it accepts, and the
token, and nothing else:

```rust,ignore
use std::sync::{Arc, RwLock};

use axess_factors::jwt::{svid::JwtSvidResolver, verifier::JwtVerifier};

let verifier = Arc::new(
    JwtVerifier::new(Arc::new(RwLock::new(jwks)))
        .with_issuer("https://spire.prod.example.com")
        .with_audience("https://api.example.com")
        .with_clock_skew(Duration::from_secs(30)),
);
let resolver = JwtSvidResolver::new(
    verifier,
    "prod.example.com".parse()?,
    token,
);
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
is rejected. The defence is the trust-domain isolation that SPIFFE
is built around.

`expected_audiences` and the clock (`with_audience` and
`with_clock_skew` on the verifier) are configured there rather than
here; see above. A token
whose `aud` does not match is rejected by the verifier before the resolver
sees it.

**There is no `max_token_age`.** An `iat` upper bound is not implemented: a
token is accepted until its `exp`, and bounding issuance age is the issuer's
to do through a short lifetime. If you need it, check `VerifiedClaims::iat`
yourself after `verify`.

### Wiring the resolver

**There is no `JwtSvidLayer`.** axess ships no Tower middleware for SVIDs;
the resolver is a plain call you make where you like, which is what lets a
daemon with no Axum router use it at all:

```rust,ignore
use axess_identity::PrincipalResolver;

// `bearer_from` and its error are yours; axess has no opinion on how a
// request without a credential is refused.
let token = bearer_from(&headers).ok_or(MyError::NoCredential)?;
let resolver = JwtSvidResolver::new(verifier.clone(), trust_domain.clone(), token);
let principal = resolver.resolve().await?;   // Principal::Workload
```

In an Axum application, call it in a middleware of your own and insert the
`Principal` into the request extensions; the `bearer` feature's
`BearerTokenLayer` is the shipped example of that shape, for plain bearers
rather than SVIDs.

## What it checks, and what you get

Every rejection returns the same error, deliberately.

### Validation details

The validation runs through six checks in order. The order matters
because cheaper checks come first: a malformed token fails parsing
without ever fetching JWKS keys; an expired token is rejected
without engaging the signature check.

The first check is parsing. The token must be a well-formed JWT
with header, payload, and signature segments. Malformed input is
rejected without further work.

One thing to know before reading the rest: `resolve` reports every one
of these failures as `IdentityError`, because that is what
`PrincipalResolver` returns. A failed SPIFFE-ID decomposition or a
trust-domain mismatch surfaces as `IdentityError::InvalidSpiffeId`
with a message naming the problem; everything else collapses to
`IdentityError::NotAuthenticated`, with the underlying JWT error
logged at `debug` for operators. `JwtSvidError` does not exist. The
collapse is deliberate: a caller presenting a bad token learns only
that it was refused.

The second check is the header. The `alg` field must be one of
the configured allowed algorithms (RS256 or ES256 by default;
deployments that need others configure them explicitly). The
`kid` field must be present so the resolver can look up the right
key.

The third check is the claims. The `sub` claim must be a valid
SPIFFE URI under the configured trust domain. The `aud` claim
must contain at least one of the configured expected audiences.
The `exp` and `iat` claims must be present and within the clock
skew and max age bounds. Which claim failed appears in the debug log,
not in the returned error.

The fourth check is the signature. The resolver looks up the key
matching the token's `kid` in the cached JWKS, verifies the
signature, and falls through on success. A signature failure
triggers a JWKS cache refresh (subject to the debouncing) and a
retry against the fresh keys; a failure after refresh is final.

The fifth check is the `nbf` (not-before) claim when present.
SPIRE typically issues tokens with `nbf` slightly in the future to
allow for clock skew on the receiver side. The check uses the
same clock-skew tolerance.

The sixth check is the duplicate-`jti` check, when configured.
SPIFFE recommends a `jti` on each token so a receiver can detect
replay; a deployment that wants it implements `JtiReplayStore` and
hands it to the verifier with `with_replay_store`: a `HashSet`
behind a mutex for one process, a small Valkey cache for a fleet.
axess ships the trait and `NoReplay`, not a backend. With a store
configured, a token carrying no `jti` is rejected rather than
admitted unchecked, and entries expire with the token's own `exp`.

### What the principal looks like

A successful validation produces a `Principal::Workload`:

```rust,ignore
Principal::Workload(WorkloadPrincipal {
    workload_id: WorkloadId::new("spiffe://prod.example.com/svc/billing"),
    trust_domain: TrustDomain::new("prod.example.com"),
    issuer: Issuer::JwtSvid {
        jwks_url: "https://spire.prod.example.com/keys".parse().unwrap(),
    },
    tenant_id: derive_tenant_from_path(...),
    tenant_slug: derive_slug_from_path(...),
    service_name: derive_service_from_path(...),
    attributes: {
        "exp": 1735689600,
        "iat": 1735686000,
        "jti": "f47ac10b-...",
    },
})
```

The `workload_id` is the parsed SPIFFE URI. The `trust_domain`
mirrors the configured trust domain. The `issuer` records that
the principal came through the JWT-SVID path with the specific
JWKS URL. The tenant and service derivation depends on the
deployment's SPIFFE path convention (the example above expects
paths like `/svc/<service>/<tenant>`); the resolver's path-parsing
logic is configurable, and `examples/local_idp/` demonstrates the
pattern.

The `attributes` map carries the rest of the token's claims, so
Cedar policies can match on them if needed (a policy that demands
a specific issuer signature, for instance, reads
`principal.attributes.iss`).

## Threat model

The JWT-SVID flow is robust against the standard attacks when the
validation is complete.

Against token forgery: the signature check defeats it. An attacker
without the issuing authority's signing key cannot mint a valid
SVID.

Against token theft: the audience check defeats most of it. A
token stolen from one service cannot be used against another
service whose audience does not match.

Against token replay: the token's own lifetime is the window, so a
short `exp` at the issuer is the control, since no issuance-age
bound is implemented here. With a `JtiReplayStore` configured,
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

**Every rejection looks the same to the caller.** `resolve` returns
`IdentityError::NotAuthenticated` whichever check failed: a bad
signature, an unknown key, a wrong audience, an expired token, a
replayed `jti`, a missing or malformed `sub`. That is deliberate,
and it mirrors the user-enumeration discipline the Authn surface
follows: a caller learns that it was refused, not what to change
to get past. Do not branch on the variant, and do not expect one
that names the cause, because there isn't one.

The cause goes to the log instead, at `debug` on the
`axess_factors::jwt` target. Turn that on and the rejected
verification prints the underlying `JwtError`:

```text
RUST_LOG=axess_factors::jwt=debug
```

A key the JWKS does not advertise is the common one during SPIRE
rotation, where the cache debounce can hide a fresh key briefly;
force a refresh or wait out the TTL. An audience rejection means
the issuer mints a different `aud` than `expected_audiences`
lists. The token payload is base64 and readable, so decode it and
compare rather than guessing.

If the log shows the SPIFFE ID parsing or the trust domain, a
workload from a different domain is calling your service. If this is intentional,
configure federation (the next chapter, *Inbound: federation*,
covers the mechanism). If it is not intentional, the workload is
misconfigured.

## Fetching SVIDs from a local SPIRE agent

`JwtSvidResolver` is the **verifying** side; it consumes an SVID
presented in an HTTP request and validates it against the trust
domain's JWKS. The **issuing** side; fetching fresh SVIDs from a
local SPIRE agent socket for outbound calls; is a separate
concern.

For deployments that need to fetch SVIDs at runtime, two
adopter-direct options exist on crates.io today:

- [`spire-workload`](https://crates.io/crates/spire-workload);
  higher-level wrapper around the SPIRE Workload API gRPC,
  including JWT-SVID fetch with auto-rotation. Most adopters reach
  for this first.
- [`spire-api`](https://crates.io/crates/spire-api); lower-level
  generated gRPC client when finer control is needed.

axess does not currently wrap either crate; the SPIRE Workload API
client on the ROADMAP (feature `spire`) lands when an adopter
needs an axess-shaped surface (e.g. integration with axess-clock
for rotation timing, axess-rng for ceremony nonces, or the
`Principal::Workload` shape on the fetch result for symmetry with
the verifier). Until then, the recommended path is:

1. Use `spire-workload` directly in your application to fetch
   JWT-SVIDs against a configured audience.
2. Present the fetched SVID on outbound calls via your HTTP client.
3. On the receiving service, validate the SVID with
   `JwtSvidResolver` as documented above. The presenting and
   verifying sides interoperate without axess wrapping the fetch
   side.

If your deployment forces the issue (e.g. fetch-side rotation
needs to drive axess-clock-pinned tests), open a tracking issue;
that's exactly the adopter-demand signal the ROADMAP entry waits
for.

## Further reading

*Workload identity overview* covers the SPIFFE model and the
unified `Principal` type this resolver produces. *Inbound:
mTLS-SVID* covers the X.509 variant for deployments where mTLS is
practical. *Inbound: federation* covers the cross-trust-domain
patterns. *Cedar policy fundamentals* covers how policies match on
the workload's claims through `principal.attributes`.
