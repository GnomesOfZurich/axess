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

## Configuration

`JwtSvidResolverConfig` carries the validation parameters:

```rust,ignore
pub struct JwtSvidResolverConfig {
    pub trust_domain: TrustDomain,
    pub jwks_url: Url,
    pub expected_audiences: Vec<String>,
    pub clock_skew: Duration,
    pub max_token_age: Duration,
}

let resolver = JwtSvidResolver::new(JwtSvidResolverConfig {
    trust_domain: "prod.example.com".parse().unwrap(),
    jwks_url: "https://spire.prod.example.com/keys".parse().unwrap(),
    expected_audiences: vec!["https://api.example.com".into()],
    clock_skew: Duration::from_secs(30),
    max_token_age: Duration::from_secs(3600),
});
```

`trust_domain` is the trust domain the resolver accepts SVIDs
from. A token whose `sub` SPIFFE ID names a different trust domain
is rejected. The defence is the trust-domain isolation that SPIFFE
is built around.

`jwks_url` is where the resolver fetches signing keys. The fetch
runs through the `axess-cache` machinery: a single-flight cache
that dedupes concurrent fetches, with debouncing to prevent
denial-of-service through key-rotation thrash. The cache TTL
defaults to one hour, which matches the typical SPIRE rotation
schedule.

`expected_audiences` is the allowlist of audience values the
resolver accepts. A token whose `aud` does not contain at least one
of the expected values is rejected. Most deployments configure a
single audience (the application's URL); deployments that serve
multiple identities behind one resolver list each.

`clock_skew` is the tolerance applied to the `exp` and `iat`
checks. Thirty seconds is generous; production deployments that
synchronise clocks tightly through NTP can lower it.

`max_token_age` is the upper bound on how far in the past the
token's `iat` claim can be. The check defeats replay of stale
tokens: even if a token has not expired, a token issued more than
the configured age ago is rejected. The default is one hour, which
is generous; deployments with stricter posture set it lower.

## Wiring the resolver

The resolver is wired as a Tower middleware that runs before the
handler. The middleware reads a bearer token from the
`Authorization` header (or wherever the deployment puts it),
calls into the resolver, and on success inserts the resulting
`Principal` into the request extensions.

```rust,ignore
use axess::workload::{JwtSvidResolver, JwtSvidLayer};

let resolver = JwtSvidResolver::new(/* ... */);
let layer = JwtSvidLayer::new(resolver);

let app = Router::new()
    .route("/api/data", get(handler))
    .layer(layer);
```

The handler reads the principal through an extractor:

```rust,ignore
use axess::Principal;
use axum::Extension;

async fn handler(Extension(principal): Extension<Principal>) -> &'static str {
    match principal {
        Principal::Workload(w) => {
            tracing::info!(workload = %w.workload_id, "request from workload");
            "ok"
        }
        Principal::Human(_) => {
            // The route is workload-only; reject the human request.
            // (Or route differently. Choice is the application's.)
            unreachable!("the layer only accepts workload tokens")
        }
    }
}
```

The middleware can be composed with other authentication paths.
An application that accepts both human sessions and workload
tokens wires the session layer and the JWT-SVID layer side by
side; the first one to produce a principal wins.

## Validation details

The validation runs through six checks in order. The order matters
because cheaper checks come first: a malformed token fails parsing
without ever fetching JWKS keys; an expired token is rejected
without engaging the signature check.

The first check is parsing. The token must be a well-formed JWT
with header, payload, and signature segments. Malformed input
produces `JwtSvidError::Malformed` without further work.

The second check is the header. The `alg` field must be one of
the configured allowed algorithms (RS256 or ES256 by default;
deployments that need others configure them explicitly). The
`kid` field must be present so the resolver can look up the right
key.

The third check is the claims. The `sub` claim must be a valid
SPIFFE URI under the configured trust domain. The `aud` claim
must contain at least one of the configured expected audiences.
The `exp` and `iat` claims must be present and within the clock
skew and max age bounds. Missing or malformed claims produce
specific error variants so the operational signal is clear.

The fourth check is the signature. The resolver looks up the key
matching the token's `kid` in the cached JWKS, verifies the
signature, and falls through on success. A signature failure
triggers a JWKS cache refresh (subject to the debouncing) and a
retry against the fresh keys; a failure after refresh is final.

The fifth check is the `nbf` (not-before) claim when present.
SPIRE typically issues tokens with `nbf` slightly in the future to
allow for clock skew on the receiver side. The check uses the
same clock-skew tolerance.

The sixth check is the duplicate-jti check, when configured.
SPIFFE recommends a JTI on each token to allow receivers to
detect replay; an axess deployment that wants this protection
configures a JTI store (typically a small Valkey cache with the
configured `max_token_age` TTL), and the resolver checks for
duplicates before admitting the token.

## What the principal looks like

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

Against token replay: the `iat` + `max_token_age` bound shrinks
the replay window. With the optional JTI cache, replay is detected
explicitly.

Against trust-domain confusion: the trust-domain match defeats
cross-domain attacks. A token from a different trust domain is
rejected without further consideration.

The remaining attack surface is the issuing authority itself. A
compromised SPIRE control plane can mint compromised SVIDs, and no
client-side check catches that. The defence is operational:
secure the SPIRE control plane, monitor its audit log, rotate keys
on a schedule.

## Troubleshooting

If the resolver returns `KeyNotFound` consistently, the JWKS URL
is wrong or the key advertised in the token is not yet published
at the URL. The latter is common during SPIRE rotation; the
caching layer's debounce can hide the rotation briefly. Force a
cache refresh (or wait for the TTL) and retry.

If the resolver returns `AudienceMismatch` for tokens that should
work, the issuing service is minting tokens with a different
audience than the application expects. Either the issuer's
configuration is wrong, or the application's `expected_audiences`
list is missing the relevant value. Inspect the token (the
payload is unencoded base64, so it is readable) to see what `aud`
it carries.

If the resolver returns `TrustDomainMismatch`, a workload from a
different domain is calling your service. If this is intentional,
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

axess does not currently wrap either crate; the
`SpireWorkloadApiResolver` ROADMAP item lands when an adopter
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
