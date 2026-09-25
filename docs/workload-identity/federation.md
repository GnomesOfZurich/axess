# Inbound: federation

Federation is the pattern where workloads authenticate against your
application using credentials issued by a third party your
deployment trusts. The federating issuer typically lives outside
the trust domain your own services use: Kubernetes issues
service-account tokens for pods, GitHub issues OIDC tokens for
Actions runs, an enterprise IdP issues tokens for cross-organisation
service calls. None of these are SPIFFE issuers, but axess provides
a generic resolver that bridges any JWT-bearer issuer into the
unified workload-principal shape.

This chapter covers `WorkloadResolver`, the single resolver that
handles every non-SPIFFE federation. It is gated on the `jwt` feature,
which `jwt-svid` and the rest of the workload-identity bundle pull in.
Before 0.7.0 the facade put this module under `federation` and gated it
on `oauth`, so `features = ["jwt-svid"]` compiled the resolver and left
no path to it.

## What federation means here

The unifying claim of federation in axess is that an external
issuer's token, after validation, produces a `Principal::Workload`
with the same shape as a SPIFFE workload. The trust domain and the
SPIFFE-style path are synthesised from the issuer's claims; the
issuer field on the principal records which federation produced it
(`Issuer::OAuth` for the generic case, or one of
`Issuer::custom("github_actions")` / `Issuer::custom("kubernetes")` /
`Issuer::custom("gitlab_ci")` when audit logs need finer granularity).

The synthesis matters because the rest of the system stays
uniform. A Cedar policy that says "any workload in the finance
tenant may read this resource" works for a SPIFFE-identified
service and for a Kubernetes pod and for a GitHub Actions run,
without branching. The audit pipeline logs the same principal
shape for all three. The application's code does not need to know
which federation produced the request.

## One resolver, many issuers

axess deliberately ships **no per-issuer adapters**. Each IdP's
JWT claim shape is small (~20 lines for a `#[derive(Deserialize)]`
struct, ~30 lines for a mapping closure) and adopters care about
their *specific* IdP's exact claim semantics, not a generic
average. Hard-coding `wif-github`, `wif-k8s`, `wif-gitlab` features
in the library invites endless additions without reuse benefit.

Instead: one `WorkloadResolver<C, F, R>` is generic over

- `C`; the adopter's `#[derive(Deserialize)]` claim struct
- `F`; the closure mapping verified claims to `WorkloadMapping`
- `R`; JTI replay-store type (defaults to `NoReplay`)

The library handles JWT verification (signature against JWKS,
`iss`/`aud`/`exp`/`nbf`/`alg` checks), trust-domain pinning, and
`Principal` construction. The closure handles claim
→ identity-components.

## Ready-made recipes

`examples/workload-identity/` ships claim parsers + mappers for two
common issuers. Adopters copy the recipe that matches their IdP
into their codebase (recommended for production) or depend on the
crate directly (useful for prototypes and tests).

### Kubernetes service accounts

Kubernetes mints OIDC-style tokens for pods through the
`TokenRequest` API. A pod requests a token bound to a specific
audience (the URL of your application, say), and the cluster's
control plane returns a signed JWT carrying the pod's
service-account identity. The token's `iss` is the cluster's OIDC
issuer URL; the `kubernetes.io.{namespace,serviceaccount.name}`
custom claim block carries the pod's identity.

```rust,ignore
use axess_example_workload_identity::kubernetes::{
    k8s_sa_mapper, K8sCustomClaims,
};
use axess_factors::federation::workload::WorkloadResolver;
use axess_factors::jwt::verifier::JwtVerifier;
use axess_identity::{Issuer, TrustDomain};
use std::sync::Arc;

// Startup wiring (cache the verifier; reuse across requests):
let verifier = Arc::new(
    JwtVerifier::new(cluster_jwks_handle)
        .with_issuer("https://kubernetes.default.svc.cluster.local")
        .with_audience("axess-platform"),
);
let trust_domain = TrustDomain::new("cluster.local").unwrap();

// Per request: adopter middleware peeks at the token to look up
// tenant_id from the namespace, then constructs the resolver.
let resolver = WorkloadResolver::<K8sCustomClaims, _, _>::new(
    verifier.clone(),
    trust_domain.clone(),
    tenant_id,
    Issuer::custom("kubernetes").unwrap(),
    bearer_token,
    k8s_sa_mapper(trust_domain),
);
let principal = resolver.resolve().await?;
```

The recipe synthesises a SPIFFE-shape workload id of the form
`spiffe://cluster.local/<sa_name>/<namespace>`. Adjust the
recipe's path layout if your trust-domain convention differs.

### GitHub Actions OIDC

GitHub Actions can issue OIDC tokens for workflow runs. The token
carries claims naming the repository, the workflow, the branch,
the run id, and the actor. Combined with a trust-domain mapping,
the token authenticates a specific workflow run from your
organisation against your application.

```rust,ignore
use axess_example_workload_identity::github_actions::{
    github_actions_mapper, GitHubActionsClaims,
};
use axess_factors::federation::workload::WorkloadResolver;
use axess_factors::jwt::verifier::JwtVerifier;
use axess_identity::{Issuer, TrustDomain};
use std::sync::Arc;

let verifier = Arc::new(
    JwtVerifier::new(github_jwks_handle)
        .with_issuer("https://token.actions.githubusercontent.com")
        .with_audience("axess-platform"),
);
let trust_domain = TrustDomain::new("github.actions").unwrap();

let resolver = WorkloadResolver::<GitHubActionsClaims, _, _>::new(
    verifier.clone(),
    trust_domain.clone(),
    tenant_id,
    Issuer::custom("github_actions").unwrap(),
    bearer_token,
    github_actions_mapper(trust_domain),
);
let principal = resolver.resolve().await?;
```

The recipe synthesises `spiffe://github.actions/<repo>/<owner>`
and preserves `actor`, `workflow`, `ref`, `sha`, `event_name` as
Cedar attributes for policy use (allow only deploys from the
default branch, require a specific workflow file, etc.).

### Other issuers (GitLab CI, Okta, Azure AD, Auth0, …)

Write your own recipe. For any new IdP:

1. Decode a sample JWT to identify which claims carry the workload
   identity (`project_path`? `namespace_id`? a custom `service`?).
2. Define a `#[derive(Deserialize)] struct YourClaims { ... }` with
   only the fields you care about. `JwtVerifier` ignores unknown
   claims, so you don't have to enumerate everything the issuer
   sends.
3. Write a mapper closure
   `Fn(&VerifiedClaims<YourClaims>) -> Result<WorkloadMapping, IdentityError>`
   that produces the `(workload_id, service_name, tenant_slug,
   attributes)` shape.
4. Wire as above, with `Issuer::custom("your_idp_label").unwrap()`
   for audit-log attribution (the constructor validates the label
   format: `[a-z0-9_]{1,32}`).

`WorkloadId::build` renders `spiffe://<trust_domain>/<service>/<tenant_slug>`,
and each of those two segments is one path component: `[A-Za-z0-9._~-]`,
non-empty, with the whole URI capped at 2048 characters. A claim that is
already a path does not pass through. GitLab's `project_path` is
`group/subgroup/project`, and handing it over whole fails on the first
slash, so decide what the segments mean for your issuer and build them
rather than forwarding a claim verbatim.

The two shipped recipes are the templates; read their source,
adapt as needed.

## Where federation fits

Federation is the right answer when the deployment cannot or does
not want to issue its own workload identities. A Kubernetes-based
deployment that wants to use the pods' service-account tokens
directly fits cleanly; an open-source CI integration that accepts
tokens from any GitHub Actions run fits cleanly; an enterprise
deployment that integrates with a partner's Okta tenant fits
cleanly.

Federation is the wrong answer when the deployment runs SPIRE (or
another SPIFFE issuer) and can mint its own SVIDs. In that case
the SPIFFE-native resolvers (*Inbound: JWT-SVID*, *Inbound:
mTLS-SVID*) are simpler, the trust model is tighter, and the
federation indirection adds nothing.

Multi-resolver deployments are common. The same application
typically accepts SPIFFE-native traffic from its own services and
federated traffic from external collaborators; the resolvers wire
side by side, each with its own router or middleware path, and the
unified principal shape lets the policies stay the same across
the sources.

## Threat model

The federation flows share the threat model of the underlying
issuer. A Kubernetes-issued token is as secure as the cluster's
OIDC issuer; a GitHub Actions token is as secure as GitHub's
issuance pipeline; an OIDC IdP-issued token is as secure as the
IdP.

The defences that axess adds are the standard ones: signature
verification against the issuer's JWKS, `iss` match, `aud` match,
expiry check, optional clock-skew and max-age bounds, trust-domain
pinning at the resolver layer, and the adopter's claim-mapper
closure (which decides which subject paths the application admits).

The remaining attack surfaces are the issuer-specific ones. A
compromised Kubernetes control plane mints compromised tokens. A
misconfigured GitHub Actions workflow leaks the OIDC token. A
compromised OIDC IdP issues tokens for arbitrary identities. The
defences are operational: secure each issuer, monitor for unusual
issuance patterns, rotate keys on a schedule.

Nothing is audited for you here. `WorkloadResolver::resolve` verifies
the token and hands back a `Principal`; it writes no `AuthEvent`, and
`AuthEventType` has no variant for workload authentication, so a SIEM
rule watching the catalogue for these will wait forever. Axess emits from
its service layer, which holds an `IdentityAuthnLog` to write through,
and the workload resolvers sit outside it.

Record it at your call site if you want it: the issuer label and the
synthesised `WorkloadId` are both on the principal the resolver returns,
which is the attribution an issuer-level anomaly rule needs.

## Troubleshooting

| `resolve()` returns | Usually | What to do |
|---|---|---|
| `NotAuthenticated` | The JWT failed verification: wrong issuer, wrong audience, expired, bad signature, or a custom-claim that would not deserialise | Turn on `tracing::debug!` for `axess_factors::federation::workload` to see which step rejected it |
| `InvalidSpiffeId` | The token verified, but the trust domain in the synthesised `WorkloadId` is not the one the resolver pinned. Usually the mapper closure built the id under the wrong trust domain | Check which `trust_domain` the recipe captured |
| `InvalidComponent(...)` | The claim mapper rejected the verified claims, or a path segment carried a character outside `[A-Za-z0-9._~-]`. The message names which | Decode the payload (`base64 -d` of the JWT's middle segment) and compare it against what the mapper expects |

## Further reading

*Workload identity overview* covers the SPIFFE model the
federation resolver maps into. *Cloud STS exchange* covers the
next step for many federated tokens: exchanging a workload
identity for short-lived cloud credentials. *OAuth 2.0 and OIDC*
in Part III covers the underlying OIDC machinery that the
`JwtVerifier` builds on.
