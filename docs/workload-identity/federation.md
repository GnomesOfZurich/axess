# Inbound: federation

In federation, workloads authenticate to your application with
credentials issued by a third party your deployment trusts. The federating issuer typically lives outside
the trust domain your own services use: Kubernetes issues
service-account tokens for pods, GitHub issues OIDC tokens for
Actions runs, an enterprise IdP issues tokens for cross-organisation
service calls. None of these are SPIFFE issuers, but axess provides
a generic resolver that bridges any JWT-bearer issuer into the
unified workload-principal shape.

This chapter covers `WorkloadResolver`, the single resolver that
handles every non-SPIFFE federation. It is gated on the `jwt` feature,
which `jwt-svid` and the rest of the workload-identity bundle pull in.
It needs neither the `federation` nor the `oauth` feature, so
`features = ["jwt-svid"]` reaches the resolver with no OAuth in the build.

## What federation means here

In axess, an external issuer's token, once validated, produces a
`Principal::Workload` with the same shape as a SPIFFE workload. The trust domain and the
SPIFFE-style path are synthesised from the issuer's claims; the
issuer field on the principal records which federation produced it
(`Issuer::OAuth` for the generic case, or one of
`Issuer::custom("github_actions")` / `Issuer::custom("kubernetes")` /
`Issuer::custom("gitlab_ci")` when audit logs need finer granularity).

The synthesis keeps the rest of the system uniform. A Cedar policy that says "any workload in the finance
tenant may read this resource" works for a SPIFFE-identified
service, a Kubernetes pod and a GitHub Actions run without branching. The audit pipeline logs the same principal
shape for all three. The application's code does not need to know
which federation produced the request.

## One resolver, many issuers

axess deliberately ships **no per-issuer adapters**. Each IdP's
JWT claim shape is small (~20 lines for a `#[derive(Deserialize)]`
struct, ~30 lines for a mapping closure) and adopters care about
their *specific* IdP's exact claim semantics, not a generic
average. Features such as `wif-github`, `wif-k8s` and `wif-gitlab` would
invite endless additions with no reuse.

Instead, one `WorkloadResolver<C, F, R>` is generic over:

- `C`: the adopter's `#[derive(Deserialize)]` claim struct
- `F`: the closure mapping verified claims to `WorkloadMapping`
- `R`: the JTI replay-store type (defaults to `NoReplay`)

The library handles JWT verification (signature against JWKS,
`iss`/`aud`/`exp`/`nbf`/`alg` checks), `WorkloadId` construction under the
resolver's own trust domain, the tenant lookup from the verified claims'
slug, and `Principal` construction. The closure maps the claims to identity components (service name,
tenant slug, attributes); it cannot name the trust domain or the tenant.

## Ready-made recipes

`examples/workload-identity/` ships claim parsers and mappers for three
common issuers: GitHub Actions, GitLab CI and Kubernetes service accounts.
Copy the recipe that matches your IdP into your codebase for production, or
depend on the crate directly for prototypes and tests.

### Kubernetes service accounts

Kubernetes mints OIDC-style tokens for pods through the
`TokenRequest` API. A pod requests a token bound to a specific
audience (for example, the URL of your application), and the cluster's
control plane returns a signed JWT carrying the pod's
service-account identity. The token's `iss` is the cluster's OIDC
issuer URL; the `kubernetes.io.{namespace,serviceaccount.name}`
custom claim block carries the pod's identity.

```rust,ignore
use axess_example_workload_identity::kubernetes::{
    k8s_sa_mapper_pinned, K8sCustomClaims, SaUidPins,
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
// The service accounts you trust, each with the UID the cluster gave it.
let pins = SaUidPins::new().pin("payments", "worker", "5f6e1c0a-...");

// Per request: the resolver looks the tenant up from the namespace in the
// verified token, with the registry you give it (None refuses the token).
let resolver = WorkloadResolver::<K8sCustomClaims, _, _>::new(
    verifier.clone(),
    trust_domain.clone(),
    move |namespace: &str| tenants.get(namespace).copied(),
    Issuer::custom("kubernetes").unwrap(),
    bearer_token,
    k8s_sa_mapper_pinned(pins),
);
let principal = resolver.resolve().await?;
```

The recipe synthesises a SPIFFE-shape workload id of the form
`spiffe://cluster.local/<sa_name>/<namespace>`. Adjust the
recipe's path layout if your trust-domain convention differs.

A service account is named by `(namespace, name)`, and anyone who may create
service accounts in that namespace can delete one and create another under
the same name. The `kubernetes.io.serviceaccount.uid` claim does not survive
that: a recreated account has a new UID. The wire-up above therefore uses
`k8s_sa_mapper_pinned` with a `SaUidPins` listing the UID registered for each
`(namespace, name)` you trust; it rejects a token whose UID is missing or
different, and any account that is not listed. The unpinned `k8s_sa_mapper`
records the UID as the `sa_uid` attribute but does not require it, so a
recreated account inherits the old name's trust; avoid it.

OpenShift and Amazon EKS issue the same bound service-account token with the
same `kubernetes.io` claim block, so they use this recipe unchanged; what
differs is the issuer and the audience, and the example crate's `openshift`
and `eks` modules hold them. A default OpenShift 4 cluster signs with
`https://kubernetes.default.svc` (read the cluster's value with
`oc get authentication cluster -o jsonpath='{.spec.serviceAccountIssuer}'`),
which is the same string on every default cluster, so the issuer does not
tell clusters apart: the JWKS you trust and the audience do. An EKS cluster
signs with its own `https://oidc.eks.<region>.amazonaws.com/id/<cluster id>`
(`eks::issuer` builds it). On both, a pod's default token is for the
API server (OpenShift) or for AWS STS (`sts.amazonaws.com`, the IRSA token on
EKS): never accept those audiences. Project a second token with your own
audience in the pod spec and pin that on the verifier. Both are tested with
`k8s_sa_mapper_pinned` against a recorded token, and a wrong namespace, wrong
UID or wrong audience is refused, the first two with an error that names the
claim.

### GitLab CI

A GitLab job asks for an ID token with the `id_tokens:` keyword, naming the
audience it wants. Use your service's URL as the audience and pin it on
the verifier; the issuer is the GitLab instance's URL and its keys are at
`<instance>/oauth/discovery/keys`.

```yaml
deploy:
  stage: deploy
  environment: production
  id_tokens:
    AXESS_TOKEN:
      aud: https://axess.example.com
  script:
    - >
      curl --fail -H "Authorization: Bearer ${AXESS_TOKEN}"
      https://axess.example.com/deploy-hook
```

```rust,ignore
use axess_example_workload_identity::gitlab::{
    gitlab_mapper, GitLabAllowlist, GitLabClaims,
};
use axess_factors::federation::workload::WorkloadResolver;
use axess_factors::jwt::verifier::JwtVerifier;
use axess_identity::{Issuer, TrustDomain};
use std::sync::Arc;

let verifier = Arc::new(
    JwtVerifier::new(gitlab_jwks_handle)
        .with_issuer("https://gitlab.example.com")
        .with_audience("https://axess.example.com"),
);
let trust_domain = TrustDomain::new("gitlab.ci").unwrap();

let resolver = WorkloadResolver::<GitLabClaims, _, _>::new(
    verifier.clone(),
    trust_domain.clone(),
    move |namespace_id: &str| tenants.get(namespace_id).copied(), // None refuses
    Issuer::custom("gitlab_ci").unwrap(),
    bearer_token,
    gitlab_mapper(
        GitLabAllowlist::new()
            .namespace_id("1204")
            .project_id("4711")
            .environment("production"),
    ),
);
let principal = resolver.resolve().await?;
```

The recipe synthesises `spiffe://gitlab.ci/<project_id>/<namespace_id>` from
the numeric `project_id` and `namespace_id` claims and requires both. The
paths (`project_path`, `namespace_path`) are mutable and reusable, as GitHub's
names are: a renamed, transferred or deleted project or group frees its old
path. They are kept as attributes for audit. The mapper also requires
`ref_protected` to be `true` unless the allowlist calls
`allow_unprotected_refs`, since any developer of the project can start a job
on an unprotected branch. With environments listed, the mapper also requires
the job's `environment` to be one of them. Every refusal names the claim that
decided it. If the instance is GitLab running in your own Azure subscription,
only the issuer URL and the JWKS handle change.

### GitHub Actions OIDC

GitHub Actions can issue OIDC tokens for workflow runs, with claims naming
the repository, the workflow, the branch, the run id and the actor. With a
trust-domain mapping, the token authenticates one workflow run from your
organisation to your application.

```rust,ignore
use axess_example_workload_identity::github_actions::{
    github_actions_mapper, GitHubActionsClaims, GitHubAllowlist,
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
    move |owner_id: &str| tenants.get(owner_id).copied(), // None refuses
    Issuer::custom("github_actions").unwrap(),
    bearer_token,
    // Trust owners and repositories by immutable numeric id, not by name.
    github_actions_mapper(
        GitHubAllowlist::new()
            .owner_id("123456")
            .repository_id("987654321")
            .git_ref("refs/heads/main")
            .event("push"),
    ),
);
let principal = resolver.resolve().await?;
```

The recipe synthesises `spiffe://github.actions/<repository_id>/<owner_id>`
from the numeric `repository_id` and `repository_owner_id` claims, and
refuses a token that lacks them or whose owner is not on the allowlist.
Names are not an identity: a renamed, deleted or transferred organisation or
repository frees its old name, and whoever registers it next signs tokens
that carry the name you trusted. The names (`repository`,
`repository_owner`) are kept as attributes for audit. The recipe also
keeps `actor`, `workflow`, `ref`, `sha` and `event_name` as
Cedar attributes for policies such as allowing deploys only from the
default branch or requiring a specific workflow file.

The allowlist also restricts the run and fails closed: the token's `ref` or
`environment` must be one you listed with `git_ref` or `environment`, and its
`event_name` one you listed with `event`. A token without the claim, or an
allowlist with nothing listed, admits nothing.

### Requiring a token type

`JwtVerifier::with_typ("at+jwt")` makes the verifier refuse, before it checks
the signature, a token whose JOSE `typ` header is missing or is not that type
(compared case-insensitively, ignoring a leading `application/`).
It is off by default. Without it the header type is not read, so an ID
token, a logout token or a DPoP proof signed by the same key verifies as
whatever the caller expects, provided `iss` and `aud` match. Set it wherever an issuer
signs more than one kind of token with one key. The values are `at+jwt` for an
access token (RFC 9068), `logout+jwt` for a logout token, `dpop+jwt` for a DPoP
proof, `oauth-authz-req+jwt` for a signed authorization request (FAPI 2.0
message signing) and `token-introspection+jwt` for a signed introspection
response. `verify_jwt_with_typ` is the same check for code that calls the
primitive directly.

### Other issuers (Okta, Azure AD, Auth0, …)

Write your own recipe. For any new IdP:

1. Decode a sample JWT to identify which claims carry the workload
   identity (a project id? a tenant id? a custom `service`?).
2. Define a `#[derive(Deserialize)] struct YourClaims { ... }` with
   only the fields you use. `JwtVerifier` ignores unknown
   claims, so you need not list everything the issuer sends.
3. Write a mapper closure
   `Fn(&VerifiedClaims<YourClaims>) -> Result<WorkloadMapping, IdentityError>`
   that produces the `(service_name, tenant_slug, attributes)` shape;
   the resolver builds the workload id from them.
4. Wire it as above, with `Issuer::custom("your_idp_label").unwrap()`
   for audit-log attribution (the constructor validates the label
   format: `[a-z0-9_]{1,32}`).

`WorkloadId::build` renders `spiffe://<trust_domain>/<service>/<tenant_slug>`,
and each of those two segments is one path component: `[A-Za-z0-9._-]`,
non-empty, with the whole URI capped at 2048 characters. A path-shaped claim such as `group/subgroup/project`
fails on the first slash, so decide what the segments mean for your issuer and build them
rather than forwarding a claim verbatim.

The shipped recipes are the templates: read their source and
adapt it.

## Where federation fits

Federation is the right answer when the deployment cannot or does
not want to issue its own workload identities: a Kubernetes-based
deployment that uses its pods' service-account tokens directly, an
open-source CI integration that accepts tokens from any GitHub Actions
run, or an enterprise deployment that integrates with a partner's Okta
tenant.

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

A federated token is as secure as its issuer: a Kubernetes token as
the cluster's OIDC issuer, a GitHub Actions token as GitHub's issuance
pipeline and an OIDC IdP's token as the IdP.

The defences axess adds are the standard ones: signature
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
rule watching the catalogue for these never fires. Axess emits from
its service layer, which holds an `IdentityAuthnLog` to write through,
and the workload resolvers sit outside it.

To audit workload authentication, record it at your call site: the issuer label and the
synthesised `WorkloadId` are both on the principal the resolver returns,
which is the attribution an issuer-level anomaly rule needs.

## Troubleshooting

| `resolve()` returns | Usually | What to do |
|---|---|---|
| `NotAuthenticated` | The verifier pins no issuer or no audience, or the JWT failed verification (wrong issuer, wrong audience, expired, bad signature, or a custom claim that would not deserialise), or the tenant lookup answered `None` for the mapped slug. The GitHub Actions recipe also answers this when its allowlist refuses the run | Turn on `tracing::debug!` for `axess_factors::federation::workload` to see which step rejected it |
| `InvalidSpiffeId` | The token verified and mapped, but the synthesised `WorkloadId` is longer than 2048 characters | Shorten the service name or tenant slug the mapper returns |
| `InvalidComponent(...)` | The claim mapper rejected the verified claims, or a path segment was empty, was `.` or `..`, or carried a character outside `[A-Za-z0-9._-]`. The message names which | Decode the payload (`base64 -d` of the JWT's middle segment) and compare it against what the mapper expects |

## Further reading

*Workload identity overview* covers the SPIFFE model the
federation resolver maps into. *Cloud STS exchange* covers the
next step for many federated tokens: exchanging a workload
identity for short-lived cloud credentials. *OAuth 2.0 and OIDC*
in Part III covers the underlying OIDC machinery that the
`JwtVerifier` builds on.
