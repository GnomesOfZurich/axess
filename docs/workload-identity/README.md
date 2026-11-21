# Workload identity overview

A workload in axess is a non-human caller: a service in your service
mesh, a Kubernetes pod, a CI/CD runner, a batch job, a serverless
function. Workloads authenticate against your application as users do, but with
different credentials, lifetimes and operational characteristics. This part of the book
covers how axess models workload identity, how it resolves credentials
into a typed `Principal::Workload`, and how the Cedar policy layer
authorises workloads through the same rules it uses for human users.

The unifying claim is the one *The principal model* in Part II
already made: humans and workloads are the same type. A Cedar policy
that says `resource.tenant_id == principal.tenant_id` works for a
logged-in user and for a SPIFFE-identified payment service without
branching. The chapters in this part cover the specific resolvers
that turn each credential kind into a `Principal::Workload`.

Read the chapters that match your deployment: SPIFFE-based deployments
read *Inbound: JWT-SVID* and *Inbound: mTLS-SVID*; cloud-platform
deployments read *Inbound: federation* and *Cloud STS exchange*;
applications that call downstream services on a workload's behalf
read *Outbound: OAuth* and *Outbound: mTLS*; workloads on a node with
a SPIRE agent read *SPIRE Workload API client*. A caller that can do none
of this, and can only be given a string, reads *Shared secrets: the
last resort*, which also says why it is the last resort.

## The model

One resolver trait, and why humans and workloads share a type.

### The resolver model

Every inbound request that carries a workload credential runs
through a `PrincipalResolver`. The resolver inspects the credential
(a bearer JWT in a header, a client certificate from the TLS
handshake, a projected service-account token), validates it, and
returns a `Principal::Workload` if the validation succeeds. Axess
implements the same trait for every credential kind it supports, and an
application wires only the resolvers it needs.

```text
        ┌──────────────────────┐
        │  Inbound request     │
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │ PrincipalResolver    │
        │ (per-feature impls)  │
        └──────────┬───────────┘
                   │
      ┌────────────┴───────────┐
      │                        │
      ▼                        ▼
Principal::Human         Principal::Workload
(session + factors)      (with Issuer + WorkloadId)
                                │
      ┌─────────────────────────┘
      │
      ▼
ToCedarEntity bridge
      │
      ▼
Cedar evaluation
```

Two SPIFFE resolvers ship, plus a generic third for everything else:

- `JwtSvidResolver`, for SPIFFE JWT-SVIDs. Spec-bound, with a
  mandatory `spiffe://` URI in `sub`.
- `MtlsResolver`, for SPIFFE X.509-SVIDs over mTLS.
- `WorkloadResolver`, the generic JWT-bearer resolver. It covers every
  non-SPIFFE workload-identity flow: Kubernetes projected
  service-account tokens, GitHub Actions and GitLab CI OIDC, Okta,
  Azure AD, Auth0, axess's own `LocalIdP`, custom internal JWT
  formats.

For the generic one the adopter supplies a small claim parser and
mapping closure per issuer; `examples/workload-identity/`
has ready-made recipes for GitHub Actions and Kubernetes service
accounts. The human
side has its own `SessionResolver` covered in Part II. A
`MockResolver` is available for DST tests. Each resolver implements
the same trait and produces the same `Principal` shape.

### Why one type covers both

A traditional auth library treats human and workload identity as
two independent stacks. The session layer handles users; a separate
JWT-validation middleware handles services. Neither composes with
the other. A policy that has to apply to both, say "only callers in
the finance tenant may read this resource", ends up written twice:
once for users, in code that knows about sessions, and once for
workloads, in code that knows about tokens. The two drift apart as
the application evolves.

Unifying on `Principal` removes the duplication. The Cedar policy
quoted above works for a human and a workload because the policy
matches on a tenant id, which both variants carry. If the policy
later needs to tell the two apart (a rule that demands
human-completed MFA for an action, but admits any workload), one rule
expresses it:

```cedar,ignore
permit (
    principal,
    action == Action::"transfer-funds",
    resource
) when {
    resource.tenant_id == principal.tenant_id
    && (
        principal is axess::Workload  // workloads bypass MFA requirement
        || (
            principal is axess::Human
            && context.assurance has fido2
        )
    )
};
```

The distinction lives in one place, the policy file, rather than
scattered across handlers.

## The credential kinds

SPIFFE's vocabulary first, because everything after it assumes the terms.

### SPIFFE and SVIDs

[SPIFFE](https://spiffe.io/) is the industry-standard model for
workload identity, and the chapters that follow assume the
vocabulary. The two terms worth knowing up front:

A *SPIFFE ID* is a URI of the form
`spiffe://<trust_domain>/<path>`. The trust domain is the federation
namespace (`prod.example.com`, say); the path identifies a specific
workload within that domain (`/billing/acme`). The
combination uniquely names the workload across the federation.

An *SVID* (SPIFFE Verifiable Identity Document) is the credential
that carries the SPIFFE ID. SVIDs come in two formats: JWT-SVID (a
JWT signed by the trust domain's issuing authority) and X.509-SVID
(a leaf certificate with the SPIFFE ID in a Subject Alternative
Name URI). Both are covered in their own cookbook chapters.

[SPIRE](https://github.com/spiffe/spire) is the reference SPIFFE
implementation. It handles workload attestation (verifying that a
process running on a host is the workload it claims to be), SVID
issuance, key rotation, and trust-domain federation. Axess does not
replace SPIRE; SPIRE issues, axess validates. The two are designed
to compose.

The `spire` feature is the client side of that composition:
`SpireClient` talks to a local SPIRE agent's socket, fetches the
workload's X.509 and JWT SVIDs and the trust bundles, and keeps them
current as the agent rotates them, so nothing has to be mounted into
the filesystem. What it fetches goes to the rest of axess: the X.509
SVID to outbound mTLS, a JWT SVID to the outbound paths that present
a token, the bundles to the verifiers. *SPIRE Workload API client*
is its chapter.

### Federation

A trust domain is a unit of issuance. A workload in trust domain A
is identified by an A-issued SVID, validated against A's signing
keys. When a workload in domain A needs to call a service in domain
B, federation is the mechanism that lets B accept A's identity.

Three federation patterns appear in axess.

Same-domain is the simple case. The resolver validates the SVID
against the local trust-domain bundle (the JWKS for JWT-SVIDs, the
CA bundle for X.509-SVIDs). The SVID carries the local trust
domain; the resolver knows where to fetch the keys.

Federated is the cross-domain case, and axess ships no policy type
for it. A resolver is constructed against one expected trust domain
and refuses anything else, so accepting a second domain means
deciding, in your own code, which domains you admit, which path
prefixes within each, and how a foreign identity maps into your
namespace. That decision is
deployment configuration; axess validates, the deployment decides
the rules.

External-issuer is the non-SPIFFE case. The credential is not a
SVID at all (a Kubernetes service-account token, a GitHub Actions
OIDC token, an Azure AD workload token). All of these go through
the single generic `WorkloadResolver`. The adopter supplies a claim
parser and mapping closure that name the service and tenant slug from
whichever claims the issuer's JWT carries, and the resolver synthesises
from them a SPIFFE-shape `WorkloadId` under its own trust domain. The
synthesis lets the rest of the system work uniformly: by the
time the policy evaluator sees it, the external workload looks like any
other workload, and the audit rows you write about it carry the same
shape of identity. Axess writes none of those rows itself on these
paths; *Inbound: federation* says what that leaves you.

### Cloud STS exchange

A workload that needs to call AWS, GCP, or Azure APIs can exchange
its workload identity for short-lived cloud credentials. All three
cloud providers implement the mechanism under
similar names (AWS STS AssumeRoleWithWebIdentity, GCP Workload
Identity Federation, Azure Federated Identity Credentials), and
axess provides adapters that bridge a validated workload identity
to each of them.

The walkthroughs *Azure* and *AWS* follow one request from a pipeline job
through a service to a cloud secret store, step by step. The chapter *Cloud
STS exchange* covers the configuration and the
credential lifecycle. With the exchange, no long-lived cloud keys
live on the workload's filesystem; the credentials are minted
on demand from the workload identity, used briefly, and discarded.

### Outbound

Axess is not only an inbound authenticator. When a service
authenticates *to* a downstream service, it uses the same identity
shape it would accept inbound. The chapters *Outbound: OAuth* and
*Outbound: mTLS* cover the two ways this works: the workload
exchanges its identity for a bearer token through an OAuth flow, or
presents an mTLS client certificate to the downstream's TLS server.

One identity (the workload's SVID, or its federated equivalent) then
carries through an entire chain of service calls, so an audit trail written at each hop names the same
identity throughout, and revocation at the issuing authority propagates
to every call that was about to use it.

## Feature flags

Each resolver has its own feature, so a deployment pays the compile
cost only for the credential kinds it uses.

| Feature | Resolver | Purpose |
|---|---|---|
| `jwt-svid` | `JwtSvidResolver` | Inbound SPIFFE JWT-SVID (spec-bound) |
| `mtls` | `MtlsResolver` | Inbound SPIFFE X.509-SVID via mTLS |
| `jwt` (pulled in by `jwt-svid` and others; enable `jwt-aws-lc` or `jwt-rust-crypto` beside it; the module is `axess::jwt`, not `axess::federation::jwt`) | `WorkloadResolver` | Generic JWT-bearer workload identity for *every* non-SPIFFE issuer (GitHub Actions, k8s SA, GitLab CI, Okta, Azure AD, Auth0, `LocalIdP`, …) via an adopter-supplied claim parser and mapping closure. No per-company features; see `examples/workload-identity/` |
| `outbound-mtls` | (client side) | Outbound mTLS with workload SVID |
| `spire` | (client side) | `SpireClient`: SVIDs and trust bundles from a local SPIRE agent, kept current; in no umbrella |
| `outbound-oauth` | (client side) | Outbound OAuth client |
| `aws-sts`, `gcp-wif`, `azure-fic` | (cloud STS) | Exchange workload identity for cloud credentials |
| `workload-id` | umbrella | SPIFFE adapters + outbound + mTLS bundle |

## What this part does not cover

Three concerns are intentionally outside scope.

The SPIRE Agent and Server implementations are not part of axess.
Axess validates SVIDs and, with `spire`, fetches them from an agent;
SPIRE issues them. The two are designed to
be independent so deployments can use any SPIFFE-compliant issuer
(SPIRE, an in-house implementation, a managed service like AWS IAM
Roles Anywhere) without changing the axess side.

Trust domain bootstrap and root-of-trust ceremonies are out of
scope. Operators manage the trust-domain bundle through SPIRE's
federation API or an equivalent mechanism. Axess consumes the
bundle; it does not establish it.

Service mesh integration is out of scope. Istio, Linkerd, and
Consul handle mesh-level identity at the proxy layer. Axess works
at the application layer above the mesh. When the mesh terminates
mTLS and forwards a verified identity in a header, a custom
`PrincipalResolver` can pick it up and produce a `Principal::Workload`
the rest of the system understands.

## Further reading

The cookbook chapters in this part cover the three inbound resolvers
(JWT-SVID, mTLS-SVID, federation), the cloud STS exchange and its two
walkthroughs, the two outbound paths, the SPIRE Workload API client and
shared secrets. Start with the inbound chapter matching the credential
kind your deployment uses; the others are useful background for the
federation and outbound scenarios. *Cedar policy fundamentals*
covers how the policy engine handles workload principals. *The
principal model* in Part II covers the unified `Principal` type
that all of this resolves to.
