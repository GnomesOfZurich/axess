# Workload identity overview

A workload in axess is a non-human caller: a service in your service
mesh, a Kubernetes pod, a CI/CD runner, a batch job, a serverless
function. Workloads need to authenticate against your application
the same way users do, but the credentials, the lifetimes, and the
operational characteristics are different. This part of the book
covers how axess models workload identity, how it resolves credentials
into a typed `Principal::Workload`, and how the Cedar policy layer
authorises workloads through the same rules it uses for human users.

The unifying claim is the one *The principal model* in Part II
already made: humans and workloads are the same type. A Cedar policy
that says `resource.tenant_id == principal.tenant_id` works for a
logged-in user and for a SPIFFE-identified payment service without
branching. The chapters in this part cover the specific resolvers
that turn each credential kind into a `Principal::Workload`.

The cookbook chapters are siblings of this overview. Read them in
the order that matches your deployment: SPIFFE-based deployments
read *Inbound: JWT-SVID* and *Inbound: mTLS-SVID*; cloud-platform
deployments read *Inbound: federation* and *Cloud STS exchange*;
applications that call downstream services on a workload's behalf
read *Outbound: OAuth* and *Outbound: mTLS*.

## The resolver model

Every inbound request that carries a workload credential runs
through a `PrincipalResolver`. The resolver inspects the credential
(a bearer JWT in a header, a client certificate from the TLS
handshake, a projected service-account token), validates it, and
returns a `Principal::Workload` if the validation succeeds. The same
trait is implemented for every credential kind axess supports, and
applications wire only the resolvers their deployment needs.

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

Two resolvers ship today plus a generic third for everything else:
`JwtSvidResolver` (SPIFFE JWT-SVID, spec-bound; mandatory
`spiffe://` URI in `sub`); `MtlsResolver` (SPIFFE X.509-SVID over
mTLS); and `WorkloadResolver`, the generic JWT-bearer resolver that
covers every non-SPIFFE workload-identity flow (Kubernetes projected
service-account tokens, GitHub Actions OIDC, GitLab CI OIDC, Okta,
Azure AD, Auth0, axess's own `LocalIdP`, custom internal JWT
formats). The adopter supplies a small claim parser + mapping
closure per issuer they care about; see `examples/workload-identity/`
for ready-made recipes (GitHub Actions, Kubernetes SA). The human
side has its own `SessionResolver` covered in Part II. A
`MockResolver` is available for DST tests. Each resolver implements
the same trait and produces the same `Principal` shape.

## Why one type covers both

A traditional auth library treats human and workload identity as
two independent stacks. The session layer handles users; a separate
JWT-validation middleware handles services. Neither composes with
the other, and policies that need to apply to both ("only callers
in the finance tenant may read this resource") end up duplicated:
one rule for users in code that knows about sessions, another rule
for workloads in code that knows about tokens, and the two drift
apart over time as the application evolves.

Unifying on `Principal` removes the duplication. The Cedar policy
quoted above works for a human and a workload because the policy
matches on a tenant id, which both variants carry. If the policy
later needs to discriminate between the two (a rule that demands
human-completed MFA for an action, but admits any workload), the
discrimination is expressed in one rule:

```cedar,ignore
permit (
    principal,
    action == Action::"transfer-funds",
    resource
) when {
    resource.tenant_id == principal.tenant_id
    && (
        principal has Workload  // workloads bypass MFA requirement
        || (
            principal has Human
            && "Fido2" in principal.factors_completed
        )
    )
};
```

The discrimination is local, readable, and lives in the policy file
rather than scattered across handlers.

## SPIFFE and SVIDs

[SPIFFE](https://spiffe.io/) is the industry-standard model for
workload identity, and the chapters that follow assume the
vocabulary. The two terms worth knowing up front:

A *SPIFFE ID* is a URI of the form
`spiffe://<trust_domain>/<path>`. The trust domain is the federation
namespace (`prod.example.com`, say); the path identifies a specific
workload within that domain (`/svc/billing/tenant-acme`). The
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

A future `SpireWorkloadApiResolver` (tracked in the ROADMAP as
) will talk to a local SPIRE agent socket directly, fetching
fresh SVIDs on demand rather than relying on adopters to mount them
into the filesystem. For now, adopters mount short-lived SVIDs into
pod filesystems and configure axess against them.

## Federation

A trust domain is a unit of issuance. A workload in trust domain A
is identified by an A-issued SVID, validated against A's signing
keys. When a workload in domain A needs to call a service in domain
B, federation is the mechanism that lets B accept A's identity.

Three federation patterns appear in axess.

Same-domain is the simple case. The resolver validates the SVID
against the local trust-domain bundle (the JWKS for JWT-SVIDs, the
CA bundle for X.509-SVIDs). The SVID carries the local trust
domain; the resolver knows where to fetch the keys.

Federated is the cross-domain case. The resolver validates the
SVID against a remote trust-domain bundle, then runs the resulting
identity through a `TrustDomainFederation` policy that maps the
foreign identity (which trust domains are accepted, which path
prefixes within each are admitted, how the identity is rewritten
into the local namespace if at all). The federation policy is
deployment configuration; axess validates, the deployment decides
the rules.

External-issuer is the non-SPIFFE case. The credential is not a
SVID at all (a Kubernetes service-account token, a GitHub Actions
OIDC token, an Azure AD workload token). All of these go through
the single generic `WorkloadResolver`: the adopter supplies a
claim parser + mapping closure that synthesises a SPIFFE-shape
`WorkloadId` from whichever claims the issuer's JWT carries. The
synthesis is what lets the rest of the system (Cedar policies,
audit events, the principal type) work uniformly: the external
workload looks like any other workload by the time the policy
evaluator sees it.

## Cloud STS exchange

A workload that needs to call AWS, GCP, or Azure APIs can exchange
its workload identity for short-lived cloud credentials. The
mechanism is implemented by all three cloud providers under
similar names (AWS STS AssumeRoleWithWebIdentity, GCP Workload
Identity Federation, Azure Federated Identity Credentials), and
axess provides adapters that bridge a validated workload identity
to each of them.

The chapter *Cloud STS exchange* covers the configuration and the
credential lifecycle. The benefit is that no long-lived cloud keys
ever live on the workload's filesystem; the credentials are minted
on demand from the workload identity, used briefly, and discarded.

## Outbound

Axess is not only an inbound authenticator. When a service
authenticates *to* a downstream service, it uses the same identity
shape it would accept inbound. The chapters *Outbound: OAuth* and
*Outbound: mTLS* cover the two ways this works: the workload
presents an mTLS client certificate to the downstream's TLS server,
or the workload exchanges its identity for a bearer token through
an OAuth flow.

The pattern matters because it lets one identity (the workload's
SVID, or its federated equivalent) carry through an entire chain of
service calls. The audit trail records the same identity at every
hop; revocation at the issuing authority propagates to every call
that was about to use the identity.

## Feature flags

The resolvers are individually feature-gated so a deployment only
pays the compile cost for the credential kinds it actually uses.

| Feature | Resolver | Purpose |
|---|---|---|
| `jwt-svid` | `JwtSvidResolver` | Inbound SPIFFE JWT-SVID (spec-bound) |
| `mtls` | `MtlsResolver` | Inbound SPIFFE X.509-SVID via mTLS |
| `jwt` (auto-pulled by `jwt-svid` etc.) | `WorkloadResolver` | Generic JWT-bearer workload identity for *every* non-SPIFFE issuer (GitHub Actions, k8s SA, GitLab CI, Okta, Azure AD, Auth0, `LocalIdP`, …) via adopter-supplied claim parser + mapping closure. No per-company features; see `examples/workload-identity/` |
| `outbound-mtls` | (client side) | Outbound mTLS with workload SVID |
| `outbound-oauth` | (client side) | Outbound OAuth client |
| `aws-sts`, `gcp-wif`, `azure-fic` | (cloud STS) | Exchange workload identity for cloud credentials |
| `workload-id` | umbrella | SPIFFE adapters + outbound + mTLS bundle |

## What this part does not cover

Three concerns are intentionally outside scope.

The SPIRE Agent and Server implementations are not part of axess.
Axess validates SVIDs; SPIRE issues them. The two are designed to
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

The cookbook chapters in this part each cover one resolver in
detail. Start with the one matching the credential kind your
deployment uses; the others are useful background for the
federation and outbound scenarios. *Cedar policy fundamentals*
covers how the policy engine handles workload principals. *The
principal model* in Part II covers the unified `Principal` type
that all of this resolves to.
