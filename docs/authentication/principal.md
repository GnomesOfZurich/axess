# The principal model

A `Principal` in axess is the answer to "who is making this request?"
The unusual choice, and the one this chapter explains, is that the
same type answers the question for human users and for service-to-service
workloads. A signed-in employee opening a page and a CI job calling
an API are both principals, with different variants but the same trait
surface, the same authorisation contract, and the same place in the
audit trail.

This chapter covers the type, where each variant comes from, how the
unified shape lets a Cedar policy treat humans and workloads with one
set of rules, and why the alternative (two parallel authentication
stacks) was rejected.

## The type

`Principal` lives in `axess-identity`:

```rust,ignore
pub enum Principal {
    Human(HumanPrincipal),
    Workload(WorkloadPrincipal),
}

pub struct HumanPrincipal {
    pub user_id: UserId,
    pub tenant_id: TenantId,
    pub session_id: Option<SessionId>,
    pub attributes: BTreeMap<String, serde_json::Value>,
}

pub struct WorkloadPrincipal {
    pub workload_id: WorkloadId,
    pub trust_domain: TrustDomain,
    pub issuer: Issuer,
    pub tenant_id: TenantId,
    pub tenant_slug: String,
    pub service_name: String,
    pub attributes: BTreeMap<String, serde_json::Value>,
}
```

The two variants are intentionally not symmetric. They carry the data
each principal kind actually has. A human has a `user_id` and is
optionally inside a session (some flows act on behalf of a user without
a live HTTP session, which is why the field is `Option`). A workload
has a `workload_id` (a SPIFFE-format URI), a trust domain, and an
issuer that says how the principal was authenticated (which OIDC
provider, which JWKS, which SPIFFE control plane).

Both variants carry a `tenant_id` (because every request happens in
the context of a tenant, whether the caller is human or not) and an
open `attributes` map (because policies need to ask questions that the
fixed fields cannot answer). The attribute map is JSON-valued so that
custom attributes (a hardware-key serial, a CI build hash, a regulator
classification) can be carried without changing the type.

## Where each variant comes from

The two variants are constructed by two different resolvers. The split
is what keeps the human and workload sides from contaminating each
other.

A `HumanPrincipal` is constructed by a `SessionResolver` from an
`AuthSession`. The resolver reads the session's `AuthState`, returns
`None` if the state is not `Authenticated`, and otherwise reads
`user_id`, `tenant_id`, and the session id off the variant. The
attributes map is populated from the resolved user's stored profile
data (which fields depend on the application's identity store).
Construction is synchronous and cheap because everything the resolver
needs is already on the session.

A `WorkloadPrincipal` is constructed by a `PrincipalResolver` from
an inbound credential (a bearer JWT, an mTLS client certificate, a
projected Kubernetes service-account token, a GitHub Actions OIDC
token). The resolver does the verification work (signature, audience,
expiry, sometimes a token-exchange against a control plane) and on
success returns a `WorkloadPrincipal` with the validated identity. The
work is async because verifying tokens typically involves a JWKS
fetch or an STS round-trip. The chapter *Workload identity overview*
covers the resolver landscape end-to-end.

The two resolvers are independent. An application that has no
workloads (a customer-facing SaaS, say) never wires a
`PrincipalResolver` and never sees a `Workload` variant. An
application that has only workloads (an internal data-pipeline API,
say) never wires a `SessionResolver` and never sees a `Human` variant.
An application that mixes both wires both resolvers and a small piece
of glue that decides which to consult given the incoming request shape.

## Why one type

The natural alternative is two types and two stacks: a `User` for
humans, a `Service` for workloads, a different middleware for each,
a different authorisation contract for each, two parallel audit trails.
That shape is what most libraries ship, and it is what axess
deliberately rejects.

The argument for one type is straightforward when you start to write
the authorisation policy. A request to a billing endpoint might be
made by a finance staff member during office hours, or by a scheduled
job running the monthly invoicing batch. The policy that decides
whether the request is allowed is the same in both cases: this caller,
in this tenant, has the right to read this resource. With one
`Principal` type, the policy is one rule. With two types, the policy
either duplicates the rule (and the duplicates drift) or branches on
the caller kind (and the branches obscure the intent).

The same applies to the audit trail. A regulatory audit log that
records "principal X performed action Y against resource Z at time
T" works uniformly across human and workload callers when the
principal type is unified. The downstream SIEM rules ("alert on any
principal making more than N requests per minute to the
high-sensitivity endpoint") fire on both human attacks and runaway
workloads, without separate detection logic.

The unification has a cost. The `Principal` enum must accommodate
both variants, which makes its memory footprint larger than either
variant alone, and pattern-matching code has to handle both arms even
when the application only uses one. The cost is paid mostly in code
that loads the principal (one match per request), and not in policy
evaluation or audit emission (which see the trait surface). On
balance, the unification pays for itself by simplifying the policy
layer.

## SPIFFE shape for workloads

The `WorkloadPrincipal` is shaped after SPIFFE because SPIFFE is the
right shape for workload identity even when the underlying credential
is not literally a SVID.

A SPIFFE identity is a URI of the form
`spiffe://<trust_domain>/<path>`. The trust domain is the federation's
namespace (`prod.example.com`, say), and the path identifies a
specific workload within that domain (`/svc/billing/tenant-acme`).
The combination uniquely names the workload, the trust domain
parameterises the verification (each domain has its own signing keys),
and the path is structured enough for policies to match on patterns
("any workload under `/svc/billing/*`") without inventing parallel
identity stacks.

Axess's workload identity layer uses this shape even when the inbound
credential is a Kubernetes service-account token (which is an OIDC
token, not a SVID) or a GitHub Actions OIDC token (which is also not
a SVID). The relevant resolver constructs a SPIFFE-format `WorkloadId`
from the inbound claims; downstream code sees a uniform identity.
*Workload identity overview* covers the construction rules for each
resolver.

The trust domain and issuer fields on `WorkloadPrincipal` are the part
that policies can use to discriminate between identity sources. A
policy that says "only workloads issued by our production control
plane may write to the production database" reads the issuer and
matches against a fixed list. A policy that says "any workload in the
finance trust domain may read the audit log" reads the trust domain.

## The Cedar bridge

Cedar policies take principals as entities. Axess implements
`ToCedarEntity` for both `HumanPrincipal` and `WorkloadPrincipal`,
producing entities with the canonical shape Cedar expects.

A `HumanPrincipal` becomes a Cedar entity with UID
`User::"<user_id>"`, attributes including `tenant_id`,
`factors_completed`, and `authn_time`, and parent entities for the
tenant and any groups the user belongs to (which the application
provides through `AuthzEntityProvider`, covered in *Entity providers
and request context*).

A `WorkloadPrincipal` becomes a Cedar entity with UID
`Workload::"<spiffe-uri>"`, attributes including `trust_domain`,
`issuer`, and `tenant_id`, and parent entities for the trust domain
and the tenant. Policies that want to match all workloads in a trust
domain write `principal in TrustDomain::"prod.example.com"`;
policies that want to match a specific workload pattern write
`principal.workload_id like "spiffe://prod.example.com/svc/billing/*"`.

The bridge is what makes one type into one policy. A Cedar policy
that says

```cedar,ignore
permit (
  principal,
  action == Action::"read",
  resource in TenantData::"acme"
) when {
  principal.tenant_id == "acme"
};
```

allows both a human user in tenant acme and a workload bound to
tenant acme. The principal type does not appear in the rule because
it does not need to. If the policy later needs to discriminate (say,
to require MFA for humans but not for workloads), the rule that
expresses the discrimination is local and readable.

## When the type is empty

Some flows operate without a principal: a health check, a metrics
endpoint, the login page itself. Axess models this by representing
the request as `Option<Principal>`. The resolver returns `None`, the
authorisation layer either short-circuits (for unauthenticated
endpoints) or evaluates against `principal == Principal::None` (for
endpoints that take a deny-by-default position toward unauthenticated
callers).

The pattern matters for one specific reason. A misconfigured resolver
that returns a stub principal for unauthenticated requests, instead
of `None`, silently widens the authorisation surface. The Cedar policy
evaluates against the stub and may allow actions that should require
authentication. Treating "no principal" as the absence of a value,
rather than as a kind of value, makes the policy author's life harder
in the short term and easier in the long term: a policy that does not
explicitly admit `None` denies it by default.

## What this enables

The unified principal type is what makes the rest of the workload
identity story (Part VII) and the Cedar authorisation story (Part IV)
short. A handler reads `Principal`, the authorisation layer evaluates
policies against it, and the audit pipeline emits events keyed by
it. None of these layers need to know whether the caller is a human
or a workload, because the type carries both possibilities and the
policy author resolves the discrimination where it actually matters.

## Further reading

*Workload identity overview* covers the resolvers that produce
`WorkloadPrincipal` values: SPIFFE JWT-SVID, SPIFFE mTLS, Kubernetes
ServiceAccount tokens, GitHub Actions OIDC, generic OAuth-RS, and
cloud STS exchange. *Cedar policy fundamentals* covers the
`AuthzSession::require` and `AuthzSession::decide` calls that take a
`Principal` and return an `AuthzDecision`. *Audit events* covers the
log emitted for each authentication and authorisation decision,
including the principal serialisation.
