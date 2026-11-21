# The principal model

A `Principal` answers "who is making this request?" This chapter explains axess's unusual choice: one type answers the question for human users and for service-to-service workloads. A signed-in employee opening a page and a CI job calling
an API are both principals: two variants of one `Principal` type, with the
same authorisation contract and the same place in the audit trail.

The alternative, two parallel authentication stacks, is rejected; *Why one type* below gives the reasons.

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
    pub session_id: Option<SessionKey>,
    pub impersonator: Option<UserId>,
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

The two variants are deliberately asymmetric: each carries the data its kind of principal has. A human has a `user_id` and is
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

Different resolvers construct the two variants, which keeps the human and
workload sides apart. Each implements the same `PrincipalResolver` trait,
whose one method, `resolve`, is async and answers a `Principal` or an
`IdentityError`.

A `SessionResolver` constructs a `HumanPrincipal` from an `AuthSession`. The resolver reads the session's `AuthState`, answers
`Err(IdentityError::NotAuthenticated)` if the state is not `Authenticated`, and otherwise reads
`user_id`, `tenant_id`, the administrator of an impersonation, and the session's key off the variant: the
principal names the session as its records do, by the 64 hexadecimal
characters of its key, never by the id its cookie carries. A Cedar policy
that reads `principal.session_id` reads those 64 characters. A principal serialised by an earlier release holds the session's id in `session_id`; that value reads as the key of that id. The
attributes map is left empty. Resolution is cheap: it reads the
session and nothing else, with no store lookup.

A workload resolver (`JwtSvidResolver`, `MtlsResolver`, `WorkloadResolver`
and the others) constructs a `WorkloadPrincipal` from an inbound credential (a bearer JWT, an mTLS client certificate, a
projected Kubernetes service-account token, a GitHub Actions OIDC
token). The resolver does the verification work (signature, audience,
expiry, sometimes a token-exchange against a control plane) and on
success returns a `WorkloadPrincipal` with the validated identity. The
work is async because verifying tokens typically involves fetching the
issuer's signing keys (its JWKS, the JSON Web Key Set published at a
well-known URL) or a round-trip to a Security Token Service (STS),
which exchanges one credential for another. *Workload identity overview* covers every resolver.

The two resolvers are independent. An application that has no
workloads (a customer-facing SaaS, say) never wires a
workload resolver and never sees a `Workload` variant. An
application that has only workloads (an internal data-pipeline API,
say) never wires a `SessionResolver` and never sees a `Human` variant.
An application with both wires both resolvers into one
`PrincipalResolverChain`, which states the order they are tried in.

## Resolving in a handler

The Axum extractors `AuthPrincipal`, `AuthHumanPrincipal` and
`AuthWorkloadPrincipal` resolve through the `PrincipalResolverChain` the
application installs in the request's extensions, once for the router:

```rust,ignore
use axess_core::PrincipalResolverChain;
use axum::http::request::Parts;

let chain = PrincipalResolverChain::new()
    .workload(move |parts: &Parts| {
        // `None` when the request presents no bearer token: the step
        // passes.
        let token = bearer_token(&parts.headers)?;
        Some(
            JwtSvidResolver::new(verifier.clone(), trust_domain.clone(), token)
                .with_tenant_lookup(lookup.clone()),
        )
    })
    .session();
let app = Router::new()
    .route("/reports", get(reports))
    .layer(axum::Extension(chain));
```

Every step runs, in the order it was added, for every request. A session
step resolves the human of an authenticated session and passes a session
that is not authenticated. A workload step builds a resolver from the
request, or answers `None` when the request presents nothing it reads,
and passes; once a resolver runs, a credential it refuses refuses the
request (401), whatever another step resolved, before it or after it.
The steps that resolve someone must agree: two that resolve different
principals, a signed-in session beside a workload credential or two
workloads, refuse the request with 401
(`PrincipalRejection::ConflictingCredentials`), and the request is
admitted as neither. Two credentials of the same principal (the same
workload over a certificate and a token, say) are one principal. A
request with no chain installed resolves through the session alone.

All three extractors run the chain this way, and differ only in what
they admit. `AuthPrincipal` yields the principal the request resolves to,
a `Workload` when a workload step resolved it. `AuthHumanPrincipal` and
`AuthWorkloadPrincipal` admit it when it is of their kind, and answer 403
(`PrincipalRejection::WrongKind`) when it is of the other; all three
answer 401 when nobody is resolved. A session step without the session
layer installed answers 500 (`PrincipalRejection::SessionLayerMissing`),
a wiring error.

## Why one type

The natural alternative is two types and two stacks: a `User` for
humans, a `Service` for workloads, a different middleware for each,
a different authorisation contract for each, two parallel audit trails.
Most libraries ship that shape; axess rejects it.

The case for one type shows as soon as you write the authorisation policy. A request to a billing endpoint might be
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
principal type is unified. Rules downstream in a SIEM (the security information and event management system that collects these logs), such as "alert on any principal making more than N requests per minute to the high-sensitivity endpoint", fire on both human attacks and runaway workloads without separate detection logic.

The unification has a cost. The `Principal` enum must accommodate
both variants, which makes its memory footprint larger than either
variant alone, and pattern-matching code has to handle both arms even
when the application only uses one. The cost is paid mostly in code
that loads the principal (one match per request), and not in policy
evaluation or audit emission (which see the `Principal` type through its
accessors, such as `tenant_id()`, and through `ToCedarEntity`). On
balance, the unification pays for itself by simplifying the policy
layer.

## SPIFFE shape for workloads

The `WorkloadPrincipal` is shaped after SPIFFE because SPIFFE is the
right shape for workload identity even when the underlying credential
is not literally an SVID.

A SPIFFE identity is a URI of the form
`spiffe://<trust_domain>/<path>`. The trust domain is the federation's
namespace (`prod.example.com`, say), and the path identifies a
specific workload within that domain (`/billing/acme`).
The combination uniquely names the workload, the trust domain
parameterises the verification (each domain has its own signing keys),
and the path is structured enough for policies to match on patterns
("any workload under `/billing/*`") without inventing parallel
identity stacks.

Axess's workload identity layer uses this shape even when the inbound
credential is a Kubernetes service-account token (which is an OIDC
token, not an SVID) or a GitHub Actions OIDC token (which is also not an SVID). The relevant resolver constructs a SPIFFE-format `WorkloadId`
from the inbound claims; downstream code sees a uniform identity.
*Workload identity overview* covers the construction rules for each
resolver.

Policies use the trust domain and issuer fields on `WorkloadPrincipal` to tell identity sources apart. A
policy that says "only workloads issued by our production control
plane may write to the production database" reads the issuer and
matches against a fixed list. A policy that says "any workload in the
finance trust domain may read the audit log" reads the trust domain.

## The Cedar bridge

Cedar policies take principals as entities. Axess implements
`ToCedarEntity` for both `HumanPrincipal` and `WorkloadPrincipal`,
producing entities with the canonical shape Cedar expects.

A `HumanPrincipal` becomes a Cedar entity with UID
`axess::Human::"<user_id>"`, the attributes `user_id` and `tenant_id`,
`session_id` when the principal carries one, `impersonator` for an
impersonated session, and the keys of its `attributes` map (a key that
collides with a built-in name is dropped). The completed factors and the
time of authentication are not attributes. The entity has no parents: the
tenant and the groups a user belongs to are what the application provides
through `AuthzEntityProvider`, covered in *Entity providers and request
context*.

A `WorkloadPrincipal` becomes a Cedar entity with UID
`axess::Workload::"<spiffe-uri>"`, the attributes `workload_id`,
`trust_domain`, `issuer`, `tenant_id`, `tenant_slug` and `service_name`,
the keys of its `attributes` map, and no parents. Policies that want to
match all workloads in a trust domain write
`principal.trust_domain == "prod.example.com"`;
policies that want to match a specific workload pattern write
`principal.workload_id like "spiffe://prod.example.com/billing/*"`.

The bridge is what makes one type into one policy.
`AuthzStore::for_principal` (and `for_principal_with_context`, for
policies that read `context`) begins an authorization session for any
`Principal`: its Cedar principal is the entity `ToCedarEntity` makes,
`axess::Human` or `axess::Workload`, the session is in the principal's
tenant, and the session adds that entity to the ones the
`AuthzEntityProvider` supplies, so the provider does not build it. A
provider that supplies an entity of the same UID must supply the same
entity; one that differs denies the check. The user-id constructors
(`for_user_id` and its siblings) are the user case of the same path, with
a `User` principal whose entity the provider supplies.

With a schema, declare `axess::Human` and `axess::Workload` with the
attributes above and name them among the principal types of each action.
A Cedar policy that says

```cedar,ignore
permit (
  principal,
  action == Action::"read",
  resource in TenantData::"acme"
) when {
  principal.tenant_id == resource.tenant_id
};
```

allows both a human user in tenant acme and a workload bound to
tenant acme to read a document of acme's data, whose `tenant_id` is
acme's, and refuses a workload of another tenant: `principal.tenant_id`
is the tenant's id on both kinds. A test of axess-core runs this policy,
word for word, through `for_principal` for the three. The principal type
does not appear in the rule because it does not need to. If the policy later needs to discriminate (say,
to require MFA for humans but not for workloads), the rule that
expresses the discrimination is local and readable.

### Groups and other parents

The principal's entity is the library's, in a session begun with
`for_principal`: the session builds it from the `Principal`, with the
attributes above and no parents, and a provider entity of the principal's
UID must be that same entity, or the check is denied (the decision reason
is `principal_entity_conflict`). So a provider cannot make the principal a
member of a group by giving the principal's entity a parent.

Groups come from the provider as entities of their own instead. The
provider supplies each group (`Group::"payroll"`), with the parent links
between groups on the groups themselves (`Group::"payroll"` within
`Group::"finance"`), and names the group's members on the group, as an
attribute that holds their principal entities (`members`). A policy then
reads membership from the group:

```cedar,ignore
permit (
  principal,
  action == Action::"read",
  resource
) when {
  principal in Group::"payroll".members && Group::"payroll" in Group::"finance"
};
```

A policy written as `principal in Group::"finance"` asks for the
principal's own parents, which its entity does not have, and is never
satisfied in such a session. A membership the resolver already knows,
such as a group claim of the token, can travel as one of the principal's
attributes (`HumanPrincipal::attributes`), which the entity carries, and
be read as `principal.groups.contains("finance")`. A test of axess-core
runs the policy above with a provider that supplies the two groups.

## When the type is empty

Some flows operate without a principal: a health check, a metrics
endpoint, the login page itself. Axess models this as the absence of a
principal, not as a variant: there is no `Principal::None`. For a session
that is not authenticated, `SessionResolver::resolve` answers
`Err(IdentityError::NotAuthenticated)`, and the `AuthPrincipal`,
`AuthHumanPrincipal` and `AuthWorkloadPrincipal` extractors refuse the
request with 401 (`PrincipalRejection::NotAuthenticated`). An endpoint
open to unauthenticated callers takes no principal extractor.

The pattern matters because a misconfigured resolver
that returns a stub principal for unauthenticated requests, instead
of an error, silently widens the authorisation surface. The Cedar policy
evaluates against the stub and may allow actions that should require
authentication. Treating "no principal" as the absence of a value,
rather than as a kind of value, makes the policy author's life harder
in the short term and easier in the long term: a request without a
principal never reaches a policy. `AuthzStore::for_session` refuses a
session that is not authenticated with `AuthzError::NoPrincipal`.

## What the unified type saves you

The unified principal type is what makes the rest of the workload
identity story (Part VII) and the Cedar authorisation story (Part IV)
short. A handler reads `Principal`, the authorisation layer evaluates
policies against it, and the audit pipeline emits events keyed by
it. None of these layers needs to know whether the caller is a human or a workload, because the type carries both and the policy author tells them apart only where it matters.

## Further reading

*Workload identity overview* covers the resolvers that produce
`WorkloadPrincipal` values: SPIFFE JWT-SVID, SPIFFE mTLS, Kubernetes
ServiceAccount tokens, GitHub Actions OIDC, generic OAuth-RS, and
cloud STS exchange. *Cedar policy fundamentals* covers the
`AuthzSession::require` and `AuthzSession::is_permitted` calls, which
decide an action on a resource for the user the `AuthzSession` was built
for: `require` answers
`Err(AuthzDenied)` on a denial and `is_permitted` answers a `bool`. *Audit events* covers the
log emitted for each authentication and authorisation decision,
including the principal serialisation.
