# Cedar policy fundamentals

Most application authorisation is the `if user.role == "admin"` style:
a check scattered across handlers, expressed in code, written by
whoever happened to be in the file at the time, with no shared
schema and no way to review the policy as a whole. The pattern works
for small applications and fails for everything else, because the
authorisation logic is the part of the application that needs the
most review and is also the part most likely to drift.

[Cedar](https://cedarpolicy.com/) is a policy language designed for
this exact problem. It is declarative, deny-by-default, statically
checkable against a schema, and built to express RBAC, ReBAC, and
ABAC in one set of rules. Axess loads a Cedar policy set at startup,
validates it against a schema, and exposes per-request evaluation
through a small typed interface. This chapter covers the lifecycle:
loading, validation, the per-request evaluator, the contract with
the application's data layer, and the error modes.

The feature flag is `authz` (on by default in the `axess` facade).

## The lifecycle

Cedar in axess has three lifecycle phases: load, evaluate, redeploy.
Each phase has a specific failure mode, and the design is built so
the failures land at the right place.

The load phase happens once at application startup. The application
constructs a `PolicyStore` from one or more policy files, validates
the parsed policies against a schema, and produces an `AuthzStore`
that holds the result. A load failure (a malformed policy, a type
mismatch against the schema, an action that references an
undefined entity) is a startup failure: the application refuses to
start. The defence is structural: there is no path to production
with a broken policy file because the application refuses to come
up.

The evaluate phase happens once per authorisation check. The
application constructs an `AuthzSession` from the `AuthzStore`, a
`Principal` (typically extracted from the session or from a
workload-identity resolver), an `AuthzEntityProvider` that supplies
the application's entity graph for this request, and a context
(MFA status, IP address, the application's custom attributes). The
session offers two verbs: `require` (allow or deny, returning an
error on deny) and `decide` (a typed `AuthzDecision`). The
evaluation is cheap, predictable, and deterministic.

The redeploy phase happens when policies change. The application
loads a new `PolicyStore` from the new policy files, swaps it in
behind the `AuthzStore`'s `Arc`, and from the next request onward
new evaluations use the new policies. A hot reload of policies is
supported; the trade-off is that decisions in flight at swap time
see the old policies and decisions started after see the new
policies. There is no decision-caching layer in axess for this
reason: a cached decision from before a redeploy would survive into
the new policy regime and produce wrong answers. The chapter
*Entity providers and request context* expands on what does and
does not get cached.

## Loading policies

The minimal load is a directory of `.cedar` files plus a
`schema.cedarschema` file:

```rust,ignore
use axess::authz::{AuthzStore, PolicyStore};

let policy_store = PolicyStore::load_directory("./policies")?;
let schema = std::fs::read_to_string("./policies/schema.cedarschema")?;
policy_store.validate_against(&schema)?;

let authz_store = AuthzStore::new(policy_store);
```

The load is recursive: every `.cedar` file under the directory is
parsed and added to the policy set. Cedar policies have no `import`
or namespace mechanism beyond the entity-type namespace; the
collection of all files is the policy set, evaluated as one.

`validate_against` is the call that catches malformed policies
before they reach production. The validator checks that every
entity type the policies reference is defined in the schema, that
every attribute access is on an attribute the schema declares, and
that the types align (a policy that asks `principal.age > "old"`
gets caught because the schema declares `age` as a number and the
literal is a string).

The schema is its own discipline. Writing a schema that accurately
describes the application's entities is the hardest part of a
Cedar integration. The schema names the principal types (`User`,
`Workload`, `Role`, `Group`), the action types (`read`, `write`,
`administer`), the resource types (the application's domain
objects), and the parent relationships (a `User` is in `Group`s,
which are in `Role`s, which permit `Action`s). The Cedar
documentation covers schema authoring in detail; the chapter here
focuses on what axess does with a schema once it has one.

## The per-request evaluator

The `AuthzSession` is constructed per request and lives only as
long as the request:

```rust,ignore
let session: AuthzSession = authz_store.session()
    .with_principal(principal)
    .with_entity_provider(&app.entity_provider)
    .with_context(StandardRequestContext::from_request(&request))
    .build();

match session.decide(
    Action::View,
    ResourceUid::new("Document", "doc-123"),
).await {
    Ok(AuthzDecision::Allow) => proceed(),
    Ok(AuthzDecision::Deny) => render_forbidden(),
    Err(e) => render_error(e),
}
```

The `with_principal` call binds the caller. The principal carries
the user id, the tenant id, the factors completed, and the
authentication time. Cedar policies can match on any of these.

The `with_entity_provider` call binds the application's data
layer. The entity provider is the application-specific code that
loads the relevant entities (the user record, their group
memberships, the resource being accessed, its parents) for the
evaluation. The provider returns a Cedar entity graph; the session
holds it for the duration of the evaluation. The next chapter,
*Entity providers and request context*, covers the provider
contract in detail.

The `with_context` call binds the contextual attributes. The
`StandardRequestContext` covers the common cases: MFA status, IP
address, the time of the request. Applications can extend it with
custom keys (a custom-headers map, a tenant-feature-flag set, a
geographical location).

The `decide` verb evaluates the policies and returns
`AuthzDecision::Allow` or `AuthzDecision::Deny`. The verb is async
because the entity provider may need to fetch entity data from a
database. The `require` verb is a thin wrapper that returns an
error on `Deny`, suitable for handlers that want to short-circuit
on a denied request.

## What policies look like

A Cedar policy is a `permit` or `forbid` statement against a
principal, action, and resource, with optional `when` conditions.
The simplest possible policy:

```cedar,ignore
permit (
    principal,
    action == Action::"read",
    resource
);
```

This is the "everyone can read everything" policy. It permits any
principal to perform the read action against any resource. It is
useful for nothing in production but illustrates the shape.

A real RBAC policy:

```cedar,ignore
permit (
    principal in Role::"finance-viewer",
    action == Action::"read",
    resource in TenantData::"acme"
) when {
    principal.tenant_id == "acme"
};
```

This permits any principal in the `finance-viewer` role to read any
resource in the `acme` tenant's data, but only when the principal
is also in the `acme` tenant. The `in` operator is set membership
against the entity graph: the policy is asking the entity provider
"is this principal in this role?", which the provider answers from
the application's data.

A ReBAC policy:

```cedar,ignore
permit (
    principal,
    action == Action::"edit",
    resource
) when {
    resource.owner == principal
};
```

This permits a principal to edit a resource only when the resource's
`owner` attribute equals the principal. Ownership is the ReBAC
relationship; the schema declares `Document` has an `owner`
attribute of type `User`, and the entity provider populates it from
the document's row.

An ABAC policy:

```cedar,ignore
permit (
    principal,
    action == Action::"write",
    resource in TenantData::"acme"
) when {
    principal.tenant_id == "acme"
    && context.mfa == true
    && context.ip like "10.*"
};
```

This permits writes to the `acme` tenant's data when the principal
is in the tenant, has completed MFA, and is connecting from an
internal IP range. Context attributes come from the
`StandardRequestContext` (or custom extensions); the schema
declares them so the validator can type-check the policy.

The three styles compose freely in one rule. A real production
policy is typically a mix: roles establish broad permissions,
relationships restrict to ownership, attributes restrict to
high-assurance contexts. Cedar's deny-by-default behaviour means
the rules accumulate as positive grants; no rule denies, and the
absence of a permitting rule is itself a deny.

## Errors

The `AuthzError` enum has variants for the cases that go wrong:

```rust,ignore
pub enum AuthzError {
    PolicySetInvalid(String),       // load-time, should never reach prod
    SchemaValidationFailed(String), // load-time
    EntityNotFound { uid: String }, // evaluator could not load an entity
    ContextMissing(String),         // policy needed a context key not provided
    EvaluationFailed(String),       // Cedar internal error (rare)
    Cancelled,                      // request cancelled during evaluation
}
```

The load-time variants should never reach production because the
`PolicyStore::validate_against` call catches them at startup.

The runtime variants are recoverable but specific. `EntityNotFound`
means the entity provider returned no entity for a UID a policy
referenced; the deployment may have a stale Cedar reference or a
race between policy and data. `ContextMissing` means a policy
referenced a context key the request did not provide; the schema
should have caught this at load time but did not (a context key
the schema declared as optional, used in a policy as if required).
`EvaluationFailed` is the catch-all for Cedar's own errors, which
are rare in well-formed policy sets.

Every variant produces a deny. There is no path where an
evaluation error produces an allow. The defence is structural and
is one of the reasons Cedar was chosen.

## When to use require versus decide

The two verbs differ in their failure handling. `require` returns
an error on `Deny` (so the handler short-circuits with an error
without needing an explicit match); `decide` returns the typed
decision (so the handler can branch).

The recommendation is to use `require` in handlers (the most
common case: deny gives a 403, allow proceeds), and `decide` in
code that needs to express a non-binary outcome (a UI that hides
buttons rather than displaying them and denying on click, an
admin panel that shows what the current user could do).

```rust,ignore
// require version: handler short-circuits on deny
async fn delete_document(
    session: AuthzSession,
    Path(doc_id): Path<String>,
) -> Result<Json<()>, AppError> {
    session
        .require(Action::Delete, ResourceUid::new("Document", &doc_id))
        .await?;
    // ... proceed with delete
}

// decide version: branch on the decision
async fn dashboard(
    session: AuthzSession,
) -> impl IntoResponse {
    let can_create_doc = matches!(
        session.decide(Action::Create, ResourceUid::new("Document", "*")).await,
        Ok(AuthzDecision::Allow)
    );
    render_dashboard(can_create_doc)
}
```

The wildcard resource UID in the second example is a Cedar
convention for "is the principal allowed to perform this action at
all?"; it relies on the policy set being written with that question
in mind.

## What policies cannot do

Cedar is the right tool for asking "is this allowed?". It is not
the right tool for everything that pattern-matches like
authorisation but is actually something else.

It is not for rate limiting. Rate limits are stateful (they depend
on the rate of past requests, not the content of the current
request), expensive to express in declarative terms, and not what
Cedar is built for. Use the `RateLimitLayer` middleware (covered in
*Rate limiting*).

It is not for input validation. A request with an invalid body
fails at deserialisation, not at authorisation. Cedar policies
that try to enforce body-shape constraints duplicate validation
logic and run after the body has already been parsed.

It is not for state transitions. A workflow that allows a
transition from `Pending` to `Approved` but not from `Pending` to
`Closed` is a state machine, not a policy. Implement the state
machine in code (or in a `axess`-style typed state machine for the
workflow); use Cedar to gate access to the transition operations.

It is not for caching decisions across requests. Policies and
entity graphs are mutable; cached decisions are stale by
construction. Axess deliberately caches entity graphs (which are
much more stable) and not decisions.

The next chapter, *Entity providers and request context*, covers
the entity-graph caching mechanism and the contract between Cedar
and the application's data layer.

## Further reading

*Entity providers and request context* covers the
`AuthzEntityProvider` trait, the `StandardRequestContext` extension
points, and the caching posture. *RBAC, ReBAC, and ABAC patterns*
walks through worked examples of each style and how they compose
in one policy set. *The principal model* covers the principal types
the evaluator binds to.
