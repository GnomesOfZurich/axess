# Cedar policy fundamentals

Most application authorisation is the `if user.role == "admin"` style:
a check scattered across handlers, expressed in code, written by
whoever happened to be in the file at the time, with no shared
schema and no way to review the policy as a whole. The pattern works
for small applications and fails for everything else, because the
authorisation logic is the part of your system that needs the
most review and is also the part most likely to drift.

[Cedar](https://cedarpolicy.com/) is a policy language designed for
this exact problem. It is declarative, deny-by-default, statically
checkable against a schema, and built to express RBAC, ReBAC, and
ABAC in one set of rules. Axess loads a Cedar policy set at startup,
validates it against a schema, and exposes per-request evaluation
through a small typed interface.

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
undefined entity) is a startup failure: the process refuses to
start. The defence is structural: there is no path to production
with a broken policy file, because the process refuses to come
up.

The evaluate phase happens once per authorisation check. The
application constructs an `AuthzSession` from the `AuthzStore`, a
`Principal` (typically extracted from the session or from a
workload-identity resolver), an `AuthzEntityProvider` that supplies
your entity graph for this request, and a context
(MFA status, IP address, your custom attributes). The
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
describes your entities is the hardest part of a
Cedar integration. The schema names the principal types (`User`,
`Workload`, `Role`, `Group`), the action types (`read`, `write`,
`administer`), the resource types (your domain
objects), and the parent relationships (a `User` is in `Group`s,
which are in `Role`s, which permit `Action`s). The Cedar
documentation covers schema authoring in detail; the chapter here
focuses on what axess does with a schema once it has one.

## The per-request evaluator

The `AuthzSession` is constructed per request and lives only as
long as the request:

```rust,ignore
// One `AuthzStore` for the process, built from the policy set, the
// schema and your entity provider. It is held in an `Arc`.
let session = authz_store.for_user_id_with_context(
    &user_id.to_string(),
    StandardRequestContext::new(mfa_verified, client_ip),
)?;

if session.is_permitted("View", &doc_id).await {
    proceed()
} else {
    render_forbidden()
}
```

`for_user_id` binds the caller. It turns the user id into the Cedar
`User` UID your schema declares, and the session carries that UID for
every check it makes. Use `for_user_id_with_context` when policies need
request attributes; `for_user_id` alone gives an empty Cedar context.

The entity provider is bound to the *store*, not the session, because
it is process-wide application code rather than per-request state. It
is what loads the relevant entities (the user record, their group
memberships, the resource being accessed, its parents) for each
evaluation. The next chapter, *Entity providers and request context*,
covers the contract in detail.

`StandardRequestContext::new(mfa_verified, ip_address)` covers the
common context keys. Applications needing more implement
`BuildRequestContext` themselves and pass their own type; the session
is generic over it.

The resource is your provider's `ResourceId`, not a Cedar UID. You pass
the id your application already has, and the provider's `resource_uid`
turns it into the UID the policies match on. The action is a plain
`&str` naming the action in your schema.

The session caches entities per `(action, resource)` for its lifetime,
so a handler that checks the same pair twice pays for the provider
once.

There are three verbs, and no method returns an error for a denial.

`require(action, resource)` returns `Result<(), AuthzDenied>`, so a
handler can `?` it and let a deny become a 403. `AuthzDenied` is a
unit type: it says access was refused, and deliberately says nothing
about why, because the reason is exactly what an attacker probing
policies would like to learn. Log the detail on your side of the call.

`is_permitted(action, resource)` returns a plain `bool`, for code that
needs a non-binary outcome: a UI that hides a button rather than
showing it and denying on click, an admin panel listing what this user
could do.

`batch_check(&[(action, resource)])` evaluates several pairs and
returns `Vec<(String, AuthzDecision)>`, sharing the session's entity
cache across them. Use it to answer "which of these may I do?" in one
pass instead of a loop of `is_permitted`.

All three are async because the provider is: loading entities usually
means a database round trip.

```rust,ignore
// require version: handler short-circuits on deny
async fn delete_document(
    session: AuthzSession,
    Path(doc_id): Path<String>,
) -> Result<Json<()>, AppError> {
    session.require("Delete", &doc_id).await?;
    // ... proceed with delete
}

// is_permitted version: branch on the boolean
async fn dashboard(
    session: AuthzSession,
) -> impl IntoResponse {
    let can_create_doc = session.is_permitted("Create", &template_id).await;
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
and your data layer.

## Further reading

*Entity providers and request context* covers the
`AuthzEntityProvider` trait, the `StandardRequestContext` extension
points, and the caching posture. *RBAC, ReBAC, and ABAC patterns*
walks through worked examples of each style and how they compose
in one policy set. *The principal model* covers the principal types
the evaluator binds to.
