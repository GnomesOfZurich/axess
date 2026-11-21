# Entity providers and request context

A Cedar policy evaluates a request (a principal, an action and a
resource) against an entity graph that gives the policies the data
they need (which roles the principal is in, which group owns the
resource).
The principal and action come from the request. The entity graph and
the request context come from you, per request, through the two
interfaces this chapter covers: the `AuthzEntityProvider` trait and the
`StandardRequestContext` extension surface. The policy set is loaded at
startup and can be replaced live (see *Live policy reload*, which also
covers registering entity caches so a reload drops them).

Implementing both interfaces well decides whether the Cedar integration
holds up under load. An entity provider that loads a user's entire group
membership on every request becomes the slowest part of the request. A request context that omits an attribute
a policy expects produces denies that are hard to debug. The shapes
below avoid both failure modes.

## The contract

What you must supply, and how much of it.

### The entity provider contract

`AuthzEntityProvider` is the trait you implement. It takes a
request's principal UID and resource id and returns a Cedar entity
graph rich enough for the evaluator to answer the policy questions:

```rust,ignore
pub trait AuthzEntityProvider: Send + Sync {
    /// How your application names a resource: a `String` id, a typed
    /// key, whatever the domain uses.
    type ResourceId: Send + Sync;
    type Error: std::error::Error + Send + Sync + 'static;

    fn entities_for(
        &self,
        principal: &EntityUid,
        resource_id: &Self::ResourceId,
        action: &EntityUid,
    ) -> impl Future<Output = Result<Entities, Self::Error>> + Send;

    /// `entities_for` for a session opened in a tenant (`None` without one).
    fn entities_for_tenant(
        &self,
        principal: &EntityUid,
        tenant: Option<&str>,
        resource_id: &Self::ResourceId,
        action: &EntityUid,
    ) -> impl Future<Output = Result<Entities, Self::Error>> + Send;

    /// Turn one of your resource ids into the Cedar UID policies match on.
    fn resource_uid(&self, id: &Self::ResourceId) -> Result<EntityUid, AuthzError>;

    /// Check this provider's entity types against the schema.
    fn validate_schema(&self, schema: &Schema) -> Result<(), AuthzError>;
}
```

The provider receives a Cedar `EntityUid` for the principal, one
resource id, and the action `EntityUid`. It returns Cedar's own
`Entities`, the typed entity graph the evaluator reads: each entity
carries a UID, a map of attributes, and a set of parent UIDs.

Three things about that signature shape an implementation.

The resource is singular, not a slice. One call answers one
authorization question, so the provider loads exactly what this
decision needs and nothing more.

The principal arrives as an `EntityUid`, not as a `Principal`. Its
`id()` is the string you look up, and its type is whatever your schema
calls a principal. That keeps the provider a translation from your
storage into Cedar's vocabulary, with no branch on human versus
workload unless your schema has one.

`action` is passed so a provider can load less when the action does not
need it. Many providers ignore it and name the parameter `_action`.

The contract is "return enough to answer the policies, no more."
An entity set that omits an entity a policy references denies
quietly at evaluation time, because a decision has no error to
return. An entity set that includes hundreds of entities the policy
never touches wastes database time.

### What "enough" means

The policies typically need five categories of data.

The principal's parents. Every role the principal is in, every
group they belong to. A policy that says
`principal in Role::"finance-viewer"` needs the principal's
`parents` list to include `Role::"finance-viewer"` if the principal
is in that role. The provider populates this from your
role-and-group store.

The principal's durable attributes. The user's tenant id, department,
clearance level, custom attributes the policies use: facts that are
the same for every session of that user. The provider attaches them
as Cedar attributes on the principal entity. Facts about the current
session or request (MFA status, how recently the user authenticated,
an impersonation flag) do not belong here: put them in the Cedar
context (see *Request context* below), because the entity set is
cached across sessions.

The resource's parents. The tenant that owns it, the project it
belongs to, any logical grouping the policies might match against.
A policy that says `resource in TenantData::"acme"` needs the
resource's `parents` list to include `TenantData::"acme"` if the
resource belongs to that tenant.

The resource's attributes. The owner, the visibility setting, the
classification level, anything the policies need. The provider
populates these from the resource's row.

The principal's relationships to the resource. A ReBAC policy that
matches `resource.owner == principal` needs the resource's `owner`
attribute to equal the principal's UID. If the resource is shared
with the principal through a separate sharing record, the provider
either expresses it as an attribute on the resource (a `shared_with`
list) or as a parent (the principal is `in` a "viewers" group
attached to the resource).

The application's data model is the source of truth for all of
this; the provider's job is to shape the data into Cedar's vocabulary.

## Building one

A concrete implementation, and where to put a cache.

### A worked provider

This is the provider from `examples/authz`, included from the file CI
compiles, so what you read here cannot drift from something that builds.
It reads its rows from an in-memory map so the example needs no database;
a provider backed by Postgres issues the equivalent queries and keeps
the same shape.

```rust,ignore
{{#include ../../examples/authz/src/provider.rs:provider}}
```

Build the entities with the schema, as the example does
(`Entities::from_entities(entities, Some(&schema))`), so Cedar checks
their shape. The policy store also adds the schema's action entities
(the actions and the action groups they belong to) to every
evaluation, so a `forbid` over an action group such as
`action in Action::"Mutating"` applies even to a provider that builds
its entities without a schema. You do not build action entities in a
provider.

Cedar evaluates against the entities you hand it and nothing else: an
entity a policy dereferences but the provider did not build is absent,
and the policy that needed it does not match. The failure looks like a
too-strict policy rather than a missing row. Build every entity any
policy in your set can reach from the principal or the resource.

The shape is uniform: one principal entity (with parents from the
role-and-group store), one or more resource entities (each with
parents from the tenant model and attributes from the resource's
row). The rows can live anywhere; batch the loads per request (one query
for memberships, one or two for the resources), not per policy or per
entity.

### Caching entities, not decisions

The most important performance choice in a Cedar integration is what
to cache. Axess caches entity graphs aggressively and never caches
decisions.

Decisions cannot be cached because they are functions of the
entity graph, the policy set, and the context. Any of the three
can change between the cache write and the cache read: the entity
graph because the database has updated (a role granted, a
relationship added), the policy set because of a redeploy or a live reload, the context because the request is different. A cached
decision that survives any of these changes is wrong.

Entity graphs can be cached because they are functions of the
database state at a known point in time. The cache key is the
principal UID, the session's tenant, the resource UID and the action;
the cache value is the entity set; the cache TTL is set by how much staleness the application tolerates.

### The caching contract

The key holds nothing else from the session. Every session of the
same user and tenant that asks for the same resource and action is
served the same entity set for the TTL, whichever session built it.
A provider that writes session state into the entities breaks that:
after MFA in one session, a password-only session of the same user
would read the entities built for the first and pass a
`principal.mfa_verified` policy.

So the supported shape is: entities hold durable facts (roles, group
membership, ownership, tenant), and per-session facts go in the Cedar
context, where `context.mfa_verified` is built for each request and
never cached.

A provider that must put session state into the entities declares it
by overriding `cache_discriminator`, which returns a string naming
that state (for example `"mfa=1"`). The caches add it to the key
(hashed in Valkey), so sessions with different state get different
entries. The default returns `None`: the entities depend on nothing
beyond the key. The caching decorators forward the call to the
provider they wrap.

An invalidation also discards a load that was running when it was
called, so a stale build cannot repopulate the entry that was just
removed.

Axess provides `EntityCache`, an LRU-plus-TTL decorator around a
`RequestEntityProvider`, so repeat checks skip the inner provider's
entity-build work:

```rust,ignore
let cached = EntityCache::new(provider)
    .with_capacity(10_000)
    .with_ttl(Duration::from_secs(60));
```

It is keyed by `(principal, tenant, resource, action)`, and every TTL
decision goes through an injected `Clock`, so a deterministic test can
drive expiry without sleeping.

Invalidation is yours. Call `EntityCache::invalidate` from whatever
mutates a principal's roles or a resource's authorization-relevant
attributes; axess cannot know when your data changed, so it does not
try. When a resource changes (owner, classification, sharing) and you
cannot list the principals that read it, call `invalidate_resource`
with the resource's UID. It drops every entry built for that resource,
whoever asked for it, and every entry whose entity set holds that UID,
so it is also the call for a parent (a folder, group or role) whose
attributes the entries built under it carry. This holds for the
in-process and the Valkey cache alike; the Valkey cache keeps a per-UID index
set beside each entry to find them. `invalidate_principal` and
`invalidate_tenant` are the equivalents for the other two scopes, and
all of them are on the `CacheInvalidator` trait.

On a Valkey cluster, give the cache a prefix with a hash tag
(`ValkeyEntityCache::with_prefix("{axess}")`), so that every entry and
index key hashes to one slot and an invalidation's `SCAN` and `DEL`
reach all of them. With a clustered client and a prefix without a hash tag, the entries
would spread over the nodes, where an invalidation cannot find them
all, so the cache stores nothing: every check reads the provider, and
the first check logs the reason at `warn`.

The TTL is the lever. Sixty seconds suits a deployment where a role
change may take a minute to propagate (most internal admin panels).
Anything tighter requires your role-mutation code to invalidate the
affected entries through the `CacheInvalidator` trait on `EntityCache`.

The chapter *Session lifecycle and crypto envelope* covers the
generic `axess-cache` machinery the entity cache uses. *Operations
runbook* covers the operational signals for the cache (hit rate,
eviction rate, invalidation rate).

## Request context

What the evaluator sees beyond the entities.

### The standard request context

The context is the third input to a policy evaluation. It carries the
per-request and per-session attributes that are not on the principal
or the resource: every fact that differs between two sessions of one
user, such as the MFA status, the IP address, the time of the request
and any keys of your own you expose to policies.

`StandardRequestContext` is the built-in implementation:

```rust,ignore
pub struct StandardRequestContext {
    pub mfa_verified: bool,
    pub ip_address: Option<IpAddr>,
    pub timestamp: Option<Timestamp>,
    pub assurance: Option<AssuranceContext>,
    pub key_bound: Option<bool>,
}

impl StandardRequestContext {
    pub fn new(mfa_verified: bool, ip_address: Option<IpAddr>) -> Self { /* ... */ }
    pub fn at(mfa_verified: bool, ip_address: Option<IpAddr>, timestamp: Timestamp) -> Self { /* ... */ }
    pub fn with_assurance(self, assurance: AssuranceContext) -> Self { /* ... */ }
    pub fn with_key_bound(self, key_bound: bool) -> Self { /* ... */ }
}
```

`new` takes the MFA status and the client IP, which the `ClientIp`
handler argument carries from the trusted-proxy walk. `at` adds the
request time, read from your `Clock`. The MFA status is a fact your
application derives from what it recorded when the user completed the
factors its policy demands; the session itself carries the
authentication state, not an MFA flag.

The context carries `mfa_verified` always, `ip_address` when it is
`Some`, `timestamp` only when built with `at`, and `assurance` and
`key_bound` only when added with their builders. A key beyond these
needs a type of your own that implements `BuildRequestContext` (see
*When to extend the context* below).

Policies can match on any of these:

```cedar,ignore
permit (
    principal,
    action == Action::"write",
    resource
) when {
    context.mfa_verified
    && context.ip_address like "10.*"
};
```

The action's schema declares the context shape (Cedar's JSON schema
format, which `PolicyStore::from_text` reads):

```json
"context": {
  "type": "Record",
  "attributes": {
    "mfa_verified": { "type": "Boolean" },
    "ip_address": { "type": "String" }
  }
}
```

Policies are checked against the schema when the set is loaded or
reloaded. Strict validation refuses a policy that reads an attribute
the schema does not declare, or reads an optional one without a
`has` guard. A request is checked against the schema at evaluation. A
request that omits a required attribute, or carries one the schema
does not declare, fails that check and is denied. A request that omits
an optional attribute makes every policy that guards it with
`context has` stop matching: a `permit` no longer grants, and a
`forbid` no longer forbids. Neither case raises an `AuthzError`. The
reason for a denial is on the `axess::authz::decision` target.

### The context in `require_authz!`

A `require_authz!` gate decides with one value, an `AuthzInstallation`,
built where the router is built and added as a layer outside the gates:

```rust,ignore
let installation = AuthzInstallation::new(
    policy_store.clone(),   // Arc<PolicyStore>
    entities,               // Arc<dyn RequestEntityProvider>
    Some(context),          // Arc<dyn RequestContextProvider>
)?;
let app = Router::new()
    .route("/documents/{id}", delete(remove).layer(require_authz!(
        "DocApp", "DeleteDocument", "Document:{id}",
        validator = authn.session_validator())))
    .layer(installation);
```

The gate calls the context provider's
`context_for(&session, &request_parts)` to build the Cedar context for
each request. A provider that returns an error makes the gate answer
403. Derive values such as MFA status from the session, never from the
request.

The third argument is `None` only for a store in which no policy or
template reads the `context` variable. When one does,
`AuthzInstallation::new` returns `AuthzError::ContextProviderRequired`
and the application does not start, because an empty context turns a
guarded `forbid` into nothing and the `permit` beside it allows. The
check is per store, not per action. Declare the attributes policies rely
on as required. `examples/authz` shows the `DeleteDocument` rule that
needs `mfa_verified`.

The gate reads nothing else from the request. A policy store or a
provider put into the request extensions on its own is not read, and a
gate that finds no installation answers 500 and logs an error.

A policy reload can bring a read of `context` in after an installation
was built with `None`. Until a set that does not read it is in force
again, the gate answers 500 for every request and logs an error naming
the installation. An application that reloads policies passes a context
provider from the start; see *Live policy reload*.

The store answers from the parsed policies (`PolicyStore::mentions_context`
walks Cedar's syntax tree of each policy and template), not from their
text. The word in a comment, a string, an attribute name, an entity id or
an annotation is not a read. A read in a `when` or an `unless` clause, a
`context has ..` test alone and a read nested inside another expression
each count, and a template counts whether or not a policy is linked to it.

`axess::authz::require`, the function form, takes the `Context` as its
last argument and evaluates with exactly that; pass `Context::empty()` only
when no policy reads `context`.

### Authentication assurance

`context.assurance` carries what each factor of the session proved: whether
the user was verified, whether the credential is synced or device-bound, the
trust anchor of an attested authenticator, and its age in seconds.
`AssuranceContextProvider` installs it for `require_authz!`;
`StandardRequestContext::with_assurance` adds it beside `mfa_verified`. The
schema types ship as `ASSURANCE_SCHEMA_FRAGMENT`, and a rule annotated with
`@step_up("<name>")` makes a gate answer `step_up_required` with that name
when only the assurance is short. See
[Authentication assurance and ceremonies](assurance.md).

### Device-bound sessions

`StandardRequestContext::with_key_bound` adds `context.key_bound`, a
Boolean: whether the request ran as a session bound to a device key and
proved that key, as `AuthSession::key_bound` answers. Declare it as
`key_bound: Bool` in the context of the actions that read it. A deployment
that prefers device keys without requiring them demands one where it
matters with a `forbid ... unless { context.key_bound }` rule, and every
other action stays open to a browser without a key store. See
[Design: device-bound sessions](../sessions/device-bound-sessions.md).

### When to extend the context

Keys of your own bridge application state that does not fit on the
principal or the resource. They come from a type you write: one that
implements `BuildRequestContext` for an `AuthzSession`, or
`RequestContextProvider` for a `require_authz!` gate. Common cases:

**A tenant feature flag.** A policy that gates a beta
feature on "this tenant has opted in" reads `context.beta`,
which you set from the tenant's feature-flag state.

**The request's geographical context.** A policy that
restricts certain actions to certain regions reads
`context.region`, which you populate from the
load balancer's geo-IP information or from an explicit header.

**A stepped-up factor your application tracks itself,** for example one
completed for a different reason. A policy that wants to know "did the
user complete a fresh password challenge in the last five minutes"
reads `context.password_challenge_at`, which you populate from
a sidecar store of recent challenges.

The pattern across all three: you own the data, the
context is the carrier, the policy sees a typed attribute it can
match on.

## Failure modes and visibility

Two mistakes account for most surprising denies, and neither announces
itself as an error: `is_authorized` returns `Allow` or `Deny` and
nothing else, so both appear as a deny.

**A policy referencing an entity the provider did not load.** The fix
is in the provider: load it, or stop referencing it.

**A policy written against a context key you do not supply.** The fix
is to supply it. Declare a key optional only where its absence is safe
for every policy that reads it, because a `forbid` guarded with
`context has` stops applying when the key is missing. Building the
context can also fail outright, which is `AuthzError::Context`, raised
before evaluation rather than during it.

Visibility comes from `tracing`, not from an audit row. Every decision
emits on the target `axess::authz::decision` with `principal`,
`action`, `resource`, `decision`, `reasons` and `latency_us`; a
validation failure emits `decision = "deny"` with a `reason` naming
what went wrong. Route that target and alert on the deny rate:
a spike is usually a policy set that has drifted from the data model
rather than users doing anything new.

## Fitting Cedar to an arbitrary data model

The provider-and-context contract makes Cedar usable against an
arbitrary application data model. The schema names the
shape; the policies match on the shape; the provider populates the
shape from your storage, whatever its layout.
The three layers are independent, which means a database migration
that changes how roles are stored does not break the policies (the
provider updates; the rest stays), and a policy change does not
touch the database (the policy file updates; the rest stays).

The chapter *RBAC, ReBAC, and ABAC patterns* covers worked examples
that show the three styles composed in real policies.

## Further reading

*Live policy reload* covers replacing the policy set in a running
service and keeping instances in step. *Cedar policy fundamentals*
covers the policy lifecycle and the
evaluator surface this chapter feeds. *RBAC, ReBAC, and ABAC
patterns* covers the policy authoring style with concrete examples
for each pattern. *Identity store implementation* covers how the
provider's principal-loading queries fit into your
identity-store implementation. *Audit events* covers the
decision events the evaluator emits on
`axess::authz::decision`.
