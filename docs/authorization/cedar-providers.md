# Entity providers and request context

A Cedar policy evaluates against three inputs: a principal, an
action, a resource, plus an entity graph that gives the policies
the data they need to reason about (which roles the principal is in,
which group owns the resource, what the principal's MFA status is).
The policy set is loaded once at startup. The principal and action
come from the request. The entity graph and the request context
come from you, per request, through two interfaces this
chapter covers: the `AuthzEntityProvider` trait and the
`StandardRequestContext` extension surface.

Doing both of these well determines whether the Cedar integration
holds up under load. A naive entity provider that loads an entire
user's group membership on every request will be the slowest part
of the request lifecycle. A request context that omits an attribute
a policy expects produces denies that are hard to debug. The shapes
below avoid both failure modes.

## The entity provider contract

`AuthzEntityProvider` is the trait you implement. The
job is to take a request's principal and resource UIDs, and return
a Cedar entity graph rich enough that the evaluator can answer the
policy questions:

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

    /// Turn one of your resource ids into the Cedar UID policies match on.
    fn resource_uid(&self, id: &Self::ResourceId) -> Result<EntityUid, AuthzError>;
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
need it. Many providers ignore it; `_action` in the signature is a
perfectly good implementation.

The contract is "return enough to answer the policies, no more."
An entity set that omits an entity a policy references denies at
evaluation time, quietly, because a decision has no error to
return. An entity set that
includes hundreds of entities the policy never touches wastes the
database time. The right shape is the minimum set the policies
need for this request.

## What "enough" means

The policies that the evaluator runs against the entity set
typically need a few categories of data.

The principal's parents. Every role the principal is in, every
group they belong to. A policy that says
`principal in Role::"finance-viewer"` needs the principal's
`parents` list to include `Role::"finance-viewer"` if the principal
is in that role. The provider populates this from your
role-and-group store.

The principal's attributes. The user's tenant id, MFA status,
factors completed, custom attributes the policies use. Many of
these are already on the `Principal` value; the provider attaches
them as Cedar attributes on the principal entity.

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

## A worked provider

A typical provider for a document-management application looks
like this:

```rust,ignore
struct AppEntityProvider {
    db: PgPool,
}

impl AuthzEntityProvider for AppEntityProvider {
    type ResourceId = String;
    type Error = ProviderError;

    async fn entities_for(
        &self,
        principal: &EntityUid,
        resource_id: &String,
        _action: &EntityUid,
    ) -> Result<Entities, Self::Error> {
        let mut entities = Vec::new();

        // Principal: load roles, build them as entities, attach as parents.
        let user_id = principal.id().as_ref();
        let roles = sqlx::query_as::<_, (String,)>(
            "SELECT role_name FROM user_roles WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await?;

        let mut role_uids = HashSet::new();
        for (role_name,) in roles {
            let role_uid = self.make_uid("Role", &role_name)?;
            entities.push(Entity::new(role_uid.clone(), HashMap::new(), HashSet::new())?);
            role_uids.insert(role_uid);
        }
        entities.push(Entity::new(principal.clone(), HashMap::new(), role_uids)?);

        // Resource: its row, and the attributes policies match on.
        let doc = sqlx::query_as::<_, (String, String)>(
            "SELECT owner_id, tenant_id FROM documents WHERE id = $1",
        )
        .bind(resource_id)
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| ProviderError::NotFound(resource_id.clone()))?;

        let owner_uid = self.make_uid("User", &doc.0)?;
        let mut attrs = HashMap::new();
        attrs.insert(
            "owner".to_string(),
            RestrictedExpression::new_entity_uid(owner_uid.clone()),
        );
        let tenant_uid = self.make_uid("Tenant", &doc.1)?;
        entities.push(Entity::new(
            self.resource_uid(resource_id)?,
            attrs,
            HashSet::from([tenant_uid]),
        )?);

        // Anything a policy can reach must be in the set. An `owner`
        // attribute pointing at a User entity that is absent evaluates
        // to a deny, not an error, so build the owner too.
        if doc.0 != user_id {
            entities.push(Entity::new(owner_uid, HashMap::new(), HashSet::new())?);
        }

        Entities::from_entities(entities, None).map_err(ProviderError::build)
    }

    fn resource_uid(&self, id: &String) -> Result<EntityUid, AuthzError> {
        self.make_uid("Document", id)
    }
}
```

The last step is the one that bites. Cedar evaluates against the
entities you hand it and nothing else, so an entity a policy
dereferences but the provider did not build is simply absent, and the
policy that needed it does not match. The failure looks like a
too-strict policy rather than a missing row. Build every entity any
policy in your set can reach from the principal or the resource.

`examples/authz/` is a complete working version of this provider,
against an in-memory store rather than Postgres.

The shape is uniform: one principal entity (with parents from the
role-and-group store), one or more resource entities (each with
parents from the tenant model and attributes from the resource's
row). The provider uses Postgres in this example; the choice is
yours. The key shape is that the loads are batched per
request (one query for memberships, one or two for the resources),
not per policy or per entity.

## Caching entities, not decisions

The single most important performance choice in a Cedar integration
is what to cache. Axess takes the conservative line: entity graphs
are cached aggressively, decisions are never cached.

Decisions cannot be cached because they are functions of the
entity graph, the policy set, and the context. Any of the three
can change between the cache write and the cache read: the entity
graph because the database has updated (a role granted, a
relationship added), the policy set because a redeploy has
happened, the context because the request is different. A cached
decision that survives any of these changes produces a wrong
answer. The defence is to not cache decisions at all.

Entity graphs can be cached because they are functions of the
database state at a known point in time. The cache key is the
principal UID plus the resource UIDs; the cache value is the
entity set; the cache TTL is a function of how stale the
application is willing to tolerate.

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
try.

The TTL is the lever. Sixty seconds is fine for a deployment where
a role change can take a minute to propagate (most internal admin
panels). Anything tighter requires the cache to be invalidated on
role changes, which means your role-mutation code
calls into the cache to flush the affected entries. The
`CacheInvalidator` trait on `EntityCache` is the surface for this;
applications that need stricter consistency wire the invalidations
explicitly.

The chapter *Session lifecycle and crypto envelope* covers the
generic `axess-cache` machinery the entity cache uses. *Operations
runbook* covers the operational signals for the cache (hit rate,
eviction rate, invalidation rate).

## The standard request context

The context is the third input to a policy evaluation. It carries
the per-request attributes that are not on the principal or the
resource: the MFA status, the IP address, the time of the request,
the custom keys you want to expose to policies.

`StandardRequestContext` is the built-in implementation:

```rust,ignore
pub struct StandardRequestContext {
    pub mfa: bool,
    pub ip: Option<IpAddr>,
    pub now: DateTime<Utc>,
    pub custom: BTreeMap<String, serde_json::Value>,
}

impl StandardRequestContext {
    pub fn from_request(req: &Request) -> Self { /* ... */ }

    pub fn with_custom(mut self, k: impl Into<String>, v: serde_json::Value) -> Self {
        self.custom.insert(k.into(), v);
        self
    }
}
```

The `from_request` constructor pulls what it can from the request:
the IP from the trusted-proxy chain, the MFA status from the
session's `factors_completed`, the time from the clock. The
`with_custom` builder adds application-specific keys.

Policies can match on any of these:

```cedar,ignore
permit (
    principal,
    action == Action::"write",
    resource
) when {
    context.mfa == true
    && context.ip like "10.*"
    && context.custom.region == "eu"
};
```

The schema declares the context shape:

```cedar,ignore
type Context = {
    mfa: Bool,
    ip: String,
    custom: {
        region?: String,
        ...
    }
};
```

Required fields are checked at policy load time; optional fields
are checked at evaluation time. A policy that uses a required
field the request omits produces a startup error (good, caught
early). A policy that uses an optional field the request omits
denies at runtime, which is the conservative answer but a silent
one: the reason is on the `axess::authz::decision` target, not in
a returned error.

## When to extend the context

The custom keys exist to bridge application state that does not
fit on the principal or the resource. Common cases:

**A tenant feature flag.** A policy that gates a beta
feature on "this tenant has opted in" reads `context.custom.beta`,
which you set from the tenant's feature-flag state.

**The request's geographical context.** A policy that
restricts certain actions to certain regions reads
`context.custom.region`, which you populate from the
load balancer's geo-IP information or from an explicit header.

**A stepped-up factor not in `factors_completed`,** because it was
completed for a different reason. A policy that wants to know "did the
user complete a fresh password challenge in the last five minutes"
reads `context.custom.password_challenge_at`, which you populate from
a sidecar store of recent challenges.

The pattern across all three: you own the data, the
context is the carrier, the policy sees a typed attribute it can
match on.

## Failure modes and visibility

Two mistakes account for most surprising denies, and neither announces
itself as an error: `is_authorized` returns `Allow` or `Deny` and
nothing else, so both simply deny.

**A policy referencing an entity the provider did not load.** The fix
is in the provider: load it, or stop referencing it.

**A policy written against a context key you do not supply.** The fix
is in the schema: declare the key optional and handle its absence, or
supply it. Building the context can also fail
outright, which is `AuthzError::Context`, raised before evaluation
rather than during it.

Visibility comes from `tracing`, not from an audit row. Every decision
emits on the target `axess::authz::decision` with `principal`,
`action`, `resource`, `decision`, `reasons` and `latency_us`; a
validation failure emits `decision = "deny"` with a `reason` naming
what went wrong. Route that target and alert on the deny rate:
a spike is usually a policy set that has drifted from the data model
rather than users doing anything new.

## Fitting Cedar to an arbitrary data model

The provider-and-context contract is what makes Cedar usable
against an arbitrary application data model. The schema names the
shape; the policies match on the shape; the provider populates the
shape from whatever your storage actually looks like.
The three layers are independent, which means a database migration
that changes how roles are stored does not break the policies (the
provider updates; the rest stays), and a policy change does not
touch the database (the policy file updates; the rest stays).

The chapter *RBAC, ReBAC, and ABAC patterns* covers worked examples
that show the three styles composed in real policies.

## Further reading

*Cedar policy fundamentals* covers the policy lifecycle and the
evaluator surface this chapter feeds. *RBAC, ReBAC, and ABAC
patterns* covers the policy authoring style with concrete examples
for each pattern. *Identity store implementation* covers how the
provider's principal-loading queries fit into your
identity-store implementation. *Audit events* covers the
decision events the evaluator emits on
`axess::authz::decision`.
