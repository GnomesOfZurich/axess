# Entity providers and request context

A Cedar policy evaluates against three inputs: a principal, an
action, a resource, plus an entity graph that gives the policies
the data they need to reason about (which roles the principal is in,
which group owns the resource, what the principal's MFA status is).
The policy set is loaded once at startup. The principal and action
come from the request. The entity graph and the request context
come from the application, per request, through two interfaces this
chapter covers: the `AuthzEntityProvider` trait and the
`StandardRequestContext` extension surface.

Doing both of these well determines whether the Cedar integration
holds up under load. A naive entity provider that loads an entire
user's group membership on every request will be the slowest part
of the request lifecycle. A request context that omits an attribute
a policy expects produces denies that are hard to debug. The shapes
below avoid both failure modes.

## The entity provider contract

`AuthzEntityProvider` is the trait the application implements. The
job is to take a request's principal and resource UIDs, and return
a Cedar entity graph rich enough that the evaluator can answer the
policy questions:

```rust,ignore
#[async_trait]
pub trait AuthzEntityProvider: Send + Sync {
    async fn entities(
        &self,
        principal: &Principal,
        resources: &[ResourceUid],
    ) -> Result<EntitySet, AuthzProviderError>;
}
```

The provider receives the principal (so it can load the
principal's groups, roles, and any attributes the policies need)
and the list of resource UIDs the request is touching (so it can
load the resources, their parents, and their attributes). It
returns an `EntitySet`, which is Cedar's typed entity graph: each
entity has a UID, a set of attributes, and a list of parent
entities.

The contract is "return enough to answer the policies, no more."
An entity set that omits an entity a policy references produces an
`EntityNotFound` error at evaluation time. An entity set that
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
is in that role. The provider populates this from the application's
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

#[async_trait]
impl AuthzEntityProvider for AppEntityProvider {
    async fn entities(
        &self,
        principal: &Principal,
        resources: &[ResourceUid],
    ) -> Result<EntitySet, AuthzProviderError> {
        let mut set = EntitySet::new();

        // Principal: load roles and groups, attach as parents.
        let user_id = principal.user_id().ok_or(AuthzProviderError::NotHuman)?;
        let memberships = sqlx::query_as::<_, (String,)>(
            "SELECT role_uid FROM user_roles WHERE user_id = $1"
        )
        .bind(user_id.to_string())
        .fetch_all(&self.db)
        .await?;

        let principal_uid = ResourceUid::new("User", &user_id.to_string());
        set.insert(Entity {
            uid: principal_uid.clone(),
            attrs: principal_attrs(principal),
            parents: memberships
                .into_iter()
                .map(|(uid,)| ResourceUid::parse(&uid).unwrap())
                .collect(),
        });

        // Resources: load each resource's row + tenant parent.
        for resource in resources {
            if resource.entity_type() == "Document" {
                let row: DocumentRow = sqlx::query_as("SELECT * FROM documents WHERE id = $1")
                    .bind(resource.id())
                    .fetch_one(&self.db)
                    .await?;
                set.insert(Entity {
                    uid: resource.clone(),
                    attrs: document_attrs(&row),
                    parents: vec![ResourceUid::new("TenantData", &row.tenant_id)],
                });
            }
        }

        Ok(set)
    }
}
```

The shape is uniform: one principal entity (with parents from the
role-and-group store), one or more resource entities (each with
parents from the tenant model and attributes from the resource's
row). The provider uses Postgres in this example; the choice is
the application's. The key shape is that the loads are batched per
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

Axess provides an `AuthzSessionCache` decorator that wraps an
`AuthzSession`. The decorator caches the entity graph for a
configurable TTL (default sixty seconds for low-sensitivity
deployments, one second or less for high-sensitivity deployments,
or even off for the highest-sensitivity ones). The cache is keyed
by `(tenant_id, principal_uid, resource_uids)`.

The TTL is the lever. Sixty seconds is fine for a deployment where
a role change can take a minute to propagate (most internal admin
panels). Anything tighter requires the cache to be invalidated on
role changes, which means the application's role-mutation code
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
the custom keys the application wants to expose to policies.

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
produces a deny at runtime with `ContextMissing` (acceptable, deny
is the conservative answer).

## When to extend the context

The custom keys exist to bridge application state that does not
fit on the principal or the resource. Common cases:

The first is a tenant feature flag. A policy that gates a beta
feature on "this tenant has opted in" reads `context.custom.beta`,
which the application sets from the tenant's feature-flag state.

The second is the request's geographical context. A policy that
restricts certain actions to certain regions reads
`context.custom.region`, which the application populates from the
load balancer's geo-IP information or from an explicit header.

The third is a stepped-up factor that is not in `factors_completed`
because it was completed for a different reason. A policy that
wants to know "did the user complete a fresh password challenge in
the last five minutes" reads
`context.custom.password_challenge_at`, which the application
populates from a sidecar store of recent challenges.

The pattern across all three: the application owns the data, the
context is the carrier, the policy sees a typed attribute it can
match on.

## Failure modes and visibility

The two failure modes worth knowing are `EntityNotFound` and
`ContextMissing`, both of which surface as `Deny` from the
evaluator. The right response is the same in both cases: log the
failure with enough detail to diagnose, surface a generic deny to
the user, and keep the audit trail.

`EntityNotFound` typically means the entity provider should have
loaded an entity but did not. The fix is in the provider: load the
missing entity, or update the policy to not reference it.

`ContextMissing` typically means a policy was written against a
context key the application does not provide. The fix is in the
schema: declare the key as optional and update the policy to handle
its absence, or update the application to provide it.

Axess emits an `AuthzEvent` for every evaluation, regardless of
outcome. The chapter *Audit events* covers the event surface; the
relevant variants here are `AuthzEvent::EntityNotFound` and
`AuthzEvent::ContextMissing`, both of which name the missing key
and the policy that referenced it. A spike in either suggests a
mismatch between the policy set and the rest of the deployment;
operational dashboards should alert on it.

## What this enables

The provider-and-context contract is what makes Cedar usable
against an arbitrary application data model. The schema names the
shape; the policies match on the shape; the provider populates the
shape from whatever the application's storage actually looks like.
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
provider's principal-loading queries fit into the application's
identity-store implementation. *Audit events* covers the
`AuthzEvent` variants the evaluator emits.
