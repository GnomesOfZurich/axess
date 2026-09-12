# Scope hierarchy

Methods and factor configurations live at three tiers: System, Tenant,
and User. The mechanism is simple, the consequences are not. Done well,
the three-tier hierarchy makes multi-tenant SaaS deployment feel like
one configuration with two override surfaces. Done badly, it becomes
a maze where nobody can answer "what method is this user actually
using?" without running a query. This chapter walks through the
mechanism and the patterns that keep it operationally clear.

## The three tiers

`AuthnScope` lives in
[`axess-core/src/authn/types.rs`](https://github.com/GnomesOfZurich/axess/blob/main/axess-core/src/authn/types.rs).
It is a three-variant enum, ordered from broadest to narrowest:

```rust,ignore
pub enum AuthnScope {
    System,
    Tenant(TenantId),
    User { tenant_id: TenantId, user_id: UserId },
}
```

`System` is the platform-owned default tier. A method or factor
configured at system scope is a *template* the platform makes
available; tenants adopt it explicitly (see "Adoption, not silent
inheritance" below).

`Tenant(TenantId)` is a per-tenant configuration. A method configured
at tenant scope applies to every user in that tenant.

`User { tenant_id, user_id }` is a per-user configuration. A method
configured at user scope applies to that one user.

The ordering is the ordering of authority. Narrower beats broader.

## Adoption, not silent inheritance

The mental model is important: **System is a template tier, not a
runtime broadcast tier.** A factor configured at System scope does not
automatically become a login option for every tenant; a tenant adopts
the template explicitly at provisioning time or through an
administrative reconfiguration. The `FactorTemplate` catalog in
`axess-core::authn::factor` is the surface for this: platform operators
curate a set of templates; tenant provisioning selects which templates
this tenant will use and materialises tenant-scoped rows.

This preserves the invariant that a tenant admin never gets surprised
by a factor they did not opt into. Silent inheritance would make
platform-wide changes propagate to tenants who had reasons for their
existing configuration; explicit adoption forces those changes to
route through the tenant's own configuration surface.

At *runtime*, once a user has an active method that includes some
factor kind, the store walks the User → Tenant → System resolution
chain to find the applicable config data (see next section). The
System row is legitimate as the config *source* for a factor the user
has already activated (through their method); it is never the *grant*.

## How resolution works

At `begin_login` time and again at each `verify_factor` step, the
service asks the factor store for the applicable config for the
factor kind that is next in the user's method. Resolution walks the
scope chain from narrowest to broadest, returning the first hit.

The chain helper `AuthnScope::resolution_chain` produces the ordered
sequence of scopes to query. For a user with `tenant_id = T` and
`user_id = U`, the chain is
`[User { T, U }, Tenant(T), System]`.

Application code does not walk the chain: the store does, in one
query, and returns a [`ResolvedFactor`] carrying both the config and
the scope it was resolved from:

```rust,ignore
pub struct ResolvedFactor {
    pub config: FactorConfig,
    pub resolved_from: AuthnScope,
}

// In service code, one call:
let resolved = factors
    .resolve_factor(&user_scope, kind)
    .await?
    .ok_or(AuthnError::NoFlow)?;
```

Backends implement `resolve_factor` as a single ordered `SELECT`
(the SQLite example does this via a `UNION ALL` with a `rank` column
and `LIMIT 1`). Latency-wise this is one round trip regardless of
where the config actually lives.

The `resolved_from` field lets callers know which tier served the
request: used by the failure-counter CAS logic to know whether to
CAS against an existing user-scope row or to create a new one from a
tenant/system template.

For admin and display code that wants "what did this tenant
*explicitly* configure?", the store also exposes `load_factor`
which returns the config at exactly the requested scope with no
fallback. Never on the auth hot path: use `resolve_factor` there.

The same chain is used for each factor in the method. A method that
chains password and TOTP resolves the password config first (which
might be a user-scoped override) and then the TOTP config (which might
be a tenant default). Each factor's configuration is resolved
independently, which is the right shape for the common case where the
user has chosen their own TOTP device but the tenant has standardised
the password policy.

## Storage encoding

The factor store schema has `tenant_id` (NOT NULL) and `user_id`
(nullable) columns:

| `tenant_id`     | `user_id` | Scope                            |
|-----------------|-----------|----------------------------------|
| `TenantId::SYSTEM` | `NULL`   | `System`                         |
| `<tenant>`      | `NULL`    | `Tenant(tenant)`                 |
| `<tenant>`      | `<user>`  | `User { tenant, user }`          |

`tenant_id` is **never NULL** for configuration scope; platform-owned
rows live under the reserved `TenantId::SYSTEM` tenant. This keeps
FK integrity uniform (`tenant_id REFERENCES tenants(id)`) and lets
SQL callers use a single `tenant_id = ?` clause without the
`IS NULL` special-cases that a two-optional encoding would need.

`ScopeColumns` in
[`axess-core/src/authn/types.rs`](https://github.com/GnomesOfZurich/axess/blob/main/axess-core/src/authn/types.rs)
is the in-code representation of the pair; it exposes `tenant_id:
TenantId` (always populated) and `user_id: Option<UserId>` (populated
only for User scope).

Note this is **distinct** from audit-event storage, where a NULL
`tenant_id` means "tenant not yet known" (pre-authenticated event,
failed login for an unknown user), never "System scope."

## What gets scoped

The hierarchy applies to three kinds of object: factor configurations,
methods, and lockout policies. Each plays the same game, with the same
chain-walking resolution.

*Factor configurations* are the per-factor stored data: the password
hash for a user, the TOTP secret for a user, the FIDO2 credential
public keys for a user, the LDAP bind parameters for a tenant, the
system default Argon2id parameters, the system default TOTP drift
window. Most user-specific factor configurations are user-scoped
because they belong to a specific user (a password hash is
intrinsically per-user). Policy-shaped configurations
(Argon2id parameters, drift windows) are typically tenant-scoped or
system-scoped.

*Methods* are the ordered sequences of factor steps. A tenant typically
configures a single default method (password-plus-TOTP, say), and a
small minority of tenants override it (a regulated tenant requires
FIDO2 instead of TOTP). Individual users very rarely have a custom
method; when they do, it is because policy demands a stronger factor
for a flagged user. Methods live at User or Tenant scope only; the
SQLite example rejects System scope on `save_method` and friends,
because runtime authentication methods must be materialised per
tenant.

*Lockout policies* are the rate and threshold for locking out a user
after repeated failed attempts. System defaults exist. Tenants with
stricter risk postures override at tenant scope. Per-user lockout
policies exist but are rare; they usually mean "this user is on a
watch list and gets locked out faster than the rest".

The pattern across all three is identical. Configure a sensible
system default. Let tenants adopt it or override when they have a
real reason. Reach for the user-scoped override only when policy
demands per-individual differentiation. The more configuration you do
at the narrowest scope, the more state you have to reason about
during incidents.

## Migration patterns

The scope hierarchy is the right tool for rolling out factor changes
in a controlled way. The pattern is to introduce the change at the
narrowest scope, verify it on a small population, and broaden as
confidence accumulates: but broadening happens through explicit
per-tenant adoption, never through silent system-wide broadcast.

A worked example. A SaaS deployment wants to require FIDO2 for all
users, replacing the existing password-plus-TOTP method. The cautious
roll-out has three phases.

Phase one is User-scoped pilot. The operations team configures the
new method (`Required(Password)` then `Required(Fido2)`) at user scope
for a small set of internal users. These users go through the new
flow first, surface any UX problems, and validate that the FIDO2
ceremony works end-to-end against the application's relying-party
configuration.

Phase two is Tenant-scoped pilot. The team configures the new method
at tenant scope for a single early-adopter tenant. Their users
transition next, and the pilot widens to a population that includes
real customer traffic. The user-scoped overrides from phase one are
removed (they no longer differ from the tenant default).

Phase three is Per-tenant rollout. With confidence from both pilot
phases, the team iterates the remaining tenants, either by updating
each tenant's method configuration to the new FIDO2-plus-password
sequence, or (if the tenant admin is empowered) by prompting the
admin to adopt the new method template. Each tenant transitions
independently, with an audit event per change. There is no
system-wide broadcast: if a tenant deliberately does not adopt the
new method (e.g. their user base has no FIDO2 hardware), they retain
the old method and the roll-out simply skips them.

The pattern works in reverse for emergency revocation. If the new
method has a bug that surfaces during rollout, the team can override
at tenant scope or user scope for the affected population without
redeploying the application. The narrower scope wins; the affected
users walk the old method while the bug is fixed.

## How Cedar policy interacts

The scope hierarchy answers "what method does this user authenticate
with?" Cedar answers "what is this user allowed to do once
authenticated?" The two surfaces are distinct, and confusing them
leads to authorization-as-authentication mistakes.

A common pattern is to use Cedar to *require* a method outcome rather
than to choose one. A policy might require that
`factors_completed.contains("Fido2")` for an action against a sensitive
resource. The method itself remains the resolved one from the scope
hierarchy. If the method does not include FIDO2, the user reaches the
sensitive route and gets a deny; the application then offers step-up
to add FIDO2 (covered in *Factors and methods* §"Step-up
authentication"), the user completes it, and the policy now passes.

The split between choice (scope hierarchy) and demand (Cedar policy)
is what makes this work. The hierarchy decides what factors are
available; the policy decides which of them are required for which
actions. A user can have a stronger method than the policy minimum and
satisfy the policy without effort; a user with a weaker method gets
prompted for step-up.

## Anti-patterns

The hierarchy invites a few mistakes that are worth naming explicitly.

The first is overusing user-scoped configuration. Every user-scoped
row in the factor store is a piece of state that an operator has to
maintain. If a tenant decides to change its method, the tenant-scoped
row updates; the user-scoped overrides do not. After a few months of
incremental changes, the user-scoped rows are out of sync with the
intended policy, and nobody remembers why each row exists. The fix is
to use user scope only when policy genuinely requires per-individual
differentiation, and to document the reason in a separate field next
to the row.

The second is treating System as a runtime broadcast tier. A factor
configured at System scope is a *template*: the correct pattern is
to adopt (materialise a tenant-scoped row) rather than to depend on
resolution to reach it silently. Depending on system-tier fallback
turns platform-wide edits into surprise tenant-level changes.
Materialise on adoption; treat runtime fallback to System as a
convenience, not a management model.

The third is conflating method scope with tenant identity. The
hierarchy says nothing about which tenants exist; it says only how to
resolve a configuration for a given (tenant, user) pair. Tenant
provisioning, tenant suspension, and tenant deletion are covered in
*Multi-tenancy*.

## What this enables

The hierarchy is the reason an axess deployment scales from "one
company with one method" to "a SaaS with hundreds of tenants, each
with its own posture, and a few high-risk users on stricter policies"
without restructuring the application. The same code path
(`begin_login`, `verify_factor`, `Authenticated`) handles the
single-tenant case and the hundred-tenant case. The only difference is
which scope holds the configuration.

The pattern is not unique to axess. Cedar policies, audit retention
policies, and rate-limit thresholds all follow the same three-tier
pattern. The vocabulary is consistent across the library so a reviewer
who has internalised the resolution rule does not have to re-learn it
for each subsystem.

## Further reading

*Multi-tenancy* covers tenant provisioning, the `TenantId` lifecycle,
cross-tenant refusal, and the three-lever lockout. *Cedar policy
fundamentals* covers how authorisation policy reads the resolved
method's `factors_completed` field. *Identity store implementation*
walks through the storage adapter that resolves the scope chain
against a relational schema.
