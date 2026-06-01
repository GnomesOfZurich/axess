# Scope hierarchy

Methods and factor configurations live at three tiers: Global, Tenant,
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
    Global,
    Tenant(TenantId),
    User { tenant_id: TenantId, user_id: UserId },
}
```

`Global` is the workspace-wide default. A method or factor configured
at global scope applies to every user in every tenant unless something
overrides it.

`Tenant(TenantId)` is a per-tenant override. A method configured at
tenant scope applies to every user in that tenant, overriding the
global default for that tenant.

`User { tenant_id, user_id }` is a per-user override. A method
configured at user scope applies to that one user, overriding both the
tenant and global defaults for that user.

The ordering is the ordering of authority. Narrower beats broader.

## How resolution works

At `begin_login` time the service needs to know which method this user
should authenticate against. The resolution walks the scope chain from
narrowest to broadest, returning the first match it finds.

The chain helper `AuthnScope::lookup_chain` produces the ordered
sequence of scopes to query. For a user with `tenant_id = T` and
`user_id = U`, the chain is
`[User { T, U }, Tenant(T), Global]`. The factor store walks this list
and returns the first configured method.

```rust,ignore
async fn load_factor_with_fallback(
    user_scope: &AuthnScope,
    tenant_id: &TenantId,
    kind: &FactorKind,
) -> Result<Option<FactorConfig>, FactorStoreError> {
    for scope in user_scope.lookup_chain() {
        if let Some(config) = factor_store.load_factor(&scope, kind).await? {
            return Ok(Some(config));
        }
    }
    Ok(None)
}
```

The same chain is used for each factor in the method. A method that
chains password and TOTP looks up the password config first (which
might be a user-scoped override) and then the TOTP config (which might
be a tenant default). Each factor's configuration is resolved
independently, which is the right shape for the common case where the
user has chosen their own TOTP device but the tenant has standardised
the password policy.

The storage convention matches the tier model. The factor store schema
typically has `tenant_id` and `user_id` columns that are nullable,
with the following semantics:

| `tenant_id` | `user_id` | Scope |
|---|---|---|
| `NULL` | `NULL` | `Global` |
| set | `NULL` | `Tenant(tenant_id)` |
| set | set | `User { tenant_id, user_id }` |

`ScopeColumns` is the in-code representation of this pair; it lives
next to `AuthnScope` and is what the SQL adapters use when building
queries.

## What gets scoped

The hierarchy applies to three kinds of object: factor configurations,
methods, and lockout policies. Each plays the same game, with the same
chain-walking resolution.

*Factor configurations* are the per-factor stored data: the password
hash for a user, the TOTP secret for a user, the FIDO2 credential
public keys for a user, the LDAP bind parameters for a tenant. Most
factor configurations are user-scoped because they belong to a
specific user (a password hash is intrinsically per-user). A few are
tenant-scoped because they belong to a tenant configuration (LDAP bind
parameters, OIDC discovery URLs). A very few are global (the system
default Argon2id parameters, the system default TOTP drift window).

*Methods* are the ordered sequences of factor steps. A tenant typically
configures a single default method (password-plus-TOTP, say), and a
small minority of tenants override it (a regulated tenant requires
FIDO2 instead of TOTP). Individual users very rarely have a custom
method; when they do, it is because policy demands a stronger factor
for a flagged user.

*Lockout policies* are the rate and threshold for locking out a user
after repeated failed attempts. Defaults are global. Tenants with
stricter risk postures override at tenant scope. Per-user lockout
policies exist but are rare; they usually mean "this user is on a
watch list and gets locked out faster than the rest".

The pattern across all three is identical. Configure a sensible
global default. Let tenants override when they have a real reason.
Reach for the user-scoped override only when policy demands
per-individual differentiation. The more configuration you do at the
narrowest scope, the more state you have to reason about during
incidents.

## Migration patterns

The scope hierarchy is the right tool for rolling out factor changes
in a controlled way. The pattern is to introduce the change at the
narrowest scope, verify it on a small population, and broaden the
scope as confidence accumulates.

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

Phase three is Global rollout. With confidence from both pilot phases,
the team configures the new method at global scope. The
tenant-scoped override for the early-adopter tenant is removed at the
same time, since it no longer differs from the global default. The
roll-out is complete; the method store has one row (the global
default) instead of many.

The pattern works in reverse for emergency revocation. If the new
method has a bug that surfaces after global rollout, the team can
override at tenant scope or user scope for the affected population
without redeploying the application or reverting the global config.
The narrower scope wins; the affected users walk the old method while
the bug is fixed.

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

The second is using the hierarchy as a feature flag. The temptation
is to roll out a new factor by user-scoping it to internal users, then
forget about the user-scoped rows after the global rollout. The
hierarchy is a good migration tool but a bad permanent home for
temporary state. After a rollout completes, remove the narrower-scope
overrides that no longer differ from the broader-scope default. The
audit trail still records the historical use; the live configuration
is clean.

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
