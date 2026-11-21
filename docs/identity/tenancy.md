# Multi-tenancy

A tenant in axess is the unit of isolation. Users, factor
configurations, sessions, devices, policies, and audit events all
carry a `TenantId`, and the library refuses to leak data across
tenants by construction.

Tenancy is always on: no feature flag toggles it, and the `TenantId`
field is present on every relevant record. A single-tenant deployment uses one fixed `TenantId` (a
UUID, like every id; `"default"` is a common choice for the tenant's
lookup `identifier`, not for its id) and runs the same
multi-tenant machinery, ready for a second tenant.

## The model

What a tenant is, and the boundary the type system enforces.

### The tenant record

The `Tenant` struct lives in `axess-core` and is deliberately thin:

```rust,ignore
pub struct Tenant {
    pub id: TenantId,
    pub identifier: Arc<str>,      // slug or domain used for lookup
    pub display_name: Arc<str>,
    pub status: EntityState,       // same lifecycle enum a user's status uses
    pub created_by: UserId,
    pub created_at: Timestamp,
    pub updated_by: UserId,
    pub updated_at: Timestamp,
}
```

The struct carries no per-tenant lockout policy, no fingerprint pepper
and no retention setting. Per-tenant policy is
resolved through `IdentityLookup`, not stored on the struct:
`lockout_policy_for_tenant`, `password_rules_for_tenant` and
`ip_policy_for_tenant` are required trait methods, with no default, so
no decorator can drop a tenant's policy by forgetting to forward it. A
deployment with one policy returns it from each; one that sells a
stricter tier answers from its own
table. That keeps `Tenant` a row an adopter can map onto whatever they
already have, rather than a schema axess imposes.

`status` is `EntityState` (`Guest`, `Candidate`, `Pending`, `Active`,
`Suspended`, and the two closed states, `Terminated` and `Archived`),
shared with users rather than a
tenant-specific enum, which is what makes "is this principal usable"
one question at both levels.

`created_by` and `updated_by` are `UserId`s, so every tenant row names
the actor behind it. For an operator-onboarded tenant that is
`UserId::system()`; for a self-service signup it is typically the first
admin.


The `TenantId` is a typed UUID (the convention in axess-identity).
The settings that vary per tenant live outside the struct: the device
fingerprint pepper comes from the `TenantPepperResolver` of *Device
identity*, the lockout policy from `lockout_policy_for_tenant`
(covered in the lockout section below), and device retention from the
`SweepConfig` the deployment passes to the device store.

### Cross-tenant refusal as a structural rule

Every operation in axess that touches a user, a session, a device,
a factor, or an event carries a tenant scope. The library checks
the scope first and refuses any operation whose scopes do not
match.

The pattern is uniform across the API. A `begin_login` call
takes the tenant's lookup identifier and resolves the tenant from it;
the user lookup is scoped to that tenant; a
user with the same username in a different tenant is not
returned. A `verify_factor` call works against the session's
tenant id; a factor configuration registered in a different
tenant is not consulted. `find_sessions_for_user` is an exception: it
takes a user id and a limit, not a tenant id, and lists the sessions
that carry that user id, whatever their tenant, so it is scoped only as
far as user ids are unique across tenants (the memory store implements
it; the SQL and Valkey stores return an `Unsupported` error).

The structural defence lets a multi-tenant deployment claim more than
that the application does not leak across tenants: the library
underneath cannot. A top-level Cedar `forbid` rule can then catch an
application bug that tries to authorise across tenants:

```cedar,ignore
forbid (
    principal,
    action,
    resource
) when {
    principal.tenant_id != resource.tenant_id
};
```

The rule applies to every action on every resource. With the library
refusing cross-tenant lookups and the policy denying cross-tenant
decisions, a cross-tenant access is structurally impossible.

## Provisioning

A tenant comes into existence through `create_tenant`, the verb behind
any "sign up a new organisation" or "administrator provisions a new
tenant" flow.

```rust,ignore
use axess_core::authn::provisioning::{TenantBootstrap, create_tenant};

let tenant = Tenant::new(
    tenant_id,
    "acme",                      // lookup identifier
    "Acme Inc.",                 // display name
    EntityState::Active,         // status
    UserId::system(),            // created_by
    clock.now(),
)?;

let (tenant, method) = create_tenant(
    &identity_store,
    &factor_store,
    TenantBootstrap {
        tenant,
        // Which factors this tenant may use. `default_catalog()` is the
        // shipped set; filter or extend it per tenant.
        factors: default_catalog(),
        // `None` takes a method derived from the factors.
        method: Some(AuthMethod {
            name: "password-then-totp".into(),
            steps: vec![
                FactorStep::Required(FactorKind::Password),
                FactorStep::Required(FactorKind::Totp),
            ],
            scope: AuthnScope::Tenant(tenant_id),
        }),
    },
)
.await?;
```

`create_tenant` is a free function over an `IdentityStore` and a
`FactorStore`, not a method on `AuthnService`, because provisioning
touches both and belongs to neither. It returns the tenant and the
`AuthMethod` it installed.

The bootstrap creates no administrator. Creating the first
user is a separate `create_user` call; a caller who wants "tenant plus
admin, or neither" wraps both in its own transaction.
Bootstrapping with an empty `factors` list is refused outright
(`ProvisioningError::NoFactorsSpecified`), because a tenant whose users
cannot present any factor cannot be logged into.

A partially provisioned tenant is dangerous, so the steps run in the
order that leaves the least harmful partial states. A
tenant that exists in the tenant table but has no configured method
admits any user with the system default method, which may not be what
the new tenant wants. A tenant with a method but no factor
configurations for the admin user produces an immediate lockout.

`create_tenant` is a sequence of store calls (the tenant row, one
`save_factor` per template, then `save_method`), not a transaction.
If one fails it returns the error and leaves whatever the earlier calls
wrote; retry or compensate. A backend that wants all-or-nothing makes
`create_tenant`, `save_factor` and `save_method` share one transaction in
its own implementation.

What the bootstrap does enforce is on the input side: `create_tenant`
refuses an empty `factors` list and the reserved system tenant id before
it writes anything, and it saves the method through `save_method`, which
marks it enabled. It does not check that a user's own factor
configuration exists for every factor the method requires; that belongs
to whatever creates the first user.

## The three-lever lockout

Lockout stops an attacker from brute-forcing credentials. Axess has three levers that compose: two
in the login path, and one you mount in front of it.

The first lever is per-user lockout. After a configurable number
of failed factor verifications against the same user account,
that account is locked for a configurable interval. The default
is five failed attempts within an hour, followed by a
fifteen-minute lockout of fixed length.

The second lever is the throttle, which acts before the lockout.
Each failure against an account from one address earns a delay
before the next guess from that pair is taken: one second,
doubling to sixty-four by default. It slows a guesser without
locking the account's owner out from another address.

The third lever is the rate limiter, `RateLimitLayer`, which is
middleware and not part of the login path: nothing limits by
address or by tenant unless you mount it. Its default is a hundred
requests per minute for each peer address, and its key can be the
resolved client address or the tenant instead. It rejects requests
without engaging the factor verifier, which is what catches a single
source attempting many accounts.

A successful attack needs to dodge all three: stay below the
per-user threshold, wait out the throttle, and either spread across
many source addresses or stay below the rate limit.

`LockoutPolicy` holds the lockout configuration:

```rust,ignore
pub struct LockoutPolicy {
    pub max_attempts: u32,             // default 5
    pub duration: Option<Duration>,    // default 15 min; None = indefinite
    pub attempt_window: Duration,      // default 1 hour
    pub on_counter_unavailable: CounterUnavailable,   // default Lock
    pub throttle: Option<Throttle>,    // default 1 s doubling to 64 s,
                                       // keyed on account and address
}
```

`max_attempts` is compared against the count
`IdentityAuthnLog::record_failed_attempt` returns. `duration` is how
long the lock lasts, and `None` means it does not expire on its own:
an administrator has to clear it. `attempt_window` is how far back
failures count, so five failures spread over two hours do not lock an
account whose window is one hour.

The lock's scoping is per user only. Per-tenant and per-IP lockout
scales do not exist on this type, and this type is the wrong place for them: a
per-IP threshold that locks *accounts* is a denial-of-service tool in
an attacker's hands. Rate-limit by IP instead, at the middleware layer,
where the response is a 429 rather than a locked account
(*Rate limiting* covers `KeyExtractor::LoginIdentifier`, which is the
per-account half of that defence).

`throttle` is the one place the client address enters this type, and it
locks nothing: consecutive wrong guesses under a key of account and
address earn a delay that doubles per failure (one second to sixty-four
by default) and is answered as `FactorOutcome::Throttled { retry_after }`,
a refusal with the time left, never a sleep. A right guess clears it, a
known device is exempt from it as from the lock, and `max_attempts` still
caps the whole. `ThrottleKey::Account` drops the address from the key;
`LockoutPolicy::without_throttle()` turns it off. *Factors* has the
schedule and the pipeline order.

`on_counter_unavailable` decides what happens when the counter store
itself is down. That case is not hypothetical: `record_failed_attempt`
is a write, and the read-replica split this library encourages puts
reads on a replica and writes on the primary, so a primary outage
leaves logins working and the counter dead. While that lasts the count
never rises and `max_attempts` is never reached.

`CounterUnavailable::Lock` is the default and treats the attempt as
locked, so brute force stays bounded while the counter is dead. A user
who mistypes is told they are locked and retries after `duration`.
`CounterUnavailable::Allow` keeps those users logging in and disables
lockout until the counter returns, which is an unbounded brute-force
window at exactly the moment monitoring is degraded. Choose it only
with a compensating control, such as a `KeyExtractor::LoginIdentifier`
rate limiter in front of the route.

One interaction to watch: `Lock` together with `duration: None` means a
persistently broken counter store needs an administrator to clear each
affected account. Deployments running indefinite lockouts should alert
on `FactorMetrics::factor_counter_store_outage`, which fires on exactly
this path, or pick `Allow` knowingly.

Neither setting changes what an attacker sees for an identifier that
does not exist. Those are refused at `begin_login` with timing
equalisation and never reach the counter.

The policy is resolved per tenant through
`IdentityLookup::lockout_policy_for_tenant`, a required method: a
store with one policy returns `LockoutPolicy::default()` (or its own)
for every tenant, and one whose tenants differ looks the policy up.

## Tenant lifecycle

Suspending and deleting, and what each does to live sessions.

### Tenant suspension

`Tenant` carries `status: EntityState`, the same type a user's status
uses, so a suspended tenant is representable. **Axess ships no
operation to suspend one.** `IdentityStore` has `suspend_user` and
`activate_user` and no tenant equivalent, the session registry
invalidates by user and by session and not by tenant, and there is no
tenant lifecycle event in the audit vocabulary.

What exists today is per-user: `suspend_user` sets the
status, invalidates that user's sessions through the registry, and
emits `AccountSuspended` attributed to the actor who did it.

If you need "this tenant has not paid" or "this tenant is under
compliance review" now, it is yours to build: set the tenant's status
through your own `IdentityStore` implementation, and invalidate the
sessions of its users yourself. Doing it inside axess would mean new
required methods on both `IdentityStore` and the session registry,
which every adopter would have to implement, so leaving it out is
deliberate.

Whatever drives the status, a tenant that is not `Active` refuses its
users before factor verification. That is a state the application may
want to render specifically ("your organisation is suspended, contact
support") rather than as the generic invalid-credentials page, so check
the tenant's status rather than inferring it from the login outcome.

### Tenant deletion

The same gap as suspension, one step further along. `EntityState` has
closed states (`Terminated`, `Archived`), so a deleted tenant is representable, and **axess ships
no operation to delete one and no cascade to run.** `IdentityAdmin` has
`delete_user`, which is the GDPR erasure primitive for a single user;
there is no tenant equivalent.

What a customer exit or a tenant-wide erasure request needs, you build:
enumerate the tenant's users, call `delete_user` for each, and remove
the tenant row. Two details from that verb carry over. Its contract
says what must be gone afterwards (the user row, the factor configs,
the refresh tokens, the sessions, the password history), and it leaves
audit events in place, to be retained under an independent lawful basis
with identifying columns pseudonymised. A tenant-level erasure inherits
both.

If you build it, do two things a naive cascade will not:

- **Mark the tenant `Suspended` first**, then remove. The cascade is
  expensive on a large tenant, and the gap between the two is the only
  window in which an accidental deletion is recoverable without a
  backup restore.
- **Write your own audit row**, naming the operator, the instant and the
  counts. Axess has no tenant lifecycle event to emit, and the deletion
  is exactly the thing you will later be asked to defend.

## Configuration and conventions

There is no tenant trait, and the consolidation is deliberate.

### Per-tenant configuration storage

There is no `TenantStore` trait. Tenant reads and writes live on the
identity tiers alongside everything else: `IdentityLookup::find_tenant`
and `default_tenant` read, `IdentityAdmin::create_tenant` writes, and
the three `*_for_tenant` policy methods resolve per-tenant
configuration from wherever you keep it.

A separate tenant
trait would be a second surface every adopter has to implement, against
the same database, with its own error type and its own transaction
boundary. Provisioning a tenant already has to touch users and
factors, so it could not stay inside that boundary anyway.

The practical consequence is that per-tenant policy has no prescribed
schema. A deployment with one policy for everyone returns it from the
three policy methods, which are a line each. A deployment that varies policy per tenant adds
a column or a table of its own and returns it from
`lockout_policy_for_tenant` and the other two. Axess never reads that storage
directly, which is why it cannot dictate its shape.

### Reserved principals

A handful of principals are reserved across all tenants. The
`system()` principal is the actor of work no person performs: the rows
that seeding or operator onboarding writes carry it as `created_by` and
`updated_by`, as do the tenant and user rows the in-memory backend
installs. The device retention sweep takes no actor and is run by the
deployment. It is `UserId::system()`, and it pairs with the reserved
`TenantId::SYSTEM`; its actions are attributed to the system itself,
not to any customer tenant or user.

The reservation prevents an application from creating a user that
carries the reserved id, whose actions would then read as the system's
own. `UserId::is_system` and
`TenantId::is_system` are the predicates, and
`ensure_user_id_not_reserved(user_id, tenant_id)` is the guard,
returning `IdError::Reserved` for either.

Nothing calls that guard for you on the `IdentityAdmin::create_user`
path, because the row is built in your code before the call. Put it at
the top of your `create_user` implementation, which is what its
documentation asks for. Tenant provisioning does check: `create_tenant`
refuses a bootstrap whose tenant id is the reserved one.

The set of reserved principals is small and stable. The chapter
*Audit events* lists them.

## What a SaaS gets from this

Multi-tenancy in axess is what lets a SaaS application provision
new organisations without restructuring the data model. Suspending
and deleting a tenant are the application's to build on the per-user
primitives, as the lifecycle section says. The fingerprint pepper is
per tenant; the lockout policy varies per tenant; device retention
can vary per tenant where the deployment keeps a `SweepConfig` for
each; the policies are scoped per tenant. The
multi-tenant deployment is the single-tenant deployment with
N>1.

## Further reading

*Scope hierarchy* covers the three-tier (`System`, `Tenant`, `User`)
resolution mechanism that determines which configuration applies
to which user. *Device identity* covers the per-tenant
fingerprint pepper and the GDPR-shaped retention sweep.
*Identity store implementation* covers the storage layer for
the tenant record and the user records under it. *Cedar policy
fundamentals* covers the cross-tenant `forbid` rule and the
policy-scoping pattern.
