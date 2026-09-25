# Multi-tenancy

A tenant in axess is the unit of isolation. Users, factor
configurations, sessions, devices, policies, and audit events all
carry a `TenantId`, and the library refuses to leak data across
tenants by construction.

The mechanism is on by default, and no feature flag exists to
toggle tenancy; the `TenantId` field is present on every relevant
record. A single-tenant deployment uses one well-known
`TenantId` (`"default"` is the convention) and effectively gets
the multi-tenant machinery for free, ready to expand when a
second tenant is added.

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
    pub created_at: DateTime<Utc>,
    pub updated_by: UserId,
    pub updated_at: DateTime<Utc>,
}
```

Note what is *not* on it. There is no per-tenant lockout policy field,
no fingerprint pepper, no retention setting. Per-tenant policy is
resolved through `IdentityLookup`, not stored on the struct:
`lockout_policy_for_tenant`, `password_rules_for_tenant` and
`ip_policy_for_tenant` are trait methods with defaults, and a
deployment that sells a stricter tier overrides them against its own
table. That keeps `Tenant` a row an adopter can map onto whatever they
already have, rather than a schema axess imposes.

`status` is `EntityState` (`Guest`, `Candidate`, `Pending`, `Active`,
`Suspended`, and the closed state), shared with users rather than a
tenant-specific enum, which is what makes "is this principal usable"
one question at both levels.

`created_by` and `updated_by` are `UserId`s, so every tenant row names
the actor behind it. For an operator-onboarded tenant that is
`UserId::system()`; for a self-service signup it is typically the first
admin.


The `TenantId` is a typed UUID (the convention in axess-identity).
The `status` carries the tenant's lifecycle state, covered below.
The `fingerprint_pepper` is the per-tenant device pepper from
*Device identity*. The `lockout_policy` is the tenant-scoped
override of the global lockout configuration, covered in the
*Three-lever lockout* section below. The `device_retention_days`
is the per-tenant GDPR-shaped retention period for device records.

### Cross-tenant refusal as a structural rule

Every operation in axess that touches a user, a session, a device,
a factor, or an event carries a tenant scope. The library checks
the scope before performing the operation, and refuses any
operation where the scopes do not align.

The pattern is uniform across the API. A `begin_login` call
takes a tenant id; the user lookup is scoped to that tenant; a
user with the same username in a different tenant is not
returned. A `verify_factor` call works against the session's
tenant id; a factor configuration registered in a different
tenant is not consulted. A `find_sessions_for_user` call takes
both user id and tenant id; sessions in other tenants are not
returned.

The structural defence is what lets a multi-tenant deployment
make the strongest possible authorisation claim: not only does
the application not leak across tenants, the library underneath
cannot. The Cedar policy layer can then add a top-level `forbid`
rule that catches the rare case of an application bug that tries
to authorise across tenants:

```cedar,ignore
forbid (
    principal,
    action,
    resource
) when {
    principal.tenant_id != resource.tenant_id
};
```

The rule applies to every action on every resource, and the
combination of "library refuses cross-tenant lookups" and "policy
denies cross-tenant decisions" produces a deployment where a
cross-tenant access is structurally impossible.

## Atomic provisioning

A tenant comes into existence through `create_tenant`, the verb behind
any "sign up a new organisation" or "administrator provisions a new
tenant" flow. It is a free function rather than an `AuthnService`
method, for the reason given below: it needs both stores.

```rust,ignore
use axess_core::authn::provisioning::{TenantBootstrap, create_tenant};

let tenant = Tenant::new(
    tenant_id,
    "acme",                      // lookup identifier
    "Acme Inc.",                 // display name
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
user is a separate `create_user` call, which means a caller who wants
"tenant plus admin, or neither" wraps both in their own transaction.
Bootstrapping with an empty `factors` list is refused outright
(`ProvisioningError::NoFactorsSpecified`), because a tenant whose users
cannot present any factor cannot be logged into.

The atomicity matters because a partially-provisioned tenant is a
landmine. A tenant that exists in the tenant table but has no
configured method admits any user with the system default method,
which may not be what the new tenant wants. A tenant with a
method but no factor configurations for the admin user produces
an immediate lockout. A tenant with an admin user but no factor
secret for them is worse: the user record exists, the admin
cannot log in, and there is no path to recovery without an
out-of-band intervention.

The bootstrap struct is the contract that says "a tenant exists
only after every one of these has succeeded." The implementation
runs the create-tenant, create-user, create-factor-config,
create-method, set-fingerprint-pepper, set-lockout-policy
operations in a single transaction. On any failure the
transaction rolls back; nothing is persisted; the call returns an
error.

A subtler invariant in the bootstrap: every tenant must have at
least one factor and one enabled method, and the admin user must
have a factor configuration for every factor the method requires.
The bootstrap checks both at construction; a misshapen bootstrap
fails before the transaction starts.

## The three-lever lockout

Lockout is the mechanism that prevents an attacker from
brute-forcing credentials. Axess has three levers, applied at
three scopes, that compose.

The first lever is per-user lockout. After a configurable number
of failed factor verifications against the same user account,
that account is locked for a configurable interval. The default
is three failed attempts followed by a fifteen-minute lockout
with exponential backoff on repeated failure.

The second lever is per-tenant lockout. After a configurable
number of failed factor verifications across any user in the
tenant within a short window, the tenant's login surface as a
whole is throttled. The default is high enough that legitimate
traffic does not trigger it; the lever exists to catch
distributed brute-forcing across many accounts in the same
tenant.

The third lever is per-IP lockout. After a configurable number
of failed verifications from the same source IP within a short
window, that IP is throttled or blocked outright. The default is
ten attempts per minute, beyond which the requests are rejected
without engaging the factor verifier. The lever catches a single
attacker source attempting many accounts.

The three levers compose multiplicatively. A successful attack
needs to dodge all three: stay below the per-user threshold,
stay below the per-tenant threshold, and either spread across
many source IPs or stay below the per-IP threshold. The cost of
the attack grows as a product of the three.

The lockout configuration is in `LockoutPolicy`, and it is one scale,
not three:

```rust,ignore
pub struct LockoutPolicy {
    pub max_attempts: u32,             // default 5
    pub duration: Option<Duration>,    // default 15 min; None = indefinite
    pub attempt_window: Duration,      // default 1 hour
    pub on_counter_unavailable: CounterUnavailable,   // default Lock
}
```

`max_attempts` is compared against the count
`IdentityAuthnLog::record_failed_attempt` returns. `duration` is how
long the lock lasts, and `None` means it does not expire on its own:
an administrator has to clear it. `attempt_window` is how far back
failures count, so five failures spread over two hours do not lock an
account whose window is one hour.

The scoping is per user only. Per-tenant and per-IP lockout
scales do not exist on this type, and adding one would be the wrong place for it: a
per-IP threshold that locks *accounts* is a denial-of-service tool in
an attacker's hands. Rate-limit by IP instead, at the middleware layer,
where the response is a 429 rather than a locked account
(*Rate limiting* covers `KeyExtractor::LoginIdentifier`, which is the
per-account half of that defence).

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
on `AuthnMetrics::factor_counter_store_outage`, which fires on exactly
this path, or pick `Allow` knowingly.

Neither setting changes what an attacker sees for an identifier that
does not exist. Those are refused at `begin_login` with timing
equalization and never reach the counter.

The policy is resolved per tenant through
`IdentityLookup::lockout_policy_for_tenant`, which defaults to
`lockout_policy()`, which defaults to `LockoutPolicy::default()`.
Override either where your tenants differ.

## Tenant lifecycle

Suspending and deleting, and what each does to live sessions.

### Tenant suspension

`Tenant` carries `status: EntityState`, the same type a user's status
uses, so a suspended tenant is representable. **Axess ships no
operation to suspend one.** `IdentityStore` has `suspend_user` and
`activate_user` and no tenant equivalent, the session registry
invalidates by user and by session and not by tenant, and there is no
tenant lifecycle event in the audit vocabulary.

What exists today is per-user: `suspend_user_in_tenant` sets the
status, invalidates that user's sessions through the registry, and
emits `AccountSuspended` attributed to the actor who did it.

If you need "this tenant has not paid" or "this tenant is under
compliance review" now, it is yours to build: set the tenant's status
through your own `IdentityStore` implementation, and invalidate the
sessions of its users yourself. Doing it inside axess would mean new
required methods on both `IdentityStore` and the session registry,
which every adopter would have to implement, so it is a deliberate
decision rather than an oversight to leave it out.

Whatever drives the status, a tenant that is not `Active` refuses its
users before factor verification. That is a state the application may
want to render specifically ("your organisation is suspended, contact
support") rather than as the generic invalid-credentials page, so check
the tenant's status rather than inferring it from the login outcome.

### Tenant deletion

The same gap as suspension, one step further along. `EntityState` has a
closed state, so a deleted tenant is representable, and **axess ships
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

If you build it, two things a naive cascade will not do:

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

That is a deliberate consolidation rather than a gap. A separate tenant
trait would be a second surface every adopter has to implement, against
the same database, with its own error type and its own transaction
boundary. Provisioning a tenant already has to touch users and
factors, so it could not stay inside that boundary anyway.

The practical consequence is that per-tenant policy has no prescribed
schema. A deployment with one policy for everyone implements nothing
and takes the defaults. A deployment that varies policy per tenant adds
a column or a table of its own and returns it from
`lockout_policy_for_tenant` and friends. Axess never reads that storage
directly, which is why it cannot dictate its shape.

### Reserved principals

A handful of principals are reserved across all tenants. The
`system()` principal is the one axess uses for its own internal
operations (retention sweeps, scheduled rotations, audit pipeline
ingestion). The principal carries no `TenantId`; its actions are
attributed to the system itself, not to any tenant or user.

The reservation prevents an application from creating a user named
"system" and inadvertently granting that user the permissions axess
reserves for its background work. `UserId::is_system` and
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
new organisations without restructuring the data model, suspend
problematic ones without affecting the rest, and delete departed
ones cleanly with an audit trail. The fingerprint pepper rotates
per-tenant; the lockout policy varies per-tenant; the device
retention complies per-tenant; the policies scope per-tenant. The
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
