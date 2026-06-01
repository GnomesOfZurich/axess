# Multi-tenancy

A tenant in axess is the unit of isolation. Users, factor
configurations, sessions, devices, policies, and audit events all
carry a `TenantId`, and the library refuses to leak data across
tenants by construction. This chapter covers the model, the
atomic provisioning pattern that ensures every tenant starts in a
sound state, the three-lever lockout, and the operational
patterns for tenant suspension and deletion.

The mechanism is on by default. There is no feature flag to
toggle tenancy; the `TenantId` field is present on every relevant
record. A single-tenant deployment uses one well-known
`TenantId` (`"default"` is the convention) and effectively gets
the multi-tenant machinery for free, ready to expand when a
second tenant is added.

## The tenant record

The `Tenant` struct lives in `axess-identity` and carries the
configuration that applies to every user under the tenant:

```rust,ignore
pub struct Tenant {
    pub tenant_id: TenantId,
    pub status: TenantStatus,                    // Active | Suspended | Deleted
    pub display_name: String,
    pub fingerprint_pepper: ZeroizedString,      // per-tenant device pepper
    pub lockout_policy: LockoutPolicy,           // tenant-scoped lockout
    pub device_retention_days: u32,              // GDPR-shaped retention
    pub created_at: DateTime<Utc>,
    pub suspended_at: Option<DateTime<Utc>>,
}
```

The `TenantId` is a typed UUID (the convention in axess-identity).
The `status` carries the tenant's lifecycle state, covered below.
The `fingerprint_pepper` is the per-tenant device pepper from
*Device identity*. The `lockout_policy` is the tenant-scoped
override of the global lockout configuration, covered in the
*Three-lever lockout* section below. The `device_retention_days`
is the per-tenant GDPR-shaped retention period for device records.

## Cross-tenant refusal as a structural rule

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

A tenant comes into existence through `AuthnService::create_tenant`,
which is the verb behind any "sign up a new organisation" or
"administrator provisions a new tenant" flow. The call is atomic
by design.

```rust,ignore
let tenant = service.create_tenant(TenantBootstrap {
    display_name: "Acme Inc.".into(),
    initial_admin: AdminUser {
        identifier: "admin@acme.example".into(),
        initial_password: Some(initial_password.into()),
    },
    initial_method: Method {
        name: "password-then-totp".into(),
        steps: vec![
            FactorStep::Required(FactorKind::Password),
            FactorStep::Required(FactorKind::Totp),
        ],
    },
    fingerprint_pepper: SecureRng::random_bytes(32),
    lockout_policy: LockoutPolicy::default(),
    device_retention_days: 90,
}).await?;
```

The atomicity matters because a partially-provisioned tenant is a
landmine. A tenant that exists in the tenant table but has no
configured method admits any user with the global default method,
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

The lockout configuration is in `LockoutPolicy`:

```rust,ignore
pub struct LockoutPolicy {
    pub per_user: LockoutScale,
    pub per_tenant: LockoutScale,
    pub per_ip: LockoutScale,
}

pub struct LockoutScale {
    pub failures_before_lockout: u32,
    pub window: Duration,
    pub backoff: BackoffPolicy,  // fixed | exponential
    pub max_lockout: Duration,
}
```

The policy is per-tenant by default (loaded from the tenant
record's `lockout_policy` field). The global default applies if
the tenant did not override.

## Tenant suspension

A suspended tenant is still in the database but cannot
authenticate. The state is reached through `AuthnService::suspend_tenant`,
which is the operational verb behind "this tenant has not paid"
or "this tenant has been flagged for compliance review."

The transition does five things atomically: it sets the tenant's
status to `Suspended`, it sets the `suspended_at` timestamp, it
invalidates every active session under the tenant (deletes the
session rows, the user's next request comes through as `Guest`),
it revokes every refresh token under the tenant (sets `revoked
= true` on each), and it emits a `TenantSuspended` audit event.

A suspended tenant's users hit `TenantSuspended` on every login
attempt instead of proceeding to factor verification. The error
is distinct from `UserNotFound` because the application typically
wants to render a specific page for it (a "your organisation is
suspended, contact support" message), not the generic invalid-credentials
flow.

Unsuspending is the inverse: `unsuspend_tenant` flips the status
back to `Active`, clears `suspended_at`, and emits a
`TenantReactivated` event. Sessions are not restored; users have
to log in again, which is the right behaviour because their
device records may have aged or rotated during the suspension.

## Tenant deletion

A deleted tenant is the irreversible end of the lifecycle. The
state is reached through `AuthnService::delete_tenant`, typically
in response to a customer exit or a GDPR erasure request.

The deletion runs as a cascade. All sessions, refresh tokens,
devices, factor configurations, audit events, and the tenant
record itself are removed. The deletion is two-phase: the first
phase marks the tenant as `Deleted` and stops accepting new
operations on it; the second phase runs the cascade asynchronously
(typically as a background task) and removes the underlying
rows.

The two-phase pattern matters for two reasons. First, the
cascade is potentially expensive on large tenants; running it
synchronously blocks the operator's request. Second, the
two-phase approach gives a recovery window: if the deletion was
accidental, the first phase is reversible by flipping the status
back to `Suspended` before the cascade runs. After the cascade,
recovery requires a backup restore.

The audit events emitted during the cascade are preserved (in a
separate `axess.audit.tenant_deletion` log) so the deletion is
defensible against later inquiry. The events name the
operator who initiated, the timestamp, and the counts (how many
users, how many sessions, how many tokens).

## Per-tenant configuration storage

The per-tenant fields (fingerprint pepper, lockout policy,
device retention, methods) live in dedicated tables keyed by
tenant id. The application's tenant store is one of the adopter-
implemented surfaces; axess provides traits, the implementation
is yours. The pattern is uniform across the surfaces:

```rust,ignore
#[async_trait]
pub trait TenantStore: Send + Sync {
    async fn get(&self, id: &TenantId) -> Result<Tenant, TenantStoreError>;
    async fn create(&self, bootstrap: TenantBootstrap) -> Result<Tenant, ...>;
    async fn suspend(&self, id: &TenantId, at: DateTime<Utc>) -> Result<(), ...>;
    async fn unsuspend(&self, id: &TenantId) -> Result<(), ...>;
    async fn delete(&self, id: &TenantId, mode: DeleteMode) -> Result<(), ...>;
    async fn update_lockout_policy(&self, id: &TenantId, policy: LockoutPolicy) -> Result<(), ...>;
    async fn rotate_fingerprint_pepper(&self, id: &TenantId, new: ZeroizedString) -> Result<(), ...>;
}
```

The trait surface is the tenant lifecycle in code. An adopter
implements it against their own tenant table; axess calls into
it on each lifecycle event.

## Reserved principals

A handful of principals are reserved across all tenants. The
`system()` principal is the one axess uses for its own internal
operations (retention sweeps, scheduled rotations, audit pipeline
ingestion). The principal carries no `TenantId`; its actions are
attributed to the system itself, not to any tenant or user.

The reservation prevents an application from creating a user
named "system" and inadvertently granting that user the
permissions axess reserves for its background work. The
`UserId::is_reserved` check fires at user-creation time;
attempting to provision a reserved principal returns an error.

The set of reserved principals is small and stable. The chapter
*Audit events* lists them.

## What this enables

Multi-tenancy in axess is what lets a SaaS application provision
new organisations without restructuring the data model, suspend
problematic ones without affecting the rest, and delete departed
ones cleanly with an audit trail. The fingerprint pepper rotates
per-tenant; the lockout policy varies per-tenant; the device
retention complies per-tenant; the policies scope per-tenant. The
multi-tenant deployment is the single-tenant deployment with
N>1.

## Further reading

*Scope hierarchy* covers the three-tier (Global, Tenant, User)
resolution mechanism that determines which configuration applies
to which user. *Device identity* covers the per-tenant
fingerprint pepper and the GDPR-shaped retention sweep.
*Identity store implementation* covers the storage layer for
the tenant record and the user records under it. *Cedar policy
fundamentals* covers the cross-tenant `forbid` rule and the
policy-scoping pattern.
