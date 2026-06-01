# Identity store implementation

Most of axess works against traits, and the identity store is the
most consequential of them. The library does not prescribe a user
schema, a tenant schema, or a factor schema; it prescribes a set
of trait methods that the application implements against whatever
schema it already has. This chapter walks through the three-tier
trait split, the verbs each tier carries, the patterns for
implementing them against a SQL backend, and the
read-replica-and-fixtures variant that the `NoopAuthnLog` adapter
enables.

## The three tiers

The identity store is split into three trait tiers, in order of
increasing privilege. An adopter that needs only read access
implements the narrowest tier; an adopter that needs write access
for audit purposes implements the middle tier; an adopter that
needs full administrative control implements the widest tier.

```rust,ignore
// Tier 1: read-only.
#[async_trait]
pub trait IdentityLookup: Send + Sync {
    async fn get_user(&self, user_id: &UserId) -> Result<User, StoreError>;
    async fn find_user(
        &self,
        identifier: &str,
        tenant_id: &TenantId,
    ) -> Result<Option<User>, StoreError>;
    // ... eight more verbs
}

// Tier 2: read + per-attempt audit writes.
#[async_trait]
pub trait IdentityAuthnLog: IdentityLookup {
    async fn record_attempt(
        &self,
        attempt: AttemptRecord,
    ) -> Result<(), StoreError>;
    async fn record_lockout(
        &self,
        lockout: LockoutRecord,
    ) -> Result<(), StoreError>;
    async fn clear_lockout(
        &self,
        user_id: &UserId,
        tenant_id: &TenantId,
    ) -> Result<(), StoreError>;
    async fn last_attempts(
        &self,
        user_id: &UserId,
        tenant_id: &TenantId,
        limit: usize,
    ) -> Result<Vec<AttemptRecord>, StoreError>;
}

// Tier 3: read + audit + administrative writes.
#[async_trait]
pub trait IdentityAdmin: IdentityAuthnLog {
    async fn create_user(&self, user: NewUser) -> Result<User, StoreError>;
    async fn suspend_user(&self, user_id: &UserId, at: DateTime<Utc>) -> Result<(), StoreError>;
    async fn erase_user(&self, user_id: &UserId, gdpr_reason: &str) -> Result<(), StoreError>;
    // ... six more verbs covering admin lifecycle
}

// The umbrella for production: all three tiers.
pub trait IdentityStore: IdentityAdmin {}
impl<T: IdentityAdmin> IdentityStore for T {}
```

The hierarchy reads from narrowest to widest. An
`IdentityAuthnLog` is an `IdentityLookup` plus the audit writes.
An `IdentityAdmin` is an `IdentityAuthnLog` plus the
administrative writes. The umbrella `IdentityStore` is the
all-three-tiers shape that production backends implement.

## Why three tiers

The split is the answer to two adopter situations the library has
seen often enough to model explicitly.

The first situation is a read-replica deployment. A high-traffic
application runs the login flow against a read-replica of the
user database for latency reasons. The replica cannot accept
writes; the application needs the read verbs without the write
verbs. The `IdentityLookup` tier covers this. The application
implements `IdentityLookup` against the replica and
`IdentityAuthnLog` (which needs writes) against the primary.

The second situation is a fixture deployment. A test or an
embedded usage of axess does not have a real database; the
application uses an in-memory backend for the read verbs and does
not care about the audit writes. The `NoopAuthnLog` adapter
wraps an `IdentityLookup` and provides no-op implementations of
the `IdentityAuthnLog` write verbs. The fixture has the trait
surface it needs without writing an audit-table mock.

The third situation, less common, is a deployment with a
separation between the application code that handles login and
the administrative code that creates users. The application
implements `IdentityAuthnLog`; the admin code separately
implements `IdentityAdmin`. The split prevents the application
code from accidentally calling `delete_user` or `suspend_user`
because it never has the trait method in scope.

## What the verbs actually do

The verbs split cleanly across the tiers.

`IdentityLookup` is reads. `get_user` is a primary-key lookup by
`UserId`. `find_user` is a credentials-side lookup by identifier
and tenant: the user typed `alice@example.com`, the application
needs to know if this is a real user in this tenant. Other read
verbs cover the variants: looking up a user by email when email
is separately indexed, looking up a user by a federated identity
key when the application supports federated login, listing the
users in a tenant for admin tooling.

`IdentityAuthnLog` is the audit writes the lockout system
depends on. `record_attempt` is called by `verify_factor` after
every factor check; the record carries the user id, the tenant
id, the factor kind, the outcome (success, failure, locked), the
timestamp, the IP. `record_lockout` is called when the lockout
policy fires; the record marks the user as locked until a
specific moment. `clear_lockout` is called when the lockout
window expires or when an administrator manually clears the
state. `last_attempts` is the read verb the policy consults to
make the next lockout decision.

`IdentityAdmin` is the privileged writes. `create_user` is the
verb behind signup or admin provisioning. `suspend_user` is the
verb behind administrative suspension (compliance, fraud
investigation). `erase_user` is the GDPR-shaped verb: the user
has invoked their right to be forgotten, and the verb cascades
through every record that references them. Other admin verbs
cover password reset (administrative, not user-initiated),
identifier changes, and the per-user method override.

## Implementing against SQL

The typical implementation against a SQL database is verbose but
mechanical. The pattern is to implement each verb as one query
(or one transaction), with the right indexes on the user table
to keep the reads fast.

A reference implementation against PostgreSQL is in
[`examples/sqlite/`](https://github.com/GnomesOfZurich/axess/tree/main/examples/sqlite)
(the SQLite version of the pattern). The shape:

```rust,ignore
struct OurBackend {
    pool: SqlitePool,
}

#[async_trait]
impl IdentityLookup for OurBackend {
    async fn get_user(&self, user_id: &UserId) -> Result<User, StoreError> {
        let row = sqlx::query_as::<_, UserRow>(
            "SELECT id, tenant_id, identifier, display_name, status, created_at
             FROM users
             WHERE id = ?1"
        )
        .bind(user_id.to_string())
        .fetch_one(&self.pool)
        .await?;
        Ok(row.into())
    }

    async fn find_user(
        &self,
        identifier: &str,
        tenant_id: &TenantId,
    ) -> Result<Option<User>, StoreError> {
        let row = sqlx::query_as::<_, UserRow>(
            "SELECT id, tenant_id, identifier, display_name, status, created_at
             FROM users
             WHERE identifier = ?1 AND tenant_id = ?2"
        )
        .bind(identifier)
        .bind(tenant_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }
    // ... eight more verbs
}
```

The patterns to note:

The tenant scope is on every query. `find_user` filters by both
identifier and tenant id; the same identifier in a different
tenant is not returned. The discipline is what enforces cross-tenant
refusal at the storage layer.

The identifier comparison is whatever the deployment chose. The
example treats the identifier as case-sensitive; deployments that
want case-insensitive matching apply `LOWER()` to both sides (and
index on `LOWER(identifier)`). The trait does not opinionate; the
implementation decides.

The error type is the implementation's. The trait returns
`StoreError`; the implementation maps `sqlx::Error` into it. The
mapping preserves the kind of failure (connection error, query
error, constraint violation) so the upstream callers can act on
specific cases.

## Implementing the audit writes

`IdentityAuthnLog` is the layer that requires care. The verbs
fire on every login attempt; a slow implementation is the
bottleneck of the entire authentication flow.

The pattern is to batch where possible and to keep each write
small. The `record_attempt` table is append-only and indexed on
(user_id, tenant_id, timestamp) for the `last_attempts` query.
The lockout state lives in a separate table keyed by user; the
`record_lockout` and `clear_lockout` verbs are upserts.

```rust,ignore
#[async_trait]
impl IdentityAuthnLog for OurBackend {
    async fn record_attempt(&self, attempt: AttemptRecord) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO authn_attempts (user_id, tenant_id, factor_kind, outcome, ip, ts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        )
        .bind(attempt.user_id.to_string())
        .bind(attempt.tenant_id.to_string())
        .bind(attempt.factor_kind.as_str())
        .bind(attempt.outcome.as_str())
        .bind(attempt.ip.map(|ip| ip.to_string()))
        .bind(attempt.ts)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn last_attempts(
        &self,
        user_id: &UserId,
        tenant_id: &TenantId,
        limit: usize,
    ) -> Result<Vec<AttemptRecord>, StoreError> {
        let rows = sqlx::query_as::<_, AttemptRow>(
            "SELECT user_id, tenant_id, factor_kind, outcome, ip, ts
             FROM authn_attempts
             WHERE user_id = ?1 AND tenant_id = ?2
             ORDER BY ts DESC
             LIMIT ?3"
        )
        .bind(user_id.to_string())
        .bind(tenant_id.to_string())
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
    // ... record_lockout, clear_lockout
}
```

The `last_attempts` query is the hottest read in the audit layer.
The index (user_id, tenant_id, ts DESC) makes it cheap; without
the index, the query degrades to a table scan and the login flow
slows under load.

The append-only attempts table grows. The retention story for it
is in *Audit pipeline*: typically a hot/cold split where recent
attempts (the ones the lockout policy consults) stay in the
attempts table and older attempts archive to a cold store.

## The NoopAuthnLog adapter

`NoopAuthnLog<L>` wraps an `IdentityLookup` and provides no-op
implementations of the `IdentityAuthnLog` write verbs. The
wrapper exists for two cases.

The first is fixtures. A test uses `MockIdentityStore`
(implementing `IdentityLookup`), and `verify_factor` needs
`IdentityAuthnLog`. The test wraps the mock in `NoopAuthnLog`,
satisfies the trait, and runs without recording anything.

The second is read-replica deployments where the audit writes go
through a different code path (an out-of-band log shipper, a
Kafka topic, an external SIEM). The application implements
`IdentityLookup` against the replica, wraps in `NoopAuthnLog`,
and routes the audit writes through the side channel.

The trade-off is that the lockout policy will not function
correctly under `NoopAuthnLog`. The policy consults
`last_attempts`, which depends on the audit writes the noop
silently discarded. Deployments that use `NoopAuthnLog` for the
read-replica case must accept that the lockout policy is degraded
unless they implement an alternative.

The chapter warns about this in the docstring of `NoopAuthnLog`;
the warning is worth repeating: do not use `NoopAuthnLog` in
production without an alternative lockout source.

## What about workload identities

Workloads have their own identity surface, not the same one
humans use. The `IdentityStore` traits do not cover workloads;
the workload identity resolvers (*Workload identity overview*)
have their own machinery.

The split is deliberate. Humans live in a user table; workloads
live in a workload table (or do not live anywhere durable, when
they are short-lived service-to-service callers). The audit
events for workloads route differently from human events. The
lockout policy does not apply to workloads at all. Trying to
unify the two would produce a trait that does too many jobs.

The same is true for the principal model: the `Principal` enum
has two variants, the read paths for the two variants go through
two different stores. The application implements both stores and
the resolver code routes appropriately.

## Schema migration

The identity store is the part of the application most likely to
need migrations over time: a new factor adds a column to the
factor configurations table, a regulatory change requires a new
field on the audit-attempts table, a refactor renames a column.

The migration mechanism is the application's, not axess's.
`sqlx::migrate!` is the standard pattern; alternative migration
tools (Diesel migrations, Atlas, custom SQL) work the same way.
Axess does not need to know about the migrations; the
implementation just needs to keep satisfying the trait against
the new schema.

The pattern in `examples/sqlite/` is the reference. The
`migrations/` directory carries the SQL files; the `main.rs`
runs them at startup; the implementation queries against the
latest schema.

## What this enables

The trait split is what lets axess fit into existing applications
without forcing a schema rewrite. The library knows nothing about
the user table; it knows only that there is a trait it can call
to look up users. The application's data model is the source of
truth, and the trait surface is the bridge.

The three tiers and the noop adapter give the application enough
flexibility to fit the awkward shapes (read replicas, fixtures,
split admin) without forcing every adopter to implement the full
set of verbs.

## Further reading

*Multi-tenancy* covers the per-tenant configuration that the
identity store reads and writes. *Audit events* covers the
`AuthEvent` variants the audit-log verbs emit. *Audit pipeline*
covers the hot/cold retention story for the attempts table.
*Migration guide* covers the cross-version migrations that affect
the user table.
