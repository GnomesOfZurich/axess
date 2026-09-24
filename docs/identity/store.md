# Identity store implementation

Most of axess works against traits, and the identity store is the
most consequential of them. The library does not prescribe a user
schema, a tenant schema, or a factor schema; it prescribes a set
of trait methods you implement against whatever
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
pub trait IdentityLookup: Send + Sync + 'static {
    /// Your error type, not ours. Every method below returns it.
    type Error: std::error::Error + Send + Sync + 'static;

    fn find_user(
        &self,
        identifier: &str,
        tenant_id: &TenantId,
    ) -> impl Future<Output = Result<Option<User>, Self::Error>> + Send;

    fn get_user(
        &self,
        user_id: &UserId,
    ) -> impl Future<Output = Result<Option<User>, Self::Error>> + Send;

    fn find_tenant(
        &self,
        identifier: &str,
    ) -> impl Future<Output = Result<Option<Tenant>, Self::Error>> + Send;

    fn account_status(
        &self,
        user_id: &UserId,
    ) -> impl Future<Output = Result<EntityState, Self::Error>> + Send;

    // `get_user_in_tenant`, `default_tenant`, and the per-tenant policy
    // getters (`lockout_policy_for_tenant`, `password_rules_for_tenant`,
    // `ip_policy_for_tenant`) have defaults you can take as given.
}

// Tier 2: read + the writes the login flow makes as it runs.
pub trait IdentityAuthnLog: IdentityLookup {
    fn record_event(
        &self,
        event: AuthEvent,
    ) -> impl Future<Output = Result<AuditOutcome, Self::Error>> + Send;

    /// Returns the running count *after* this failure, which is what
    /// the lockout policy compares against its threshold.
    fn record_failed_attempt(
        &self,
        user_id: &UserId,
    ) -> impl Future<Output = Result<u32, Self::Error>> + Send;

    fn reset_failed_attempts(
        &self,
        user_id: &UserId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    // `record_last_login` defaults to a no-op.
}

// Tier 3: read + audit + administrative writes.
pub trait IdentityAdmin: IdentityAuthnLog {
    fn create_tenant(
        &self,
        tenant: Tenant,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn create_user(
        &self,
        user: User,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn activate_user(
        &self,
        user_id: &UserId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    // Plus the password-history and suspension verbs, which default to
    // `unimplemented!()` with a message naming the feature that needs
    // them. See below.
}

// The umbrella for production: all three tiers.
pub trait IdentityStore: IdentityAdmin {}
impl<T: IdentityAdmin> IdentityStore for T {}

// Separate, and required rather than defaulted. Only the password-reset
// flow asks for it, and only a store that implements it can call that
// flow.
pub trait IdentityPasswordReset: IdentityLookup {
    fn store_reset_token(
        &self,
        user_id: &UserId,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn verify_reset_token(
        &self,
        user_id: &UserId,
        token_hash: &str,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;
}
```

Four things about that surface are worth stating plainly, because
each one shapes an implementation.

The futures are native `impl Future`, not `#[async_trait]` boxes. Your
methods are ordinary `async fn` bodies and cost no allocation per call.

The error is an associated `Self::Error`, declared once on
`IdentityLookup` and inherited by the other two tiers. Axess never asks
you to convert into an error type of its own; `sqlx::Error` is a
perfectly good `Self::Error`.

There is no `AttemptRecord`, `LockoutRecord` or `NewUser`. The audit
tier writes a single flat `AuthEvent` through `record_event`, and
failure counting is a pair of numeric verbs rather than a record type.
`record_failed_attempt` returns the count after the increment, which is
the number the lockout policy compares against its threshold. Lockout
state is derived from that count and the policy, not stored as its own
row. `create_user` takes a fully-formed `User`, so identifier
generation and defaulting happen in your code, before the call.

Two `IdentityAdmin` methods have default bodies that `unimplemented!()`
rather than returning an error: password-reuse prevention needs
`record_password_hash` and `password_history`, and a backend that never
raises `history_count` above zero should not have to write stubs for
them. The panic is uniform when it does fire, on an authenticated
change-password call, so it costs availability and nothing else.

The reset-token methods are not among them, and the reason is worth
knowing because it is the shape of a mistake rather than a preference.
`begin_password_reset` answers `Ok(None)` for an identifier it cannot
find and reaches the store only for one it can. A panicking default
therefore answered an unauthenticated "forgot password" request with a
200 for an address that is not registered and a 500 for one that is:
a user-enumeration oracle, in the function that equalizes its own
timing specifically to avoid leaking that. A silently-succeeding
default would be worse, since recovery would appear to work while no
token was ever stored.

So those two live on `IdentityPasswordReset`, with no defaults, and the
reset flow is bounded on it. A store that has not implemented them
cannot call the flow, and the omission is a compile error naming both
methods.

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
writes, so you need the read verbs without the write
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
separation between the code that handles login and
the administrative code that creates users. The application
implements `IdentityAuthnLog`; the admin code separately
implements `IdentityAdmin`. The split prevents the login path
code from accidentally calling `delete_user` or `suspend_user`
because it never has the trait method in scope.

## What the verbs actually do

The verbs split cleanly across the tiers.

`IdentityLookup` is reads. `get_user` is a primary-key lookup by
`UserId`. `find_user` is a credentials-side lookup by identifier
and tenant: the user typed `alice@example.com`, and you
needs to know if this is a real user in this tenant. Other read
verbs cover the variants: looking up a user by email when email
is separately indexed, looking up a user by a federated identity
key when you support federated login, listing the
users in a tenant for admin tooling.

`IdentityAuthnLog` is the writes the login flow makes as it runs.
`record_event` takes one flat `AuthEvent`, carrying the event type, the
status, the timestamp in epoch microseconds, and whatever attribution
was resolvable: user, tenant, session, factor kind, IP, user agent,
request id, error string. It is called throughout the flow, not only
after a factor check, and its argument is the same type the audit query
surface returns. `record_failed_attempt` increments the user's failure
counter and returns the new count, which is the number the
`LockoutPolicy` compares against its threshold;
`reset_failed_attempts` zeroes it on a successful login or an
administrative clear. Lockout keeps no record of its own: the locked
state is derived from the counter and the policy.

`IdentityAdmin` is the privileged writes. `create_tenant` and
`create_user` are the provisioning verbs, and `create_user` takes an
already-built `User`, so identifier generation and defaulting happen in
your code, not behind the trait. `activate_user` moves a user out of
the pending state. The rest of the tier covers password history,
out-of-band reset tokens, and suspension; several of those have
defaults that `unimplemented!()` until the feature that needs them is
turned on.

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

impl IdentityLookup for OurBackend {
    type Error = BackendError;

    async fn get_user(&self, user_id: &UserId) -> Result<Option<User>, Self::Error> {
        let row = sqlx::query(
            "SELECT id, tenant_id, identifier, display_name, status,
                    failed_attempts, locked_until, created_at, updated_at
             FROM users
             WHERE id = ?1",
        )
        .bind(user_id.to_string())
        .fetch_optional(self.pool())
        .await?;

        Ok(row.map(|r| user_from_row(self.clock(), &r)))
    }

    async fn find_user(
        &self,
        identifier: &str,
        tenant_id: &TenantId,
    ) -> Result<Option<User>, Self::Error> {
        let row = sqlx::query(
            "SELECT id, tenant_id, identifier, display_name, status,
                    failed_attempts, locked_until, created_at, updated_at
             FROM users
             WHERE tenant_id = ?1 AND identifier = ?2",
        )
        .bind(tenant_id.to_string())
        .bind(identifier)
        .fetch_optional(self.pool())
        .await?;

        Ok(row.map(|r| user_from_row(self.clock(), &r)))
    }
    // ... find_tenant, default_tenant, account_status
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

The error type is the implementation's own, declared once as
`type Error = BackendError` on `IdentityLookup` and inherited by the
other two tiers. `?` on a `sqlx` call works because `BackendError`
implements `From<sqlx::Error>`; nothing converts into an axess type.
Keep the kind of failure (connection, query, constraint violation)
distinguishable in that enum, because your own callers will want to act
on it even though axess only logs it.

Both read verbs return `Option<User>`. A missing user is `Ok(None)`,
not an error: the login flow treats "no such user" and "wrong password"
identically, on purpose, so that a failed login does not reveal which
identifiers exist.

## Implementing the audit writes

`IdentityAuthnLog` is the layer that requires care. Its verbs fire on
every login attempt, so a slow implementation is the bottleneck of the
whole authentication flow.

There are three of them, and they divide neatly. `record_event` appends
one flat `AuthEvent` row. `record_failed_attempt` and
`reset_failed_attempts` maintain a single counter on the user.

```rust,ignore
impl IdentityAuthnLog for OurBackend {
    async fn record_event(&self, event: AuthEvent) -> Result<AuditOutcome, Self::Error> {
        // Unresolved attribution, a pre-auth failure or a malformed
        // OAuth claim, persists as NULL so audit queries can tell "we do not
        // know who" from a real principal. Both columns allow NULL.
        let user_id: Option<String> = event.user_id.as_ref().map(|u| u.to_string());
        let tenant_id: Option<String> = event.tenant_id.as_ref().map(|t| t.to_string());
        let event_time = DateTime::<Utc>::from_timestamp_micros(event.event_time)
            .expect("event_time micros in range")
            .to_rfc3339();

        sqlx::query(
            "INSERT INTO auth_events
             (id, user_id, tenant_id, session_id, event_type, event_status,
              event_time, factor_kind, ip_address, user_agent, request_id,
              geo_country, error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&user_id)
        .bind(&tenant_id)
        .bind(event.session_id.map(|sid| sid.to_string()))
        .bind(event.event_type.to_string())
        .bind(event.event_status.to_string())
        .bind(&event_time)
        .bind(event.factor_kind.as_ref().map(|k| k.as_str()))
        .bind(event.ip_address.as_deref())
        .bind(event.user_agent.as_deref())
        .bind(event.request_id.as_deref())
        .bind(event.geo_country.as_deref())
        .bind(event.error.as_deref())
        .execute(self.pool())
        .await?;
        // `Shed` instead, to drop an event under load without failing
        // the login. Key that decision on something identifier-independent.
        Ok(AuditOutcome::Recorded)
    }

    /// Returns the count *after* the increment: that is the number the
    /// lockout policy compares against its threshold.
    async fn record_failed_attempt(&self, user_id: &UserId) -> Result<u32, Self::Error> {
        sqlx::query("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?1")
            .bind(user_id.to_string())
            .execute(self.pool())
            .await?;

        let row = sqlx::query("SELECT failed_attempts FROM users WHERE id = ?1")
            .bind(user_id.to_string())
            .fetch_one(self.pool())
            .await?;
        let count: i64 = row.get("failed_attempts");
        Ok(count as u32)
    }

    async fn reset_failed_attempts(&self, user_id: &UserId) -> Result<(), Self::Error> {
        sqlx::query("UPDATE users SET failed_attempts = 0 WHERE id = ?1")
            .bind(user_id.to_string())
            .execute(self.pool())
            .await?;
        Ok(())
    }
}
```

Two properties of that shape matter operationally.

`auth_events` is append-only and flat. Every event lands in that one table,
and no join to reconstruct an attempt; every event carries its own
`event_type`, `event_status` and nullable attribution. Index it on
`(user_id, tenant_id, event_time DESC)` for the "what happened to this
account" query, and on `(tenant_id, event_time DESC)` for the
tenant-wide one.

The failure counter is a column on `users`, not a row count over
`auth_events`. Lockout is derived from that counter and the
`LockoutPolicy`, so there is no lockout table to upsert and no
`clear_lockout` verb: `reset_failed_attempts` is the whole of it. The
increment-then-read above is two statements; under contention, prefer
whatever single-statement form your database offers (`UPDATE ...
RETURNING failed_attempts` on PostgreSQL) so two concurrent failures
cannot both read the same count.

The audit read is the hottest query in this layer.
The index (user_id, tenant_id, event_time DESC) makes it cheap; without
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

The trade-off is that the lockout policy will not function correctly
under `NoopAuthnLog`. The policy decides from the count
`record_failed_attempt` returns, and the noop discards the increment,
so the count never rises and the threshold is never reached.
Deployments that use `NoopAuthnLog` for the read-replica case must
accept a degraded lockout policy unless they implement an alternative.

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

The identity store is the part of your system most likely to
need migrations over time: a new factor adds a column to the
factor configurations table, a regulatory change requires a new
field on the audit-attempts table, a refactor renames a column.

The migration mechanism is yours, not axess's.
`sqlx::migrate!` is the standard pattern; alternative migration
tools (Diesel migrations, Atlas, custom SQL) work the same way.
Axess does not need to know about the migrations; the
implementation just needs to keep satisfying the trait against
the new schema.

The pattern in `examples/sqlite/` is the reference. The
`migrations/` directory carries the SQL files; the `main.rs`
runs them at startup; the implementation queries against the
latest schema.

## Fitting into a schema you already have

The trait split is what lets axess fit into existing applications
without forcing a schema rewrite. The library knows nothing about
the user table; it knows only that there is a trait it can call
to look up users. The application's data model is the source of
truth, and the trait surface is the bridge.

The three tiers and the noop adapter give you enough
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
