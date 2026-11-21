# Identity store implementation

Most of axess works against traits, and the identity store is the
most consequential of them. The library does not prescribe a user
schema, a tenant schema, or a factor schema; it prescribes a set
of trait methods you implement against whatever
schema your application already has. The traits are split into three tiers by
privilege, so code of your own can ask for no more than it uses. The
login service itself runs on all three.

## The traits

Split by privilege: reads, the writes a login makes, and administration.

### The three tiers

The three trait tiers, in order of increasing privilege, are reads,
the writes the login flow makes as it runs, and administrative writes.
`AuthnService` is bounded on the umbrella `IdentityStore`, which is all
three: the store a deployment hands it implements every tier, and no
axess entry point takes less. The narrower tiers are bounds for code of your own
that needs less: a function that only looks users up can take an
`IdentityLookup` and be given no way to write.

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

    fn get_tenant(
        &self,
        tenant_id: &TenantId,
    ) -> impl Future<Output = Result<Option<Tenant>, Self::Error>> + Send;

    fn find_tenant(
        &self,
        identifier: &str,
    ) -> impl Future<Output = Result<Option<Tenant>, Self::Error>> + Send;

    fn account_status(
        &self,
        user_id: &UserId,
    ) -> impl Future<Output = Result<EntityState, Self::Error>> + Send;

    fn default_tenant(&self) -> impl Future<Output = Result<Tenant, Self::Error>> + Send;

    /// The tenant's policies. Required, with no permissive default: a
    /// decorator that forgot to forward one would switch the tenant's
    /// policy off without a compile error.
    fn lockout_policy_for_tenant(&self, tenant_id: &TenantId) -> LockoutPolicy;

    fn password_rules_for_tenant(
        &self,
        tenant_id: &TenantId,
    ) -> impl Future<Output = Result<PasswordRules, Self::Error>> + Send;

    fn ip_policy_for_tenant(
        &self,
        tenant_id: &TenantId,
    ) -> impl Future<Output = Result<IpPolicy, Self::Error>> + Send;

    // `get_user_tenant` and `get_user_in_tenant` have defaults derived from
    // `get_user`; override them for a narrower query.
}

// Tier 2: read + the writes the login flow makes as it runs.
pub trait IdentityAuthnLog: IdentityLookup {
    fn record_event(
        &self,
        event: AuthEvent,
    ) -> impl Future<Output = Result<AuditOutcome, Self::Error>> + Send;

    /// Returns the running count *after* this failure, and stores the time
    /// of the failure beside it.
    fn record_failed_attempt(
        &self,
        user_id: &UserId,
    ) -> impl Future<Output = Result<u32, Self::Error>> + Send;

    /// The count and the time of the last failure, `(0, None)` for none.
    /// The library derives the lockout from this and the policy.
    fn failed_attempts(
        &self,
        user_id: &UserId,
    ) -> impl Future<Output = Result<(u32, Option<Timestamp>), Self::Error>> + Send;

    /// Atomically count one guess before the credential is checked:
    /// `Some(count)` while the account is under its limit, `None` (and no
    /// change) at it. Failures older than the attempt window, and a timed
    /// lockout that has run out, start the count over.
    fn reserve_attempt(
        &self,
        user_id: &UserId,
        policy: &LockoutPolicy,
    ) -> impl Future<Output = Result<Option<u32>, Self::Error>> + Send;

    /// Give a reservation back after the credential verified.
    fn release_attempt(
        &self,
        user_id: &UserId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn reset_failed_attempts(
        &self,
        user_id: &UserId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Required as well; a store without a last-login column answers
    /// `Ok(())`.
    fn record_last_login(
        &self,
        user_id: &UserId,
        at: Timestamp,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
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

    // Plus the suspension verbs and `delete_user`. `delete_user` is
    // required like the rest, with no default body: a backend that
    // cannot erase does not compile, and the service's `delete_user`
    // calls it. See below.
    // `delete_candidates_created_before(before, limit)` is required: it
    // deletes Candidates older than `before` and returns them, for the
    // `purge_expired_candidates` sweep.
}

// The umbrella for production: all three tiers.
pub trait IdentityStore: IdentityAdmin {}
impl<T: IdentityAdmin> IdentityStore for T {}

// Separate, and required rather than defaulted. Only the password-reset
// flow asks for it, and only a store that implements it can call that
// flow.
pub trait IdentityPasswordReset: IdentityLookup {
    // Adds a token unless the user already holds `max_live` live ones
    // (`Ok(false)`); never replaces a live one. A successful
    // `verify_reset_token` deletes all of the user's tokens.
    fn store_reset_token(
        &self,
        user_id: &UserId,
        token_hash: &str,
        expires_at: Timestamp,
        now: Timestamp,
        max_live: usize,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    fn verify_reset_token(
        &self,
        user_id: &UserId,
        token_hash: &str,
        now: Timestamp,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    // Same comparison, but the row stays: the flow checks with this
    // first and spends the token with `verify_reset_token` last.
    fn check_reset_token(
        &self,
        user_id: &UserId,
        token_hash: &str,
        now: Timestamp,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;
}
```

Four properties of that surface shape an implementation.

The futures are native `impl Future`, not `#[async_trait]` boxes. Your
methods are ordinary `async fn` bodies and cost no allocation per call.

The error is an associated `Self::Error`, declared once on
`IdentityLookup` and inherited by the other two tiers. Axess never asks
you to convert into an error type of its own; `sqlx::Error` is a
valid `Self::Error`.

There is no `AttemptRecord`, `LockoutRecord` or `NewUser`. The audit
tier writes a single flat `AuthEvent` through `record_event`, and
failure counting is a pair of numeric verbs rather than a record type.
`record_failed_attempt` returns the count after the increment and stores
the time of the failure; `failed_attempts` reads both back. The library
derives lockout state from that pair and the policy; it is not stored as
its own row and not reported through `account_status`. `create_user` takes a fully-formed `User`, so identifier
generation and defaulting happen in your code, before the call.

Five methods that a store may not support are not on `IdentityAdmin`.
They live on two capability traits with no default bodies,
and the flows that need them are bounded on those traits, so a store that
has not implemented them cannot reach the flow and the omission is a
compile error rather than a panic.

`IdentityPasswordReset` holds `store_reset_token`, `verify_reset_token`
and `check_reset_token`. The reason is a failure mode, not a preference. `begin_password_reset` answers `Ok(None)` for an identifier
it cannot find. When the methods had panicking defaults it reached the
store only for an identifier it could find, so a store that had not
overridden them answered an unauthenticated "forgot password" request with
a 200 for an address that is not registered and a 500 for one that is: a
user-enumeration oracle, in the function that equalises its own timing
specifically to avoid leaking that. (Today the unknown path makes the
same store writes as the found one, against a dummy user, for that
timing.) A silently succeeding default would
have been worse, since recovery would appear to work while no token was
ever stored.

`begin_password_reset` holds a per-identifier cooldown, 60 seconds unless
`AuthnServiceBuilder::with_password_reset_cooldown` sets another window or
`without_password_reset_cooldown` removes it. A second request
for the same tenant and identifier inside the window answers `Ok(None)`, as
an unknown identifier does. The key is the identifier as normalised (NFKC,
lower case, invisible format characters dropped, trimmed), whether or not an
account has it, so two spellings of one address are one request and the
cooldown tells a caller nothing about who is registered. The record is per
process and holds at most 100,000 identifiers, each for the window and no
longer. When that many are live, the oldest cooldown is dropped to make
room for a new identifier, so a caller who mints identifiers cannot refuse
a real user's reset, and can at most cut a cooldown short. Put the route
behind a shared rate limit as well: it bounds identifier minting, and it
holds across several instances, which the per-process record does not.

A completed reset invalidates the user's registered cookie sessions but
not their refresh tokens: a refresh token is a separate credential that
mints a new session. Hand the service the store the application issues
refresh tokens into with `AuthnServiceBuilder::with_refresh_store`.
`complete_password_reset` and the `suspend_user` family then revoke every
refresh token of the user through the store's `revoke_user_tokens`, after
the change itself is made and audited, and return an error if the
revocation fails. Without that store a refresh token stolen before a reset keeps working
after it. A password the application changes by itself (a signed-in
person choosing a new one) goes through neither: call
`RequestAuthnService::invalidate_other_sessions` after the change, which
ends the person's other sessions and revokes the refresh tokens the same
way.

`IdentityPasswordHistory` holds `record_password_hash` and
`password_history`, for a plainer reason. `record_password_hash` is
called on **every** password change with no guard, so a backend that had
not overridden it panicked the first time any user changed their
password, on a method that looked optional, as every defaulted trait
method does.

The reset flow is bounded on both traits together, so a store that offers
`begin_password_reset` implements `IdentityPasswordHistory` as well; a
deployment with no password-reuse policy records the hash and answers an
empty history. A deployment with no password reset at all implements
neither and loses nothing.

### Why three tiers

The split says which verbs a concern needs, so that code can be given
no more than it uses.

The login service is not where the split is taken: `AuthnService`,
its builder and the request-scoped handle are all bounded on
`IdentityStore`, the three tiers together, because one login reads the
user, counts the attempt, writes the audit row and may suspend the
account. A store the service runs on implements all three; serving reads from a
replica and writes to the primary is a routing decision inside that
one implementation.

The split is taken in code of your own that is bounded on a narrower
tier. A function
that renders a profile can take `&impl IdentityLookup` and cannot
suspend anyone, because the method is not in scope; one that records an
event can take `&impl IdentityAuthnLog` and cannot create or delete a
user. The `NoopAuthnLog` adapter serves that same code: it wraps an
`IdentityLookup` and adds no-op `IdentityAuthnLog` verbs, for a caller
bounded on the middle tier that has only a lookup to give. It does not
implement `IdentityAdmin`, so it is not a store `AuthnService` can be
built on.

### What the verbs actually do

The verbs split cleanly across the tiers.

`IdentityLookup` is reads. `get_user` is a primary-key lookup by
`UserId`. `find_user` is a credentials-side lookup by identifier
and tenant: the user typed `alice@example.com`, and the
store says whether that is a real user in this tenant. The other read
verbs are `get_user_tenant` and `get_user_in_tenant` (narrower forms
of `get_user`), the tenant lookups (`get_tenant`, `find_tenant`,
`default_tenant`), `account_status`, and the three per-tenant policy
methods. There is no lookup by email, none by a federated identity
key, and no listing of a tenant's users in the trait: those are
queries of your own.

`IdentityAuthnLog` is the writes the login flow makes as it runs.
`record_event` takes one flat `AuthEvent`, carrying the event type, the
status, the timestamp in epoch microseconds, and whatever attribution
was resolvable: user, tenant, session, factor kind, the client address
as an `IpAddr`, user agent, request id, and the failure reason as an
`AuthFailureReason` rather than free text. It is called throughout the
flow, not only after a factor check, and its argument is the same type
the audit query surface returns.

Give three of those fields a nullable column: the address, user agent
and request id are `None`
on every event unless the request path called
`AuthnService::with_audit_context`. Axess cannot resolve a trustworthy
client address on its own, since that needs your TCP peer and your
trusted-proxy set, so it records nothing rather than something
forgeable. *Cookies, fingerprinting, hijack detection* covers the
wiring.

**What you return decides whether the login succeeds.** `Err` fails the
authentication: an authentication that leaves no evidence has not, for
evidence purposes, happened. Reserve it for a sink that is
broken, and expect logins to fail while yours is. `Ok(Shed)` says you
dropped the event deliberately under load, and the flow continues.

Shed on something independent of the identifier: a global rate, a queue
depth or a disk watermark. A shed decision derived from *which* identifier was
tried is observable per identifier, and rebuilds the user-enumeration
oracle that writing unattributable rejections exists to close.

`record_failed_attempt` increments the user's failure
counter, stores the time of the failure and returns the new count;
`failed_attempts` returns the count and that time;
`reset_failed_attempts` zeroes both on a successful login or an
administrative clear. Lockout keeps no record of its own, and a store does
not have to suspend the account: the library reads `failed_attempts` at
every gate that runs before a verifier (`begin_login`, `prepare_factor`,
`verify_factor`, the passkey login) and applies the tenant's
`LockoutPolicy`. An account whose count has reached `max_attempts` (zero
reads as the default of five) is locked until `duration` after the last
failure, or until an administrator resets the counter when `duration` is
`None`. When the store cannot report the time of the last failure, the account
stays locked; the library does not guess. A password reset still works for a locked
account and clears the counter. A store that reports failures older than
`attempt_window` as zero while the count is below the limit gets the
sliding window for free. At the limit it reports the raw count and time
whatever their age: the window bounds how long failures accumulate, and
the lockout's end comes from `duration`, so an indefinite lockout, or
one longer than the window, is not ended by the window. The sqlite
example's `failed_attempts` and `reserve_attempt` show the condition.

The throttle beside the lock is three more methods, keyed on a
`ThrottleSubject` (tenant, user and, under the default
`ThrottleKey::AccountAndAddress`, the client address) that the library
builds from the request: `throttle_state` reads the consecutive failures
and the time of the last as a `ThrottleState`, `record_throttle_failure`
adds one at the store's current time, atomically, as `record_failed_attempt`
does, and `clear_throttle` forgets the key when a guess is right. None has
a default body: a store that silently reported nothing would leave every
account unthrottled. An entry older than `Throttle::forget_after` (twice
the longest delay) is as good as absent, and a store must not let such
entries grow without bound: the sqlite example sweeps them in
`record_throttle_failure` with one `DELETE` before its upsert, and the
in-memory stores drop them from the map on every record.

`IdentityAdmin` is the privileged writes. `create_tenant` and
`create_user` are the provisioning verbs. `activate_user` moves a user out of
the pending state. The rest of the tier is suspension and deletion.
Password history and reset tokens are not on this tier; they are
capability traits of their own, for the reasons above.

### A suspension says why

`Pending`, `Suspended`, `Terminated` and `Archived` each carry a
`StatusDetail`: a `reason` for display, `since`, an optional `until`, and
a `cause`. The cause is a `StatusCause`, and it says what put the account
in the state:

- `Administrative`: an operator's act, `suspend_user` from a console or
  your own tooling. It ends when an operator ends it, or at `until` when
  the operator set one.
- `Verification`: the account awaits activation, an email or a document
  check. `activate_user` ends it.
- `Lockout`: a store materialises a failed-attempt lockout as a stored
  state. Axess itself never writes this one: its lockout is derived from
  `failed_attempts` at every gate and is never an `EntityState`. The
  variant exists so a store that keeps a lock in its status column can
  say so, and so a reader never has to guess it from `reason`.
- `Closure`: the account is closed; `Terminated` and `Archived` carry it.
- `Other(key)`: your own cause under a short machine key. A row written
  before the field existed reads as `Other("unspecified")`.

Build a detail with the constructor that names its cause:
`StatusDetail::administrative(reason, since)`, `verification`, `lockout`,
`closure` or `other(key, reason, since)`, and `.with_until(Some(t))` for
a timed one. A store that keeps its own status columns writes the cause
beside them so it reads back; the sqlite example keeps a `status_cause`
column.

Two questions an eligibility check asks are methods on `EntityState`, so
nobody keys a decision on the spelling of `reason`:

- `is_administratively_disabled()`: did an operator put this account out
  of service? True for any detail-carrying state whose cause is
  `Administrative`.
- `can_self_recover()`: may the person start a recovery themselves, a
  second-factor reset or a password reset that bypasses the login? True
  for `Active` and for `Suspended` with cause `Lockout`, and for nothing
  else: not an administrative suspension, not a closure, not a pending
  verification, not an unspecified cause. The account a lockout holds is
  exactly who recovery exists for; the account an operator disabled must
  never pass.

Ask them of `effective_at(now)`, so a timed suspension that has ended
answers as the active account it is.

The login error merges states. `AuthnError::Locked` covers both the
counter's lockout, which ends by itself, and a `Suspended` account;
`NotActive` covers every other state. One message serves a login screen, so
the error does not separate them, and it says nothing about the state:
an eligibility decision reads the account's `EntityState` and asks the
two questions above.

## Implementing them

Against SQL, and the two places the contract is easy to get wrong.

### Implementing against SQL

An implementation against a SQL database is verbose but mechanical:
each verb is one query (or one transaction), with indexes on the user
table to keep the reads fast.

A reference implementation against SQLite is in
[`examples/sqlite/`](https://github.com/GnomesOfZurich/axess/tree/main/examples/sqlite).
The shape:

```rust,ignore
struct OurBackend {
    pool: SqlitePool,
}

impl IdentityLookup for OurBackend {
    type Error = BackendError;

    async fn get_user(&self, user_id: &UserId) -> Result<Option<User>, Self::Error> {
        let row = sqlx::query(
            "SELECT id, tenant_id, identifier, display_name, status, status_cause, failed_attempts,
                    locked_until, created_by, created_at, updated_by, updated_at
             FROM users
             WHERE id = ?1",
        )
        .bind(user_id.to_string())
        .fetch_optional(self.pool())
        .await?;

        row.map(|r| user_from_row(self.clock(), &r)).transpose()
    }

    async fn find_user(
        &self,
        identifier: &str,
        tenant_id: &TenantId,
    ) -> Result<Option<User>, Self::Error> {
        let row = sqlx::query(
            "SELECT id, tenant_id, identifier, display_name, status, status_cause, failed_attempts,
                    locked_until, created_by, created_at, updated_by, updated_at
             FROM users
             WHERE tenant_id = ?1 AND identifier = ?2",
        )
        .bind(tenant_id.to_string())
        .bind(identifier)
        .fetch_optional(self.pool())
        .await?;

        row.map(|r| user_from_row(self.clock(), &r)).transpose()
    }
    // ... get_tenant, find_tenant, default_tenant, account_status, and the
    // three tenant policies
}
```

The patterns to note:

The tenant scope is on every query. `find_user` filters by both
identifier and tenant id; the same identifier in a different
tenant is not returned. That discipline enforces cross-tenant
refusal at the storage layer.

The identifier comparison is whatever the deployment chose. The
example treats the identifier as case-sensitive; deployments that
want case-insensitive matching apply `LOWER()` to both sides (and
index on `LOWER(identifier)`).

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

### Implementing the audit writes

`IdentityAuthnLog` needs care: its verbs run on every login attempt, so
a slow implementation slows the whole authentication flow.

There are ten of them, in four groups. `record_event` appends one flat
`AuthEvent` row. `record_failed_attempt`, `failed_attempts`,
`reserve_attempt`, `release_attempt` and `reset_failed_attempts` maintain
a single counter, and the time of its last increment, on the user.
`throttle_state`, `record_throttle_failure` and `clear_throttle` keep the
pre-lockout throttle. `record_last_login` stamps a successful login.

```rust,ignore
{{#include ../../examples/sqlite/src/models/backend/identity.rs:authn_log}}
```

Several properties of that shape matter operationally.

`auth_events` is append-only and flat. Every event lands in that one table,
so no join is needed to reconstruct an attempt; every event carries its own
`event_type`, `event_status` and nullable attribution. Index it on
`(user_id, tenant_id, event_time DESC)` for the "what happened to this
account" query, and on `(tenant_id, event_time DESC)` for the
tenant-wide one.

The failure counter is a column on `users`, not a row count over
`auth_events`. Lockout is derived from that counter and the
`LockoutPolicy`, so there is no lockout table to upsert and no
`clear_lockout` verb: `reset_failed_attempts` is the whole of it. The trait
requires the increment and the read to be one atomic step: the example above does both in one statement (`UPDATE ...
RETURNING failed_attempts`), so two concurrent failures cannot both
read the same count.

The throttle entry is its own small table, keyed on tenant, user and
address (the empty string for the account-only key), because one account
has one counter but as many throttle keys as addresses have guessed at
it. The sqlite example's `login_throttle` migration and
`record_throttle_failure` show the shape: an `INSERT ... ON CONFLICT DO
UPDATE SET failures = failures + 1` so parallel guesses all count, with
the stale-row sweep beside it.

The login flow never reads `auth_events`: the lockout consults the
counter, not the rows. The audit read is the query your SOC and admin
tooling run (`AuditQuery::query_events`); the index on
(user_id, tenant_id, event_time DESC) keeps it from a table
scan.

The query answers an `AuditTrail`: the events it read, and in
`UnreadableRows` how many matching rows it could not read, by
`UnreadableReason` (a session field that names no session, an event
type the release does not know, any other field that does not decode).
Such a row is counted, never dropped in silence and never allowed to
fail the query, and its text is neither returned nor logged. A screen
that shows the trail shows the count when it is not zero.
`testing::store_contract::assert_unreadable_rows_contract` holds your
store to this; the sqlite example runs it.

The append-only `auth_events` table grows. *Audit pipeline* covers its
retention: typically a hot/cold split where recent events
stay in the table and older ones archive to a cold store.

### The NoopAuthnLog adapter

`NoopAuthnLog<L>` wraps an `IdentityLookup` and provides no-op
implementations of the `IdentityAuthnLog` write verbs. It implements
those two tiers and not `IdentityAdmin`, so it satisfies a bound of
`IdentityAuthnLog` in code of your own and cannot be the store of an
`AuthnService`. Tests of an `AuthnService` use `MockIdentityStore`, which
implements every tier.

The case it exists for is a read-only source (a replica, a directory
export) handed to code that is bounded on the middle tier, where the
audit writes go through a different path (an out-of-band log shipper,
a Kafka topic, an external SIEM).

The cost is that the lockout policy does not work under `NoopAuthnLog`. The policy decides from the count
`record_failed_attempt` returns and `failed_attempts` reports; the noop
discards the increment and returns zero for both, so the count never rises
and the threshold is never reached (not even a threshold of one).
Deployments that use `NoopAuthnLog` for the read-replica case must
accept a degraded lockout policy unless they implement an alternative.

The `NoopAuthnLog` docstring carries the same warning: do not use
`NoopAuthnLog` in production without an alternative lockout source.

## Fitting an existing system

Where axess bends to a schema you already run.

### What about workload identities

Workloads have their own identity surface, not the same one
humans use. The `IdentityStore` traits do not cover workloads;
the workload identity resolvers (*Workload identity overview*)
have their own machinery.

The split is deliberate. Humans live in a user table; workloads
live in a workload table (or do not live anywhere durable, when
they are short-lived service-to-service callers). The audit
events for workloads route differently from human events. The
lockout policy does not apply to workloads at all. Unifying the
two would produce a trait with too many jobs.

The same is true for the principal model: the `Principal` enum
has two variants, and their read paths go through two different
stores. The application implements both stores and
the resolver code routes appropriately.

### Schema migration

The identity store is the part of your system most likely to
need migrations over time: a new factor adds a column to the
factor configurations table, a regulatory change requires a new
field on the audit events table, a refactor renames a column.

The migration mechanism is yours, not axess's.
`sqlx::migrate!` is the standard pattern; alternative migration
tools (Diesel migrations, Atlas, custom SQL) work the same way.
Axess does not see the migrations; the implementation only has to
keep satisfying the trait against the new schema.

`examples/sqlite/` is the reference: its `migrations/` directory
holds the SQL files, its `main.rs` runs them at startup, and the
implementation queries the latest schema.

### Fitting into a schema you already have

The trait split lets axess fit into existing applications without a
schema rewrite. The library knows nothing about
the user table; it knows only that there is a trait it can call
to look up users. The application's data model is the source of
truth, and the trait surface is the bridge.

The three tiers and the noop adapter let code of your own fit the
awkward shapes (read replicas, fixtures, split admin) by bounding on
the tier it needs. An `AuthnService` still takes a store that
implements all three.

## Further reading

*Multi-tenancy* covers the per-tenant configuration that the
identity store reads and writes. *Audit events* covers the
`AuthEventType` variants the audit-log verbs emit. *Audit pipeline*
covers the hot/cold retention of the audit events table.
*Migration guide* covers the cross-version migrations that affect
the user table.
