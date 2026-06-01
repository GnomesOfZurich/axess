# Backends: SQLite, Postgres, MySQL, Valkey

Axess ships four first-party session storage backends. The choice
between them is the operational decision the deployment makes when
it picks a database, not a technical decision the application code
needs to revisit. This chapter covers the capability matrix, the
configuration shape per backend, and the operational notes that
have caught real deployments by surprise.

The feature flags are `sqlite`, `postgres`, `mysql`, and `valkey`,
all off by default. Enable the one your deployment uses.

## What the backends actually do

A session storage backend implements the `SessionStore` trait. The
trait is small and on purpose: it offers a key-value-with-TTL
surface plus a handful of session-specific verbs the typical
application needs.

```rust,ignore
#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn load(&self, id: &SessionId) -> Result<Option<SessionRow>, StoreError>;
    async fn save(&self, row: &SessionRow) -> Result<(), StoreError>;
    async fn delete(&self, id: &SessionId) -> Result<(), StoreError>;
    async fn cycle(&self, old: &SessionId, new: &SessionId) -> Result<(), StoreError>;
    async fn cleanup_expired(&self) -> Result<usize, StoreError>;
    async fn find_sessions_for_user(
        &self,
        user_id: &UserId,
        tenant_id: &TenantId,
    ) -> Result<Vec<SessionId>, StoreError>;
}
```

The verbs map to operations the lifecycle in the previous chapter
exercises. `load` retrieves a session by id. `save` writes a
dirty session. `delete` removes a session on logout. `cycle`
atomically rotates the session id (used at the `Guest` to
`Authenticated` transition, and at sensitive step-up points).
`cleanup_expired` removes rows whose expiry has passed.
`find_sessions_for_user` is the verb behind
"log this user out of all sessions" admin operations.

The implementations differ in how they store the rows and how they
implement the verbs, but the surface is the same.

## Capability matrix

| Capability | Memory | SQLite | Postgres | MySQL | Valkey |
|---|---|---|---|---|---|
| Required feature | always-on | `sqlite` | `postgres` | `mysql` | `valkey` |
| Encryption at rest | none | optional (AES-GCM) | optional (AES-GCM) | optional (AES-GCM) | optional (AES-GCM) |
| Cluster-safe | no | with care | yes | yes | yes |
| Native TTL | n/a | manual sweep | manual sweep | manual sweep | yes |
| Session registry support | yes | adopter | adopter | adopter | yes |
| Schema migration | n/a | sqlx-migrate | sqlx-migrate | sqlx-migrate | none needed |

The encryption-at-rest column is the AES-256-GCM envelope from the
previous chapter. The application configures it with a 32-byte
key; the backend wraps the envelope around the serialised session
data before writing. The envelope is optional because some
deployments accept the unencrypted at-rest store (when the database
is itself encrypted, when the threat model does not require it),
and decrypting on every read costs a few microseconds per session.
The recommendation for production is to enable encryption unless
the deployment has a specific reason not to.

The cluster-safe column says whether multiple application instances
can share the same backend without coordination issues. SQLite is
single-writer; a deployment with one application instance behind a
load balancer is fine, but multiple instances need to share the
SQLite file over a filesystem the database supports (which is
operating-system-dependent and risky). Postgres, MySQL, and Valkey
are cluster-safe out of the box.

The native TTL column says whether the database has a native
mechanism for removing expired rows. SQLite, Postgres, and MySQL
do not; the application runs a periodic cleanup task. Valkey
expires keys automatically as they age past their TTL, which means
the cleanup task is unnecessary.

## SQLite

The SQLite backend is right for development, for tests, for
single-instance production deployments, and for embedded-style
applications where the database lives on the same machine as the
application.

Configuration:

```rust,ignore
use axess::backends::sqlite::SessionStore;
use axess::session::SessionCrypto;

let pool = sqlx::SqlitePoolOptions::new()
    .max_connections(5)
    .connect("sqlite:axess.db")
    .await?;

let crypto = SessionCrypto::new(envelope_key);  // optional encryption
let store = SessionStore::new(pool.clone(), crypto);
store.init_schema().await?;
```

`init_schema` creates the `sessions` table and the indexes the
backend needs. It is idempotent; calling it on a database that
already has the table is a no-op.

The cleanup pattern is a background task that runs
`store.cleanup_expired` on an interval, typically once per hour.
The
[`examples/sqlite/`](https://github.com/GnomesOfZurich/axess/tree/main/examples/sqlite)
reference application demonstrates this in `main.rs`.

The operational notes:

- SQLite locks on writes. The `max_connections` setting on the pool
  determines how many concurrent writes the database admits, and
  WAL mode (configured in the connection string) is what enables
  concurrent reads alongside writes. Use WAL mode for any deployment
  that has more than one request at a time.

- The schema migration story is `sqlx::migrate!`: the migrations
  directory under the application is the source of truth, and the
  pool runs them at startup. Axess does not include its own
  migrations; `init_schema` is enough.

- Backups: a SQLite session store can be backed up with the
  standard `sqlite3 .backup` command, which works against a live
  database. The session data is encrypted at rest if the envelope
  is configured, so a backup carries the same security posture as
  the live data.

## Postgres

Postgres is the right backend for most production deployments. It
is cluster-safe, has good concurrency, supports JSONB if a
deployment wants to index into the session's custom map, and is
the most-tested backend in axess after SQLite.

Configuration:

```rust,ignore
use axess::backends::postgres::SessionStore;

let pool = sqlx::PgPoolOptions::new()
    .max_connections(20)
    .connect("postgres://app@db:5432/axess")
    .await?;

let store = SessionStore::new(pool.clone(), SessionCrypto::new(envelope_key));
store.init_schema().await?;
```

The pool sizing depends on the application's request rate; twenty
is a reasonable starting point for a single application instance,
multiplied by the number of instances and tuned against the
database's `max_connections` setting.

The operational notes:

- The `init_schema` call creates the `sessions` table with an
  index on the expiry timestamp (for `cleanup_expired`) and on the
  user id plus tenant id (for `find_sessions_for_user`). The
  indexes are essential at any meaningful scale; do not remove
  them.

- CockroachDB is wire-compatible with Postgres and works against
  this backend with one caveat: Cockroach's lock semantics differ
  in edge cases (a `SELECT ... FOR UPDATE` pattern that works on
  Postgres can produce different behaviour on Cockroach). The
  axess CI runs the Postgres integration suite against Cockroach
  to catch divergence; the failures that have surfaced are noted
  in this chapter when they affect adopter code.

- Postgres extensions: pgcrypto can be used as an alternative to
  the AES-GCM envelope, but the axess envelope is faster (the
  encryption happens in the application before the network write,
  not on the database side) and uses the same key as other axess
  encryption. Stick with the envelope unless a specific deployment
  reason argues for pgcrypto.

## MySQL

The MySQL backend is right for deployments where MySQL is the
already-deployed database. The capability surface is the same as
Postgres, with a handful of dialect differences that affect the
implementation but not the application.

Configuration:

```rust,ignore
use axess::backends::mysql::SessionStore;

let pool = sqlx::MySqlPoolOptions::new()
    .max_connections(20)
    .connect("mysql://app@db:3306/axess")
    .await?;

let store = SessionStore::new(pool.clone(), SessionCrypto::new(envelope_key));
store.init_schema().await?;
```

The operational notes:

- The dialect differences from Postgres are mostly invisible: `ON
  CONFLICT DO UPDATE` becomes `ON DUPLICATE KEY UPDATE`, the
  placeholder syntax shifts from `$1` to `?`, datetime precision
  defaults to seconds rather than microseconds. Axess handles all
  three internally; the application code is identical.

- MariaDB 10.x and later versions are compatible with the same
  schema and the same SQL. The CI runs against both MySQL 8.x and
  MariaDB 10.x.

- Timezone handling differs. MySQL stores `DATETIME` values as
  naive timestamps in the server's timezone; the backend
  serialises expiries as UTC and reads them back as UTC,
  sidestepping the implicit-conversion trap.

- Connection options: pool sizing is the same as Postgres. MySQL
  has a default `wait_timeout` of eight hours, after which idle
  connections are closed; the sqlx pool handles reconnection
  automatically, but be aware of the setting if connection-state
  matters to your application.

## Valkey

The Valkey backend is right for deployments where a Redis-style
key-value store is already present in the architecture, or for
deployments where the session-store load is high enough that the
overhead of a relational database is undesirable. Valkey's TTL
mechanic makes session expiry automatic: the cleanup task is not
needed.

Configuration:

```rust,ignore
use axess::backends::valkey::SessionStore;

let client = redis::Client::open("redis://valkey:6379")?;
let store = SessionStore::new(client, SessionCrypto::new(envelope_key));
```

The Valkey backend does not need a schema initialisation; the keys
are written directly with TTLs.

The operational notes:

- Cluster mode: the Valkey client supports cluster mode through
  the `cluster` feature of the underlying redis crate. The keys
  axess writes are prefixed (`axess:session:`, `axess:registry:`,
  ...) so cluster sharding by key works without conflict.

- Persistence: Valkey can be configured for in-memory only, for
  RDB snapshots, or for AOF (append-only file) durability. The
  axess session store is fine on any of the three; the choice
  trades latency against durability. For sessions specifically,
  in-memory is acceptable if the deployment tolerates losing all
  active sessions on a Valkey restart; AOF is the standard choice
  when sessions matter.

- The session registry: Valkey is the only first-party backend
  with a session registry (the verb behind "list all sessions for
  a user", which the SQL backends require an adopter to wire up).
  The registry uses a sorted set keyed by user id, with the
  session ids as members and the expiry timestamp as the score.
  Operations on the registry are O(log n) in the number of
  sessions per user.

- Eviction policy: Valkey under memory pressure can evict keys.
  If the eviction policy is `allkeys-lru`, the session store can
  lose sessions before their TTL fires. The recommendation is to
  configure Valkey with `volatile-lru` (only TTL'd keys are
  candidates for eviction), and to monitor the eviction rate. If
  evictions happen at all, the Valkey instance is undersized;
  scale up before the user-visible behaviour becomes painful.

## Choosing between them

The decision tree is short.

If the deployment already has a database, use the matching backend.
Postgres for Postgres, MySQL for MySQL, Valkey for Redis or Valkey.

If the deployment is starting fresh and the application is
single-instance, SQLite is the simplest choice and works fine for
small-to-medium scale.

If the deployment is multi-instance and starting fresh, Postgres
is the conservative default. The operational tooling for Postgres
is mature, the backup story is well understood, and the schema
flexibility leaves room for future extensions.

If the deployment expects very high session throughput (tens of
thousands of writes per second, or pathologically high read rates),
Valkey is the choice. The latency is the lowest of the four, the
TTL mechanic removes the cleanup task, and the cluster scaling is
proven.

The choice is not irreversible. The session storage backend is
behind a trait, the data shape is uniform across backends, and
migrating between backends is a matter of reading from the old
store and writing to the new one (during a deploy window where
both are active, or with a one-time migration script that runs
against a paused application). No data shape changes; the
migration is purely operational.

## Cross-backend `Store<K, V>` access

All four backends also implement the generic
`axess_core::store::Store<SessionId, SessionData>` trait. This
matters for adopters who want backend-agnostic access (test
doubles, ops endpoints that work against any deployment, code that
needs to switch backends at runtime).

```rust,ignore
use axess::store::Store;
use std::sync::Arc;

async fn dump_session(
    store: Arc<dyn Store<SessionId, SessionData>>,
    id: &SessionId,
) -> Option<SessionData> {
    store.get(id).await.ok().flatten()
}
```

The generic trait omits session-domain operations (`cycle`,
`find_sessions_for_user`). Code that needs those operations uses
the concrete `SessionStore` trait directly; code that only needs
key-value-with-TTL semantics uses `Store`.

The duplication is deliberate. The generic trait is the common
denominator across backends; the specific trait carries the
session vocabulary. Mixing them lets each callsite use the
narrowest surface it needs.

## Further reading

*Session lifecycle and crypto envelope* covers the full lifecycle
that exercises these backends. *Cookies, fingerprinting, hijack
detection* covers the cookie attributes and the fingerprint
binding the backends store. *Schema migration* covers what happens
when the session data shape changes between deployments.
*Operations runbook* covers signing-key and envelope-key rotation
across all four backends.
