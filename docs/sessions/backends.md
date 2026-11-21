# Backends: SQLite, Postgres, MySQL, Valkey

Axess ships four first-party session storage backends. Choosing one
follows from the database the deployment runs; your code does
not change with it. This chapter covers the capability matrix, the
configuration of each backend, and its operational notes.

The feature flags are `sqlite`, `postgres`, `mysql`, and `valkey`,
all off by default. Enable the one your deployment uses.
`sqlite-unbundled` is `sqlite` linked to the system's SQLite library
(see [SQLite](#sqlite) below).

## What the backends actually do

A session storage backend implements the `SessionStore` trait. The
trait is small by design: a key-value-with-TTL surface plus a few
session-specific verbs.

```rust,ignore
pub trait SessionStore: Send + Sync + Clone + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    fn load(
        &self,
        key: &SessionKey,
    ) -> impl Future<Output = Result<Option<SessionData>, Self::Error>> + Send;

    fn save(
        &self,
        key: &SessionKey,
        data: &SessionData,
        ttl: Duration,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn delete(
        &self,
        key: &SessionKey,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Replace a session that is still stored; `Ok(false)` when it is gone.
    fn update(
        &self,
        key: &SessionKey,
        data: &SessionData,
        ttl: Duration,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    /// Replace a stored session only while it still carries
    /// `expected_revision`: `Conflict` when another write landed first,
    /// `Gone` when the row no longer exists. One atomic step.
    fn update_if_revision(
        &self,
        key: &SessionKey,
        expected_revision: u64,
        data: &SessionData,
        ttl: Duration,
    ) -> impl Future<Output = Result<ConditionalUpdate, Self::Error>> + Send;

    /// Atomically delete the old row and store the data under the new key.
    /// With `require_old`, a missing old row returns
    /// `CycleOutcome::SessionGone` and writes nothing.
    fn cycle(
        &self,
        old: &SessionKey,
        new: &SessionKey,
        data: &SessionData,
        ttl: Duration,
        require_old: bool,
    ) -> impl Future<Output = Result<CycleOutcome, Self::Error>> + Send;

    /// `cycle`, but only while the old row still holds `expected_revision`;
    /// a write that landed since the caller read it answers
    /// `CycleOutcome::Conflict` and writes nothing. The default reads the row
    /// and then calls `cycle`, which leaves a window open; override it where
    /// the backend can make the comparison part of its own delete.
    fn cycle_if_revision(
        &self,
        old: &SessionKey,
        new: &SessionKey,
        data: &SessionData,
        ttl: Duration,
        require_old: bool,
        expected_revision: u64,
    ) -> impl Future<Output = Result<CycleOutcome, Self::Error>> + Send;

    fn prune_expired(&self) -> impl Future<Output = Result<u64, Self::Error>> + Send;

    /// Required, with no default. A backend that cannot list (its rows are
    /// sealed blobs with the user inside) answers an error, as the SQL and
    /// Valkey stores do; only the memory store lists.
    fn find_sessions_for_user(
        &self,
        user_id: &UserId,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<(SessionKey, SessionData)>, Self::Error>> + Send;
}
```

Five things about that surface shape an implementation.

A session is named by its `SessionKey`, never by the `SessionId` its
cookie carries. The key is the SHA-256 of a fixed tag and the id, 64
lowercase hexadecimal characters as text (`key.to_string()`) and 32 bytes
as `key.as_bytes()`. The layer computes it once from the cookie and no
method of the trait receives the id, so a store cannot hold a value a
cookie could carry: a read of the session table, or of a backup of it,
names sessions and opens none. A store of your own keeps the text form
where it kept the id; a text column must hold 64 characters.

`Clone` is a supertrait. The layer holds the store by value and clones
it per request, so the type must be cheap to clone: a connection pool
or an `Arc<Mutex<HashMap<..>>>` behind the struct, never the data itself.

The error is your associated `Self::Error`, not a type axess defines.

There is no row type. `load` and `save` deal in `SessionData`
directly, and the TTL is a `save` argument rather than a field, because
expiry is the store's to enforce however its backend does it: a column
plus `prune_expired` for SQL, a native key TTL for Valkey.

`cycle` is the session-fixation defence, and its contract is stricter
than it looks. It is a write as well as a move: the data and TTL come
with it, so the rotation is one statement rather than a delete followed
by a save. The caller supplies the new key; the store does not mint
it: a login registers the key the response will carry before the
layer persists the rotation, and the layer moves the registry entry of a
rotated session after it.

What an implementation must hold is narrower than one transaction: the
removal of the old row decides the rotation (when `require_old` is set
and it removed nothing, the call answers `SessionGone` and writes
nothing), so of two racing rotations exactly one wins, and the user never
holds both rows. A backend that can do the removal and the write in one step does so
(one transaction for SQL, one script for Valkey). One that cannot
removes the old row first and writes the new one second, so a failure
between them leaves neither row: the user is signed out, and the layer
fails closed on that anyway. The Valkey store takes that sequenced form
where its script cannot run.

The verbs map to operations the lifecycle in the previous chapter
exercises. `load` retrieves a session by its key. `save` writes a session
that is not stored yet (a fresh guest's first write). A change to a
stored session goes through `update_if_revision`, so two requests that
loaded the same revision cannot both write; the layer merges and tries
again when it loses. Logout does not call `delete`: `AuthSession::clear`
resets the session to a guest's and changes its id, so the old row goes
with the rotation described below. A session the
layer ends by itself (one past an age cap, one the registry no longer
holds) goes through both: an `update_if_revision` that stamps the layer's
claim on the row (`SessionData::ending`), then, once the audit row is
written, the `delete`.

A rotation of the
session id (at every transition of the session's state, logout
included, and at each `AuthSession::regenerate`) goes through one of
two verbs. A session the
request loaded from the store rotates through `cycle_if_revision`, which
removes the old row only while it still holds the revision the request
read, and then writes the new one; on Valkey that is a one-key
compare-and-delete followed by a write. A session that was never stored
(a fresh guest's) rotates through `cycle`, which the shipped stores also
use for a rotation whose TTL is zero. `prune_expired` removes rows whose
expiry has passed.

Ending every session of a user is the registry's job
(`SessionRegistry::invalidate_user`), not `find_sessions_for_user`: the
SQL and Valkey stores answer that method with an error, because their
rows are sealed blobs with the user inside, so it cannot drive a
revocation.

Ending every session but one (the cut-off after a credential change) is
also the registry's job (`SessionRegistry::invalidate_other_sessions`),
in one step: the memory registry takes one lock over the user's set, the
Valkey registry runs one script over the user's keys, which share a slot
(so it runs on a cluster as on a single node), and a registry of your own
does the same in a transaction or a script. A listing followed by one
removal per session would let a session that registers in between
outlive the step.

### What a registry must do

A registry implements every method of `SessionRegistry` except
`watch_revocation`; no other method has a default. Besides registering, checking,
listing and ending sessions, two methods carry a rotation:

- `SessionRegistry::move_session` moves a session from its key to a new
  one in one step of the registry, under the lock or the script that
  guards the user's entries. When the old key is live, the new key takes
  its place with the old key's registration time (so the oldest-first
  order the session limit evicts by does not move), the old key goes,
  and the registry keeps a record that the session under the old key is
  under the new one now (`MoveOutcome::Moved`). When the old key is not
  live (never registered, revoked, lapsed), nothing changes, the new key
  included (`MoveOutcome::OldGone`): a revoked session is not brought
  back by moving it. A registration of the new key followed by a removal
  of the old one is not enough: between the two the registry holds both,
  and a cut-off or a revocation that lands there misses one of them.
- `SessionRegistry::current_key` answers the key a session is under now
  for a key it held before, or `None`, by reading the records. A record's
  target is always the session's present key: a move re-points every
  record that led to the key it moves, so resolving a former key is one
  hop. A record never makes a key valid: `is_valid` reads only the
  entries.

Two methods follow the records:

- `SessionRegistry::invalidate_session` ends the session the key names,
  or the one a move took it to, and removes the records that led to it.
  So an ending by a key the session held before a rotation (the session
  limit's eviction from a list read a moment earlier, a provider's
  logout by the key it knows) ends the session.
- `SessionRegistry::invalidate_other_sessions` answers a `CutOff`. When
  the key to keep is live, every other session ends
  (`CutOff::KeptOne`). When it was moved to another key before the step
  ran, another request carrying the same cookie rotated the session, and
  nothing tells a second tab from a copy of the cookie: every session of
  the user ends, that one included (`CutOff::KeptNone`), and the person
  signs in again with the new credential. Otherwise nothing ends
  (`CutOff::NotHeld`).

A record lives as long as the entry it leads to, inside a bound per
user: `MAX_MOVE_RECORDS_PER_USER`, 1024. The bound keeps the work of
every registry step that reads a user's records bounded, whatever a
session does. At the bound a move drops the oldest record that is not the first
former key of its session. It never drops the first one: that is the
key the session was registered under, the key the sid store and a
provider's logout know it by. So no session is ended for
rotating often, the first former key finds the session for as long as it
lives, and a key read a moment ago finds it too. `MoveOutcome::Full` comes
only when the user holds that many live sessions that each moved, and
then the move changes nothing.

`testing::registry_contract::assert_registry_contract` holds a registry
of your own to all of this; run it against a fresh registry.

The implementations differ in how they store the rows and how they
implement the verbs, but the surface is the same.

## Capability matrix

| Capability | Memory | SQLite | Postgres | MySQL | Valkey |
|---|---|---|---|---|---|
| Required feature | `memory` | `sqlite` or `sqlite-unbundled` | `postgres` | `mysql` | `valkey` |
| Encryption at rest | none | on, opt-out (AES-GCM) | on, opt-out (AES-GCM) | on, opt-out (AES-GCM) | on, opt-out (AES-GCM) |
| Cluster-safe | no | with care | yes | yes | yes |
| Native TTL | n/a | manual sweep | manual sweep | manual sweep | yes |
| Session registry support | yes | adopter | adopter | adopter | yes |
| Schema migration | n/a | `init_schema`, plus the `ALTER TABLE` each store's docs name for a table an earlier release made | same | same | none needed |

The encryption-at-rest column is the AES-256-GCM envelope from the
previous chapter. The application configures it with a 32-byte
key; the backend wraps the envelope around the serialised session
data before writing. Each store's `new` takes the key (the SQL stores as a
`SessionCrypto`), and only the
`plaintext_insecure` constructor builds a store without the envelope,
because some deployments accept the unencrypted at-rest store (when
the database is itself encrypted, when the threat model does not
require it), and decrypting on every read costs a few microseconds per
session. Keep encryption on in production unless the deployment has a
specific reason not to.

The cluster-safe column says whether multiple application instances
can share the same backend without coordination issues. SQLite is
single-writer; a deployment with one application instance behind a
load balancer is fine, but multiple instances need to share the
SQLite file over a filesystem the database supports (which is
operating-system-dependent and risky). Postgres, MySQL, and Valkey
are cluster-safe out of the box.

The native TTL column says whether the database has a native
mechanism for removing expired rows. SQLite, Postgres, and MySQL
do not, so a periodic cleanup task runs: each SQL store has
`spawn_cleanup_task(interval)`, which you call once at start. Valkey
expires keys automatically as they age past their TTL, so no cleanup
task is needed.

## The backends

What each one is good at, and what it costs you.

### SQLite

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

let crypto = SessionCrypto::new(envelope_key);
let store = SessionStore::new(pool.clone(), crypto);
store.init_schema().await?;
```

`new` takes the crypto: a store without encryption is the other
constructor, `SessionStore::plaintext_insecure(pool)`.

`init_schema` creates the `sessions` table and the indexes the
backend needs. It is idempotent; calling it on a database that
already has the table is a no-op.

The cleanup pattern is a background task that runs
`store.cleanup_expired` on an interval, typically once per hour:
`store.spawn_cleanup_task(interval)` spawns it for you. The
[`examples/sqlite/`](https://github.com/GnomesOfZurich/axess/tree/main/examples/sqlite)
reference application writes the loop out in `main.rs`.

The operational notes:

- SQLite locks on writes. The `max_connections` setting on the pool
  determines how many concurrent writes the database admits, and
  WAL mode (configured in the connection string) is what enables
  concurrent reads alongside writes. Use WAL mode for any deployment
  that has more than one request at a time.

- Axess ships no migrations. `init_schema` creates the table when it
  is absent and leaves an existing one as it is, so a table an earlier
  release created needs the `ALTER TABLE` the store's module docs name
  (the binary `data_bin` column), run once before the new code serves a
  request. Your own `sqlx::migrate!` directory is the place for it.

- Backups: a SQLite session store can be backed up with the
  standard `sqlite3 .backup` command, which works against a live
  database. The session data is encrypted at rest if the envelope
  is configured, so a backup carries the same security posture as
  the live data.

- Which SQLite is linked: the `sqlite` feature compiles the SQLite
  source that sqlx bundles into the binary, so the library is updated
  by a release of sqlx. The `sqlite-unbundled` feature enables the same
  stores and links the SQLite library installed on the system, so the
  library is patched with the system. Enable it in place of `sqlite`;
  with both on, the bundled source is compiled. The build then needs the system SQLite's header beside its library
  (`libsqlite3-dev` on Debian and Ubuntu, or the paths in
  `SQLITE3_INCLUDE_DIR` and `SQLITE3_LIB_DIR`) and libclang
  (`libclang-dev`), which generates the bindings; a build with
  `--all-features` switches the feature on and needs libclang too. The
  feature turns on sqlx's `sqlite-unbundled` and nothing else: sqlx's
  `sqlite-unlock-notify`, which makes a connection wait out a table
  lock another connection of a shared-cache database holds
  (`sqlite::memory:` is one), is yours to add to your own `sqlx`
  dependency when the system library is built with it.

### Postgres

Postgres is the right backend for most production deployments. It
is cluster-safe, has good concurrency, and is the most-tested backend
in axess after SQLite. The session is stored as one sealed binary
blob, so nothing inside it (the custom map included) can be indexed
or queried from SQL.

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

Size the pool to your request rate. Twenty is a reasonable start for
one application instance; multiply by the number of instances and keep
the total within the database's `max_connections` setting.

The operational notes:

- The `init_schema` call creates the `sessions` table with an
  index on the expiry timestamp (for `cleanup_expired`). The index
  is essential at any meaningful scale; do not remove it. There is
  no user or tenant column to index: the row is the session's key, the
  sealed blob and the expiry.

- CockroachDB is wire-compatible with Postgres and works against
  this backend with one caveat: Cockroach's lock semantics differ
  in edge cases (a `SELECT ... FOR UPDATE` pattern that works on
  Postgres can produce different behaviour on Cockroach). The
  axess CI runs the Postgres integration suite against Cockroach
  to catch divergence; the failures that have surfaced are noted
  in this chapter when they affect adopter code.

- Postgres extensions: pgcrypto can be used as an alternative to
  the AES-GCM envelope, but the axess envelope is faster (the
  encryption happens in your process before the network write,
  not on the database side) and uses the same key as other axess
  encryption. Stick with the envelope unless a specific deployment
  reason argues for pgcrypto.

### MySQL

The MySQL backend is right for deployments where MySQL is the
already-deployed database. The capability surface is the same as
Postgres, with a handful of dialect differences that affect the
implementation but not your code.

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
  placeholder syntax shifts from `$1` to `?`, and the binary column
  is a `LONGBLOB`. Axess handles them internally; your code is
  identical.

- MariaDB 10.x and later are meant to work with the same schema and
  the same SQL, but CI runs the live session and device suites
  against MySQL 8 only, so MariaDB is untested.

- A MySQL 8 account uses `caching_sha2_password` by default, and
  sqlx can sign in with it only over TLS or with its `mysql-rsa`
  feature. Without either, the pool fails to connect with "RSA auth
  backend disabled". The pool is yours, so the choice is in your own
  `sqlx` dependency: enable a TLS feature such as
  `tls-rustls-aws-lc-rs` and connect with TLS required, or enable
  `mysql-rsa`. Axess enables neither.

- There is no timezone to handle. The expiry is a `BIGINT` of Unix
  seconds, as in the other SQL stores, not a `DATETIME`, so the
  server's timezone never enters into it.

- Connection options: pool sizing is the same as Postgres. MySQL
  has a default `wait_timeout` of eight hours, after which idle
  connections are closed; the sqlx pool handles reconnection
  automatically, but mind the setting if connection state
  matters to your application.

### Valkey

The Valkey backend is right for deployments where a Redis-style
key-value store is already present in the architecture, or for
deployments where the session-store load is high enough that the
overhead of a relational database is undesirable. Valkey's TTL
mechanic makes session expiry automatic: the cleanup task is not
needed.

Configuration:

```rust,ignore
use axess::backends::valkey::{SessionRegistry, SessionStore};
use fred::prelude::*;
use std::time::Duration;

// The client is `fred`'s, not the `redis` crate's.
let client = Client::new(Config::from_url("redis://valkey:6379")?, None, None, None);
client.init().await?;

// The key is the AES-256-GCM envelope key: encryption at rest is on,
// not opt-in. `with_prefix` overrides the default `axess` namespace,
// which is how one Valkey serves several deployments.
let store = SessionStore::new(client.clone(), envelope_key).with_prefix("axess");

// The registry has a prefix of its own, which `with_prefix` on the
// store does not change. `SessionRegistry::new(client).await?` takes
// `axess` and 24 hours; `with_options` names both. Either one checks, on
// the connected client, that the prefix keeps one user's keys in one
// cluster slot and that the server runs the registry's scripts, and
// refuses to start otherwise.
let registry =
    SessionRegistry::with_options(client, "axess", Duration::from_secs(24 * 60 * 60)).await?;
```

The Valkey backend does not need a schema initialisation; the keys
are written directly with TTLs.

The operational notes:

- Cluster mode: a clustered `fred` client needs no feature beyond the
  ones axess already asks for (`i-cluster` only adds the cluster
  administration commands, which axess does not call). The session
  store writes one kind of key and the registry four, each prefixed and
  typed: `axess:sess:<key>` for a session (the 64 hexadecimal
  characters of its `SessionKey`, never the id a cookie carries), and
  four registry keys of one user, where the braces are literal: the
  user id is the keys' hash tag. `axess:reg:{<user>}` and
  `axess:reg-at:{<user>}` are the two sorted sets of the user's
  sessions; `axess:fwd:{<user>}` is a hash of the records of their
  moves (a former key to the key the session is under now), and
  `axess:fwd-at:{<user>}` a sorted set of the same former keys, scored
  by the order the moves were made. Every member, field and value is a
  session's key, never a value a cookie carries. The
  two `revoked-*` names, `axess:revoked-session:<key>` (the 64
  characters of the session's key) and `axess:revoked-user:<user>`, are
  not keys: they are the pub/sub
  channels the registry publishes revocations on, and a channel takes
  no slot.

  The rotation of a stored session is the same on every deployment, a
  single node and a cluster alike: a one-key compare-and-delete of the
  old key, followed by the write of the new one, with no `warn` line.

  Only a rotation of a session the request did not load from the store
  goes through `SessionStore::cycle` and its two-key script: a login or
  a signup begun on a fresh guest (or any other change of id on one), a
  request whose fingerprint binding did not match and was reset to a
  fresh id, or a direct call. With the default prefix the two keys of
  such a rotation rarely hash to the same slot. The store reads the two
  slots before it sends anything, and on a cluster where they differ it
  sends no script: the call takes its sequenced form (the old key is
  deleted, then the new one is written). A server that refuses scripting
  (`NOSCRIPT`, an ACL without `@scripting`) puts `cycle` in the same
  sequenced form, and nothing else falls back: every write and every rotation of a
  stored session is a one-key script with no other form, so on a server
  without scripting those fail with an error rather than fall back to a
  weaker compare. A
  rotation whose TTL is zero is forwarded to `cycle` as well, where it
  runs no script: it removes the two keys with one delete each.

  On such a cluster the sequenced form is the steady state, so it does
  not log a line per call: the store warns once, on its first sequenced
  rotation, naming the hash tag that restores the script, and every
  later one is a `debug` line (target `axess::session::valkey`). A hash
  tag in the store's prefix, `SessionStore::with_prefix("{axess}")`,
  puts every session key in one slot and the rotation script runs as one
  step again. Under a hash tag the rotation of a stored session is
  still a compare-and-delete followed by a write, not one step.

  The registry needs no hash tag in its prefix. Every key of one user
  carries the user id as its hash tag, so the four keys of a user share
  a slot under the default prefix, and the registry's scripts (the move
  of a session to a new key, the ending of a session by a key it held,
  the cut-off of a user's other sessions and the cleanup of registration
  times whose session left the registry) each run as one script on any
  cluster. The registry has no sequenced form. A prefix that closes a tag of its own,
  `SessionRegistry::with_options(client, "{axess}", ttl)`, still works
  and puts every user's keys in that tag's one slot, on one node. A
  prefix that opens a brace it does not close (`a{b`) would put one
  user's keys in two slots: `ValkeySessionRegistry::with_options` refuses it
  with `ValkeyStoreError::Unsupported`, and every call of a registry
  under it fails the same way and sends nothing.

  The registry is built only on a server that runs scripts.
  `ValkeySessionRegistry::new` and `ValkeySessionRegistry::with_options`
  send a script that reads and writes nothing over a user's keys and answer
  `ValkeyStoreError::ScriptsRefused` when the server refuses it (an ACL
  without `@scripting`, scripting disabled), so a deployment learns it
  at start and not at the first rotation of a signed-in session or the
  first cut-off of a user's other sessions.
  The client must be connected first (`client.init().await?`). The
  registry's health check sends the same script, so a server that
  answers a `PING` but refuses scripts is reported unhealthy. A server
  that stops running scripts after the registry was built gets no
  other form either: the move of a session answers
  `ValkeyStoreError::Unsupported` and changes nothing, the cut-off
  answers it and ends nothing, and the cleanup of registration times is
  skipped with a `warn` line (a registration time without a session
  costs memory until its key expires, and decides nothing). An ending by
  key is a revocation, and one that failed would leave a session signed
  in, so it runs as separate commands there, with a `warn` line: the
  session is ended, and the records that led to it stay until the user's
  keys expire, never followed, since their target is gone. A deployment
  whose registry server refuses scripts must allow them (`+@scripting`)
  before it upgrades: the registry needs them for every rotation of a
  signed-in session.

  The keys an earlier release wrote for the registry,
  `axess:reg:<user>` and `axess:reg-at:<user>` without braces, are
  never read or written again and expire with their own TTL, one
  registry lifetime after the last node of that release touched them.

  The store's and the registry's live tests run against a single node
  (`VALKEY_URL`) and against a three-node cluster
  (`VALKEY_CLUSTER_URL`), with and without a hash tag.

  `ValkeyDeviceStore` has no sequenced form: every write of a device is
  one script over several keys, so on a cluster its prefix must hold a
  hash tag. `ValkeyDeviceStore::with_prefix` refuses a prefix without one
  there (`try_with_prefix` returns
  `ValkeyDeviceStoreError::PrefixWithoutHashTag`), and a store left on the
  default prefix refuses its writes with the same error and reports it as
  the reason it is unhealthy, so a health check at start shows it before
  the first device write does.

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
  The registry keeps two sorted sets per user, with the sessions'
  keys as members (64 hexadecimal characters each, never a value a
  cookie carries): one scored by when the session was last seen, from
  which an entry's expiry follows, and one by when it was first
  registered; and the records of the sessions' moves, which expire
  with the sets. Operations on the registry are O(log n) in the number
  of sessions per user, and a move or a cut-off reads the user's
  records, at most `MAX_MOVE_RECORDS_PER_USER` of them.

- Eviction policy: Valkey under memory pressure can evict keys.
  Every key the session store and the registry write carries a TTL,
  so under `allkeys-lru` and under `volatile-lru` alike the session
  store can lose sessions before their TTL fires. The recommendation
  is to configure Valkey with `maxmemory-policy noeviction`, and to
  monitor memory use. If the instance reaches its memory limit, it is
  undersized; scale it up.

## Choosing between them

If the deployment already has a database, use the matching backend.
Postgres for Postgres, MySQL for MySQL, Valkey for Redis or Valkey.

If the deployment is starting fresh and your service is
single-instance, SQLite is the simplest choice and works fine for
small-to-medium scale.

If the deployment is multi-instance and starting fresh, Postgres
is the conservative default. Its operational tooling is mature and its backup practice well
understood.

If the deployment expects very high session throughput (tens of
thousands of writes per second, or very high read rates), choose
Valkey: its latency is the lowest of the four, its TTL removes the
cleanup task, and it scales out as a cluster.

The choice is reversible. The backend sits behind a trait and the
data shape is the same in every backend. A migration does need a way
to list the old store's rows, and neither store
trait has one, so a copy reads the old backend's own table or keys
(a one-time script against a paused application). The simpler
migration is none: point the application at the new store and let
users sign in again.

## Cross-backend `Store<K, V>` access

All four backends also implement the generic
`axess_core::store::Store<SessionKey, SessionData>` trait. This
matters for adopters who want backend-agnostic access (test
doubles, ops endpoints that work against any deployment). The trait
is generic-only: it has an associated error type and returns `impl
Future`, so it cannot be a `dyn Store`, and code that picks a backend
at run time wraps the choices in an enum of its own.

`Store` is one of the few things the facade does not re-export, so this
needs a direct `axess-core` dependency alongside `axess`:

```rust,ignore
use axess_core::store::Store;

async fn dump_session<S: Store<SessionKey, SessionData>>(
    store: &S,
    key: &SessionKey,
) -> Option<SessionData> {
    store.get(key).await.ok().flatten()
}
```

The generic trait omits session-domain operations (`cycle`,
`find_sessions_for_user`). Code that needs those operations uses
the concrete `SessionStore` trait directly; code that only needs
key-value-with-TTL semantics uses `Store`.

The duplication is deliberate. The generic trait is the common
denominator across backends; the specific trait carries the
session vocabulary. Having both lets each call site use the
narrowest surface it needs.

## Further reading

*Session lifecycle and crypto envelope* covers the full lifecycle
that exercises these backends. *Cookies, fingerprinting, hijack
detection* covers the cookie attributes and the fingerprint
binding the backends store. *Schema migration* covers what happens
when the session data shape changes between deployments.
*Operations runbook* covers signing-key and envelope-key rotation
across all four backends.
