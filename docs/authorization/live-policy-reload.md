# Live policy reload

A running service can replace its Cedar policy text and compiled schema
without a restart. Before this, `PolicyStore` was immutable after
construction: role, group and ownership state were live per request through
the entity provider, but a change to the policies themselves waited for the
next deploy. This page is the design: what holds, the API, the invariants,
how it fails, and what an adopter changes (nothing, unless they call it).

## What you get

- `AuthzStore::reload_policies(policy_text, schema_json)` compiles and
  validates a new policy set and, only if every check passes, makes it the
  set the next decision uses.
- A reload that fails leaves the previous set in force and answers with the
  named error (`PolicyParse`, `SchemaParse`, `PolicyValidation`, or the
  provider's own `validate_schema` error).
- After a successful swap the store drops the entity caches you registered,
  because cached entity sets were built for the retired policies' questions.
- With a coordinator, one reload reaches every instance. A receiving
  instance re-reads the policy from a source you supply; the notice carries
  nothing it applies.

## The swap slot

`AuthzStore` holds the evaluator in an `arc_swap::ArcSwap`. A request takes a
snapshot with `load()` (a wait-free read, no lock, no `.await`), evaluates one
decision against that snapshot, and drops it. A reload builds the new
evaluator off to the side and stores it with one atomic pointer write.

`arc-swap` is chosen over an `RwLock<Arc<..>>` because the request path must
not take a lock: a writer waiting on a read lock stalls every new reader on
some lock implementations, and a policy reload is exactly the moment the
service is under an operator's attention and traffic. `arc-swap` is already
in the dependency tree (`fred` carries it), so this adds a direct dependency
on a crate the `valkey` feature already compiled; it is not a new crate in
the lockfile.

The slot holds an `Arc<dyn PolicyEvaluator>`, so a `MockPolicyEvaluator` in a
test and a `PolicyStore` in production live in the same slot, and
`AuthzStore::try_new` is unchanged.

## The reload entry point

```text
reload_policies(policy_text, schema_json)
  1. take the reload lock            (reloads are serialised, requests are not)
  2. PolicyStore::from_text(..)      parse, schema parse, validate_policies
  3. provider.validate_schema(new)   the provider still fits the new schema
  4. swap the slot                   the only step that changes behaviour
  5. invalidate registered caches    invalidate_all() on each
  6. announce on the coordinator     if one is set
  7. return Reloaded { digest, cache_invalidated, announced }
```

**Invariant: validate before swap.** Steps 2 and 3 complete before step 4.
`PolicyStore::from_text` already runs `validate_policies` in strict mode, and
the provider check is the same `validate_schema` that `try_new` runs at
startup, now run against the schema that is about to be in force. No path
reaches the slot with a set that failed either. A refusal returns before the
swap and the previous set keeps answering.

**The digest.** `Reloaded::digest` is the SHA-256 (hex) of the policy text
and the schema JSON, each length-prefixed. It names exactly what is in force,
appears in the tracing event, and is what instances compare. Two texts that
differ only in whitespace have different digests; that costs a redundant
swap, never a wrong one. `AuthzStore::policy_digest()` returns the digest in
force, or `None` for an evaluator that has none (a mock).

**Steps 5 and 6 after the swap.** A cache that fails to invalidate, or an
announce that fails, does not undo the swap: the new set is valid and in
force. The outcome says so (`cache_invalidated: false`, `announced: false`),
an error event is logged, and the caller decides. The stale entity sets age
out by their TTL; an instance that missed the announce catches up by its poll
(below).

## Caches

`with_cache_invalidator(cache)` registers any `CacheInvalidator` (the
in-process `EntityCache`, `ValkeyEntityCache`, your own). After every
successful swap the store calls `invalidate_all()` on each. `invalidate_all`
is the right scope: a policy change can make any cached entity set stale, and
there is no cheaper correct answer.

A schema change that removes or retypes an attribute is the reason this is
automatic: a cached entity carrying the retired attribute would be evaluated
against a schema that no longer declares it, and the strict request
validation would deny every request that hit it until the TTL ran out. The
invalidation removes the entry; the generation guard in the caches already
stops a load that started before the swap from writing its result back.

## Coordination across instances

```text
instance A                         Valkey                      instance B
reload_policies(..) ok
announce(digest) ------------- PUBLISH {prefix}:authz-policy-reloaded
                                                     -------> notice(digest)
                                                              source.load()
                                                              digest differs?
                                                              apply (no announce)
```

`ReloadCoordinator` is a small trait: `announce(digest)` and `subscribe()`
returning a `tokio::sync::broadcast::Receiver<ReloadNotice>`. Two
implementations ship:

- `InProcessCoordinator`, for tests and for several stores in one process.
- `ValkeyReloadCoordinator`, behind the `valkey-cache` feature (which carries
  `valkey`), publishing and subscribing on `{prefix}:authz-policy-reloaded`,
  a sibling of the `{prefix}:authz-entities-invalidated:{principal}` channel
  the entity cache documents. The subscription is held on its own connection
  and re-subscribes after a reconnect.

`AuthzStore::follow_reloads(source, poll_every)` starts the follower. It needs
a coordinator and a `PolicySource`, a one-method trait you implement to
return the current `PolicyBundle { policy_text, schema_json }` from wherever
your policies live (a file, a database row, an object store).

**A message cannot inject policy.** The notice is a hint to look, nothing
more. The follower ignores the notice's contents, calls `source.load()`, and
applies what the source returns, after the same validation as a local reload.
Anyone who can publish on the channel can cause a re-read of the source, and
no more. The source, not the channel, is the trust boundary; protect it as you
protect the policy files.

**An instance that misses a notice.** Pub/sub is at-most-once. The follower
therefore also re-reads the source every `poll_every` and applies it when its
digest differs from the one in force. `poll_every` is a required argument, not
a default: how long an instance may run on a retired policy is the adopter's
decision, and a zero duration is refused by name (`CoordinationError`). A
lagging broadcast receiver is treated as a missed notice and triggers the
same re-read.

**Convergence.** A source that returns the same bundle to every instance makes
every instance converge to one digest. A source that is itself mid-update can
hand two instances different bundles; they converge at the next poll.

## Failure modes

| Failure | Result |
|---|---|
| Policy text does not parse, or fails strict validation | Reload refused; previous set in force; `PolicyParse` / `PolicyValidation` |
| Schema does not parse | Refused; `SchemaParse` |
| Provider does not fit the new schema | Refused; the provider's `validate_schema` error; previous set in force |
| Source cannot be read by the follower | Event logged, nothing applied; retried at the next notice or poll |
| Source returns a bad bundle to the follower | Refused on that instance only, event logged and counted; previous set in force |
| Cache invalidation fails | Swap stands; `cache_invalidated: false`; entries age out by TTL |
| Announce fails | Swap stands; `announced: false`; peers catch up by poll |
| Notice missed or lagged | Next poll re-reads the source |
| Two reloads at once | Serialised by the reload lock; the later one wins, each fully validated |

**A reload racing a request.** A decision takes one snapshot of the slot at
the moment it evaluates and uses it to the end, so every decision is made
against one complete set: the old or the new, never a mixture. The entity set
a request built before the swap was built for the old policies; it is
evaluated against whichever set the snapshot returns. That is safe because
entities are facts (roles, owners, attributes) and the strict request check
denies an entity that no longer fits the schema; the cache invalidation after
the swap removes such entries for later requests. A request that straddles
the swap may therefore be decided by the old or the new set, and is never
decided by a set that was not valid.

## Observability

- A successful reload emits `tracing::info!` on target
  `axess::authz::reload` with the `digest`, the `previous_digest`, and
  `cache_invalidated` / `announced`. A refusal emits `warn!` with the error
  name; a follower application emits the same with `origin = "notice"` or
  `"poll"`.
- `AuthzCacheMetrics` gains `authz_policy_reloaded()` and
  `authz_policy_reload_refused()`, both no-op by default, wired with
  `AuthzStore::with_metrics(MetricSinks)`, which reads the authorization sink.

## Migration

Nothing changes for an adopter that never calls `reload_policies`: the
constructors, `try_new` and the request path behave as before, and
`AuthzCacheMetrics` gains two defaulted methods. The one new direct dependency is
`arc-swap`, already compiled for `valkey` builds. `PolicyEvaluator` gains a
defaulted `digest()` method.

Reloading authentication providers (OAuth, FIDO2, LDAP) is on its own page,
[live provider reload](../authentication/live-provider-reload.md). It reuses
`ReloadCoordinator` on a channel of its own (`{prefix}:provider-reloaded`), so
a policy notice never wakes a provider follower and the reverse.
