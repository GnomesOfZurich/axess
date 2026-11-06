# Observability and metrics

This page is the contract for what axess reports to an operator: which
signals are metrics, which are events, how the metric traits are cut, how
they are named and labelled, and how one exporter is wired to all of them.
It replaces the single `AuthnMetrics` trait of 0.16.0 with one narrow trait
per concern. No existing page covered metrics as a subject (the operations
runbook lists alerts, the rate-limiting page lists two counters), so this is
a new page; those pages link here for the contract.

## Why the trait is split

`AuthnMetrics` grew a method for every subsystem that wanted a counter. A
new capability then had two bad choices: extend the trait, so that one more
name sits in a 28-method surface that every exporter has to read, or log a
line and leave the operator to grep. Capabilities took the second path: a
CSRF refusal, a duplicate provider registration, a signing-key fallback, a
`sid` map eviction and a fingerprint fallback were all `tracing` lines with
no counter behind them. An operator cannot alert on a log line without
building a second pipeline.

The fix is structural. A counter belongs to a concern, each concern is its
own trait with default no-op methods, and an adopter implements the concerns
it exports. A method added to one concern cannot break, or even be seen by,
an implementor of another.

## The census, at 0.16.0

### Methods of `AuthnMetrics` and where they fire

| Method | New home | Fired from |
|--------|----------|------------|
| `auth_attempt` | `AuthFlowMetrics` | `authn/service/login.rs:47` |
| `auth_success` | `AuthFlowMetrics` | `authn/service/account.rs:432` |
| `auth_failure` | `AuthFlowMetrics` | `login.rs:55,129,163,241,302`, `fido2_service/discoverable.rs:52` |
| `account_locked` | `AuthFlowMetrics` | `login.rs:181`, `account.rs:185`, `factor_pipeline.rs:131,360,400`, `factor_pipeline/reserve.rs:70,90`, `fido2_service/enrolment_gate.rs:60`, `fido2_service/discoverable.rs:162`, `oauth_service/login/complete.rs:206` |
| `factor_attempt` | `FactorMetrics` | `login/local_factor.rs:55`, `ldap_service.rs:77` |
| `factor_success` | `FactorMetrics` | `login/local_factor.rs:123`, `ldap_service.rs:159` |
| `factor_failure` | `FactorMetrics` | `factor_pipeline.rs:335`, `ldap_service.rs:208` |
| `factor_counter_store_outage` | `FactorMetrics` | `factor_pipeline.rs:170,352`, `factor_pipeline/reserve.rs:80`, `factor_pipeline/throttle.rs:96,131` |
| `attempt_throttled` | `FactorMetrics` | `factor_pipeline.rs:140` |
| `recovery_codes_under_previous_pepper` | `FactorMetrics` | `login/local_factor.rs:95` |
| `session_created` | `SessionMetrics` | `session/layer/lifecycle/finalize.rs:85` |
| `session_invalidated` | `SessionMetrics` | `account.rs:147`, `login.rs:610` |
| `session_binding_mismatch` | `SessionMetrics` | `session/layer/lifecycle.rs:353` |
| `rate_limit_allowed` | `RequestGuardMetrics` | `middleware/ratelimit.rs:658` |
| `rate_limit_rejected` | `RequestGuardMetrics` | `middleware/ratelimit.rs:675` |
| `authz_cache_hit`, `_miss`, `_eviction`, `_invalidation` and the four batched forms | `AuthzCacheMetrics` | `authz/cache/entity_cache.rs:328-331` (`flush_metrics`) |
| `authz_policy_reloaded`, `authz_policy_reload_refused` | `AuthzCacheMetrics` | `authz/reload.rs` (`reload_from`) |
| `provider_reloaded(ProviderCategory)`, `provider_removed(ProviderCategory)`, `provider_reload_refused(ProviderCategory)` | `ProviderRegistryMetrics` | `authn/service/provider_reload/install.rs` (`settle`) |
| `fido2_rp_id_changed` | `ProviderRegistryMetrics` | `authn/service/provider_reload/install.rs` (`install_fido2`) |
| `audit_store_outage` | `AuditMetrics` | `authn/service.rs:489` |
| `audit_event_shed` | `AuditMetrics` | `authn/service.rs:478` |

### Log lines that stood in for a metric

| Line | File | What it counts | Now |
|------|------|----------------|-----|
| `csrf: no session id on state-changing request` | `middleware/csrf/presented.rs:28` | CSRF refusal, no session | `csrf_rejected(NoSession)` |
| `csrf: Origin/Referer validation failed` | `middleware/csrf/presented.rs:42` | CSRF refusal, origin | `csrf_rejected(OriginMismatch)` |
| `csrf: request rejected during token extraction` | `middleware/csrf/presented.rs:56` | CSRF refusal, unreadable | `csrf_rejected(TokenUnreadable)` |
| `csrf: token validation failed` | `middleware/csrf/presented.rs:73` | CSRF refusal, bad token | `csrf_rejected(TokenInvalid)` |
| `csrf: WebSocket upgrade refused` | `middleware/csrf.rs:496` | CSRF refusal, upgrade | `csrf_rejected(WebSocketOrigin)` |
| `session: WebSocket upgrade refused` | `session/layer/service.rs:166` | the same refusal, made by the session layer | `csrf_rejected(WebSocketOrigin)` |
| `oauth: replacing existing provider registration` | `federation/oauth.rs:42` | duplicate registration | `provider_duplicate_registration` |
| `session decryption failed with current key; trying previous key` | `session/crypto.rs:343` | rotation fallback | `encryption_key_fallback` |
| `blob opened with the previous (rotated) key` | `session/crypto.rs:585` | rotation fallback | `encryption_key_fallback` |
| `session fingerprint verified with previous (rotated) signing key` | `session/layer/lifecycle.rs:358` | fingerprint fallback | `fingerprint_key_fallback` |
| `binding an authenticated session that stored no fingerprint` | `session/layer/lifecycle.rs:368` | fingerprint backfill | `session_fingerprint_backfilled` |
| `sid_map capacity reached; dropped oldest mapping` | `authn/service/oauth_service/login/complete.rs:369` | capacity eviction | `sid_map_evicted(count)` |

The lines that stay events only, because nothing about them is counted by an
operator: the TTL prune of the `sid` map (routine housekeeping), the stale
re-seal failures of the stores (the store error already surfaces as a
request error), and the configuration warnings at build time such as
`CsrfConfig::secure(false)`.

### Implementors in the tree

| Implementor | File | Notes |
|-------------|------|-------|
| `NoopMetrics` | `axess-core/src/metrics.rs` | now implements every concern |
| the sqlite example newtype handle | `examples/sqlite/src/web/app.rs` | atomic counters behind `/metrics`; the only exporter in the examples (no Prometheus or OpenTelemetry adapter is carried) |
| `FactorCounts` | `axess-core/tests/authn_flow.rs` | test recorder |
| `FailureCount` | `axess-core/tests/fido2_login.rs` | test recorder |
| `BatchMetrics`, `PerEvent` | `axess-core/src/authz/cache/entity_cache/tests.rs` | test recorders |
| `CountingMetrics` | `axess-core/src/session/layer/lifecycle/helper_tests.rs` | test recorder |

Neither known adopter, the platform nor nomos, names `AuthnMetrics` or calls
`with_metrics`: both run with the default no-op sink today. That decides the
migration question below.

## The traits

| Trait | Concern | Fed by |
|-------|---------|--------|
| `AuthFlowMetrics` | logins and lockouts | `AuthnService` |
| `FactorMetrics` | factor verification, throttle, lockout counter store, recovery-code pepper | `AuthnService` |
| `SessionMetrics` | session lifecycle, binding, the `sid` map | `AuthnService`, `SessionLayer` |
| `RotationMetrics` | use of a previous key during a rotation window | `SessionCrypto`, `SessionLayer` |
| `ProviderRegistryMetrics` | duplicate provider registrations; provider reloads, removals and refusals | `AuthnService` |
| `RequestGuardMetrics` | rate limiting and CSRF | `RateLimitLayer`, `CsrfLayer` |
| `AuthzCacheMetrics` | entity-cache hits, misses, evictions; policy reloads and refusals | `EntityCache::flush_metrics`, `AuthzStore::reload_policies` |
| `AuditMetrics` | audit store outage, audit shedding | `AuthnService` |

Every method has a default empty body, and `NoopMetrics` implements every
trait. A type implements the traits of the concerns it exports and nothing
else; it still compiles when a later release adds a method to a concern.

The new signals are these methods:

| Method | Trait | Alert on |
|--------|-------|----------|
| `csrf_rejected(CsrfRefusal)` | `RequestGuardMetrics` | a rise in `token_invalid` after a deploy, any `no_session` (a mis-ordered layer stack) |
| `provider_duplicate_registration` | `ProviderRegistryMetrics` | any count: a provider was silently replaced |
| `encryption_key_fallback` | `RotationMetrics` | rate that does not fall to zero after a rotation: the previous key is still needed |
| `fingerprint_key_fallback` | `RotationMetrics` | same, for the fingerprint signing key |
| `session_fingerprint_backfilled` | `SessionMetrics` | a rate that does not fall after binding was turned on |
| `sid_map_evicted(count)` | `SessionMetrics` | any steady count: the `sid` map capacity is too small |
| `provider_reloaded(category)` | `ProviderRegistryMetrics` | a reload nobody ordered; compare the count across instances after one |
| `provider_removed(category)` | `ProviderRegistryMetrics` | a removal nobody ordered: a tenant lost its IdP |
| `provider_reload_refused(category)` | `ProviderRegistryMetrics` | any count: a provider that does not work was published and the previous one stays in force |
| `fido2_rp_id_changed` | `ProviderRegistryMetrics` | any count: an acknowledged reload changed the relying-party id and the passkeys under the old id stopped verifying |
| `authz_policy_reloaded` | `AuthzCacheMetrics` | a reload nobody ordered; compare the count across instances after one |
| `authz_policy_reload_refused` | `AuthzCacheMetrics` | any count: a bad policy set was published and the previous one stays in force |

The two reload counters live on `AuthzCacheMetrics` and not on a trait of
their own: the trait already is the authorization concern (it is fed by the
same `AuthzStore` that owns the cache the reload invalidates), an exporter
that wants reload counts wants the cache counts beside them, and a ninth
trait would add one `with_*` slot for two methods. `AuthzStore::with_metrics`
takes a `MetricSinks` like every other component and reads only that sink.

`ProviderCategory` is a closed enum (`OAuth`, `Fido2`, `Ldap`) with `as_str()`, the one label the provider counters may carry.

`CsrfRefusal` is a closed enum (`NoSession`, `OriginMismatch`,
`WebSocketOrigin`, `TokenUnreadable`, `TokenInvalid`) with `as_str()`
returning the snake_case label value.

## Metric or event

A **metric** is a numeric aggregation an operator alerts on or graphs: a
count of something that happened, with no per-occurrence detail. An
**event** is one observation with structured fields: a `tracing` line, or an
`AuthEvent` in the audit trail.

The rule:

1. Anything an operator would count gets a metric. If a runbook says "watch
   the log for X" or "alert when X appears more than N times", X is a
   metric. The log line is not removed when it carries fields an operator
   reads while investigating (the issuer of a dropped `sid`, the provider
   name of a duplicate); it is demoted to the event that explains the
   counter.
2. A metric carries no identity. User ids, session ids, IPs and provider
   names do not go on a counter; they go on the event, where they can be
   redacted, sampled and retained under the audit rules.
3. The audit trail is not a metric source. It is complete and durable; a
   counter is lossy and cheap. Both exist for a login failure on purpose.
4. A signal that is configuration, not behaviour (`CsrfConfig::secure(false)`),
   is a build-time event and has no metric.

## Naming

Exporters should use one prefix and one shape, so dashboards written for one
adopter read on another:

- the prefix is `axess_`, then the concern, then what was counted:
  `axess_auth_attempts_total`, `axess_csrf_rejected_total`;
- snake_case throughout, counters end in `_total`, durations in `_seconds`,
  sizes in `_bytes`, anything else is a bare noun;
- a method's name is its metric name: `auth_attempt` becomes
  `axess_auth_attempts_total`, `sid_map_evicted(count)` adds `count` to
  `axess_sid_map_evicted_total`.

The traits do not enforce the names (an exporter owns its registry), and the
sqlite example prints the scheme at `/metrics`.

## Labels

A label multiplies a series by the number of its values, so a label must be a
bounded set the library defines:

- allowed: a closed enum the trait passes (`CsrfRefusal::as_str()`), the
  factor kind (`FactorKind::as_str()`, a closed set) where a method gains it;
- not allowed on a counter: user id, session id, IP address, provider name,
  path, and **tenant** unless the deployment's tenant count is small and
  known. An unbounded tenant label is a cardinality bomb that grows with
  sign-ups, and a hostile caller who can mint tenants controls the size of
  your time-series database. Where tenant breakdown is wanted, emit it from
  the audit pipeline, which is built for unbounded keys;
- a per-method argument is added only when its type is a closed enum.

The traits take `&self` and no context, so an exporter that wants a label
the method does not carry reads it from the surrounding span. That is a
choice the exporter makes knowingly; the library never supplies an
unbounded one.

## Wiring one exporter

`MetricSinks` holds one sink per concern. Every component that reports takes
it through `with_metrics`, and reads only the concerns it feeds.

```rust,ignore
let exporter = Arc::new(Exporter::new());          // implements all eight traits
let sinks = MetricSinks::all(exporter);

let authn = AuthnService::builder(identity, factors)
    .with_metrics(sinks.clone())
    .build();
let sessions = SessionLayer::new(store, key, registry).with_metrics(sinks.clone());
let limits = RateLimitLayer::new(limiter).with_metrics(sinks.clone());
let csrf = CsrfLayer::new(config).with_metrics(sinks.clone());
let crypto = SessionCrypto::new(key).with_metrics(sinks.rotation());
```

An exporter for part of the surface wires part:

```rust,ignore
let sinks = MetricSinks::noop()
    .with_auth_flow(exporter.clone())
    .with_request_guard(exporter);
```

`SessionCrypto` is built before the layers and shared with the stores, so it
takes the rotation sink directly.

`AxessMetrics` is the bound for `MetricSinks::all`: any type that implements
all eight traits has it, with no impl to write.

## Migration: replace, not facade

The old trait is replaced outright, and the 0.16.0 to 0.17.0 migration page
carries the bullet. A one-release facade (an `AuthnMetrics` that forwards to
the new traits) was weighed and rejected:

- A forwarding facade needs `impl<T: AuthnMetrics> AuthFlowMetrics for T`
  and the same for the other seven. Rust's coherence rules then forbid any
  type from implementing a new trait directly while the facade exists, which
  is the opt-in the split is for.
- A facade would keep the monolith callable for a release and invite code
  written against it, which the next release removes again: two migrations
  for one adopter.
- The cost of replacing is a compile error naming the trait, in code that
  has to change anyway. The platform and nomos do not implement the trait;
  the only implementor in the examples is the sqlite example, updated here.

The mapping from old to new is a table on the migration page: change
`impl AuthnMetrics for X` into one `impl` per concern, move each method under
the concern in the table above, and change `.with_metrics(x)` to
`.with_metrics(MetricSinks::all(Arc::new(x)))`.

## Failure modes

- A sink that panics: the call is on the request path, so an exporter must
  not panic or block. The traits are synchronous on purpose: an exporter
  that must do I/O queues the increment.
- A concern wired to nothing: the no-op sink. There is no state in which a
  component lacks a sink, so no call site checks for one.
- Duplicate registrations are reported when the service is built, once per
  duplicate, because the sinks may be attached after the providers. In a
  debug build the build then panics, as the registration itself did before.
