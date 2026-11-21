# Observability and metrics

This page is the contract for what axess reports to an operator: which
signals are metrics, which are events, how the metric traits are cut, how
they are named and labelled, and how one exporter is wired to all of them.
The metrics are cut into one narrow trait per concern. The operations
runbook lists alerts and the rate-limiting page lists two counters; both
link here for the contract.

## Why one trait per concern

One trait for every counter grows a method for every subsystem that wants
one. A new capability then has two bad choices: extend the trait, so that
one more name sits in a surface every exporter has to read, or log a line
and leave the operator to grep. An operator cannot alert on a log line
without building a second pipeline, so a CSRF refusal, a duplicate provider
registration, a signing-key fallback, a `sid` map eviction and a
fingerprint fallback each have a counter beside their `tracing` line.

The cut is structural. A counter belongs to a concern, each concern is its
own trait with default no-op methods, and an adopter implements the concerns
it exports. A method added to one concern cannot break, or even be seen by,
an implementor of another.

## Where each signal fires

Paths are under `axess-core/src/`; `service/` is `authn/service/`. Each
site is named by the function that reports.

### The authentication, session and request counters

| Method | Trait | Fired from |
|--------|-------|------------|
| `auth_attempt` | `AuthFlowMetrics` | `service/login.rs` (`begin_login`) |
| `auth_success` | `AuthFlowMetrics` | `service/account.rs` (`complete_factor_step`) |
| `auth_failure` | `AuthFlowMetrics` | `service/login.rs` (`begin_login`, `find_loginnable_user`, `select_first_factor`, `reject_pre_user`), `service/fido2_service/discoverable.rs` (`refuse_cross_tenant`) |
| `account_locked` | `AuthFlowMetrics` | `service/login.rs` (`find_loginnable_user`), `service/account.rs` (`recheck_status_after_register`), `service/factor_pipeline.rs` (`enforce_account_status`, `record_factor_failure_after`), `service/factor_pipeline/reserve.rs` (`reserve_guess`), `service/fido2_service/enrolment_gate.rs` (`refuse_inactive_account`), `service/fido2_service/discoverable.rs` (`admit_discoverable_login`), `service/oauth_service/login/complete.rs` (`refuse_unless_active`) |
| `factor_attempt` | `FactorMetrics` | `service/login/local_factor.rs` (`verify_local_factor`), `service/ldap_service.rs` (`verify_ldap_factor`) |
| `factor_success` | `FactorMetrics` | `service/login/local_factor.rs` (`verify_local_factor`), `service/ldap_service.rs` (`ldap_bind_succeeded`) |
| `factor_failure` | `FactorMetrics` | `service/factor_pipeline.rs` (`record_factor_failure_after`), `service/ldap_service.rs` (`ldap_unavailable`) |
| `factor_counter_store_outage` | `FactorMetrics` | `service/factor_pipeline.rs` (`derived_lockout`, `record_factor_failure_after`), `service/factor_pipeline/reserve.rs` (`reserve_guess`), `service/factor_pipeline/throttle.rs` (`throttle_for`, `record_throttled_guess`) |
| `attempt_throttled` | `FactorMetrics` | `service/factor_pipeline.rs` (`enforce_account_status`) |
| `recovery_codes_under_previous_pepper` | `FactorMetrics` | `service/login/local_factor.rs` (`verify_local_factor`) |
| `session_created` | `SessionMetrics` | `session/layer/lifecycle/finalize.rs` (`finalize_session`) |
| `session_row_refused` | `SessionMetrics` | `session/layer/lifecycle/load.rs` (`load_stored_session`) |
| `session_invalidated` | `SessionMetrics` | `service/account.rs` (`evict_sessions`), `service/login.rs` (`logout`) |
| `session_binding_mismatch` | `SessionMetrics` | `session/layer/lifecycle.rs` (`check_binding`) |
| `rate_limit_allowed` | `RequestGuardMetrics` | `middleware/ratelimit.rs` (`RateLimitService`'s `call`) |
| `rate_limit_rejected` | `RequestGuardMetrics` | `middleware/ratelimit.rs` (`RateLimitService`'s `call`) |
| `authz_cache_hit`, `_miss`, `_eviction`, `_invalidation` and the four batched forms | `AuthzCacheMetrics` | `authz/cache/entity_cache.rs` (`flush_metrics`) |
| `authz_policy_reloaded`, `authz_policy_reload_refused` | `AuthzCacheMetrics` | `authz/reload.rs` (`reload_from`) |
| `provider_reloaded(ProviderCategory)`, `provider_removed(ProviderCategory)`, `provider_reload_refused(ProviderCategory)` | `ProviderRegistryMetrics` | `authn/service/provider_reload/install.rs` (`settle`) |
| `fido2_rp_id_changed` | `ProviderRegistryMetrics` | `authn/service/provider_reload/install.rs` (`install_fido2`) |
| `audit_store_outage` | `AuditMetrics` | `authn/service.rs` (`emit_audit_at`) |
| `audit_event_shed` | `AuditMetrics` | `authn/service.rs` (`emit_audit_at`) |

### Log lines with a counter beside them

| Line | Logged in | What it counts | Counter |
|------|-----------|----------------|---------|
| `csrf: no session id on state-changing request` (field `route`: the matched route template, `-` when none matched) | `middleware/csrf/presented.rs` (`validate_state_changing`) | CSRF refusal, no session | `csrf_rejected(NoSession)` |
| `csrf: Origin/Referer validation failed` (field `route`: the matched route template, `-` when none matched) | `middleware/csrf/presented.rs` (`validate_state_changing`) | CSRF refusal, origin | `csrf_rejected(OriginMismatch)` |
| `csrf: request rejected during token extraction` | `middleware/csrf/presented.rs` (`validate_state_changing`) | CSRF refusal, unreadable | `csrf_rejected(TokenUnreadable)` |
| `csrf: token validation failed` (field `route`: the matched route template, `-` when none matched) | `middleware/csrf/presented.rs` (`validate_state_changing`) | CSRF refusal, bad token | `csrf_rejected(TokenInvalid)` |
| `csrf: WebSocket upgrade refused` (field `route`: the matched route template, `-` when none matched) | `middleware/csrf.rs` (`CsrfService`'s `call`) | CSRF refusal, upgrade | `csrf_rejected(WebSocketOrigin)` |
| `session: WebSocket upgrade refused` (field `route`: the matched route template, `-` when none matched) | `session/layer/service.rs` (`websocket_admitted`) | the same refusal, made by the session layer | `csrf_rejected(WebSocketOrigin)` |
| `oauth: replacing existing provider registration` | `federation/oauth.rs` (`OAuthRegistrySlot::add`) | duplicate registration | `provider_duplicate_registration`, counted when the service is built (`report_duplicate_providers`) |
| `session decryption failed with current key; trying previous key` | `session/crypto.rs` (`decrypt_with_aad_reporting`) | rotation fallback | `encryption_key_fallback` |
| `blob opened with the previous (rotated) key` | `session/crypto/bound.rs` (`open_subkeyed`) | rotation fallback | `encryption_key_fallback` |
| `session fingerprint verified with previous (rotated) signing key` | `session/layer/lifecycle.rs` (`check_binding`) | fingerprint fallback | `fingerprint_key_fallback` |
| `binding an authenticated session that stored no fingerprint` | `session/layer/lifecycle.rs` (`check_binding`) | fingerprint backfill | `session_fingerprint_backfilled` |
| `sid_map capacity reached; dropped oldest mapping` | `service/oauth_service/login/complete.rs` (`evict_for_capacity`) | capacity eviction | `sid_map_evicted(count)` |
| `a stored session below the current schema version was not served` (`warn`; fields `session`, `version`, `current`) | `session/layer/lifecycle/load.rs` (`load_stored_session`) | a stored row below `SESSION_DATA_VERSION`, refused | `session_row_refused`; alert on any count above zero after the upgrade window: something beside the library writes rows to the session store |

These lines stay events only, because an operator has nothing in them to count: the TTL prune of the `sid` map (routine housekeeping), the stale
re-seal failures of the stores (the store error already surfaces as a
request error), and the configuration warnings at build time such as
`CsrfConfig::secure(false)`.

### Implementors in the tree

| Implementor | File | Notes |
|-------------|------|-------|
| `NoopMetrics` | `axess-core/src/metrics.rs` | implements every concern |
| the sqlite example newtype handle | `examples/sqlite/src/web/app.rs` | atomic counters behind `/metrics`; the only exporter in the examples (no Prometheus or OpenTelemetry adapter is carried) |
| `FactorCounts` | `axess-core/tests/authn_flow.rs` | test recorder |
| `FailureCount` | `axess-core/tests/fido2_login.rs` | test recorder |
| `BatchMetrics`, `PerEvent` | `axess-core/src/authz/cache/entity_cache/tests.rs` | test recorders |
| `CountingMetrics` | `axess-core/src/session/layer/lifecycle/helper_tests.rs` | test recorder |

An adopter that never calls `with_metrics` runs with the default sink,
`MetricSinks::noop()`, and nothing is counted. Counting starts when it
passes sinks of its own (see [Wiring one exporter](#wiring-one-exporter)).

## The traits

| Trait | Concern | Fed by |
|-------|---------|--------|
| `AuthFlowMetrics` | logins and lockouts | `AuthnService` |
| `FactorMetrics` | factor verification, throttle, lockout counter store, recovery-code pepper | `AuthnService` |
| `SessionMetrics` | session lifecycle, binding, the `sid` map | `AuthnService`, `SessionLayer` |
| `RotationMetrics` | use of a previous key during a rotation window; SVID and bundle rotation from a SPIRE agent | `SessionCrypto`, `SessionLayer`, `SpireClient` |
| `ProviderRegistryMetrics` | duplicate provider registrations; provider reloads, removals and refusals | `AuthnService` |
| `RequestGuardMetrics` | rate limiting and CSRF | `RateLimitLayer`, `CsrfLayer` |
| `AuthzCacheMetrics` | entity-cache hits, misses, evictions; policy reloads and refusals | `EntityCache::flush_metrics`, `AuthzStore::reload_policies` |
| `AuditMetrics` | audit store outage, audit shedding | `AuthnService` |
| `DeviceKeyMetrics` | device-key offers, registrations and proofs; request proofs; requests of a bound session that arrived without a proof and ran as a guest; unbound sessions `Require` ended | `DeviceKeyService` (`with_metrics`), and the `SessionLayer` it is given to |

Every method has a default empty body, and `NoopMetrics` implements every
trait. A type implements the traits of the concerns it exports and nothing
else; it still compiles when a later release adds a method to a concern.

These methods, with what to alert on:

| Method | Trait | Alert on |
|--------|-------|----------|
| `csrf_rejected(CsrfRefusal)` | `RequestGuardMetrics` | a rise in `token_invalid` after a deploy, any `no_session` (a mis-ordered layer stack) |
| `provider_duplicate_registration` | `ProviderRegistryMetrics` | any count: a provider was silently replaced |
| `encryption_key_fallback` | `RotationMetrics` | a rate that does not fall to zero after a rotation: the previous key is still needed |
| `fingerprint_key_fallback` | `RotationMetrics` | same, for the fingerprint signing key |
| `session_fingerprint_backfilled` | `SessionMetrics` | a rate that does not fall after binding was turned on |
| `sid_map_evicted(count)` | `SessionMetrics` | any steady count: the `sid` map capacity is too small |
| `session_row_refused` | `SessionMetrics` | any count above zero after the upgrade window: sessions of the earlier release are signed out once at the upgrade, so a row below the current schema version after that was written by something beside the library |
| `back_channel_logout_unmatched` | `SessionMetrics` | a steady rate: logout tokens reach an instance that cannot find the session (instances that do not share a `sid` store), or arrive for sessions that already ended |
| `provider_reloaded(category)` | `ProviderRegistryMetrics` | a reload nobody ordered; compare the count across instances after one |
| `provider_removed(category)` | `ProviderRegistryMetrics` | a removal nobody ordered: a tenant lost its IdP |
| `provider_reload_refused(category)` | `ProviderRegistryMetrics` | any count: a provider that does not work was published and the previous one stays in force |
| `fido2_rp_id_changed` | `ProviderRegistryMetrics` | any count: an acknowledged reload changed the relying-party id and the passkeys under the old id stopped verifying |
| `authz_policy_reloaded` | `AuthzCacheMetrics` | a reload nobody ordered; compare the count across instances after one |
| `authz_policy_reload_refused` | `AuthzCacheMetrics` | any count: a bad policy set was published and the previous one stays in force |
| `workload_credential_rotated(kind)` | `RotationMetrics` | a rate of zero over an SVID's lifetime: the SPIRE agent is not rotating |
| `workload_credential_refresh_failed(kind)` | `RotationMetrics` | a rate that does not fall back to zero: the next expiry will not be met |
| `workload_credential_expired(kind)` | `RotationMetrics` | any count: the workload's SVID ran out with no replacement, a bundle set went stale and its peers are refused, or the SPIRE agent withdrew what it had issued |
| `workload_credential_withdrawal_deferred(kind)` | `RotationMetrics` | any count: the SPIRE agent refused the workload and a source serves what it held under the withdrawal grace |
| `workload_bundle_skipped(kind)` | `RotationMetrics` | any count: a federated trust domain's bundle did not read and its peers cannot be verified |

The two reload counters live on `AuthzCacheMetrics` and not on a trait of
their own: the trait already covers the authorization concern (it is fed by the
same `AuthzStore` that owns the cache the reload invalidates), an exporter
that wants reload counts wants the cache counts beside them, and a tenth
trait would add one `with_*` slot for two methods. `AuthzStore::with_metrics`
takes a `MetricSinks` like every other component and reads only that sink.

The five workload counters live on `RotationMetrics` for the
reason above: they are the rotation of a credential, an exporter that watches
one rotation wants the other beside it, and a tenth trait would add a slot for
five methods. `SpireClientBuilder::with_metrics` takes a `MetricSinks` and
reads only that sink; the SPIFFE ID, the expiry and the error are in the
`axess::workload::spire` event and in the `WorkloadApiEvent` a
`WorkloadApiListener` receives.

`WorkloadCredentialKind` is a closed enum (`X509Svid`, `JwtSvid`,
`X509Bundles`, `JwtBundles`) with `as_str()`, the one label those counters
may carry.

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
- the metric name follows the method name: `auth_attempt` becomes
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
let exporter = Arc::new(Exporter::new());          // implements all nine traits
let sinks = MetricSinks::all(exporter);

let authn = AuthnService::builder(identity, factors)
    .with_metrics(sinks.clone())
    .build();
let sessions = SessionLayer::new(store, key, registry, authn.session_end_audit())
    .with_metrics(sinks.clone());
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
all nine traits has it, with no impl to write. A type that implements the
other eight adds an empty `impl DeviceKeyMetrics for Exporter {}`, or counts
what device keys report.
The device-key counters are `key_offered`, `key_registered`,
`key_registration_refused`, `key_proof_accepted`, `key_proof_challenged`,
`key_proof_refused`, `request_proof_accepted`, `request_proof_refused`,
`unbound_request_proof_refused`, `request_proof_unanswered`,
`bound_session_unproven` and
`unbound_session_ended`. `key_offered` counts once per offer, and an offer
is made once per factor verification. `request_proof_unanswered` counts a
request proof that could not be judged because the device store or the
replay store did not answer; it is counted apart from the refusals.
`DeviceKeyService::with_metrics` gives the key service the sinks, and the key
service also counts what the session layer does with key-bound sessions.

## Failure modes

- A sink that panics: the call is on the request path, so an exporter must
  not panic or block. The traits are synchronous on purpose: an exporter
  that must do I/O queues the increment.
- A concern wired to nothing: the no-op sink. There is no state in which a
  component lacks a sink, so no call site checks for one.
- Duplicate registrations are reported when the service is built, once per
  duplicate, because the sinks may be attached after the providers. In a
  debug build, building the service then panics.
