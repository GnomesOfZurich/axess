# Operations runbook

For whoever carries the pager. Read the pre-launch checklist before
launch; the rest is reference for when something is wrong at three in
the morning.

The first half of this chapter is operational guidance specific to
axess. The second half is the canonical
[`OPERATIONS.md`](https://github.com/GnomesOfZurich/axess/blob/main/OPERATIONS.md)
from the repo root, included so the runbook is in one place.

## Pre-launch checklist

The list below is the minimum a deployment should clear before serving
real traffic. Other chapters cover each item in detail; this list is the
inventory.

The session signing key is loaded from the deployment's secrets
manager. The key is 32 bytes of cryptographic randomness, stable
across process restarts. It replaces the per-start random key from
*Getting started*.

The session envelope key is loaded the same way. The two keys
are independent: one HMAC-signs the cookie, the other encrypts the
session payload at rest with AES-256-GCM.
*Session lifecycle and crypto envelope* covers the distinction.

The device fingerprint pepper is loaded for the device layer. Each
tenant has its own, returned by the `TenantPepperResolver` the
application supplies (axess stores none, and the tenant record has no
field for it); *Device identity* covers the mechanism. The session's
own fingerprint binding has no pepper: it is keyed from the signing
key.

The session cookie has `Secure=true` set. TLS terminates at the
edge, your service sees only HTTPS traffic, and the cookie is
sent only over HTTPS. The CSRF cookie is `Secure` too (the default of
`CsrfConfig`, which only local development turns off).

The CSRF signing key is persistent and stable across restarts and
instances, and is not the session key used raw. Derive it from the
session layer with `SessionLayer::derive_subkey`, or load a separate
key from the secrets manager. `CsrfConfig::require_origin` names the
deployment's public origins, so a state-changing request from another
origin is refused even before the token is checked.

A session registry is wired with `AuthnServiceBuilder::with_registry`
(Valkey for more than one instance), so a password reset or an admin
action can revoke live sessions, and the same registry is the third
argument of `SessionLayer::new`, so the revocation reaches the stored row
on every route. Without a registry those calls have nothing to revoke and
sessions stay valid until they expire (`SessionLayer::without_registry_insecure`
builds a layer that way and logs an error).

The fourth argument of `SessionLayer::new` is the service's
`session_end_audit()`, so each session the layer ends by itself (an age
cap, a registry entry gone, a rotation that could not be kept) has its
audit row, written before the session is removed. A layer built with
`UnrecordedSessionEnds::insecure()` records none of them and logs an error
saying so.

The trusted-proxy list is configured. The application reads the
forwarded header (`X-Forwarded-For` or `Forwarded`) only when
the immediate peer is in the trusted list. Without this, the
fingerprint and the rate-limit keys can be spoofed.

The rate limit is configured on the login, signup, password-reset,
and any other authentication-adjacent endpoints. The defaults
from *Rate limiting* are starting points; calibrate to the
deployment's legitimate-traffic envelope.

The lockout policy is configured (or the system default is
accepted). The three levers (per-user, per-tenant, per-IP) all
have explicit thresholds suited to the deployment's risk
posture. *Multi-tenancy* §"Three-lever lockout" covers the
configuration.

The audit pipeline is wired. The regulatory sink is the
`IdentityAuthnLog` the lockout policy already uses; the
analytics sink (if configured) is the deployment's SIEM
connector. The retention loop is configured with the
deployment's required retention period. *Audit pipeline* covers
the full pipeline configuration.

The health check is wired. `/healthz` (or whatever the
deployment chooses) queries the session store, the identity
store, and the device store. The public answer is the aggregate
(healthy or unhealthy) only; per-component detail and backend error
text go to the log or to an internal-only listener, because they can
carry connection strings and host names. The canonical `OPERATIONS.md` below covers the
deployment expectations.

The metrics are exported. The metric traits of the concerns you
export (see [Observability and metrics](observability.md)) are
implemented and wired with `MetricSinks`; the metric values flow into Prometheus or
OpenTelemetry; the dashboards cover the auth-attempt rate, the
failure rate, the rate-limit rejection rate, and the lockout
trigger rate. *Health checks and metrics* below covers the
production-dashboard expectations.

The Cedar policy set is loaded and validated against the
schema. Startup stops if the validation fails, so a misconfigured policy
set never serves traffic. *Cedar policy fundamentals* covers the validation
flow.

The cleanup tasks are scheduled. The session cleanup, the device
retention sweep, the audit retention loop and the OAuth JWKS cache
refresh run on intervals, and the application schedules them. *Backends* §"SQLite" and similar
sections cover the per-backend cleanup patterns.

## Key rotation

The deployment has four secrets to rotate on a schedule: the
session signing key, the session envelope key, the CSRF key and the
per-tenant fingerprint pepper. The signing key and the envelope key rotate the same way: provide
the new key alongside the old one for a transition window, let
in-flight sessions and devices roll over, then remove the old key.
The CSRF key and the pepper have no previous-key fallback; their
sections below say what a rotation costs.

### Session signing key

The signing key HMAC-protects the session cookie. Rotating it
without invalidating sessions means keeping the old key available
for verification during the transition.

```rust,ignore
let session_layer = SessionLayer::new(store, new_signing_key, registry, authn.session_end_audit())
    .with_previous_signing_key(old_signing_key)
    .with_ttl(session_ttl);
```

`with_previous_signing_key` accepts the old key. Cookies signed with the
old key continue to validate; new cookies sign with the new key.
Once every old cookie has expired (one session TTL plus a safety
margin), remove the previous key: drop the call,
or call `remove_previous_signing_key` on the freshly built layer.

The rotation sequence:

1. Deploy with `new_signing_key = old_key` and
   `previous_key = old_key`. Nothing has changed; this is the
   baseline.
2. Generate a fresh 32-byte signing key. Store it in the secrets
   manager alongside the existing one.
3. Deploy with `new_signing_key = fresh_key` and
   `previous_key = old_key`. New cookies sign with the fresh
   key; existing cookies continue to validate against the old.
4. Wait one session TTL. By the end of this window, every
   existing session has either expired or been refreshed (which
   re-signs the cookie with the fresh key).
5. Deploy without `with_previous_signing_key`.
   The old key is now unused.
6. Remove the old key from the secrets manager.

### Session envelope key

The envelope key protects the session payload at rest with
AES-256-GCM. Its rotation works like the signing-key rotation:
sessions stored before the rotation stay readable, and new writes
use the new key.

```rust,ignore
let crypto = SessionCrypto::new(new_envelope_key)
    .with_previous_key(old_envelope_key);
let store = SessionStore::new(pool, crypto);
```

The rotation sequence is the same as the signing key. The
transition window covers one session TTL. A store re-seals a session
under the new key when it reads it and on its next write, so after
that window every stored session has been re-sealed or has expired.

With a long session TTL (a week or a month), a rotation on the
compliance cycle (quarterly, semiannually) still needs a transition
window of at least the TTL. To finish sooner, run a background scan
that rewrites stored sessions with the new key.

#### The envelope key has no write budget

AES-GCM under one key with random 96-bit nonces must stay under about 2^32
seals (NIST SP 800-38D, section 8.3), which a busy deployment could reach in
weeks. The stores do not spend that budget: each session, device row and
device-bindings blob is sealed under a key derived for that one record from
the envelope key, a fresh 16-byte salt and the record's row identity
(HMAC-SHA256, see `session::crypto`). Every derived key encrypts one message,
and a blob costs 16 bytes more than before. Rotate the envelope key on your
compliance cycle, not to stay inside a count.

A device row or a device-bindings blob written by an earlier release (the
key used directly) is a legacy blob: it is read only while the `LegacyBlobs` policy
is `AcceptUntil` or `Accept` (the default `Reject` refuses it) and is
re-sealed in the new layout by the read that finds it, as any stale blob is:
after an upgrade each such row costs one extra write the first time it is
read. A session blob is read in the current sealed form only, whatever the
policy says: a session stored by an earlier release is not read, and its user
signs in again. Only a caller that
seals with `SessionCrypto::encrypt_with_aad` itself draws on the budget;
`SessionCrypto::seals` counts those calls, per process, so sum it across
replicas and alert well before 2^32.

#### Device store rows

Device rows outlive sessions: a device lives for its whole retention
ladder (ninety days trusted, thirty seen, seven revoked by default, and an
`Unknown` device never expires on its own), and a sighting changes only
`last_seen_at`, not the encrypted part of the row. One session TTL is
therefore **not** a safe wait before dropping the previous key from a
device store.

A row sealed under the previous key is read with it, and the read writes the
row back under the current key (a conditional write of the exact bytes it
read, so a save that landed meanwhile is not overwritten). A row that nobody
reads or writes keeps the old key. The SQL stores (`SqliteDeviceStore`,
`PostgresDeviceStore`, `MysqlDeviceStore`) take the key in the
`SessionCrypto` they are built with; `ValkeyDeviceStore` takes it through
`ValkeyDeviceStore::with_crypto` or `with_previous_key`:

```rust,ignore
let crypto = SessionCrypto::new(new_envelope_key)
    .with_previous_key(old_envelope_key);
let devices = ValkeyDeviceStore::with_crypto(client, crypto);
```

Drop the previous key only after every row has been read or written since
the rotation. A tenant sweep (`DeviceStore::sweep`) reads every row of the
tenant on Valkey, so one full sweep of every tenant after the new key is
deployed covers the rows still there. The SQL stores re-seal on the reads
that find them, so run a pass that lists each user's devices, or keep the
previous key for the longest device retention you configured. Dropping it
early makes the unread rows fail to decode: lookups return an error for
them, and (on a SQL store) a save of such a device overwrites its bindings
blob.

### CSRF key

The CSRF key signs the double-submit token. If it is derived with
`SessionLayer::derive_subkey`, it follows the current session signing
key only: after a signing-key rotation the derived key changes at once
and there is no previous-key fallback, so tokens already rendered into
open forms fail once and the page must be reloaded. That is a visible
but harmless cost; schedule the switch outside peak form-filling hours.
A separately stored CSRF key rotates the same way: deploy the new key
and accept one round of reloads.

### Per-tenant fingerprint pepper

The fingerprint pepper rotates per tenant rather than globally. axess
holds no pepper: the application supplies a `TenantPepperResolver`, a
function from a tenant id to 32 bytes, when it builds the device
layer. To rotate one tenant, change what the resolver returns for that
tenant (new secret in the secrets manager, then redeploy or reload).
There is no rotation call to make.

What the rotation does depends on how devices are found. Under the
stock `LifecycleDeviceResolver` a device is found by the token on its
cookie, so existing devices and sessions go on as before, and only the
hash stored on devices created from then on differs. Under a resolver
that looks devices up by fingerprint (`ensure_device`), the stored
hashes no longer match and each client registers as a new `Unknown`
device and walks the assurance ladder again. In either case a refresh
token issued with the fingerprint as its `device_info` stops matching
what its client presents.

Nothing in axess rotates the pepper on a schedule or on a tenant's
suspension; the cadence is the deployment's to set.

## Multi-instance considerations

Running several application instances behind a load balancer adds
the following considerations.

Shared session store. The session backend must be cluster-safe:
Postgres, MySQL, or Valkey. SQLite is single-writer and works
only for single-instance deployments. *Backends* covers the
choices.

Shared signing and envelope keys. Every instance must use the
same keys; otherwise a cookie issued by one instance fails
validation on another instance that receives the next request. The secrets manager is the source of truth;
each instance pulls the keys at startup.

Rate-limit state is per instance. axess keeps the buckets in process
memory and provides no distributed limiter, so with N instances an
attacker who reaches all of them gets up to N times the configured
limit. Enforce the shared limit at the gateway or load balancer
(*Rate limiting* covers the layering), or divide the per-instance
limit by the instance count to keep the total near the target.

Session affinity (sticky sessions). Optional. The
session is stored server-side; any instance can serve any
session. Some deployments prefer sticky sessions to improve
local cache hit rates; the trade-off is reduced resilience to
instance failure.

Load-balancer-level fingerprint handling. The load balancer
must forward the real client IP through `X-Forwarded-For` (or
the load balancer's specific header). The application's
trusted-proxy list must include the load balancer's IP range.
Without this, every request looks like it came from the load
balancer, and the fingerprint and rate-limit keys are useless.

## Graceful shutdown

A graceful shutdown drains in-flight requests before stopping
the process. The pattern in axess:

The process receives a SIGTERM (from Kubernetes, systemd, or
whatever orchestrator). The application's shutdown handler sets
a flag that tells the HTTP server to stop accepting new
connections.

In-flight requests continue. The HTTP server is in
draining mode; new connections get refused (which the load
balancer treats as the signal to route elsewhere), existing
connections complete their request.

The shutdown handler waits for the in-flight requests to
complete, with a timeout (typically 30 seconds; long enough for
real requests, short enough that a stuck request does not block
shutdown forever).

The audit trail needs no drain: axess awaits each
`IdentityAuthnLog::record_event` call on the request path and buffers
nothing, so a completed request leaves no audit row waiting to be
written. The one buffer is the
optional analytics stream. If you wrap the log in
`AuditLogWithAnalytics`, call its `shutdown` and then await the
handle `AnalyticsWorker::spawn` returned, so the sink sees every
queued event. Bound that wait yourself. Axess keeps no recovery log:
analytics events still queued when the process exits are lost.

The session store closes. The connection pool drains; in-flight
queries complete; the pool releases its connections.

The process exits.

Axum's `with_graceful_shutdown` provides the pattern; the
application wires the shutdown signal through the standard
shutdown handler. No axess-specific code is needed beyond the
analytics drain, and none at all without the analytics stream.

## Health checks and metrics

A production deployment exposes `/healthz` and `/metrics`
endpoints. The health check confirms your
backends are reachable; the metrics expose the operational
counters.

The health check pattern:

```rust,ignore
let health = Arc::new(
    CompositeHealthCheck::new()
        .add("session_store", session_store.clone())
        .add("identity_store", identity_store.clone())
        .add("device_store", device_store.clone())
);
// `identity_store` here must implement `HealthCheck`. axess does not
// implement it for your identity backend; the sqlite example shows a
// bounded `SELECT 1`.

async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    let status = state.health.check_all().await;
    let code = if status.is_healthy() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    if !status.is_healthy() {
        // Detail goes to the log, never to an unauthenticated caller.
        tracing::warn!(components = ?status.components, "health check failed");
    }
    let body = serde_json::json!({
        "status": if status.is_healthy() { "healthy" } else { "unhealthy" },
    });
    (code, axum::Json(body))
}
```

Serve a detailed probe, if operators need one, on an internal-only
listener. The public route returns the aggregate and nothing else.

Each backend that implements `HealthCheck` provides its own probe
(typically a bounded `SELECT 1` for SQL backends or a `PING` for
Valkey). The composite aggregates the results; the endpoint
returns 200 on all-healthy or 503 on any-unhealthy.

The metrics pattern:

```rust,ignore
async fn metrics_endpoint(State(state): State<AppState>) -> impl IntoResponse {
    let m = &state.metrics;
    axum::Json(serde_json::json!({
        "auth_attempts": m.auth_attempts.load(Ordering::Relaxed),
        "auth_successes": m.auth_successes.load(Ordering::Relaxed),
        "auth_failures": m.auth_failures.load(Ordering::Relaxed),
        "rate_limit_rejections": m.rate_limit_rejections.load(Ordering::Relaxed),
    }))
}
```

The metrics implementation (the concern traits, covered in [Observability and metrics](observability.md))
exposes the counters; the endpoint serialises them in whatever
format the deployment's metrics system expects (Prometheus
text format, JSON, OpenMetrics).

The dashboards the operational team uses combine these counters
with the audit-event volumes from the SIEM. *Audit events*
§"SIEM query patterns" covers the SIEM-side queries.

## Common failures and remedies

Failures that recur in production, and the standard response to each.

Spike in `auth_failures`: typically a credential-stuffing attack
or a credential leak elsewhere. The rate limiter should be
absorbing the bulk; the lockout policy catches the rest.
Investigate the source IPs in the failure events; if the spike
is concentrated on a small set of IPs, block them at the WAF; if
it is spread broadly, the leak is the larger concern.

Spike in `rate_limit_rejections`: either an attack (real
attacker getting throttled) or a misconfiguration (legitimate
traffic hitting a limit too tight). *Rate limiting*
§"Distinguishing attack from misconfiguration" covers the
signals.

Health check failing on session store: the session backend is
unreachable. Investigate the database. Until the backend is
back, you cannot serve authenticated traffic; the
load balancer treats the 503 as a signal to route around the
instance.

Session cookie validation failing for known-good sessions: the
signing key has changed without the previous-key transition. Add
the previous key to the configuration; sessions will start
validating again as soon as the deployment picks up the change.

Spike in `session fingerprint mismatch` warnings (and in the
binding-mismatch metric): the session binding's material changes
under legitimate users. The comparison is exact and has no tolerance
to widen; the stock `UserAgentBinding` diverges only on a browser
update, so look at a `SessionBinding` of your own that reads an
address or a header a proxy rewrites. *Cookies, fingerprinting,
hijack detection* covers the binding. `DeviceFingerprintMismatch` is
an event only a `DeviceResolver` of your own writes.

Logins slowing with no change in traffic: look at the audit sink.
`IdentityAuthnLog::record_event` is awaited on the login path, so
whatever it does, the login waits for it. A SIEM under maintenance
behind a synchronous sink shows up as login latency, not as an audit
alert. If that is a risk you carry, buffer inside your own sink
implementation; *Audit pipeline* covers exactly how far axess goes
here, and where you take over.

Logins failing in a burst with the store reachable: check
`AuditMetrics::audit_store_outage` before `auth_failure`. A failed audit
write fails the login, so an audit problem presents as an
authentication problem. `audit_event_shed` rising instead means the sink
is deliberately dropping events to protect itself: nothing is failing,
but the trail has gaps and something is driving volume at you.

## Canonical OPERATIONS.md

The rest of this chapter is the canonical `OPERATIONS.md` from
the repo root.

{{#include ../../OPERATIONS.md}}

## Further reading

*Security posture* covers the production-readiness posture and
the compliance touch-points. *Audit pipeline* covers the audit
retention and the buffer-overflow policies. *Migration guide*
covers cross-version upgrades and the security-relevant
breaking changes. *Backends* covers the per-backend operational
notes (CockroachDB caveats, MySQL timezone handling, Valkey
eviction policies).
