# Operations runbook

This chapter is the operator-facing runbook. It covers the
pre-launch checklist, the routine rotations the deployment needs
to schedule, the multi-instance considerations that catch
deployments off-guard, the graceful-shutdown sequence, the
health-check and metrics surfaces, and the emergency procedures
for the categories of incident that recur.

The chapter has two halves. The first half is operational
guidance specific to axess. The second half is the canonical
[`OPERATIONS.md`](https://github.com/GnomesOfZurich/axess/blob/main/OPERATIONS.md)
from the repo root, included so the deployment's runbook
checklist is in one place.

## Pre-launch checklist

The list below is the minimum an axess-instrumented deployment
should clear before serving real traffic. Each item is covered in
detail in another chapter; the list here is the inventory.

The session signing key is loaded from the deployment's secrets
manager. The key is 32 bytes of cryptographic randomness, stable
across process restarts. The development placeholder
(`[0; 32]` from *Getting started*) is replaced.

The session envelope key is loaded the same way. The two keys
are independent; one is for HMAC signing the cookie, the other
is for AES-256-GCM encrypting the session payload at rest.
*Session lifecycle and crypto envelope* covers the distinction.

The fingerprint pepper is loaded for the fingerprint binding.
Each tenant has its own pepper, stored alongside the tenant
record; *Multi-tenancy* and *Cookies, fingerprinting, hijack
detection* cover the mechanism.

The session cookie has `Secure=true` set. TLS terminates at the
edge; the application sees only HTTPS traffic; the cookie is
only sent on HTTPS.

The trusted-proxy list is configured. The application reads the
forwarded header (`X-Forwarded-For` or `Forwarded`) only when
the immediate peer is in the trusted list. Without this, the
fingerprint and the rate-limit keys can be spoofed.

The rate limit is configured on the login, signup, password-reset,
and any other authentication-adjacent endpoints. The defaults
from *Rate limiting* are starting points; calibrate to the
deployment's legitimate-traffic envelope.

The lockout policy is configured (or the global default is
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
store, and the device store; the response is a JSON document
that aggregates the per-component states. *Operations runbook*
in the canonical SECURITY/OPERATIONS section covers the
deployment expectations.

The metrics are exported. The `AuthnMetrics` trait is
implemented; the metric values flow into Prometheus or
OpenTelemetry; the dashboards cover the auth-attempt rate, the
failure rate, the rate-limit rejection rate, and the lockout
trigger rate. *Operations runbook* below covers the
production-dashboard expectations.

The Cedar policy set is loaded and validated against the
schema. The startup path refuses if the validation fails; a
production launch with a misconfigured policy set never gets to
serve traffic. *Cedar policy fundamentals* covers the validation
flow.

The cleanup tasks are scheduled. The session cleanup, the device
retention sweep, the audit retention loop, the OAuth JWKS cache
refresh: all of these run on intervals; the scheduler is the
application's responsibility. *Backends* §"SQLite" and similar
sections cover the per-backend cleanup patterns.

## Key rotation

The deployment has three keys to rotate on a schedule: the
session signing key, the session envelope key, and the per-tenant
fingerprint pepper. The mechanism is the same shape for all three:
provide the new key alongside the old one for a transition window,
let in-flight sessions and devices roll over, then remove the old
key.

### Session signing key

The signing key is what HMAC-protects the session cookie.
Rotating it without invalidating sessions requires keeping the
old key available for verification during the transition.

```rust,ignore
let session_layer = SessionLayer::new(store, new_signing_key)
    .with_previous_key(old_signing_key)
    .with_ttl(session_ttl);
```

`with_previous_key` accepts the old key. Cookies signed with the
old key continue to validate; new cookies sign with the new key.
After enough time for all old cookies to expire (one session TTL
plus a safety margin), the previous key can be removed.

The rotation sequence:

1. Deploy the application with `new_signing_key = old_key` and
   `previous_key = old_key`. Nothing has changed; this is the
   baseline.
2. Generate a fresh 32-byte signing key. Store it in the secrets
   manager alongside the existing one.
3. Deploy the application with `new_signing_key = fresh_key` and
   `previous_key = old_key`. New cookies sign with the fresh
   key; existing cookies continue to validate against the old.
4. Wait one session TTL. By the end of this window, every
   existing session has either expired or been refreshed (which
   re-signs the cookie with the fresh key).
5. Deploy the application with `previous_key = None` (or absent).
   The old key is now unused.
6. Remove the old key from the secrets manager.

### Session envelope key

The envelope key is what AES-256-GCM protects the session payload
at rest. Rotating it without invalidating sessions is similar to
the signing-key rotation, with the additional consideration that
sessions stored before the rotation continue to be readable but
new writes use the new key.

```rust,ignore
let crypto = SessionCrypto::new(new_envelope_key)
    .with_previous_key(old_envelope_key);
let store = SessionStore::new(pool, crypto);
```

The rotation sequence is the same as the signing key. The
transition window covers one session TTL; after that, every
stored session has been rewritten with the new key.

For deployments with long session TTLs (a week or a month),
rotating the envelope key per the deployment's compliance cycle
(quarterly, semiannually) requires the transition window to be
at least the TTL. Alternative: a background scan that proactively
rewrites stored sessions with the new key, finishing the
rotation faster than the TTL would.

### Per-tenant fingerprint pepper

The fingerprint pepper rotates per-tenant rather than globally.
The mechanism is on the tenant record:

```rust,ignore
service.rotate_fingerprint_pepper(
    &tenant_id,
    new_pepper,
).await?;
```

The rotation invalidates every device record under the tenant.
Existing sessions remain valid (they do not depend on the device
record), but the next request from each user re-registers their
device from scratch (transitioning the device to `Unknown` and
walking the assurance ladder again). Users see no break; the
device store sees a churn.

The pepper rotates on tenant suspension and on demand. The
default cadence is annual; tighter cadences are appropriate for
high-sensitivity deployments.

## Multi-instance considerations

A deployment that runs multiple application instances behind a
load balancer has a handful of considerations the single-instance
deployment does not.

Shared session store. The session backend must be cluster-safe:
Postgres, MySQL, or Valkey. SQLite is single-writer and works
only for single-instance deployments. *Backends* covers the
choices.

Shared signing and envelope keys. Every instance must use the
same keys; otherwise an instance that issued a cookie cannot
have the cookie validated by a different instance that receives
the next request. The secrets manager is the source of truth;
each instance pulls the keys at startup.

Shared rate-limit state. If the rate limiter is keyed by
`PeerIp` and the buckets live in memory per instance, an
attacker hitting all instances in parallel evades the limit.
The fix is `BucketStore::Valkey { client }`, which moves the
state to a shared Valkey instance; every application instance
sees the same buckets.

Session affinity (sticky sessions). Optional, not required. The
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

The audit pipeline drains. The shutdown handler triggers the
pipeline to flush its buffer to all sinks. The wait is bounded
(typically 10 seconds); buffered events that do not flush in
time are written to a local recovery log for the next process
start to pick up.

The session store closes. The connection pool drains; in-flight
queries complete; the pool releases its connections.

The process exits.

The pattern is what Axum's `with_graceful_shutdown` enables; the
application wires the shutdown signal through the standard
shutdown handler. No axess-specific code is needed beyond the
audit-pipeline drain.

## Health checks and metrics

A production deployment exposes `/healthz` and `/metrics`
endpoints. The health check confirms the application's
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

async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    let status = state.health.check_all().await;
    let code = if status.is_healthy() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let body = serde_json::json!({
        "status": if status.is_healthy() { "healthy" } else { "unhealthy" },
        "components": status.components,
    });
    (code, axum::Json(body))
}
```

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

The metrics implementation (covered in `AuthnMetrics` trait)
exposes the counters; the endpoint serialises them in whatever
format the deployment's metrics system expects (Prometheus
text format, JSON, OpenMetrics).

The dashboards the operational team uses combine these counters
with the audit-event volumes from the SIEM. *Audit events*
§"SIEM query patterns" covers the SIEM-side queries.

## Common failures and remedies

The categories of failure that recur in production deployments,
and the standard responses.

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
back, the application cannot serve authenticated traffic; the
load balancer treats the 503 as a signal to route around the
instance.

Session cookie validation failing for known-good sessions: the
signing key has changed without the previous-key transition. Add
the previous key to the configuration; sessions will start
validating again as soon as the deployment picks up the change.

Spike in `DeviceFingerprintMismatch` events: typically the
fingerprint tolerance is too tight. Calibrate against the warn
rate; widen the IP-prefix tolerance or the user-agent matching.
*Cookies, fingerprinting, hijack detection* covers the tolerance
configuration.

Audit pipeline buffer filling: the analytics sink is slow or
down. Inspect the sink's metrics; if it is the SIEM under
maintenance, the buffer fills until the policy fires
(`DropOldest`, `Block`, or `ShutdownAuthn`). Plan for the
maintenance window through the deployment's standard
notification process.

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
