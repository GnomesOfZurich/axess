# Axess; Operations Guide

Deployment, key management, and operational procedures for production environments.

## Key rotation (zero-downtime)

Session signing keys and encryption keys can be rotated without invalidating active sessions.

### Signing key rotation

The signing key is the 32-byte master fed to `SessionLayer::new(store, signing_key)`. HKDF-Expand derives two sub-keys from it: one for session-cookie HMAC and one for session-binding fingerprint HMAC. `SessionLayer` supports zero-downtime rotation via `with_previous_signing_key(old_master)`; sessions signed under the previous master transparently re-authenticate and their cookies + stored fingerprints are re-issued under the new master.

**Procedure:**
1. Generate a new 32-byte signing master in your secrets manager.
2. Deploy with both masters wired: new as current, old as previous.
   ```rust,ignore
   let layer = SessionLayer::new(store, new_master)
       .with_previous_signing_key(old_master);
   ```
3. On every request, the layer tries current-master verification first; on mismatch it falls back to the previous master. Fallback matches trigger:
   - A fresh `Set-Cookie` header signed under the current master.
   - An update to the stored session fingerprint (computed under the current master) so the next request hits the fast path without falling back.
4. Watch for the `"session cookie verified with previous (rotated) signing key"` and `"session fingerprint verified with previous (rotated) signing key"` `tracing::debug!` events to gauge migration progress.
5. After one full session-TTL window (the longest a legit cookie signed under the old master can still be in flight), retire the previous slot: either drop the `with_previous_signing_key(...)` call from the deployment, or call `SessionLayer::remove_previous_signing_key()` on the freshly-built layer (same "mutate before cloning" contract). `SessionLayer::has_previous_signing_key()` returns `false` after that.

**Operational rule: only one previous slot.** Plan rotations so at most one is in flight per session-TTL window. Rotating again while the previous slot is still populated overwrites it: the pre-first-rotation master falls out of the ring and its cookies fail both current and previous verification. This is the correct security behavior for emergency chained rotations (a compromised previous master must not remain valid) but it forces re-authentication for any session still holding a pre-first-rotation cookie. In the non-emergency case, wait one full session-TTL between rotations.

**CSRF / adopter-derived sub-keys.** Sub-keys derived from the session master via `SessionLayer::derive_subkey(info)` (e.g. an adopter's own CSRF signing key) do NOT get rotation-aware verify-with-fallback for free. The returned bytes come from the CURRENT master only. Adopters that rotate through `derive_subkey` must maintain their own previous-key state and implement their own try-current-then-previous verification. axess's own CSRF layer takes an independent key and is unaffected.

### Encryption key rotation

`SessionCrypto` supports transparent key rotation via `with_previous_key()`:

```rust,ignore
let crypto = SessionCrypto::new(new_key)
    .with_previous_key(old_key);
```

**Procedure:**
1. Generate a new 32-byte encryption key in your secrets manager.
2. Deploy with both keys: new as `current`, old as `previous`.
3. Sessions encrypted with the old key are transparently re-encrypted with the new key on next access.
4. After all sessions have been accessed (or after the session TTL expires), remove the previous key from the deployment.
5. Monitor the `"session decrypted with previous (rotated) key"` log message to track migration progress.

## Multi-instance deployment

### Shared state requirements

| Component | Sharing requirement |
|-----------|-------------------|
| Signing key | **Must be identical** across all instances |
| Encryption key | **Must be identical** across all instances |
| Session store | Valkey, PostgreSQL, or MySQL (shared). SQLite is single-instance only. |
| Session registry | Valkey-backed (`ValkeySessionRegistry`). In-memory is single-instance only. |
| OIDC sid_map | In-memory per instance. Back-channel logout works when the IdP sends to the instance that handled the login. Use sticky sessions or a shared store for full coverage. |
| Rate limit buckets | In-memory per instance. For distributed rate limiting, use an external solution (e.g. Valkey-based sliding window at the reverse proxy). |

### Health checks

Implement a `/healthz` endpoint using the `CompositeHealthCheck` trait:

```rust,ignore
use axess::{CompositeHealthCheck, HealthCheck, HealthStatus};

async fn healthz(State(health): State<CompositeHealthCheck>) -> impl IntoResponse {
    match health.check().await {
        HealthStatus::Healthy => StatusCode::OK,
        HealthStatus::Degraded(_) => StatusCode::OK, // still serving
        HealthStatus::Unhealthy(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}
```

All session store implementations (`SqliteSessionStore`, `PostgresSessionStore`, `MysqlSessionStore`, `ValkeySessionStore`) implement `HealthCheck`.

## Session store migration

To migrate from one session store to another (e.g. SQLite to Valkey):

1. **Dual-write phase**: deploy a wrapper that writes to both stores, reads from the new store first with fallback to the old store.
2. **Cutover**: once the old store's TTL has expired (default 24h), switch reads to the new store only.
3. **Cleanup**: remove the old store configuration.

There is no built-in migration tool. Sessions are short-lived (default 24h TTL), so a simpler approach is:
1. Deploy the new store.
2. Accept that active sessions on the old store will expire naturally.
3. New sessions are created on the new store.

## Session cleanup

SQLite, PostgreSQL, and MySQL stores accumulate expired sessions. Use
the built-in helper:

```rust,ignore
let store = SqliteSessionStore::new(pool, crypto);
store.init_schema().await?;
let _cleanup = store.spawn_cleanup_task(Duration::from_secs(3600));
```

`PostgresSessionStore::spawn_cleanup_task` and `MysqlSessionStore::spawn_cleanup_task` work the same way. The returned `JoinHandle` aborts the loop when dropped; store it for the lifetime of the application (or pass it through to graceful shutdown, see below).

Valkey manages expiration natively via TTL; no cleanup needed.

## Graceful shutdown

Axess spawns long-lived background tasks for everything that needs to run on a wall-clock cadence: session cleanup, JWKS refresh, back-channel-logout `sid_map` aging. None of these survive `SIGTERM` unless the application drains them; `tokio::spawn` tasks are unconditionally aborted when the runtime stops.

The standard pattern is Axum's `with_graceful_shutdown` plus explicit abort/await of every `JoinHandle` axess returns:

```rust,ignore
use axum::serve;
use std::sync::Arc;
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── Build stores and spawn axess background tasks ─────────────
    let session_store = SqliteSessionStore::new(pool.clone(), crypto);
    session_store.init_schema().await?;

    let cleanup_handle = session_store.spawn_cleanup_task(
        std::time::Duration::from_secs(3600),
    );

    let jwks_handle = oauth_provider.spawn_jwks_refresh(
        std::time::Duration::from_secs(3600),
    );

    // ── Shared shutdown signal ────────────────────────────────────
    let shutdown = async {
        let ctrl_c = async { signal::ctrl_c().await.ok(); };
        let term = async {
            #[cfg(unix)]
            {
                use signal::unix::{SignalKind, signal};
                if let Ok(mut s) = signal(SignalKind::terminate()) {
                    s.recv().await;
                }
            }
        };
        tokio::select! { _ = ctrl_c => {}, _ = term => {} }
    };

    // ── Serve until SIGTERM/SIGINT ────────────────────────────────
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;

    // ── Drain background tasks ────────────────────────────────────
    // Aborting is safe; both loops persist via the database, so a
    // killed cleanup tick at most leaves expired rows for the next
    // scheduled run, and a killed JWKS tick leaves the cached JWKS
    // intact until the next process serves a request.
    cleanup_handle.abort();
    jwks_handle.abort();
    let _ = cleanup_handle.await;
    let _ = jwks_handle.await;

    Ok(())
}
```

### What survives shutdown vs what is lost

| State | Survives? | Notes |
|-------|-----------|-------|
| Persisted sessions (SQL / Valkey) | Yes | Stored in DB; new process re-reads. |
| `MemorySessionStore` contents | **No** | In-process only; everyone is logged out. |
| `MemorySessionRegistry` contents | **No** | Same; fresh registry on restart. |
| Refresh tokens (SQL / Valkey) | Yes | Hash + family in DB; rotation continues seamlessly. |
| JWKS cache | **No** (re-fetched) | First post-restart OAuth callback warms it. |
| `sid_map` (back-channel logout) | **No** | OIDC `sid` → local session mapping is in-process. Sessions remain valid; only the `sid`-keyed lookup is lost, so a back-channel logout that arrives before re-login will silently no-op. Acceptable; the session still expires on its TTL. |
| In-flight HTTP request being served | Yes (via `with_graceful_shutdown`) | Axum waits for active connections to close before returning from `serve`. |
| In-flight `cleanup_expired` query | Aborted | The next scheduled cleanup picks up the slack. |
| In-flight `refresh_jwks` HTTP call | Aborted | The next request triggers a fresh fetch on demand. |

### Why drain the handles after `serve` returns

`with_graceful_shutdown` only drains in-flight HTTP requests. The `tokio::spawn`'d cleanup / JWKS refresh tasks are **independent** of the HTTP server and continue running until the runtime is dropped. Without an explicit `abort().await` they hold a reference to the store clone and the runtime keeps them alive; at minimum delaying shutdown to the next tick, at worst (with `tokio::main(flavor = "current_thread")`) deadlocking because the abort signal can't be processed while the runtime is also waiting for the task to yield.

## Monitoring and alerting

### Recommended SLOs and alert rules

The thresholds below are starting points for a single-region deployment serving thousands to low-millions of users. Tune to your traffic shape; a free-tier app with no MFA will see very different baselines than a banking dashboard with mandatory FIDO2. The general rule: alert on *ratios and rates*, not absolute counts, so an alert that fires at 1k DAU still fires at 100k DAU without re-tuning.

#### Critical (page on-call)

| Signal | Threshold | Why it matters |
|--------|-----------|----------------|
| `auth_failure / (auth_success + auth_failure)` | `> 50%` for 5 min | Either a brute-force campaign is in progress or the IdP is down. Either way, real users are locked out. |
| `account_locked` rate | `> 10 / minute` for 5 min | Sustained password-spray; tens of accounts being locked per minute is well above any realistic legitimate spike. |
| `session_binding_mismatch` rate | `> 1 / minute` per tenant for 5 min | Either a stolen session cookie is being replayed across user agents, or a buggy client is rotating UAs mid-session. Investigate immediately. |
| Health check returns `Unhealthy` | for 2 consecutive checks | Session store / database is unreachable; users cannot log in. |
| `JWKS RwLock was poisoned` log | any occurrence | A panic happened while holding the JWKS lock; OAuth verification may be silently degraded. |

#### Warning (alert in chat / ticket queue)

| Signal | Threshold | Why it matters |
|--------|-----------|----------------|
| `factor_failure / factor_attempt` (per factor kind) | `> 30%` for 15 min | Targeted factor probe (e.g. TOTP guessing) or a regression in the factor verification code. |
| `rate_limit_rejected / (rate_limit_allowed + rate_limit_rejected)` | `> 5%` for 10 min | Either the rate limit is mis-tuned for legitimate traffic or an attacker is sustained-firing requests. |
| `sid_map capacity reached; evicted oldest mapping` log | `> 1 / minute` | OAuth login throughput exceeds the configured `sid_map` cap (default 10 000, `DEFAULT_SID_MAP_CAPACITY`); back-channel logout precision degrades (some `sid` lookups will miss). Raise via `AuthnService::with_sid_map_capacity(N)` on startup, or shorten the TTL if the churn is real. |
| `session decrypted with previous (rotated) key` log | persists `> 7 days` after rotation | Long-lived sessions are still on the old key. The next rotation will invalidate them; communicate the cutover. |
| `account_locked` rate | `> 1 / minute` for 5 min | Background brute force or aggressive credential stuffing. Below paging threshold but worth watching. |
| `session custom data exceeds size limit` log | any occurrence | Application is writing too much to the session; investigate before users hit it in production. |

#### Info (dashboard only, no alert)

`auth_attempt`, `auth_success`, `factor_attempt`, `factor_success`, `session_created`, `session_invalidated`, `rate_limit_allowed`;
useful for trend dashboards, capacity planning, and as denominators for the ratio-based alerts above. Avoid alerting on absolute counts; they swing wildly with traffic.

### Computing rates from counters

`AuthnMetrics` exposes counters; alerts live in your monitoring system (Prometheus / Datadog / Grafana / CloudWatch). The standard pattern in Prometheus terms:

```promql
# Auth failure rate over 5 minutes
rate(axess_auth_failure_total[5m])
  / (rate(axess_auth_success_total[5m]) + rate(axess_auth_failure_total[5m]))
> 0.5
```

Implement the [`AuthnMetrics`](https://docs.rs/axess) trait against your metrics client and emit `_total`-suffixed counters for the rate queries above to compose cleanly.

### Key log messages

| Message | Severity | Action |
|---------|----------|--------|
| `"session decrypted with previous (rotated) key"` | Info | Key rotation in progress; monitor until gone |
| `"JWKS RwLock was poisoned"` | Warn | Investigate what panicked while holding the lock |
| `"sid_map capacity reached"` | Warn | Many OAuth logins; consider increasing capacity |
| `"session custom data exceeds size limit"` | Warn | Application is writing too much to session |
| `"login rejected by tenant IP policy"` | Warn | Legitimate user from blocked IP, or attack |

## Emergency procedures

### Force-logout all users

```rust,ignore
// Via session registry (if configured):
registry.invalidate_user(&user_id).await;

// Nuclear option; clear the session store:
store.cleanup_expired().await; // only clears expired
// For immediate full clear: truncate the sessions table or flush Valkey.
```

### Encryption key compromise

1. Generate a new encryption key immediately.
2. Deploy with new key only (no previous key); this invalidates all active sessions.
3. Rotate the signing key as well (the attacker may have decrypted session data containing the HMAC tag).
4. Review audit logs for suspicious session activity during the compromise window.
