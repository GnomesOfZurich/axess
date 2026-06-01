//! End-to-end device-identity wiring example.
//!
//! Demonstrates the assembly recipe documented in
//! `axess_core::device` (see the axess-core docs): one `SqlitePool` shared between
//! `SqliteSessionStore` and `SqliteDeviceStore`, the
//! `DefaultFingerprintExtractor` with a per-tenant pepper, the
//! `CachedDeviceStore` decorator for hot-path latency, the
//! `DeviceLifecycleService` for `ensure_device` / `promote_on_authn`,
//! the `LifecycleDeviceResolver` driving per-request resolution, and
//! a background task running the three-stage retention sweep.
//!
//! Run with:
//!
//! ```bash
//! cargo run -p axess-example-device
//! ```
//!
//! Then `curl -v http://localhost:3000/whoami` from a few different
//! user-agents to watch new devices materialise. `GET /devices` lists
//! the devices currently known to the test tenant.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axess::authn::{FactorKind, LoginOutcome, TenantId};
use axess::device::{
    CachedDeviceStore, DefaultFingerprintExtractor, DeviceLifecycleService, DeviceResolver,
    DeviceStore, DeviceTrustLevel, LifecycleDeviceResolver, NoopDeviceEventSink, StepUpPolicy,
    TenantPepperResolver, decide_step_up,
};
use axess::session::SessionCrypto;
use axess::testing as id_fixtures;
use axess::{
    SessionLayer,
    backends::sqlite::{DeviceStore as SqliteDeviceStore, SessionStore as SqliteSessionStore},
};
use axess_clock::SystemClock;
use axum::{
    Json, Router,
    extract::{Extension, Request},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::get,
};
use serde_json::json;
use sqlx::sqlite::SqlitePoolOptions;

/// Concrete resolver type. Spelt out once so `Extension<AppResolver>`
/// works without a `dyn` (the trait uses RPITIT, not dyn-safe).
type AppResolver = Arc<
    LifecycleDeviceResolver<
        DefaultFingerprintExtractor,
        CachedDeviceStore<SqliteDeviceStore>,
        SystemClock,
    >,
>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("info,axess_core=debug")
        .init();

    // ── 1. shared persistence ────────────────────────────────────────────
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect("sqlite::memory:")
        .await?;

    // Single envelope key reused for the session and device stores. In
    // production this comes from a KMS / vault; `[0x42; 32]` here is
    // demonstration only.
    let envelope_key = [0x42u8; 32];
    let crypto = SessionCrypto::new(envelope_key);

    // ── 2. session + device stores on the SAME pool ──────────────────────
    let sessions = SqliteSessionStore::new(pool.clone(), crypto.clone());
    let devices = SqliteDeviceStore::new(pool.clone(), crypto.clone());
    sessions.init_schema().await?;
    devices.init_schema().await?;

    // ── 3. cache decorator on the hot path ───────────────────────────────
    let cached_devices = CachedDeviceStore::with_options(
        devices.clone(),
        4096,                    // capacity
        Duration::from_secs(60), // TTL
        Arc::new(SystemClock),
    );

    // ── 4. fingerprint extractor + lifecycle service ─────────────────────
    //
    // Per-tenant HMAC pepper. In production, derive from a per-tenant
    // secret in a vault or via a KDF over a master key. Demonstration
    // hash here is fixed per tenant id; DO NOT use this in production.
    let pepper_resolver: TenantPepperResolver = Arc::new(|tenant: &TenantId| {
        let mut out = [0u8; 32];
        let tenant_bytes = tenant.as_uuid().into_bytes();
        for (i, b) in out.iter_mut().enumerate() {
            *b = tenant_bytes[i % tenant_bytes.len()] ^ 0x5a;
        }
        out
    });
    let extractor = DefaultFingerprintExtractor::new(pepper_resolver);
    let lifecycle =
        DeviceLifecycleService::new(cached_devices.clone()).with_event_sink(NoopDeviceEventSink);

    // ── 5. resolver, scoped to the single demo tenant ────────────────────
    let demo_tenant = id_fixtures::tenant("demo-tenant");
    let resolver = LifecycleDeviceResolver::new(extractor, lifecycle, SystemClock)
        .with_tenant_fn(move |_parts| Some(demo_tenant));
    let resolver: AppResolver = Arc::new(resolver);

    // ── 6. background sweep task driving the retention ladder ────────────
    //
    // 90-day Trusted-idle / 30-day Seen-idle / 7-day Revoked-grace
    // (default), at a one-minute cadence for the demo. Real deployments
    // typically run sweep every 6–24h.
    let sweep_store = devices.clone();
    let sweep_tenant = demo_tenant;
    // Reuse the same `SystemClock` the resolver was built with so wall-clock
    // reads route through the foundation crate's clock abstraction. In a DST
    // simulation the adopter swaps both call sites for a `MockClock`.
    let sweep_clock = SystemClock;
    tokio::spawn(async move {
        use axess_clock::Clock;
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            match sweep_store.sweep(&sweep_tenant, sweep_clock.now()).await {
                Ok(counts) => tracing::info!(
                    trusted_to_seen = counts.trusted_to_seen,
                    seen_to_revoked = counts.seen_to_revoked,
                    revoked_purged = counts.revoked_purged,
                    "device-sweep tick"
                ),
                Err(e) => tracing::warn!(error = %e, "device-sweep tick failed"),
            }
        }
    });

    // ── 7. Axum router ───────────────────────────────────────────────────
    let app = Router::new()
        .route("/", get(index))
        .route("/whoami", get(whoami))
        .route("/devices", get(list_devices))
        .route("/step-up-check", get(step_up_check))
        .layer(Extension(resolver))
        .layer(Extension(devices.clone()))
        .layer(Extension(demo_tenant))
        .layer(
            SessionLayer::new(sessions, envelope_key)
                .with_secure(false)
                .with_ttl(Duration::from_secs(3600)),
        );

    let addr: SocketAddr = "127.0.0.1:3000".parse()?;
    tracing::info!(%addr, "device example listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Browser-friendly landing page. The example exposes JSON endpoints
/// meant for curl; without this, hitting `/` 404s to a blank page.
async fn index() -> Html<&'static str> {
    Html(
        r#"<!doctype html>
<html><head><title>axess-example-device</title>
<style>
body{font-family:system-ui,sans-serif;max-width:780px;margin:2em auto;padding:0 1em;color:#222}
code{background:#f4f4f4;padding:.1em .35em;border-radius:3px}
li{margin:.3em 0}
section{margin-bottom:1.6em}
.method{display:inline-block;min-width:3.5em;font-weight:600;color:#0a5}
</style></head><body>
<h1>axess-example-device</h1>
<p>End-to-end device-identity wiring demo. Each request is fingerprinted
(<code>DefaultFingerprintExtractor</code>), resolved to a stored device, and
optionally promoted on authentication. Devices accumulate across requests
in an in-memory SQLite store; the background sweep runs every few seconds.</p>

<section>
<h2>How to drive it</h2>
<p>Hit <code>/whoami</code> from a few different user-agents (browser, curl,
<code>curl -A "demo-agent-2"</code>, …) and watch new devices materialise.
<code>/devices</code> lists everything the tenant has seen so far.
<code>/step-up-check</code> reports whether the resolved device would
satisfy the sample step-up policy.</p>
</section>

<section>
<h2>GET endpoints</h2>
<ul>
  <li><span class="method">GET</span> <a href="/whoami">/whoami</a>; resolve + summarise this request's device</li>
  <li><span class="method">GET</span> <a href="/devices">/devices</a>; list all devices the demo tenant currently knows</li>
  <li><span class="method">GET</span> <a href="/step-up-check">/step-up-check</a>; would this device pass the step-up policy?</li>
</ul>
</section>

<section>
<h2>Try it with curl</h2>
<pre><code>curl -v http://localhost:3000/whoami
curl -v -A "demo-agent-2" http://localhost:3000/whoami
curl http://localhost:3000/devices | jq .
</code></pre>
</section>

</body></html>"#,
    )
}

/// Resolve the device for this request and return a JSON summary.
async fn whoami(
    Extension(resolver): Extension<AppResolver>,
    Extension(devices): Extension<SqliteDeviceStore>,
    Extension(tenant): Extension<TenantId>,
    req: Request,
) -> impl IntoResponse {
    let (parts, _body) = req.into_parts();
    let device_id = match resolver.resolve(&parts).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            return (
                StatusCode::OK,
                Json(json!({"device": null, "reason": "request too thin to fingerprint"})),
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "device resolve failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "device resolve failed"})),
            );
        }
    };
    let device = match devices.load(&tenant, &device_id).await {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "device load failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "device load failed"})),
            );
        }
    };
    let payload = match device {
        Some(d) => json!({
            "device_id": d.id,
            "trust_level": trust_str(d.trust_level),
            "first_seen_at": d.first_seen_at,
            "last_seen_at": d.last_seen_at,
            "bindings": d.bindings.len(),
        }),
        None => json!({"device": null, "reason": "resolved id did not load"}),
    };
    (StatusCode::OK, Json(payload))
}

/// List every (non-revoked) device for the demo user in the demo tenant.
async fn list_devices(
    Extension(devices): Extension<SqliteDeviceStore>,
    Extension(tenant): Extension<TenantId>,
) -> impl IntoResponse {
    let demo_user = id_fixtures::user("demo-user");
    match devices.find_active_for_user(&tenant, &demo_user, 100).await {
        Ok(list) => {
            let summary: Vec<_> = list
                .into_iter()
                .map(|d| {
                    json!({
                        "device_id": d.id,
                        "trust_level": trust_str(d.trust_level),
                        "last_seen_at": d.last_seen_at,
                    })
                })
                .collect();
            (StatusCode::OK, Json(json!({"devices": summary}))).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "find_active_for_user failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "find_active_for_user failed"})),
            )
                .into_response()
        }
    }
}

/// reference flow: resolve the device, apply the default
/// [`StepUpPolicy`], and surface the decision in a shape that mirrors
/// what an application would substitute for a
/// [`LoginOutcome::FactorRequired`] coming back from
/// `AuthnService::begin_login`. When `decide_step_up` returns
/// `Some(factors)`, the application emits
/// `LoginOutcome::StepUpRequired { device_id, allowed_factors: factors }`
/// instead of the standard `FactorRequired`.
///
/// This route does not perform a real login; it just shows the
/// device → policy → outcome wiring. Drive it from a few different
/// user-agents to see how the trust level changes as the device
/// moves through `Unknown` → `Seen` over repeated visits.
async fn step_up_check(
    Extension(resolver): Extension<AppResolver>,
    Extension(devices): Extension<SqliteDeviceStore>,
    Extension(tenant): Extension<TenantId>,
    req: Request,
) -> impl IntoResponse {
    let (parts, _body) = req.into_parts();
    let device_id = match resolver.resolve(&parts).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            return (
                StatusCode::OK,
                Json(json!({"outcome": "no-device", "reason": "request too thin to fingerprint"})),
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "device resolve failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "device resolve failed"})),
            );
        }
    };
    let device = match devices.load(&tenant, &device_id).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            return (
                StatusCode::OK,
                Json(json!({"outcome": "no-device", "reason": "resolved id did not load"})),
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "device load failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "device load failed"})),
            );
        }
    };
    let policy = StepUpPolicy::default();
    match decide_step_up(&device, &policy) {
        Some(allowed_factors) => {
            // This is the substitution the application's login handler
            // would make on top of `begin_login`'s result. Constructed
            // here only so the JSON response carries a typed payload
            // shape adopters can pattern-match against.
            let outcome = LoginOutcome::StepUpRequired {
                device_id: device.id,
                allowed_factors: allowed_factors.clone(),
            };
            let factor_names: Vec<String> = allowed_factors.iter().map(factor_kind_str).collect();
            (
                StatusCode::OK,
                Json(json!({
                    "outcome": "step-up-required",
                    "device_id": device.id,
                    "trust_level": trust_str(device.trust_level),
                    "allowed_factors": factor_names,
                    "outcome_debug": format!("{outcome:?}"),
                })),
            )
        }
        None => (
            StatusCode::OK,
            Json(json!({
                "outcome": "no-step-up",
                "device_id": device.id,
                "trust_level": trust_str(device.trust_level),
            })),
        ),
    }
}

fn factor_kind_str(k: &FactorKind) -> String {
    // FactorKind::as_str() already covers the stable wire tag used in
    // audit logs and metrics; reuse it so this helper does not have
    // to maintain a parallel match arm per variant.
    k.as_str().to_string()
}

fn trust_str(level: DeviceTrustLevel) -> &'static str {
    match level {
        DeviceTrustLevel::Unknown => "unknown",
        DeviceTrustLevel::Seen => "seen",
        DeviceTrustLevel::Trusted => "trusted",
        DeviceTrustLevel::Revoked => "revoked",
    }
}
