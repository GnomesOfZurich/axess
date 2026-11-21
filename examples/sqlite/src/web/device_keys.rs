//! Device keys where a person signs in (`--features device-keys`).
//!
//! A browser that can keep a private key where no script can read it is
//! offered one on its first signed-in page. Once it has registered the key,
//! its session is served only with the short-lived proof cookie the key
//! renews: a session cookie copied off the machine, with the device cookie
//! beside it, is served as a guest, and every page behind
//! `require_authn!` sends it to the login.
//!
//! The policy is [`KeyBindingPolicy::Prefer`]: a browser without a key store
//! signs in as before, its session bound to nothing.
//!
//! Every key proof is made for the origin the application is reached at, so
//! the keys are served only where that origin is known: the address the
//! binary listens on when it runs as a development server on plain HTTP
//! (`AXESS_DEV_INSECURE_COOKIES=1`), and otherwise what `AXESS_ORIGIN`
//! names. Reached over HTTPS with `AXESS_ORIGIN` unset, the application
//! says so at start and serves no device keys.

use std::sync::Arc;

use axess::authn::TenantId;
use axess::backends::sqlite::DeviceStore as SqliteDeviceStore;
use axess::device::{
    DefaultFingerprintExtractor, DeviceCookieConfig, DeviceLifecycleService,
    IdentityStoreEventSink, LifecycleDeviceResolver,
};
use axess::device_key::{DeviceKeyConfig, DeviceKeyService, KeyBindingPolicy};
use axess::profile::SecurityProfile;
use axess::session::SessionCrypto;
use axess::{Clock, MetricSinks, SecureRng, SessionLayer, SessionStore, SystemRng};
use sqlx::SqlitePool;

use crate::models::backend::OurBackend;
use crate::web::app::{LISTEN_ADDR, ORIGIN_ENV, Serving};

/// What the device keys are built from: the application's own pool, clock,
/// metrics and audit trail, and how it is reached.
pub struct Wiring<'a> {
    pub pool: &'a SqlitePool,
    pub clock: Arc<dyn Clock>,
    pub serving: &'a Serving,
    pub sinks: &'a MetricSinks,
    /// Where the audit rows go: the store the login's own rows go to.
    pub audit: OurBackend,
}

/// The origin key proofs are made for: what the deployment named, else the
/// address the binary listens on when that is how it is reached (a
/// development server on plain HTTP). `None` when it is reached over HTTPS
/// at an origin nobody named.
fn origin_of(serving: &Serving) -> Option<String> {
    match (&serving.origin, serving.secure) {
        (Some(origin), _) => Some(origin.clone()),
        (None, false) => Some(format!("http://{LISTEN_ADDR}")),
        (None, true) => None,
    }
}

/// `layer` with device keys: the device store on the pool, the resolver that
/// gives each signed-in browser a device, and the key service. Returns the
/// layer and the key service, whose routes the caller merges into the
/// router inside the session layer. The browser posts to them itself, with
/// no form token; the session layer marks such a request, and the CSRF
/// layer lets it through.
///
/// Without an origin nothing is added and no key service is returned: the
/// layer then has no key service, so it binds nothing, offers nothing, and
/// refuses a session that was bound to a key while the origin was known.
pub async fn with_device_keys<S: SessionStore>(
    layer: SessionLayer<S>,
    wiring: Wiring<'_>,
) -> (SessionLayer<S>, Option<DeviceKeyService<SqliteDeviceStore>>) {
    let Wiring {
        pool,
        clock,
        serving,
        sinks,
        audit,
    } = wiring;
    let Some(origin) = origin_of(serving) else {
        tracing::error!(
            "built with device keys and serving none: the application is reached over HTTPS \
             and {ORIGIN_ENV} does not name its origin. Set {ORIGIN_ENV} (for example \
             https://app.example), or run the development server on plain HTTP"
        );
        return (layer, None);
    };
    // The device rows are sealed at rest under a key of their own, and the
    // fingerprint is an HMAC under a secret pepper. Both are drawn per start
    // here, as the session keys are; a deployment loads them from a secrets
    // manager so devices survive a restart.
    let mut store_key = [0u8; 32];
    let mut pepper = [0u8; 32];
    SystemRng.fill_bytes(&mut store_key);
    SystemRng.fill_bytes(&mut pepper);
    let devices = SqliteDeviceStore::new(
        pool.clone(),
        SessionCrypto::new(store_key).with_clock(clock.clone()),
    );
    devices
        .init_schema()
        .await
        .expect("failed to create the device tables");

    // The default tenant hook reads the tenant the login stored in the
    // session, so a browser gets a device on its first signed-in request.
    // Device rows and key rows go to the audit trail the logins go to.
    let extractor = DefaultFingerprintExtractor::new(Arc::new(move |_: &TenantId| pepper));
    let lifecycle = DeviceLifecycleService::new(devices.clone())
        .with_event_sink(IdentityStoreEventSink::new(audit.clone()));
    let mut resolver = LifecycleDeviceResolver::new(extractor, lifecycle, clock);
    let base = if serving.secure {
        DeviceKeyConfig::new(origin)
    } else {
        resolver = resolver.with_cookie(DeviceCookieConfig::insecure_for_local_development());
        DeviceKeyConfig::insecure_for_local_development(origin)
    };
    // The strict profile's proof and challenge lifetimes, as the rest of the
    // application runs on that profile.
    let config = SecurityProfile::Strict
        .values()
        .device_key_config(base)
        .with_policy(KeyBindingPolicy::Prefer);
    let keys = DeviceKeyService::new(devices, config)
        .unwrap_or_else(|fault| panic!("the device-key settings are refused: {fault}"))
        .with_metrics(sinks.clone())
        .with_event_sink(IdentityStoreEventSink::new(audit));
    let layer = layer
        .with_device_resolver(resolver)
        .with_device_keys(keys.clone());
    (layer, Some(keys))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn serving(secure: bool, origin: Option<&str>) -> Serving {
        Serving {
            secure,
            origin: origin.map(str::to_owned),
        }
    }

    /// The origin is the one the deployment named; without a name it is the
    /// address the binary listens on only when that is how it is reached.
    #[test]
    fn the_origin_is_named_or_is_the_plain_http_listener() {
        assert_eq!(
            origin_of(&serving(true, Some("https://app.example"))).as_deref(),
            Some("https://app.example")
        );
        assert_eq!(
            origin_of(&serving(false, Some("http://dev.example:8080"))).as_deref(),
            Some("http://dev.example:8080")
        );
        assert_eq!(
            origin_of(&serving(false, None)),
            Some(format!("http://{LISTEN_ADDR}"))
        );
        assert_eq!(origin_of(&serving(true, None)), None);
    }
}
