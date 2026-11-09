//! The security profile: `Standard` restates the library's defaults, `Strict`
//! yields exactly the documented values, and each application method writes
//! the value it names and nothing else.

use std::time::Duration;

use axess_core::middleware::csrf::CsrfConfig;
use axess_core::profile::{ProfileError, SecurityProfile};
use axess_core::session::config::{SameSite, SessionConfig};
use axess_core::session::refresh::RefreshTokenConfig;

#[cfg(all(feature = "memory", feature = "testing"))]
mod common;

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;

#[test]
fn standard_restates_the_session_and_refresh_defaults() {
    let p = SecurityProfile::Standard.values();
    let session = p.session_config_builder().build();
    let default = SessionConfig::default();
    assert_eq!(session.ttl(), default.ttl());
    assert_eq!(
        session.max_authenticated_age(),
        default.max_authenticated_age()
    );
    let refresh = p.refresh_config(RefreshTokenConfig::default());
    let default = RefreshTokenConfig::default();
    assert_eq!(refresh.ttl, default.ttl);
    assert_eq!(refresh.max_lifetime, default.max_lifetime);
}

#[test]
fn strict_yields_the_documented_session_and_refresh_values() {
    let p = SecurityProfile::Strict.values();
    let session = p.session_config_builder().build();
    assert_eq!(session.ttl(), Duration::from_secs(15 * MINUTE));
    assert_eq!(
        session.max_authenticated_age(),
        Some(Duration::from_secs(8 * HOUR))
    );
    let refresh = p.refresh_config(RefreshTokenConfig::default());
    assert_eq!(refresh.ttl, chrono::Duration::hours(24));
    assert_eq!(refresh.max_lifetime, Some(chrono::Duration::days(7)));
    assert!(
        refresh.validate().is_ok(),
        "the strict pair is a valid pair"
    );
}

#[test]
fn strict_leaves_what_it_does_not_name() {
    let p = SecurityProfile::Strict.values();
    let session = p
        .session_config_builder()
        .cookie_name("app.sid")
        .same_site(SameSite::Strict)
        .build();
    assert_eq!(session.cookie_name(), "app.sid");
    assert_eq!(session.same_site(), SameSite::Strict);
    let base = RefreshTokenConfig {
        max_per_user: 3,
        ..RefreshTokenConfig::default()
    };
    assert_eq!(p.refresh_config(base).max_per_user, 3);
}

#[test]
fn an_overridden_value_is_the_one_applied() {
    let mut p = SecurityProfile::Strict.values();
    p.session_idle_ttl = Duration::from_secs(30 * MINUTE);
    assert_eq!(
        p.session_config_builder().build().ttl(),
        Duration::from_secs(30 * MINUTE)
    );
}

#[test]
fn strict_values_read_back_as_documented() {
    let p = SecurityProfile::Strict.values();
    assert_eq!(p.fido2_max_authn_age, Some(Duration::from_secs(5 * MINUTE)));
    assert_eq!(p.jwt_leeway, Duration::from_secs(30));
    assert_eq!(p.jwt_expected_typ.as_deref(), Some("at+jwt"));
    assert!(p.logout_typ_required);
    assert!(p.egress_screened);
    assert_eq!(p.device_cache_ttl, Duration::from_secs(5));
    assert_eq!(p.device_cookie_max_age, Duration::from_secs(90 * DAY));
    assert!(p.csrf_origin_check_required);
    assert_eq!(p.ws_max_lifetime, Some(Duration::from_secs(8 * HOUR)));
    assert_eq!(p.argon2_cost.m_cost_kib(), 64 * 1024);
    assert_eq!(p.argon2_cost.t_cost(), 2);
    assert_eq!(p.argon2_cost.p_cost(), 1);
    assert_eq!(p.password_reset_ttl, Some(Duration::from_secs(30 * MINUTE)));
    assert_eq!(p.max_password_reset_ttl, Duration::from_secs(HOUR));
    assert_eq!(
        p.impersonation_max_authn_age,
        Some(Duration::from_secs(15 * MINUTE))
    );
    assert_eq!(p.auth_rate_limit_max_requests, 15);
    assert_eq!(p.auth_rate_limit_window, Duration::from_secs(MINUTE));
}

#[test]
fn standard_values_read_back_as_the_defaults() {
    let p = SecurityProfile::Standard.values();
    assert_eq!(p.fido2_max_authn_age, None);
    assert_eq!(p.jwt_leeway, Duration::from_secs(MINUTE));
    assert_eq!(p.jwt_expected_typ, None);
    assert!(!p.logout_typ_required);
    assert!(!p.egress_screened);
    assert!(!p.csrf_origin_check_required);
    assert_eq!(p.argon2_cost, axess_factors::Argon2Cost::default());
    assert_eq!(p.password_reset_ttl, None);
    assert_eq!(p.max_password_reset_ttl, Duration::from_secs(7 * DAY));
    assert_eq!(p.impersonation_max_authn_age, None);
}

#[test]
fn the_rate_limit_builder_carries_the_budget() {
    let config = SecurityProfile::Strict
        .values()
        .auth_rate_limit_builder()
        .build();
    assert_eq!(config.max_requests, 15);
    assert_eq!(config.window, Duration::from_secs(MINUTE));
    let config = SecurityProfile::Standard
        .values()
        .auth_rate_limit_builder()
        .build();
    assert_eq!(config.max_requests, 100);
}

#[test]
fn strict_csrf_refuses_an_empty_origin_list() {
    let p = SecurityProfile::Strict.values();
    let none: [&str; 0] = [];
    assert_eq!(
        p.csrf_config(CsrfConfig::new([7; 32]), &none).err(),
        Some(ProfileError::CsrfOriginsRequired)
    );
}

#[test]
fn strict_csrf_refuses_an_entry_that_is_not_an_origin() {
    let p = SecurityProfile::Strict.values();
    let err = p
        .csrf_config(
            CsrfConfig::new([7; 32]),
            &["https://app.example", "app.example"],
        )
        .err();
    assert_eq!(
        err,
        Some(ProfileError::CsrfOriginInvalid("app.example".to_owned()))
    );
}

#[test]
fn csrf_accepts_the_applications_own_origins() {
    let p = SecurityProfile::Strict.values();
    assert!(
        p.csrf_config(CsrfConfig::new([7; 32]), &["https://app.example"])
            .is_ok()
    );
}

#[test]
fn standard_csrf_leaves_the_check_off_when_no_origin_is_named() {
    let p = SecurityProfile::Standard.values();
    let none: [&str; 0] = [];
    assert!(p.csrf_config(CsrfConfig::new([7; 32]), &none).is_ok());
}

#[cfg(feature = "device")]
#[test]
fn device_values_apply_and_read_back() {
    use axess_core::device::{CachedDeviceStore, DeviceCookieConfig, MemoryDeviceStore};
    let standard = SecurityProfile::Standard.values();
    assert_eq!(
        standard
            .device_cookie_config(DeviceCookieConfig::default())
            .max_age(),
        DeviceCookieConfig::default().max_age()
    );
    assert_eq!(
        standard
            .cached_device_store(MemoryDeviceStore::default())
            .ttl(),
        CachedDeviceStore::new(MemoryDeviceStore::default()).ttl()
    );
    let strict = SecurityProfile::Strict.values();
    assert_eq!(
        strict
            .device_cookie_config(DeviceCookieConfig::default())
            .max_age(),
        Duration::from_secs(90 * DAY)
    );
    assert_eq!(
        strict
            .cached_device_store(MemoryDeviceStore::default())
            .ttl(),
        Duration::from_secs(5)
    );
}

#[cfg(feature = "ws")]
#[test]
fn the_socket_lifetime_applies() {
    use axess_core::middleware::ws::WatchOptions;
    let standard = SecurityProfile::Standard
        .values()
        .watch_options(WatchOptions::default());
    assert_eq!(standard, WatchOptions::default());
    let strict = SecurityProfile::Strict
        .values()
        .watch_options(WatchOptions::default());
    assert_eq!(strict.max_lifetime, Some(Duration::from_secs(8 * HOUR)));
    assert_eq!(strict.poll_interval, WatchOptions::default().poll_interval);
}

#[cfg(feature = "fido2")]
#[test]
fn the_passkey_recency_applies() {
    use axess_core::authn::factor::Fido2Options;
    let standard = SecurityProfile::Standard
        .values()
        .fido2_options(Fido2Options::default());
    assert_eq!(
        standard.max_authn_age,
        Fido2Options::default().max_authn_age
    );
    let strict = SecurityProfile::Strict
        .values()
        .fido2_options(Fido2Options::default());
    assert_eq!(strict.max_authn_age, Some(Duration::from_secs(5 * MINUTE)));
    assert_eq!(
        strict.ceremony_timeout,
        Fido2Options::default().ceremony_timeout
    );
}

#[cfg(feature = "jwt")]
#[test]
fn the_jwt_leeway_applies() {
    use axess_factors::jwt::verifier::JwtVerifier;
    use std::sync::{Arc, RwLock};
    let jwks = Arc::new(RwLock::new(Default::default()));
    let standard = SecurityProfile::Standard
        .values()
        .jwt_verifier(JwtVerifier::new(Arc::clone(&jwks)));
    assert_eq!(
        standard.clock_skew(),
        JwtVerifier::new(jwks.clone()).clock_skew()
    );
    let strict = SecurityProfile::Strict
        .values()
        .jwt_verifier(JwtVerifier::new(jwks));
    assert_eq!(strict.clock_skew(), Duration::from_secs(30));
}

#[cfg(all(feature = "memory", feature = "testing"))]
mod service {
    use super::*;
    use axess_core::authn::AuditContext;
    use axess_core::authn::error::AuthnError;
    use axess_core::authn::service::AuthnService;
    use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};

    use super::common;

    fn service(
        profile: SecurityProfile,
    ) -> axess_core::authn::RequestAuthnService<MockIdentityStore, MockFactorStore> {
        let identity = MockIdentityStore::new()
            .with_tenant(common::test_tenant())
            .with_user(common::test_user("u1", "alice"));
        profile
            .values()
            .authn_service_builder(AuthnService::builder(identity, MockFactorStore::new()))
            .build()
            .with_audit_context(AuditContext::default())
    }

    #[tokio::test]
    async fn strict_configures_the_reset_lifetime_and_cap() {
        let svc = service(SecurityProfile::Strict);
        assert!(
            svc.begin_password_reset_with_default_ttl("alice", "default")
                .await
                .unwrap()
                .is_some()
        );
        let over = svc
            .begin_password_reset("alice", "default", Duration::from_secs(HOUR + 1))
            .await;
        assert!(matches!(over, Err(AuthnError::Internal(_))));
    }

    #[tokio::test]
    async fn standard_configures_no_default_reset_lifetime() {
        let svc = service(SecurityProfile::Standard);
        let refused = svc
            .begin_password_reset_with_default_ttl("alice", "default")
            .await;
        assert!(matches!(refused, Err(AuthnError::Internal(_))));
        assert!(
            svc.begin_password_reset("alice", "default", Duration::from_secs(7 * DAY))
                .await
                .unwrap()
                .is_some()
        );
    }
}
