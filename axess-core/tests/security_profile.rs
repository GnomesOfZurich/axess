//! The security profile: `Standard` restates the library's defaults, `Strict`
//! yields exactly the documented values, each application method writes the
//! value it names and nothing else, and applying a profile never loosens:
//! every ordered setting comes out as the tighter of the configuration's own
//! value and the profile's, and applying twice is applying once. A service
//! builder put under a profile is held to it when the service is built: a
//! setting looser than the profile's is refused by name unless the caller
//! waived that setting, and a waived one is read back from the service.

use std::time::Duration;

use axess_core::middleware::csrf::CsrfConfig;
use axess_core::profile::{ProfileError, SecurityProfile};
use axess_core::session::config::{SameSite, SessionConfig};
use axess_core::session::refresh::RefreshTokenConfig;

#[cfg(all(feature = "memory", feature = "testing"))]
use axess_core::testing::fixtures as common;

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
    assert_eq!(refresh.ttl, Duration::from_hours(24));
    assert_eq!(refresh.max_lifetime, Some(Duration::from_hours(7 * 24)));
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
    assert_eq!(p.fido2_max_authn_age, Some(Duration::from_secs(5 * MINUTE)));
    assert_eq!(p.jwt_leeway, Duration::from_secs(MINUTE));
    assert_eq!(p.jwt_expected_typ, None);
    assert!(!p.logout_typ_required);
    assert!(
        p.egress_screened,
        "the library screens its egress by default"
    );
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

#[cfg(all(feature = "device", feature = "memory", feature = "testing"))]
#[test]
fn device_values_apply_and_read_back() {
    let clock = common::test_clock();
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
            .with_clock(std::sync::Arc::new(clock.clone()))
            .ttl(),
        CachedDeviceStore::new(MemoryDeviceStore::default())
            .with_clock(std::sync::Arc::new(clock.clone()))
            .ttl()
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
            .with_clock(std::sync::Arc::new(clock.clone()))
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

#[cfg(all(feature = "fido2", feature = "memory", feature = "testing"))]
#[test]
fn applying_the_profile_keeps_the_builders_own_fido2_options() {
    let clock = common::test_clock();
    use axess_core::authn::factor::{DiscoverableCredential, Fido2Options};
    use axess_core::authn::service::AuthnService;
    use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
    use axess_factors::fido2::Fido2Ceremony;
    let attested = Fido2Ceremony::AttestedPasskey {
        trust_anchor: "bank-ca".to_owned(),
    };
    let own = Fido2Options {
        ceremony_timeout: Duration::from_secs(60),
        max_authn_age: None,
        registration_ceremony: attested.clone(),
        login_ceremony: attested.clone(),
        discoverable_credential: DiscoverableCredential::Required,
    };
    for profile in [SecurityProfile::Standard, SecurityProfile::Strict] {
        let builder = AuthnService::builder(
            MockIdentityStore::new().with_clock(clock.clone()),
            MockFactorStore::new(),
        )
        .with_clock(clock.clone())
        .with_fido2_options(own.clone());
        let applied = profile.values().authn_service_builder(builder);
        let options = applied.fido2_options();
        assert_eq!(
            options.registration_ceremony, attested,
            "{profile:?} downgraded the registration ceremony"
        );
        assert_eq!(
            options.login_ceremony, attested,
            "{profile:?} downgraded the login ceremony"
        );
        assert_eq!(
            options.ceremony_timeout,
            Duration::from_secs(60),
            "{profile:?} reset the ceremony timeout"
        );
        assert_eq!(
            options.discoverable_credential,
            DiscoverableCredential::Required,
            "{profile:?} reset the discoverable-credential choice"
        );
        assert_eq!(
            options.max_authn_age,
            profile.values().fido2_max_authn_age,
            "{profile:?} is the one field the profile sets"
        );
    }
}

#[cfg(all(feature = "jwt", feature = "memory", feature = "testing"))]
#[test]
fn the_jwt_leeway_applies() {
    let clock = common::test_clock();
    use axess_factors::jwt::verifier::JwtVerifier;
    use std::sync::{Arc, RwLock};
    let jwks = Arc::new(RwLock::new(Default::default()));
    let standard = SecurityProfile::Standard.values().access_token_verifier(
        JwtVerifier::new(Arc::clone(&jwks)).with_clock(std::sync::Arc::new(clock.clone())),
    );
    assert_eq!(
        standard.clock_skew(),
        JwtVerifier::new(jwks.clone())
            .with_clock(std::sync::Arc::new(clock.clone()))
            .clock_skew()
    );
    assert_eq!(standard.expected_typ(), None, "Standard requires no typ");
    let strict = SecurityProfile::Strict.values().access_token_verifier(
        JwtVerifier::new(Arc::clone(&jwks)).with_clock(std::sync::Arc::new(clock.clone())),
    );
    assert_eq!(strict.clock_skew(), Duration::from_secs(30));
    assert_eq!(strict.expected_typ(), Some("at+jwt"));
    let leeway_only = SecurityProfile::Strict
        .values()
        .jwt_leeway_only(JwtVerifier::new(jwks).with_clock(std::sync::Arc::new(clock.clone())));
    assert_eq!(leeway_only.clock_skew(), Duration::from_secs(30));
    assert_eq!(leeway_only.expected_typ(), None);
}

/// A verifier of logout tokens or ID tokens is not retyped to the access
/// token's `typ`: the leeway-only method keeps the requirement it carries.
#[cfg(all(feature = "jwt", feature = "memory", feature = "testing"))]
#[test]
fn the_leeway_only_method_keeps_the_verifiers_own_typ() {
    let clock = common::test_clock();
    use axess_factors::jwt::verifier::JwtVerifier;
    use std::sync::{Arc, RwLock};
    let jwks = Arc::new(RwLock::new(Default::default()));
    let logout = JwtVerifier::new(Arc::clone(&jwks))
        .with_clock(std::sync::Arc::new(clock.clone()))
        .with_typ("logout+jwt");
    let strict = SecurityProfile::Strict.values().jwt_leeway_only(logout);
    assert_eq!(strict.expected_typ(), Some("logout+jwt"));
    assert_eq!(strict.clock_skew(), Duration::from_secs(30));
    let retyped = SecurityProfile::Strict.values().access_token_verifier(
        JwtVerifier::new(jwks)
            .with_clock(std::sync::Arc::new(clock.clone()))
            .with_typ("logout+jwt"),
    );
    assert_eq!(
        retyped.expected_typ(),
        Some("at+jwt"),
        "the access-token method assigns the profile's typ, which is why it is named for it"
    );
}

/// Both profiles hand the discovery entry points the policy they use when
/// none is named: the standard profile restates the default, it does not
/// loosen it. The opt-out is a field the adopter assigns.
#[cfg(feature = "oauth")]
#[test]
fn both_profiles_screen_egress_as_the_library_does_by_default() {
    use axess_factors::egress::EgressPolicy;
    for profile in [SecurityProfile::Standard, SecurityProfile::Strict] {
        assert_eq!(
            profile.values().egress_policy(),
            EgressPolicy::default(),
            "{profile:?}"
        );
    }
    let mut values = SecurityProfile::Standard.values();
    values.egress_screened = false;
    assert_eq!(values.egress_policy(), EgressPolicy::unscreened());
}

/// The strict cost is the documented one, not the default a failed
/// construction would have fallen back to.
#[test]
fn the_strict_argon2_cost_is_not_the_default() {
    let strict = SecurityProfile::Strict.values().argon2_cost;
    assert_ne!(strict, axess_factors::Argon2Cost::default());
    assert_eq!(strict.m_cost_kib(), 64 * 1024);
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
        let clock = common::test_clock();
        let identity = MockIdentityStore::new()
            .with_clock(clock.clone())
            .with_tenant(common::test_tenant())
            .with_user(common::test_user("u1", "alice"));
        profile
            .values()
            .authn_service_builder(
                AuthnService::builder(identity, MockFactorStore::new()).with_clock(clock.clone()),
            )
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

// ── The service holds its profile ────────────────────────────────────────────

#[cfg(all(feature = "memory", feature = "testing"))]
mod held_at_build {
    use super::*;
    use axess_core::authn::AuditContext;
    use axess_core::authn::service::{AuthnBuildError, AuthnService, AuthnServiceBuilder};
    use axess_core::profile::ProfileSetting;
    use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
    use axess_factors::Argon2Cost;

    type Builder = AuthnServiceBuilder<MockIdentityStore, MockFactorStore>;

    fn plain(clock: &axess_clock::testing::MockClock) -> Builder {
        let identity = MockIdentityStore::new()
            .with_clock(clock.clone())
            .with_tenant(common::test_tenant())
            .with_user(common::test_user("u1", "alice"));
        AuthnService::builder(identity, MockFactorStore::new()).with_clock(clock.clone())
    }

    fn strict(clock: &axess_clock::testing::MockClock) -> Builder {
        SecurityProfile::Strict
            .values()
            .authn_service_builder(plain(clock))
    }

    /// The settings the service holds in this build: the passkey recency
    /// only where passkeys are compiled.
    fn held_settings() -> Vec<ProfileSetting> {
        ProfileSetting::ALL
            .into_iter()
            .filter(|s| cfg!(feature = "fido2") || *s != ProfileSetting::Fido2MaxAuthnAge)
            .collect()
    }

    /// `builder` with `setting` written looser than the strict profile's
    /// value, by the setter an adopter would call after the profile.
    fn loosened(builder: Builder, setting: ProfileSetting) -> Builder {
        match setting {
            ProfileSetting::Argon2Cost => builder.with_argon2_cost(Argon2Cost::default()),
            ProfileSetting::MaxPasswordResetTtl => {
                builder.with_max_password_reset_ttl(Duration::from_secs(2 * HOUR))
            }
            // Within the strict cap of one hour, above its thirty minutes.
            ProfileSetting::PasswordResetTtl => {
                builder.with_password_reset_ttl(Duration::from_secs(45 * MINUTE))
            }
            ProfileSetting::ImpersonationMaxAuthnAge => {
                builder.with_impersonation_max_authn_age(Duration::from_secs(HOUR))
            }
            ProfileSetting::Fido2MaxAuthnAge => without_passkey_recency(builder),
        }
    }

    #[cfg(feature = "fido2")]
    fn without_passkey_recency(builder: Builder) -> Builder {
        let options = axess_core::authn::factor::Fido2Options {
            max_authn_age: None,
            ..builder.fido2_options().clone()
        };
        builder.with_fido2_options(options)
    }

    #[cfg(not(feature = "fido2"))]
    fn without_passkey_recency(builder: Builder) -> Builder {
        builder
    }

    /// Every setting the profile governs, written looser by a setter called
    /// after the profile was applied, is refused when the service is built:
    /// the refusal names the profile and the setting and says how to waive
    /// it. A waiver for another setting does not cover it.
    #[tokio::test]
    async fn a_setting_loosened_after_the_profile_is_refused_by_name_at_build() {
        let clock = common::test_clock();
        for setting in held_settings() {
            let another = held_settings()
                .into_iter()
                .find(|s| *s != setting)
                .expect("more than one setting");
            for builder in [
                loosened(strict(&clock), setting),
                loosened(strict(&clock), setting).waive_profile_floor(another),
            ] {
                assert_eq!(builder.security_profile(), Some(SecurityProfile::Strict));
                let refused = builder
                    .try_build()
                    .err()
                    .unwrap_or_else(|| panic!("{setting} looser than the profile was built"));
                match &refused {
                    AuthnBuildError::BelowProfileFloor {
                        profile,
                        setting: named,
                        ..
                    } => {
                        assert_eq!(*profile, SecurityProfile::Strict);
                        assert_eq!(*named, setting);
                    }
                    other => panic!("{setting}: {other}"),
                }
                let message = refused.to_string();
                assert!(message.contains(setting.name()), "{message}");
                assert!(message.contains("SecurityProfile::Strict"), "{message}");
                assert!(message.contains("waive_profile_floor"), "{message}");
            }
        }
    }

    /// The named waiver is the one way below the profile: with it the
    /// service is built, says which profile it runs under, and lists the
    /// waived setting as the one place it does not hold it. The waiver may
    /// be written after the setter, before it, or before the profile is
    /// applied.
    #[tokio::test]
    async fn a_named_waiver_builds_the_service_and_is_read_back_from_it() {
        let clock = common::test_clock();
        for setting in held_settings() {
            let waived_first = SecurityProfile::Strict
                .values()
                .authn_service_builder(plain(&clock).waive_profile_floor(setting));
            for builder in [
                loosened(strict(&clock), setting).waive_profile_floor(setting),
                loosened(strict(&clock).waive_profile_floor(setting), setting),
                loosened(waived_first, setting),
            ] {
                let service = builder
                    .try_build()
                    .unwrap_or_else(|refused| panic!("{setting} waived: {refused}"));
                assert_eq!(service.security_profile(), Some(SecurityProfile::Strict));
                assert_eq!(service.profile_deviations(), [setting]);
            }
        }
    }

    /// The impersonation recency can be taken off again. Under no profile
    /// that is the default and builds; under a profile that names a limit
    /// the build refuses it by name, and builds it with the waiver, which
    /// the service then lists.
    #[tokio::test]
    async fn the_impersonation_recency_can_be_cleared_and_a_profile_holds_it() {
        let clock = common::test_clock();
        let setting = ProfileSetting::ImpersonationMaxAuthnAge;
        let cleared = plain(&clock)
            .with_impersonation_max_authn_age(Duration::from_secs(300))
            .without_impersonation_max_authn_age();
        assert_eq!(cleared.impersonation_max_authn_age(), None);
        cleared.try_build().expect("no profile, no limit");

        let refused = strict(&clock)
            .without_impersonation_max_authn_age()
            .try_build()
            .err();
        assert!(
            matches!(
                &refused,
                Some(AuthnBuildError::BelowProfileFloor { setting: named, .. }) if *named == setting
            ),
            "{refused:?}"
        );
        let waived = strict(&clock)
            .without_impersonation_max_authn_age()
            .waive_profile_floor(setting)
            .try_build()
            .expect("the waiver is written out");
        assert_eq!(waived.profile_deviations(), [setting]);
    }

    /// A service that holds its profile lists no deviation: built as the
    /// profile left it, with a waiver it did not need, or with a value
    /// tightened after the profile. A service under no profile says none
    /// and is held to none.
    #[tokio::test]
    async fn a_service_that_holds_its_profile_lists_no_deviation() {
        let clock = common::test_clock();
        let tightened = strict(&clock)
            .with_max_password_reset_ttl(Duration::from_secs(30 * MINUTE))
            .with_impersonation_max_authn_age(Duration::from_secs(MINUTE));
        for builder in [
            strict(&clock),
            strict(&clock).waive_profile_floor(ProfileSetting::Argon2Cost),
            tightened,
        ] {
            let service = builder.try_build().expect("the profile holds");
            assert_eq!(service.security_profile(), Some(SecurityProfile::Strict));
            assert!(service.profile_deviations().is_empty());
        }

        let mut free = plain(&clock);
        for setting in held_settings() {
            free = loosened(free, setting);
        }
        let service = free.try_build().expect("no profile, nothing to hold");
        assert_eq!(service.security_profile(), None);
        assert!(service.profile_deviations().is_empty());
    }

    /// The builder is held to the profile the values came from, not to the
    /// values as edited: a field assigned looser before applying is refused
    /// like a setter called after.
    #[test]
    fn a_field_loosened_on_the_values_does_not_lower_the_bar() {
        let clock = common::test_clock();
        let mut values = SecurityProfile::Strict.values();
        values.max_password_reset_ttl = Duration::from_secs(3 * HOUR);
        assert_eq!(values.profile(), SecurityProfile::Strict);

        let refused = values.authn_service_builder(plain(&clock)).validate();

        assert!(
            matches!(
                refused,
                Err(AuthnBuildError::BelowProfileFloor {
                    profile: SecurityProfile::Strict,
                    setting: ProfileSetting::MaxPasswordResetTtl,
                    ..
                })
            ),
            "{refused:?}"
        );
    }

    /// Two profiles applied in either order leave the builder under the
    /// stricter one.
    #[test]
    fn the_stricter_profile_stays_when_two_are_applied() {
        let clock = common::test_clock();
        let (standard, strict) = (
            SecurityProfile::Standard.values(),
            SecurityProfile::Strict.values(),
        );
        for builder in [
            standard.authn_service_builder(strict.authn_service_builder(plain(&clock))),
            strict.authn_service_builder(standard.authn_service_builder(plain(&clock))),
        ] {
            assert_eq!(builder.security_profile(), Some(SecurityProfile::Strict));
            assert_eq!(builder.validate(), Ok(()));
        }
        let builder = standard.authn_service_builder(plain(&clock));
        assert_eq!(builder.security_profile(), Some(SecurityProfile::Standard));
    }

    /// A default reset lifetime above the cap is a combination that cannot
    /// work: every reset under the default would be refused. It is refused
    /// when the service is built, under a profile or not, in a sentence that
    /// names both settings.
    #[test]
    fn a_default_reset_lifetime_above_the_cap_is_refused_naming_both_settings() {
        let clock = common::test_clock();
        let (ttl, cap) = (Duration::from_secs(2 * HOUR), Duration::from_secs(HOUR));
        let refused = plain(&clock)
            .with_password_reset_ttl(ttl)
            .with_max_password_reset_ttl(cap)
            .validate();
        assert_eq!(
            refused,
            Err(AuthnBuildError::PasswordResetTtlAboveCap { ttl, cap })
        );
        let message = refused.unwrap_err().to_string();
        assert!(message.contains("with_password_reset_ttl"), "{message}");
        assert!(message.contains("with_max_password_reset_ttl"), "{message}");
    }

    /// A cap tightened before the profile does not leave the profile's
    /// default lifetime above it: the default comes out at the cap, the
    /// service builds, and a reset under the default lifetime is issued.
    #[tokio::test]
    async fn a_cap_tightened_before_the_profile_keeps_the_default_reset_working() {
        let clock = common::test_clock();
        let cap = Duration::from_secs(10 * MINUTE);
        let builder = SecurityProfile::Strict
            .values()
            .authn_service_builder(plain(&clock).with_max_password_reset_ttl(cap));
        assert_eq!(builder.max_password_reset_ttl(), cap);
        assert_eq!(builder.password_reset_ttl(), Some(cap));

        let service = builder.try_build().expect("a consistent pair");
        let issued = service
            .with_audit_context(AuditContext::default())
            .begin_password_reset_with_default_ttl("alice", "default")
            .await
            .expect("the default lifetime is within the cap");
        assert!(issued.is_some());
    }

    /// `build` is `try_build` for the start-up path: it stops the process
    /// with the refusal.
    #[tokio::test]
    #[should_panic(expected = "argon2_cost is looser than SecurityProfile::Strict")]
    async fn build_stops_on_a_setting_looser_than_the_profile() {
        let clock = common::test_clock();
        drop(
            strict(&clock)
                .with_argon2_cost(Argon2Cost::default())
                .build(),
        );
    }
}

// ── The on-or-off settings ───────────────────────────────────────────────────

/// A profile never turns the CSRF origin check off: with no origin named,
/// a profile that does not require the check returns a base that makes it
/// unchanged, and one that requires it refuses. With origins named, both
/// profiles install them.
#[test]
fn a_profile_never_turns_the_csrf_origin_check_off() {
    let checked = || CsrfConfig::new([7; 32]).require_origin(["https://app.example"]);
    let origins = |config: &CsrfConfig| -> Vec<String> {
        config
            .allowed_origins()
            .iter()
            .map(|origin| origin.to_string())
            .collect()
    };
    let none: [&str; 0] = [];

    let kept = SecurityProfile::Standard
        .values()
        .csrf_config(checked(), &none)
        .expect("nothing is required, nothing is named");
    assert_eq!(
        origins(&kept),
        ["https://app.example"],
        "the check stays on"
    );
    assert_eq!(
        SecurityProfile::Strict
            .values()
            .csrf_config(checked(), &none)
            .err(),
        Some(ProfileError::CsrfOriginsRequired),
        "the strict profile asks for the origins by name"
    );
    for profile in [SecurityProfile::Standard, SecurityProfile::Strict] {
        for base in [CsrfConfig::new([7; 32]), checked()] {
            let applied = profile
                .values()
                .csrf_config(base, &["https://other.example"])
                .expect("an origin");
            assert_eq!(origins(&applied), ["https://other.example"], "{profile:?}");
        }
    }
    let off = SecurityProfile::Standard
        .values()
        .csrf_config(CsrfConfig::new([7; 32]), &none)
        .expect("nothing is required");
    assert!(
        origins(&off).is_empty(),
        "a base without the check stays as it was"
    );
}

/// The logout-token `typ` requirement is on after the strict profile, kept
/// when the builder already had it whatever the profile, and left off by the
/// standard profile on a builder without it.
#[cfg(all(feature = "oauth", feature = "memory", feature = "testing"))]
#[tokio::test]
async fn a_profile_never_turns_the_logout_typ_requirement_off() {
    use axess_factors::egress::EgressPolicy;
    use axess_factors::oauth::OAuthProviderConfig;
    use axess_testing::oauth_wiremock::{oauth_generate_rsa_keypair, oauth_mount_oidc_endpoints};
    let clock = common::test_clock();
    let server = wiremock::MockServer::start().await;
    let jwk = oauth_generate_rsa_keypair().1;
    oauth_mount_oidc_endpoints(&server, &jwk).await;
    let discovered = || async {
        OAuthProviderConfig::discover_screened(
            "sso",
            &server.uri(),
            "client",
            "secret",
            "http://localhost:3000/callback",
            EgressPolicy::screened_allowing_loopback_http(),
        )
        .await
        .expect("discovery")
        .with_clock(std::sync::Arc::new(clock.clone()))
    };
    let (standard, strict) = (
        SecurityProfile::Standard.values(),
        SecurityProfile::Strict.values(),
    );

    assert!(!discovered().await.requires_logout_typ(), "off by default");
    assert!(
        strict
            .oauth_provider(discovered().await)
            .requires_logout_typ()
    );
    assert!(
        !standard
            .oauth_provider(discovered().await)
            .requires_logout_typ()
    );
    let required = discovered().await.with_required_logout_typ();
    assert!(
        standard.oauth_provider(required).requires_logout_typ(),
        "a requirement the builder had survives a profile that does not ask for it"
    );
    let twice = strict.oauth_provider(strict.oauth_provider(discovered().await));
    assert!(twice.requires_logout_typ());
}

// ── Applying a profile never loosens ─────────────────────────────────────────

/// A value tightened before the profile is applied survives it, on every
/// configuration that carries a value of its own.
#[test]
fn a_tighter_value_set_before_the_profile_survives_it() {
    let strict = SecurityProfile::Strict.values();
    let own = RefreshTokenConfig {
        ttl: std::time::Duration::from_hours(1),
        max_lifetime: Some(std::time::Duration::from_hours(12)),
        ..RefreshTokenConfig::default()
    };
    let refresh = strict.refresh_config(own);
    assert_eq!(refresh.ttl, Duration::from_hours(1));
    assert_eq!(refresh.max_lifetime, Some(Duration::from_hours(12)));
    assert!(refresh.validate().is_ok());
}

/// A value looser than the profile's, or no limit at all, comes out as the
/// profile's.
#[test]
fn a_looser_value_set_before_the_profile_is_tightened_to_it() {
    let strict = SecurityProfile::Strict.values();
    let own = RefreshTokenConfig {
        ttl: std::time::Duration::from_hours(60 * 24),
        max_lifetime: None,
        ..RefreshTokenConfig::default()
    };
    let refresh = strict.refresh_config(own);
    assert_eq!(refresh.ttl, Duration::from_hours(24));
    assert_eq!(refresh.max_lifetime, Some(Duration::from_hours(7 * 24)));
}

/// A profile whose passkey recency is `None` names no limit: the options
/// keep theirs, the library's five minutes included.
#[cfg(feature = "fido2")]
#[test]
fn a_profile_without_a_passkey_recency_leaves_the_options_their_own() {
    use axess_core::authn::factor::Fido2Options;
    let mut values = SecurityProfile::Strict.values();
    values.fido2_max_authn_age = None;
    let applied = values.fido2_options(Fido2Options::default());
    assert_eq!(
        applied.max_authn_age,
        Fido2Options::default().max_authn_age,
        "a profile that names no limit does not remove the one in force"
    );
}

/// A JWT leeway and a device cookie lifetime tightened before the profile
/// stay as set.
#[cfg(all(
    feature = "jwt",
    feature = "device",
    feature = "memory",
    feature = "testing"
))]
#[test]
fn a_tighter_leeway_and_cookie_lifetime_survive_the_profile() {
    let clock = common::test_clock();
    use axess_core::device::DeviceCookieConfig;
    use axess_factors::jwt::verifier::JwtVerifier;
    use std::sync::{Arc, RwLock};
    let strict = SecurityProfile::Strict.values();
    let verifier = JwtVerifier::new(Arc::new(RwLock::new(Default::default())))
        .with_clock(Arc::new(clock.clone()))
        .with_clock_skew(Duration::from_secs(5));
    assert_eq!(
        strict.access_token_verifier(verifier).clock_skew(),
        Duration::from_secs(5)
    );
    let cookie = DeviceCookieConfig::default().with_max_age(Duration::from_secs(DAY));
    assert_eq!(
        strict.device_cookie_config(cookie).max_age(),
        Duration::from_secs(DAY)
    );
}

#[cfg(all(feature = "memory", feature = "testing"))]
mod never_loosens {
    use super::*;
    use axess_core::authn::service::{AuthnService, AuthnServiceBuilder};
    use axess_core::profile::ProfileValues;
    use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
    use axess_factors::Argon2Cost;
    use proptest::prelude::*;

    type Builder = AuthnServiceBuilder<MockIdentityStore, MockFactorStore>;

    /// Whole seconds from one second to 500 days: every lifetime a profile
    /// names and every library default lies inside.
    fn secs() -> impl Strategy<Value = u64> {
        1..=500 * DAY
    }

    fn duration() -> impl Strategy<Value = Duration> {
        secs().prop_map(Duration::from_secs)
    }

    /// A limit that may be absent.
    fn limit() -> impl Strategy<Value = Option<Duration>> {
        proptest::option::of(duration())
    }

    /// A cost at or above the floor: one to four times the pinned memory,
    /// two to four passes, one or two lanes. Building one hashes nothing.
    fn cost() -> impl Strategy<Value = Argon2Cost> {
        (1u32..=4, 2u32..=4, 1u32..=2).prop_map(|(m, t, p)| {
            Argon2Cost::new(m * axess_factors::password::ARGON2_M_COST_KIB, t, p)
                .expect("above the floor and within range")
        })
    }

    /// The account settings a profile writes on a service builder: what a
    /// builder holds before the profile is applied, and what is read back
    /// from it after.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Account {
        cost: Argon2Cost,
        reset_ttl: Option<Duration>,
        reset_cap: Duration,
        impersonation: Option<Duration>,
    }

    fn account() -> impl Strategy<Value = Account> {
        (cost(), limit(), duration(), limit()).prop_map(
            |(cost, reset_ttl, reset_cap, impersonation)| Account {
                cost,
                reset_ttl,
                reset_cap,
                impersonation,
            },
        )
    }

    /// A profile with every ordered setting drawn at random, on top of the
    /// strict set for the rest.
    fn values() -> impl Strategy<Value = ProfileValues> {
        (
            (duration(), limit(), limit(), 0..=300u64),
            (duration(), limit(), cost()),
            (limit(), duration(), limit()),
            proptest::option::of(prop_oneof![Just("at+jwt"), Just("jwt")]),
            (60..=HOUR, 60..=2 * HOUR),
        )
            .prop_map(|(tokens, device, account, typ, keys)| {
                let mut values = SecurityProfile::Strict.values();
                values.refresh_ttl = tokens.0;
                values.refresh_max_lifetime = tokens.1;
                values.fido2_max_authn_age = tokens.2;
                values.jwt_leeway = Duration::from_secs(tokens.3);
                values.device_cookie_max_age = device.0;
                values.ws_max_lifetime = device.1;
                values.argon2_cost = device.2;
                values.password_reset_ttl = account.0;
                values.max_password_reset_ttl = account.1;
                values.impersonation_max_authn_age = account.2;
                values.jwt_expected_typ = typ.map(str::to_owned);
                values.device_key_proof_ttl = Duration::from_secs(keys.0);
                values.device_key_challenge_ttl = Duration::from_secs(keys.1);
                values
            })
    }

    /// Whether `result` is at least as tight as `other`, for a limit where
    /// `None` is no limit.
    fn no_looser<T: Ord>(result: Option<T>, other: Option<T>) -> bool {
        match (result, other) {
            (_, None) => true,
            (Some(result), Some(other)) => result <= other,
            (None, Some(_)) => false,
        }
    }

    /// The tighter of two limits, written out the long way so the property
    /// does not restate the code under test.
    fn tighter<T: Ord + Copy>(a: Option<T>, b: Option<T>) -> Option<T> {
        match (a, b) {
            (None, None) => None,
            (Some(only), None) | (None, Some(only)) => Some(only),
            (Some(a), Some(b)) => Some(if a <= b { a } else { b }),
        }
    }

    fn builder_with(clock: &axess_clock::testing::MockClock, own: &Account) -> Builder {
        let mut builder = AuthnService::builder(
            MockIdentityStore::new().with_clock(clock.clone()),
            MockFactorStore::new(),
        )
        .with_clock(clock.clone())
        .with_argon2_cost(own.cost)
        .with_max_password_reset_ttl(own.reset_cap);
        if let Some(ttl) = own.reset_ttl {
            builder = builder.with_password_reset_ttl(ttl);
        }
        if let Some(age) = own.impersonation {
            builder = builder.with_impersonation_max_authn_age(age);
        }
        builder
    }

    fn read(builder: &Builder) -> Account {
        Account {
            cost: builder.argon2_cost(),
            reset_ttl: builder.password_reset_ttl(),
            reset_cap: builder.max_password_reset_ttl(),
            impersonation: builder.impersonation_max_authn_age(),
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 256,
            ..ProptestConfig::default()
        })]

        /// The refresh lifetimes come out as the tighter of the two, a pair
        /// that was valid stays valid, and a second application changes
        /// nothing.
        #[test]
        fn the_refresh_lifetimes_are_the_tighter_and_stable(
            p in values(),
            own_ttl in duration(),
            own_max in limit(),
        ) {
            let base = RefreshTokenConfig {
                ttl: own_ttl,
                max_lifetime: own_max,
                ..RefreshTokenConfig::default()
            };
            let once = p.refresh_config(base.clone());
            prop_assert!(once.ttl <= base.ttl && once.ttl <= p.refresh_ttl);
            prop_assert!(once.ttl == base.ttl || once.ttl == p.refresh_ttl);
            prop_assert_eq!(
                once.max_lifetime,
                tighter(base.max_lifetime, p.refresh_max_lifetime)
            );
            prop_assert!(no_looser(once.max_lifetime, base.max_lifetime));
            prop_assert!(no_looser(once.max_lifetime, p.refresh_max_lifetime));
            let both_valid = base.max_lifetime.is_none_or(|max| max >= base.ttl)
                && p.refresh_max_lifetime.is_none_or(|max| max >= p.refresh_ttl);
            if both_valid {
                prop_assert!(once.validate().is_ok(), "two valid pairs gave an invalid one");
            }
            let twice = p.refresh_config(once.clone());
            prop_assert_eq!(twice.ttl, once.ttl);
            prop_assert_eq!(twice.max_lifetime, once.max_lifetime);
        }

        /// The account settings a profile writes on a service builder are
        /// each the tighter of the two, none comes out looser than the
        /// builder had it or than the values applied, the default reset
        /// lifetime is never left above the cap, and a second application
        /// changes nothing.
        #[test]
        fn the_service_builder_is_never_loosened_and_is_stable(p in values(), own in account()) {
            let clock = common::test_clock();
            let before = read(&builder_with(&clock, &own));
            prop_assert_eq!(&before, &own, "the getters read what the setters wrote");
            let once = p.authn_service_builder(builder_with(&clock, &own));
            let after = read(&once);

            prop_assert_eq!(after.reset_cap, before.reset_cap.min(p.max_password_reset_ttl));
            prop_assert_eq!(
                after.impersonation,
                tighter(before.impersonation, p.impersonation_max_authn_age)
            );
            prop_assert!(no_looser(after.impersonation, before.impersonation));
            // A default reset lifetime is configured or not; among
            // configured ones the shorter is kept, and never above the cap.
            let chosen = tighter(before.reset_ttl, p.password_reset_ttl);
            prop_assert_eq!(after.reset_ttl, chosen.map(|ttl| ttl.min(after.reset_cap)));
            prop_assert!(after.reset_ttl.is_none_or(|ttl| ttl <= after.reset_cap));
            prop_assert!(no_looser(after.reset_ttl, before.reset_ttl));
            // No component of the cost falls, on either side, and the lanes
            // stay the builder's.
            let (m, t) = (after.cost.m_cost_kib(), after.cost.t_cost());
            prop_assert_eq!(m, before.cost.m_cost_kib().max(p.argon2_cost.m_cost_kib()));
            prop_assert_eq!(t, before.cost.t_cost().max(p.argon2_cost.t_cost()));
            prop_assert_eq!(after.cost.p_cost(), before.cost.p_cost());
            prop_assert!(after.cost.is_at_least(before.cost), "the cost fell: {:?}", after.cost);
            prop_assert!(after.cost.is_at_least(p.argon2_cost));

            let twice = p.authn_service_builder(once);
            prop_assert_eq!(read(&twice), after);
        }

        /// A builder put under either profile, whatever it held before,
        /// holds every setting the profile governs: nothing is left for the
        /// build to refuse, and the builder says which profile it is under.
        #[test]
        fn a_builder_put_under_a_profile_holds_it(own in account(), strict in any::<bool>()) {
            let clock = common::test_clock();
            let profile = if strict { SecurityProfile::Strict } else { SecurityProfile::Standard };
            let applied = profile.values().authn_service_builder(builder_with(&clock, &own));
            prop_assert_eq!(applied.validate(), Ok(()));
            prop_assert_eq!(applied.security_profile(), Some(profile));
            let floor = profile.values();
            let held = read(&applied);
            prop_assert!(held.cost.is_at_least(floor.argon2_cost));
            prop_assert!(held.reset_cap <= floor.max_password_reset_ttl);
            prop_assert!(no_looser(held.impersonation, floor.impersonation_max_authn_age));
        }
    }

    #[cfg(feature = "fido2")]
    proptest! {
        /// The passkey-change recency is the tighter of the two, on the
        /// options and on a service builder that holds them, and stable.
        #[test]
        fn the_passkey_recency_is_the_tighter_and_stable(p in values(), own in limit()) {
            use axess_core::authn::factor::Fido2Options;
            let clock = common::test_clock();
            let want = tighter(own, p.fido2_max_authn_age);
            let base = Fido2Options { max_authn_age: own, ..Fido2Options::default() };
            let once = p.fido2_options(base.clone());
            prop_assert_eq!(once.max_authn_age, want);
            prop_assert!(no_looser(once.max_authn_age, own));
            prop_assert_eq!(once.ceremony_timeout, base.ceremony_timeout);
            prop_assert_eq!(p.fido2_options(once).max_authn_age, want);

            let builder = AuthnService::builder(
                MockIdentityStore::new().with_clock(clock.clone()),
                MockFactorStore::new(),
            )
            .with_clock(clock.clone())
            .with_fido2_options(base);
            let applied = p.authn_service_builder(builder);
            prop_assert_eq!(applied.fido2_options().max_authn_age, want);
            let again = p.authn_service_builder(applied);
            prop_assert_eq!(again.fido2_options().max_authn_age, want);
        }
    }

    #[cfg(feature = "jwt")]
    proptest! {
        /// The clock-skew tolerance is the smaller of the two under both
        /// verifier methods and stable; the leeway-only method keeps the
        /// verifier's `typ`, and the access-token method assigns the
        /// profile's when it names one and keeps the verifier's otherwise.
        #[test]
        fn the_jwt_leeway_is_the_smaller_and_stable(
            p in values(),
            own_skew in 0..=300u64,
            own_typ in proptest::option::of(prop_oneof![Just("logout+jwt"), Just("at+jwt")]),
        ) {
            use axess_factors::jwt::verifier::JwtVerifier;
            use std::sync::{Arc, RwLock};
            let clock = common::test_clock();
            let own_skew = Duration::from_secs(own_skew);
            let verifier = || {
                let verifier = JwtVerifier::new(Arc::new(RwLock::new(Default::default())))
                    .with_clock(Arc::new(clock.clone()))
                    .with_clock_skew(own_skew);
                match own_typ {
                    Some(typ) => verifier.with_typ(typ),
                    None => verifier,
                }
            };
            let want = own_skew.min(p.jwt_leeway);

            let leeway_only = p.jwt_leeway_only(verifier());
            prop_assert_eq!(leeway_only.clock_skew(), want);
            prop_assert_eq!(leeway_only.expected_typ(), own_typ);
            let again = p.jwt_leeway_only(leeway_only);
            prop_assert_eq!(again.clock_skew(), want);
            prop_assert_eq!(again.expected_typ(), own_typ);

            let access = p.access_token_verifier(verifier());
            prop_assert_eq!(access.clock_skew(), want);
            let typ = p.jwt_expected_typ.as_deref().or(own_typ);
            prop_assert_eq!(access.expected_typ(), typ);
            prop_assert!(
                own_typ.is_none() || access.expected_typ().is_some(),
                "a typ requirement was dropped"
            );
            let again = p.access_token_verifier(access);
            prop_assert_eq!(again.clock_skew(), want);
            prop_assert_eq!(again.expected_typ(), typ);
        }
    }

    #[cfg(feature = "device")]
    proptest! {
        /// The device-trust cookie lifetime is the shorter of the two, and
        /// stable.
        #[test]
        fn the_device_cookie_lifetime_is_the_shorter_and_stable(p in values(), own in duration()) {
            use axess_core::device::DeviceCookieConfig;
            let once = p.device_cookie_config(DeviceCookieConfig::default().with_max_age(own));
            prop_assert_eq!(once.max_age(), own.min(p.device_cookie_max_age));
            let twice = p.device_cookie_config(once.clone());
            prop_assert_eq!(twice.max_age(), once.max_age());
        }
    }

    #[cfg(feature = "device-keys")]
    proptest! {
        /// The device-key proof and challenge lifetimes are each the shorter
        /// of the two, the acceptance grace and the policy stay the
        /// configuration's, a configuration valid on both sides stays valid,
        /// and a second application changes nothing.
        #[test]
        fn the_device_key_lifetimes_are_the_shorter_and_stable(
            p in values(),
            own_proof in 60..=HOUR,
            own_challenge in 60..=2 * HOUR,
            grace in 0..=300u64,
        ) {
            use axess_core::device_key::{DeviceKeyConfig, KeyBindingPolicy};
            let base = DeviceKeyConfig::new("https://app.example")
                .with_policy(KeyBindingPolicy::Off)
                .with_acceptance_grace(Duration::from_secs(grace))
                .with_proof_ttl(Duration::from_secs(own_proof))
                .with_challenge_ttl(Duration::from_secs(own_challenge));
            let once = p.device_key_config(base.clone());
            let (proof, challenge) = (once.proof_ttl(), once.challenge_ttl());
            prop_assert!(proof <= base.proof_ttl() && proof <= p.device_key_proof_ttl);
            prop_assert!(proof == base.proof_ttl() || proof == p.device_key_proof_ttl);
            prop_assert!(
                challenge <= base.challenge_ttl() && challenge <= p.device_key_challenge_ttl
            );
            prop_assert!(
                challenge == base.challenge_ttl() || challenge == p.device_key_challenge_ttl
            );
            prop_assert_eq!(once.acceptance_grace(), base.acceptance_grace());
            prop_assert_eq!(once.policy(), KeyBindingPolicy::Off);
            let profile_side = base
                .clone()
                .with_proof_ttl(p.device_key_proof_ttl)
                .with_challenge_ttl(p.device_key_challenge_ttl);
            if base.validate().is_ok() && profile_side.validate().is_ok() {
                prop_assert_eq!(once.validate(), Ok(()), "two valid sides gave an invalid one");
            }
            let twice = p.device_key_config(once.clone());
            prop_assert_eq!(twice.proof_ttl(), proof);
            prop_assert_eq!(twice.challenge_ttl(), challenge);
        }
    }

    proptest! {
        /// The CSRF origin check is never turned off: whether the profile
        /// requires it, whether the configuration already makes it and
        /// whether the caller names origins, a check the configuration
        /// made is still made, a required one is refused without origins,
        /// and named origins turn it on.
        #[test]
        fn the_csrf_origin_check_is_never_turned_off(
            required in any::<bool>(),
            checked in any::<bool>(),
            named in any::<bool>(),
        ) {
            let mut p = SecurityProfile::Standard.values();
            p.csrf_origin_check_required = required;
            let base = if checked {
                CsrfConfig::new([7; 32]).require_origin(["https://app.example"])
            } else {
                CsrfConfig::new([7; 32])
            };
            let own: &[&str] = if named { &["https://other.example"] } else { &[] };
            match p.csrf_config(base, own) {
                Ok(applied) => {
                    prop_assert!(named || !required, "a required check went without origins");
                    prop_assert_eq!(!applied.allowed_origins().is_empty(), checked || named);
                }
                Err(refused) => {
                    prop_assert!(required && !named);
                    prop_assert_eq!(refused, ProfileError::CsrfOriginsRequired);
                }
            }
        }
    }

    #[cfg(feature = "ws")]
    proptest! {
        /// The socket lifetime is the tighter of the two, a limit beating
        /// none, and stable; nothing else in the options moves.
        #[test]
        fn the_socket_lifetime_is_the_tighter_and_stable(p in values(), own in limit()) {
            use axess_core::middleware::ws::WatchOptions;
            let base = WatchOptions { max_lifetime: own, ..WatchOptions::default() };
            let once = p.watch_options(base);
            prop_assert_eq!(once.max_lifetime, tighter(own, p.ws_max_lifetime));
            prop_assert!(no_looser(once.max_lifetime, own));
            prop_assert_eq!(once.poll_interval, base.poll_interval);
            prop_assert_eq!(once.fail_closed, base.fail_closed);
            prop_assert_eq!(p.watch_options(once), once);
        }
    }
}
