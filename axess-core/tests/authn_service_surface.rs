#![cfg(feature = "testing")]
//! `AuthnService` accessor + registry-gated surface: `SessionValidator`
//! polarity, `has_session_registry`, `invalidate_*` / `active_sessions`
//! no-registry rejection vs. wired-registry effect, max-sessions-per-user
//! eviction, LDAP bind-DN validation, `begin_login` boundary inputs, the
//! email-OTP cooldown edge, and the `oauth_providers()` accessor.

mod common;

use axess_core::authn::AuditContext;
use axess_core::authn::{
    factor::{EmailOtpConfig, FactorConfig, FactorCredential, FactorKind, ZeroizedString},
    service::{AuthnService, FactorOutcome, LoginOutcome, PrepareOutcome},
    store::AuthMethod,
    types::Tenant,
};
use axess_core::session::store::MemorySessionRegistry;
use axess_core::testing::{
    MockClock, MockRng,
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use chrono::Utc;
use common::{password_config, password_method, test_tenant, test_user, tid, uid, user_scope};

// ── SessionValidator polarity ──────────────────────────────────────────────

/// When a registry is wired AND it reports the session as valid,
/// `SessionValidator::is_valid` must return `true`. Pins the `delete !`
/// mutation on the `&& !reg.is_valid(...)` guard: removing the `!` flips
/// polarity and the mutated validator would invalidate every registered
/// session.
#[tokio::test]
async fn validator_with_live_registry_passes_registered_session() {
    let user = test_user("u1", "alice");
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(user.clone());
    let registry = MemorySessionRegistry::new();
    let svc = AuthnService::builder(identity, MockFactorStore::new())
        .with_registry(registry.clone())
        .build()
        .with_audit_context(AuditContext::default());

    let session = test_session();
    session
        .set_authenticated(uid("u1"), tid("default"), Utc::now())
        .await;
    let sid = session.session_id().await;
    use axess_core::session::store::SessionRegistry;
    registry.register(&uid("u1"), &sid).await.unwrap();

    let validator = svc.session_validator();
    assert!(
        validator.is_valid(&session).await,
        "registered, authenticated session must validate true"
    );
}

/// Counter-test: when the registry says the session is NOT valid (never
/// registered), the validator must return `false`. Pairs with the previous
/// test to discriminate the polarity flip from a stuck-true mutation.
#[tokio::test]
async fn validator_with_live_registry_rejects_unregistered_session() {
    let user = test_user("u1", "alice");
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(user);
    let registry = MemorySessionRegistry::new();
    let svc = AuthnService::builder(identity, MockFactorStore::new())
        .with_registry(registry)
        .build()
        .with_audit_context(AuditContext::default());

    let session = test_session();
    session
        .set_authenticated(uid("u1"), tid("default"), Utc::now())
        .await;
    // Deliberately do NOT register the session id with the registry.

    let validator = svc.session_validator();
    assert!(
        !validator.is_valid(&session).await,
        "unregistered session must validate false"
    );
}

// ── has_session_registry ────────────────────────────────────────────────────

#[tokio::test]
async fn has_session_registry_false_without_registry() {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let svc = AuthnService::new(identity, MockFactorStore::new())
        .with_audit_context(AuditContext::default());
    assert!(!svc.has_session_registry());
}

#[tokio::test]
async fn has_session_registry_true_with_registry() {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let registry = MemorySessionRegistry::new();
    let svc = AuthnService::builder(identity, MockFactorStore::new())
        .with_registry(registry)
        .build()
        .with_audit_context(AuditContext::default());
    assert!(svc.has_session_registry());
}

// ── invalidate_user_sessions / invalidate_session / active_sessions ────────

#[tokio::test]
async fn invalidate_user_sessions_no_registry_returns_err() {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let svc = AuthnService::new(identity, MockFactorStore::new())
        .with_audit_context(AuditContext::default());
    let result = svc.invalidate_user_sessions(&uid("u1")).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn invalidate_user_sessions_with_registry_invalidates() {
    use axess_core::session::store::SessionRegistry;
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let registry = MemorySessionRegistry::new();
    let svc = AuthnService::builder(identity, MockFactorStore::new())
        .with_registry(registry.clone())
        .build()
        .with_audit_context(AuditContext::default());

    let session = test_session();
    session
        .set_authenticated(uid("u1"), tid("default"), Utc::now())
        .await;
    let sid = session.session_id().await;
    registry.register(&uid("u1"), &sid).await.unwrap();
    assert_eq!(
        registry.active_sessions(&uid("u1")).await.unwrap(),
        vec![sid]
    );

    svc.invalidate_user_sessions(&uid("u1")).await.unwrap();
    assert!(
        registry
            .active_sessions(&uid("u1"))
            .await
            .unwrap()
            .is_empty(),
        "wired-registry path must actually invalidate the user's sessions"
    );
}

#[tokio::test]
async fn invalidate_session_no_registry_returns_err() {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let svc = AuthnService::new(identity, MockFactorStore::new())
        .with_audit_context(AuditContext::default());
    let session = test_session();
    session
        .set_authenticated(uid("u1"), tid("default"), Utc::now())
        .await;
    let sid = session.session_id().await;
    let result = svc.invalidate_session(&uid("u1"), &sid).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn invalidate_session_with_registry_removes_target_only() {
    use axess_core::session::store::SessionRegistry;
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let registry = MemorySessionRegistry::new();
    let svc = AuthnService::builder(identity, MockFactorStore::new())
        .with_registry(registry.clone())
        .build()
        .with_audit_context(AuditContext::default());

    let s1 = test_session();
    s1.set_authenticated(uid("u1"), tid("default"), Utc::now())
        .await;
    let sid1 = s1.session_id().await;
    let s2 = test_session();
    s2.set_authenticated(uid("u1"), tid("default"), Utc::now())
        .await;
    let sid2 = s2.session_id().await;
    registry.register(&uid("u1"), &sid1).await.unwrap();
    registry.register(&uid("u1"), &sid2).await.unwrap();

    svc.invalidate_session(&uid("u1"), &sid1).await.unwrap();
    let remaining = registry.active_sessions(&uid("u1")).await.unwrap();
    assert_eq!(
        remaining,
        vec![sid2],
        "only the targeted session must be invalidated"
    );
}

#[tokio::test]
async fn active_sessions_no_registry_returns_err() {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let svc = AuthnService::new(identity, MockFactorStore::new())
        .with_audit_context(AuditContext::default());
    let result = svc.active_sessions(&uid("u1")).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn active_sessions_with_registry_returns_registry_contents() {
    use axess_core::session::store::SessionRegistry;
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let registry = MemorySessionRegistry::new();
    let svc = AuthnService::builder(identity, MockFactorStore::new())
        .with_registry(registry.clone())
        .build()
        .with_audit_context(AuditContext::default());

    let session = test_session();
    session
        .set_authenticated(uid("u1"), tid("default"), Utc::now())
        .await;
    let sid = session.session_id().await;
    registry.register(&uid("u1"), &sid).await.unwrap();

    let active = svc.active_sessions(&uid("u1")).await.unwrap();
    assert_eq!(
        active,
        vec![sid],
        "wired-registry path must return the registry's actual sessions, not an empty vec"
    );
}

// ── max_sessions_per_user eviction ─────────────────────────────────────────

/// When a registry is wired AND `max_sessions_per_user` is set to `N`,
/// completing an authentication while `N` sessions already exist must evict
/// the oldest one before registering the new session, so the post-login
/// count stays exactly at the cap.
#[tokio::test]
async fn max_sessions_per_user_evicts_oldest_to_keep_under_cap() {
    use axess_core::session::id::SessionId;
    use axess_core::session::store::SessionRegistry;

    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Gnomes2+"))
        .with_method(&uid("u1"), password_method());
    let registry = MemorySessionRegistry::new();
    let svc = AuthnService::builder(identity, factors)
        .with_registry(registry.clone())
        .with_max_sessions_per_user(2)
        .build()
        .with_audit_context(AuditContext::default());

    // Pre-populate the registry with 2 sessions for the user, so the cap is
    // exactly met before the new login.
    let rng = MockRng::new(7);
    let old1 = SessionId::new(&rng);
    let old2 = SessionId::new(&rng);
    registry.register(&uid("u1"), &old1).await.unwrap();
    registry.register(&uid("u1"), &old2).await.unwrap();
    assert_eq!(
        registry.active_sessions(&uid("u1")).await.unwrap().len(),
        2,
        "pre-state: two sessions at the cap"
    );

    // Now do a real password login: `complete_factor_step` must evict
    // exactly one old session before registering the new one.
    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    let cred = FactorCredential::Password(ZeroizedString::new("Gnomes2+"));
    let outcome = svc.verify_factor(&cred, &session).await.unwrap();
    assert!(
        matches!(outcome, FactorOutcome::Authenticated),
        "got {outcome:?}"
    );

    // Post-state: exactly `max` sessions remain; the oldest evicted, the
    // second-oldest kept, the new one registered.
    let active = registry.active_sessions(&uid("u1")).await.unwrap();
    assert_eq!(
        active.len(),
        2,
        "concurrent-session cap must be respected after login; got {active:?}"
    );
    assert!(
        !active.contains(&old1),
        "oldest session must be evicted to keep within cap"
    );
    assert!(
        active.contains(&old2),
        "second-oldest must survive when only one needs eviction"
    );
}

// ── LDAP bind-DN validation ────────────────────────────────────────────────

/// LDAP factor: a successful bind through the override `bind_dn` path must
/// yield `Authenticated`.
#[cfg(feature = "ldap")]
#[tokio::test]
async fn ldap_factor_completes_login_with_valid_bind_dn_override() {
    use axess_core::authn::factor::LdapBindFactorConfig;
    use axess_factors::ldap::MockLdapProvider;

    let bind_dn = "uid=alice,ou=people,dc=example,dc=com";
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(
            user_scope(),
            FactorConfig::LdapBind(LdapBindFactorConfig {
                bind_dn: Some(bind_dn.to_string()),
            }),
        )
        .with_method(
            &uid("u1"),
            AuthMethod::sequential("ldap", vec![FactorKind::LdapBind], user_scope()),
        );
    // Template carries no `{user}` substitution: the mock's `with_user`
    // registers exactly `bind_dn` as the valid bind target, so the override
    // path's bind succeeds without going through the build_bind_dn template.
    let ldap = MockLdapProvider::new(bind_dn).with_user("alice", "ldap-secret", vec![]);
    let svc = AuthnService::builder(identity, factors)
        .with_ldap(ldap)
        .build()
        .with_audit_context(AuditContext::default());

    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    let cred = FactorCredential::Password(ZeroizedString::new("ldap-secret"));
    let outcome = svc.verify_factor(&cred, &session).await.unwrap();
    assert!(
        matches!(outcome, FactorOutcome::Authenticated),
        "valid LDAP bind must authenticate; got {outcome:?}"
    );
}

/// LDAP factor: a `bind_dn` override that is fully DN-safe but missing the
/// structural `=` separator must be rejected with `InvalidCredential` even
/// when the mock would otherwise accept the bind.
#[cfg(feature = "ldap")]
#[tokio::test]
async fn ldap_bind_dn_without_equals_rejected_even_if_provider_would_accept() {
    use axess_core::authn::factor::LdapBindFactorConfig;
    use axess_factors::ldap::MockLdapProvider;

    let bind_dn = "uidalice"; // all safe, no `=`
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(
            user_scope(),
            FactorConfig::LdapBind(LdapBindFactorConfig {
                bind_dn: Some(bind_dn.to_string()),
            }),
        )
        .with_method(
            &uid("u1"),
            AuthMethod::sequential("ldap", vec![FactorKind::LdapBind], user_scope()),
        );
    let ldap = MockLdapProvider::new(bind_dn).with_user("alice", "ldap-secret", vec![]);
    let svc = AuthnService::builder(identity, factors)
        .with_ldap(ldap)
        .build()
        .with_audit_context(AuditContext::default());

    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    let cred = FactorCredential::Password(ZeroizedString::new("ldap-secret"));
    let outcome = svc.verify_factor(&cred, &session).await.unwrap();
    assert!(
        matches!(outcome, FactorOutcome::InvalidCredential),
        "DN missing `=` must be rejected by validation; got {outcome:?}"
    );
}

/// LDAP factor: a `bind_dn` override longer than the 1024-byte cap must be
/// rejected by validation.
#[cfg(feature = "ldap")]
#[tokio::test]
async fn ldap_bind_dn_over_length_cap_rejected_even_if_provider_would_accept() {
    use axess_core::authn::factor::LdapBindFactorConfig;
    use axess_factors::ldap::MockLdapProvider;

    // 1025-byte DN: len > 1024, but otherwise fully valid: contains `=` and
    // only DN-safe ASCII.
    let bind_dn = format!("uid={}", "a".repeat(1021));
    assert_eq!(bind_dn.len(), 1025);
    assert!(bind_dn.contains('='));

    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(
            user_scope(),
            FactorConfig::LdapBind(LdapBindFactorConfig {
                bind_dn: Some(bind_dn.clone()),
            }),
        )
        .with_method(
            &uid("u1"),
            AuthMethod::sequential("ldap", vec![FactorKind::LdapBind], user_scope()),
        );
    let ldap = MockLdapProvider::new(bind_dn.as_str()).with_user("alice", "ldap-secret", vec![]);
    let svc = AuthnService::builder(identity, factors)
        .with_ldap(ldap)
        .build()
        .with_audit_context(AuditContext::default());

    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    let cred = FactorCredential::Password(ZeroizedString::new("ldap-secret"));
    let outcome = svc.verify_factor(&cred, &session).await.unwrap();
    assert!(
        matches!(outcome, FactorOutcome::InvalidCredential),
        "DN over 1024-byte cap must be rejected by validation; got {outcome:?}"
    );
}

/// LDAP factor: a password of exactly `MAX_PASSWORD_BYTES` (1024) bytes must
/// NOT be rejected by the over-cap pre-bind check: the guard uses strict `>`
/// and 1024 is the inclusive ceiling.
#[cfg(feature = "ldap")]
#[tokio::test]
async fn ldap_password_at_max_bytes_is_not_rejected_by_length_guard() {
    use axess_core::authn::factor::LdapBindFactorConfig;
    use axess_factors::ldap::MockLdapProvider;

    // Exactly 1024 bytes: the inclusive ceiling of the `>` guard.
    let password = "a".repeat(1024);
    assert_eq!(password.len(), 1024);

    let bind_dn = "uid=alice,ou=people,dc=example,dc=com";
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(
            user_scope(),
            FactorConfig::LdapBind(LdapBindFactorConfig {
                bind_dn: Some(bind_dn.to_string()),
            }),
        )
        .with_method(
            &uid("u1"),
            AuthMethod::sequential("ldap", vec![FactorKind::LdapBind], user_scope()),
        );
    let ldap = MockLdapProvider::new(bind_dn).with_user("alice", password.as_str(), vec![]);
    let svc = AuthnService::builder(identity, factors)
        .with_ldap(ldap)
        .build()
        .with_audit_context(AuditContext::default());

    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    let cred = FactorCredential::Password(ZeroizedString::new(password));
    let outcome = svc.verify_factor(&cred, &session).await.unwrap();
    assert!(
        matches!(outcome, FactorOutcome::Authenticated),
        "1024-byte password must clear the strict-> length check; got {outcome:?}"
    );
}

// ── begin_login boundary inputs ────────────────────────────────────────────

/// `begin_login` must accept identifiers of exactly `MAX_IDENTIFIER_BYTES`
/// (256); the guard uses strict `>` and 256 is the inclusive ceiling.
#[tokio::test]
async fn begin_login_identifier_at_max_bytes_is_not_rejected() {
    let long_identifier: String = "a".repeat(256);
    assert_eq!(long_identifier.len(), 256);

    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(axess_core::authn::types::User {
            identifier: long_identifier.clone().into(),
            ..test_user("u1", &long_identifier)
        });
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Gnomes2+"))
        .with_method(
            &uid("u1"),
            AuthMethod::sequential("password", vec![FactorKind::Password], user_scope()),
        );
    let svc = AuthnService::new(identity, factors).with_audit_context(AuditContext::default());

    let session = test_session();
    let outcome = svc
        .begin_login(&long_identifier, "default", &session)
        .await
        .unwrap();
    assert!(
        matches!(outcome, LoginOutcome::FactorRequired(FactorKind::Password)),
        "256-byte identifier must clear the strict-> length check; got {outcome:?}"
    );
}

/// `begin_login` must accept tenant identifiers of exactly
/// `MAX_IDENTIFIER_BYTES` (256).
#[tokio::test]
async fn begin_login_tenant_identifier_at_max_bytes_is_not_rejected() {
    let long_tenant_identifier: String = "t".repeat(256);
    assert_eq!(long_tenant_identifier.len(), 256);

    let tenant = Tenant {
        identifier: long_tenant_identifier.clone().into(),
        ..test_tenant()
    };
    let identity = MockIdentityStore::new()
        .with_tenant(tenant)
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Gnomes2+"))
        .with_method(
            &uid("u1"),
            AuthMethod::sequential("password", vec![FactorKind::Password], user_scope()),
        );
    let svc = AuthnService::new(identity, factors).with_audit_context(AuditContext::default());

    let session = test_session();
    let outcome = svc
        .begin_login("alice", &long_tenant_identifier, &session)
        .await
        .unwrap();
    assert!(
        matches!(outcome, LoginOutcome::FactorRequired(FactorKind::Password)),
        "256-byte tenant identifier must clear the strict-> length check; got {outcome:?}"
    );
}

/// The tenant IP policy gate, which until 0.7.0 was skippable.
///
/// The address used to be a `begin_login` parameter, and the check ran
/// only `if let Some(ip)`, so a caller passing `None` bypassed the policy
/// entirely. 51 of the 52 call sites in this repository passed `None`, and
/// the one test that existed installed no policy, so it passed whether or
/// not the gate ran. The address now arrives on the handle, and the four
/// cases below are the whole truth table.
mod tenant_ip_policy {
    use super::*;
    use axess_core::authn::types::IpPolicy;

    fn service_with_policy(policy: IpPolicy) -> AuthnService<MockIdentityStore, MockFactorStore> {
        let identity = MockIdentityStore::new()
            .with_tenant(test_tenant())
            .with_user(test_user("u1", "alice"))
            .with_ip_policy(&test_tenant().id, policy);
        let factors = MockFactorStore::new()
            .with_factor(user_scope(), password_config("Gnomes2+"))
            .with_method(&uid("u1"), password_method());
        AuthnService::new(identity, factors)
    }

    fn allowlist(cidr: &str) -> IpPolicy {
        IpPolicy {
            allow: vec![cidr.into()],
            deny: vec![],
        }
    }

    fn context_from(ip: &str) -> AuditContext {
        AuditContext {
            ip_address: Some(ip.parse().expect("test literal")),
            ip_source: axess_core::client_ip::Source::Forwarded,
            ..Default::default()
        }
    }

    /// An address inside the allowlist clears the gate.
    #[tokio::test]
    async fn an_allowed_address_proceeds() {
        let outcome = service_with_policy(allowlist("192.168.1.0/24"))
            .with_audit_context(context_from("192.168.1.1"))
            .begin_login("alice", "default", &test_session())
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            LoginOutcome::FactorRequired(FactorKind::Password)
        ));
    }

    /// An address outside it does not, and says nothing about why: a
    /// distinct outcome here would tell an unauthenticated caller that the
    /// tenant has an IP policy at all.
    #[tokio::test]
    async fn an_address_outside_the_allowlist_is_refused() {
        let outcome = service_with_policy(allowlist("192.168.1.0/24"))
            .with_audit_context(context_from("203.0.113.9"))
            .begin_login("alice", "default", &test_session())
            .await
            .unwrap();
        assert!(
            matches!(outcome, LoginOutcome::InvalidCredentials),
            "an address outside the allowlist must not authenticate; got {outcome:?}"
        );
    }

    /// The case the old shape got wrong. A policy that restricts and no
    /// address to test against it cannot be satisfied, so the login fails
    /// closed. Before 0.7.0 this combination sailed through the gate.
    #[tokio::test]
    async fn a_restricting_policy_with_no_address_fails_closed() {
        let outcome = service_with_policy(allowlist("192.168.1.0/24"))
            .with_audit_context(AuditContext::default())
            .begin_login("alice", "default", &test_session())
            .await
            .unwrap();
        assert!(
            matches!(outcome, LoginOutcome::InvalidCredentials),
            "a policy that cannot be evaluated must not be treated as \
             satisfied; got {outcome:?}"
        );
    }

    /// Failing closed must not mean failing everyone. A tenant with no
    /// policy permits every address, so an unknown address is no less
    /// compliant with it than a known one, and those deployments (the
    /// default, and the overwhelming majority) are untouched.
    #[tokio::test]
    async fn an_empty_policy_with_no_address_proceeds() {
        let outcome = service_with_policy(IpPolicy::default())
            .with_audit_context(AuditContext::default())
            .begin_login("alice", "default", &test_session())
            .await
            .unwrap();
        assert!(
            matches!(outcome, LoginOutcome::FactorRequired(FactorKind::Password)),
            "an unrestricted tenant must be unaffected; got {outcome:?}"
        );
    }

    /// A denylist restricts too, so the same fail-closed reading applies.
    #[tokio::test]
    async fn a_denylist_with_no_address_fails_closed() {
        let policy = IpPolicy {
            allow: vec![],
            deny: vec!["203.0.113.0/24".into()],
        };
        let outcome = service_with_policy(policy)
            .with_audit_context(AuditContext::default())
            .begin_login("alice", "default", &test_session())
            .await
            .unwrap();
        assert!(matches!(outcome, LoginOutcome::InvalidCredentials));
    }
}

// ── EmailOTP cooldown boundary ─────────────────────────────────────────────

/// EmailOTP cooldown: at the moment `now` equals `pending_until`, the guard
/// `now < until` is false, so `prepare_factor` must refresh (SendOtp), not
/// stay in cooldown.
#[tokio::test]
async fn email_otp_cooldown_boundary_at_until_refreshes_not_alreadysent() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let email_method =
        AuthMethod::sequential("email_otp", vec![FactorKind::EmailOtp], user_scope());
    let factors = MockFactorStore::new()
        .with_factor(
            user_scope(),
            FactorConfig::EmailOtp(EmailOtpConfig {
                email: "alice@example.com".into(),
                ttl_secs: 300,
                ..EmailOtpConfig::default()
            }),
        )
        .with_method(&uid("u1"), email_method);

    let clock = MockClock::now();
    let service = AuthnService::builder(identity, factors)
        .with_clock(clock.clone())
        .with_rng(MockRng::new(42))
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();
    service
        .begin_login("alice", "default", &session)
        .await
        .unwrap();

    assert!(matches!(
        service.prepare_factor(&session).await.unwrap(),
        PrepareOutcome::SendOtp { .. }
    ));

    // Advance to EXACTLY ttl_secs. `now == pending_until`. The strict `<`
    // guard is false → SendOtp again. A `<=` mutation would still report
    // cooldown.
    clock.advance_secs(300);
    let at_boundary = service.prepare_factor(&session).await.unwrap();
    assert!(
        matches!(at_boundary, PrepareOutcome::SendOtp { .. }),
        "at the exact cooldown boundary (now == pending_until), prepare_factor must refresh; got {at_boundary:?}"
    );
}

// ── oauth_providers accessor ───────────────────────────────────────────────

/// `oauth_providers()` must return a reference to the service's actual
/// registry, not a freshly defaulted one. With a provider registered,
/// `provider_count()` must reflect that.
#[cfg(feature = "oauth")]
#[tokio::test]
async fn oauth_providers_accessor_returns_live_registry() {
    use axess_factors::oauth::MockOAuthProvider;

    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let mock = MockOAuthProvider::new("mock-oauth");
    let svc = AuthnService::builder(identity, MockFactorStore::new())
        .with_oauth_provider(mock)
        .build()
        .with_audit_context(AuditContext::default());

    let registry = svc.oauth_providers();
    assert_eq!(
        registry.provider_count(),
        1,
        "oauth_providers must return the live registry, not a default empty one"
    );
    assert!(
        registry
            .provider_names()
            .into_iter()
            .any(|n| n.as_ref() == "mock-oauth"),
        "live registry must surface registered provider name"
    );
}
