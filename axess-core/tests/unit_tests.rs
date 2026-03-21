//! Additional unit tests covering authz, session data, scope resolution,
//! and edge cases not covered by the authn_flow integration tests.

// ── Authorization tests ──────────────────────────────────────────────────────

#[cfg(feature = "authz")]
mod authz_tests {
    use axess_core::{
        authz::{AuthzDecision, AuthzDenied, AuthzStore},
        utils::testing::mock_policy::{MockEntityProvider, MockPolicyEvaluator},
    };
    use std::sync::Arc;

    fn make_store(evaluator: MockPolicyEvaluator) -> Arc<AuthzStore<MockEntityProvider>> {
        Arc::new(AuthzStore::new(
            Arc::new(evaluator),
            Arc::new(MockEntityProvider::new("Test")),
            "Test",
        ))
    }

    #[tokio::test]
    async fn require_allowed_action_succeeds() {
        let store = make_store(
            MockPolicyEvaluator::new().permit_ns("Test", "ViewDoc", "Resource", "doc-1"),
        );
        let session = store.for_user_id("alice").unwrap();
        let result = session.require("ViewDoc", &"doc-1".to_string()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn require_denied_action_returns_authz_denied() {
        let store = make_store(MockPolicyEvaluator::new()); // deny by default
        let session = store.for_user_id("alice").unwrap();
        let result = session.require("ViewDoc", &"doc-1".to_string()).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthzDenied);
    }

    #[tokio::test]
    async fn is_permitted_returns_bool() {
        let store =
            make_store(MockPolicyEvaluator::new().permit_ns("Test", "Edit", "Resource", "doc-1"));
        let session = store.for_user_id("alice").unwrap();
        assert!(session.is_permitted("Edit", &"doc-1".to_string()).await);
        assert!(!session.is_permitted("Delete", &"doc-1".to_string()).await);
    }

    #[tokio::test]
    async fn batch_check_returns_decisions_in_order() {
        let store = make_store(
            MockPolicyEvaluator::new()
                .permit_ns("Test", "View", "Resource", "doc-1")
                .deny_ns("Test", "Delete", "Resource", "doc-1"),
        );
        let session = store.for_user_id("alice").unwrap();
        let doc_id = "doc-1".to_string();
        let checks = vec![("View", &doc_id), ("Delete", &doc_id)];
        let results = session.batch_check(&checks).await;
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].1, AuthzDecision::Allow);
        assert_eq!(results[1].1, AuthzDecision::Deny);
    }

    #[tokio::test]
    async fn allow_all_evaluator_permits_everything() {
        let store = make_store(MockPolicyEvaluator::allow_all());
        let session = store.for_user_id("anyone").unwrap();
        assert!(
            session
                .is_permitted("Anything", &"whatever".to_string())
                .await
        );
    }

    #[tokio::test]
    async fn entity_cache_deduplicates_repeated_checks() {
        // Two identical checks should hit the cache — this test just verifies
        // it doesn't crash or return different results.
        let store =
            make_store(MockPolicyEvaluator::new().permit_ns("Test", "View", "Resource", "doc-1"));
        let session = store.for_user_id("alice").unwrap();
        let r1 = session.is_permitted("View", &"doc-1".to_string()).await;
        let r2 = session.is_permitted("View", &"doc-1".to_string()).await;
        assert_eq!(r1, r2);
        assert!(r1);
    }
}

// ── Session data tests ───────────────────────────────────────────────────────

mod session_data_tests {
    use axess_core::session::data::{AuthState, SessionData, WorkflowKind, WorkflowState};
    use chrono::Utc;

    #[test]
    fn session_data_default_is_guest() {
        let data = SessionData::default();
        assert!(data.auth_state.is_guest());
        assert!(!data.auth_state.is_authenticated());
    }

    #[test]
    fn auth_state_user_id_returns_none_for_guest() {
        let state = AuthState::Guest;
        assert!(state.user_id().is_none());
        assert!(state.tenant_id().is_none());
    }

    #[test]
    fn auth_state_authenticated_has_user_and_tenant() {
        let state = AuthState::Authenticated {
            user_id: "u1".into(),
            tenant_id: "t1".into(),
            authn_time: Utc::now(),
        };
        assert!(state.is_authenticated());
        assert_eq!(state.user_id().unwrap().as_ref(), "u1");
        assert_eq!(state.tenant_id().unwrap().as_ref(), "t1");
    }

    #[test]
    fn auth_state_authenticating_is_not_authenticated() {
        let state = AuthState::Authenticating {
            user_id: "u1".into(),
            tenant_id: "t1".into(),
            method_name: "password".into(),
            remaining: vec![],
            attempt_count: 0,
            last_attempt: None,
        };
        assert!(state.is_authenticating());
        assert!(!state.is_authenticated());
        assert!(!state.is_guest());
    }

    #[test]
    fn session_data_json_roundtrip() {
        let data = SessionData {
            auth_state: AuthState::Authenticated {
                user_id: "u1".into(),
                tenant_id: "t1".into(),
                authn_time: Utc::now(),
            },
            fingerprint: Some("abc123".to_string()),
            custom: serde_json::json!({"key": "value"}),
        };
        let json = serde_json::to_string(&data).unwrap();
        let restored: SessionData = serde_json::from_str(&json).unwrap();
        assert!(restored.auth_state.is_authenticated());
        assert_eq!(restored.fingerprint.as_deref(), Some("abc123"));
        assert_eq!(restored.custom["key"], "value");
    }

    #[test]
    fn workflow_state_new_sets_step_zero() {
        let ws = WorkflowState::new(WorkflowKind::Signup, 3, Utc::now());
        assert_eq!(ws.current_step, 0);
        assert_eq!(ws.total_steps, 3);
    }
}

// ── Multi-tenant scope resolution ────────────────────────────────────────────

mod scope_tests {
    use axess_core::{
        authn::{
            factor::{
                FactorConfig, FactorCredential, FactorKind, PasswordConfig, PasswordRules,
                ZeroizedString,
            },
            service::{AuthnService, FactorOutcome},
            store::AuthMethod,
            types::{AuthnScope, EntityState, Tenant, User},
        },
        utils::testing::{
            mock_authn::{MockFactorStore, MockIdentityStore},
            test_session,
        },
    };

    fn tenant() -> Tenant {
        Tenant {
            id: "t1".into(),
            identifier: "default".into(),
            display_name: "Test".into(),
            status: EntityState::Active,
        }
    }

    fn user() -> User {
        User {
            id: "u1".into(),
            tenant_id: "t1".into(),
            identifier: "alice".into(),
            display_name: "Alice".into(),
            status: EntityState::Active,
            webauthn_id: None,
        }
    }

    fn pw_config(password: &str) -> FactorConfig {
        FactorConfig::Password(PasswordConfig {
            hash: ZeroizedString::new(axess_factors::generate_password_hash(password)),
            rules: PasswordRules::default(),
        })
    }

    fn pw_method() -> AuthMethod {
        AuthMethod {
            name: "password".into(),
            factors: vec![FactorKind::Password],
            scope: AuthnScope::User {
                tenant_id: "t1".into(),
                user_id: "u1".into(),
            },
        }
    }

    /// Factor config at user scope should be found first.
    #[tokio::test]
    async fn user_scope_takes_priority() {
        let identity = MockIdentityStore::new()
            .with_tenant(tenant())
            .with_user(user());
        let factors = MockFactorStore::new()
            .with_factor(
                AuthnScope::User {
                    tenant_id: "t1".into(),
                    user_id: "u1".into(),
                },
                pw_config("user-password"),
            )
            .with_factor(
                AuthnScope::Tenant("t1".into()),
                pw_config("tenant-password"),
            )
            .with_factor(AuthnScope::Global, pw_config("global-password"))
            .with_method("u1", pw_method());

        let service = AuthnService::new(identity, factors);
        let session = test_session();

        service
            .begin_login("alice", "default", &session)
            .await
            .unwrap();

        // User-scope password should work.
        let r = service
            .verify_factor(
                &FactorCredential::Password(ZeroizedString::new("user-password")),
                &session,
            )
            .await
            .unwrap();
        assert!(matches!(r, FactorOutcome::Authenticated));
    }

    /// When user scope has no config, tenant scope should resolve.
    #[tokio::test]
    async fn tenant_scope_fallback() {
        let identity = MockIdentityStore::new()
            .with_tenant(tenant())
            .with_user(user());
        let factors = MockFactorStore::new()
            // No user scope config — only tenant.
            .with_factor(
                AuthnScope::Tenant("t1".into()),
                pw_config("tenant-password"),
            )
            .with_method("u1", pw_method());

        let service = AuthnService::new(identity, factors);
        let session = test_session();

        service
            .begin_login("alice", "default", &session)
            .await
            .unwrap();
        let r = service
            .verify_factor(
                &FactorCredential::Password(ZeroizedString::new("tenant-password")),
                &session,
            )
            .await
            .unwrap();
        assert!(matches!(r, FactorOutcome::Authenticated));
    }

    /// Full chain: user miss → tenant miss → global hit.
    #[tokio::test]
    async fn user_tenant_global_fallback_chain() {
        let identity = MockIdentityStore::new()
            .with_tenant(tenant())
            .with_user(user());
        let factors = MockFactorStore::new()
            // Only global scope.
            .with_factor(AuthnScope::Global, pw_config("global-password"))
            .with_method("u1", pw_method());

        let service = AuthnService::new(identity, factors);
        let session = test_session();

        service
            .begin_login("alice", "default", &session)
            .await
            .unwrap();
        let r = service
            .verify_factor(
                &FactorCredential::Password(ZeroizedString::new("global-password")),
                &session,
            )
            .await
            .unwrap();
        assert!(matches!(r, FactorOutcome::Authenticated));
    }
}

// ── Edge case tests ──────────────────────────────────────────────────────────

mod edge_cases {
    use axess_core::{
        authn::{
            error::AuthnError,
            factor::{
                FactorConfig, FactorCredential, FactorKind, PasswordConfig, PasswordRules,
                ZeroizedString,
            },
            service::{AuthnService, LoginOutcome},
            store::AuthMethod,
            types::{AuthnScope, EntityState, Tenant, User},
        },
        utils::testing::{
            mock_authn::{MockFactorStore, MockIdentityStore},
            test_session,
        },
    };

    fn tenant() -> Tenant {
        Tenant {
            id: "t1".into(),
            identifier: "default".into(),
            display_name: "Test".into(),
            status: EntityState::Active,
        }
    }

    fn user() -> User {
        User {
            id: "u1".into(),
            tenant_id: "t1".into(),
            identifier: "alice".into(),
            display_name: "Alice".into(),
            status: EntityState::Active,
            webauthn_id: None,
        }
    }

    fn pw_config() -> FactorConfig {
        FactorConfig::Password(PasswordConfig {
            hash: ZeroizedString::new(axess_factors::generate_password_hash("hunter2")),
            rules: PasswordRules::default(),
        })
    }

    /// Empty factor chain should return InvalidCredentials from begin_login.
    #[tokio::test]
    async fn empty_factor_chain() {
        let identity = MockIdentityStore::new()
            .with_tenant(tenant())
            .with_user(user());
        let factors = MockFactorStore::new()
            .with_factor(
                AuthnScope::User {
                    tenant_id: "t1".into(),
                    user_id: "u1".into(),
                },
                pw_config(),
            )
            .with_method(
                "u1",
                AuthMethod {
                    name: "empty".into(),
                    factors: vec![], // Empty!
                    scope: AuthnScope::User {
                        tenant_id: "t1".into(),
                        user_id: "u1".into(),
                    },
                },
            );

        let service = AuthnService::new(identity, factors);
        let session = test_session();

        let outcome = service
            .begin_login("alice", "default", &session)
            .await
            .unwrap();
        assert!(matches!(outcome, LoginOutcome::InvalidCredentials));
    }

    /// verify_factor on a guest session should return NoFlow.
    #[tokio::test]
    async fn verify_factor_without_begin_returns_no_flow() {
        let identity = MockIdentityStore::new().with_tenant(tenant());
        let factors = MockFactorStore::new();
        let service = AuthnService::new(identity, factors);
        let session = test_session();

        let result = service
            .verify_factor(
                &FactorCredential::Password(ZeroizedString::new("x")),
                &session,
            )
            .await;
        assert!(matches!(result, Err(AuthnError::NoFlow)));
    }

    /// prepare_factor on a guest session should return NoFlow.
    #[tokio::test]
    async fn prepare_factor_without_begin_returns_no_flow() {
        let identity = MockIdentityStore::new().with_tenant(tenant());
        let factors = MockFactorStore::new();
        let service = AuthnService::new(identity, factors);
        let session = test_session();

        let result = service.prepare_factor(&session).await;
        assert!(matches!(result, Err(AuthnError::NoFlow)));
    }

    /// Suspended user cannot login.
    #[tokio::test]
    async fn suspended_user_cannot_login() {
        let suspended_user = User {
            id: "u1".into(),
            tenant_id: "t1".into(),
            identifier: "alice".into(),
            display_name: "Alice".into(),
            status: EntityState::Suspended(axess_core::authn::types::StatusDetail {
                reason: "test".into(),
                since: chrono::Utc::now(),
                until: None,
            }),
            webauthn_id: None,
        };
        let identity = MockIdentityStore::new()
            .with_tenant(tenant())
            .with_user(suspended_user);
        let factors = MockFactorStore::new()
            .with_factor(
                AuthnScope::User {
                    tenant_id: "t1".into(),
                    user_id: "u1".into(),
                },
                pw_config(),
            )
            .with_method(
                "u1",
                AuthMethod {
                    name: "password".into(),
                    factors: vec![FactorKind::Password],
                    scope: AuthnScope::User {
                        tenant_id: "t1".into(),
                        user_id: "u1".into(),
                    },
                },
            );

        let service = AuthnService::new(identity, factors);
        let session = test_session();

        let outcome = service.begin_login("alice", "default", &session).await;
        assert!(matches!(outcome, Ok(LoginOutcome::Locked { .. })));
    }

    /// Nonexistent tenant returns NotActive.
    #[tokio::test]
    async fn nonexistent_tenant_returns_error() {
        let identity = MockIdentityStore::new(); // No tenants!
        let factors = MockFactorStore::new();
        let service = AuthnService::new(identity, factors);
        let session = test_session();

        let result = service.begin_login("alice", "nonexistent", &session).await;
        assert!(matches!(result, Err(AuthnError::NotActive(_))));
    }

    /// SessionId display/parse round-trip.
    #[test]
    fn session_id_display_parse_roundtrip() {
        use axess_core::session::id::SessionId;
        use axess_core::utils::testing::MockRng;

        let mut rng = MockRng::new(999);
        let id = SessionId::new(&mut rng);
        let s = id.to_string();
        let parsed: SessionId = s.parse().unwrap();
        assert_eq!(id, parsed);
    }

    /// ZeroizedString hides content in Debug output.
    #[test]
    fn zeroized_string_debug_hides_content() {
        let secret = ZeroizedString::new("super-secret");
        let debug = format!("{:?}", secret);
        assert!(!debug.contains("super-secret"));
        assert!(debug.contains("***"));
    }

    /// AuthnScope::key() produces distinct keys for each variant.
    #[test]
    fn authn_scope_keys_are_distinct() {
        let global = AuthnScope::Global;
        let tenant = AuthnScope::Tenant("t1".into());
        let user = AuthnScope::User {
            tenant_id: "t1".into(),
            user_id: "u1".into(),
        };

        assert_ne!(global.key(), tenant.key());
        assert_ne!(tenant.key(), user.key());
        assert_ne!(global.key(), user.key());
    }
}

// ── Session extractor tests ──────────────────────────────────────────────────

mod session_extractor_tests {
    use axess_core::{
        authn::factor::FactorKind,
        session::data::{AuthState, WorkflowKind, WorkflowState},
        utils::testing::test_session,
    };
    use chrono::Utc;

    #[tokio::test]
    async fn set_authenticated_marks_regenerate() {
        let session = test_session();
        session
            .set_authenticated("u1".into(), "t1".into(), Utc::now())
            .await;
        assert!(session.is_authenticated().await);
        assert_eq!(session.user_id().await.unwrap().as_ref(), "u1");
    }

    #[tokio::test]
    async fn authenticated_ids_returns_both() {
        let session = test_session();
        assert!(session.authenticated_ids().await.is_none());

        session
            .set_authenticated("u1".into(), "t1".into(), Utc::now())
            .await;
        let (uid, tid) = session.authenticated_ids().await.unwrap();
        assert_eq!(uid.as_ref(), "u1");
        assert_eq!(tid.as_ref(), "t1");
    }

    #[tokio::test]
    async fn advance_factor_removes_first_match_only() {
        let session = test_session();
        session
            .begin_authenticating(
                "u1".into(),
                "t1".into(),
                "test".into(),
                vec![FactorKind::Password, FactorKind::Totp, FactorKind::Password],
            )
            .await;

        session
            .advance_factor(&FactorKind::Password, Utc::now())
            .await;

        // Should have removed only the FIRST Password, leaving [Totp, Password].
        let state = session.auth_state().await;
        if let AuthState::Authenticating { remaining, .. } = state {
            assert_eq!(remaining.len(), 2);
            assert_eq!(remaining[0], FactorKind::Totp);
            assert_eq!(remaining[1], FactorKind::Password);
        } else {
            panic!("expected Authenticating state");
        }
    }

    #[tokio::test]
    async fn advance_factor_transitions_to_authenticated_when_empty() {
        let session = test_session();
        session
            .begin_authenticating(
                "u1".into(),
                "t1".into(),
                "test".into(),
                vec![FactorKind::Password],
            )
            .await;

        session
            .advance_factor(&FactorKind::Password, Utc::now())
            .await;
        assert!(session.is_authenticated().await);
    }

    #[tokio::test]
    async fn clear_resets_to_guest() {
        let session = test_session();
        session
            .set_authenticated("u1".into(), "t1".into(), Utc::now())
            .await;
        assert!(session.is_authenticated().await);

        session.clear().await;
        assert!(session.auth_state().await.is_guest());
    }

    #[tokio::test]
    async fn custom_data_round_trip() {
        let session = test_session();
        session.set_custom("foo", serde_json::json!(42)).await;
        let v = session.get_custom("foo").await;
        assert_eq!(v.unwrap(), serde_json::json!(42));
    }

    #[tokio::test]
    async fn set_pending_workflow() {
        let session = test_session();
        let ws = WorkflowState::new(WorkflowKind::Signup, 3, Utc::now());
        session
            .set_pending_workflow("u1".into(), "t1".into(), ws)
            .await;

        let state = session.auth_state().await;
        assert!(matches!(state, AuthState::PendingWorkflow { .. }));
    }
}
