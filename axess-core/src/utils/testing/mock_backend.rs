//! In-memory mock backend utilities for Axess tests.
//!
//! This module provides [`MockBackend`], mock tenant/user identifiers, and helpers to
//! exercise the [`AuthnBackend`] and [`AuthnAdminBackend`] contracts without a real datastore.
//!
//! Use these types to write deterministic, fast unit and integration tests for authentication flows,
//! factor/method provisioning, session state transitions, and audit event recording.
//!
//! # Features
//! - Implements all required async methods for [`AuthnBackend`] and [`AuthnAdminBackend`].
//! - Stores users, tenants, factors, methods, states, and events in thread-safe in-memory maps.
//! - Provides mock types: [`MockUser`], [`MockTenant`], [`TestUserId`], [`TestTenantId`].
//! - Compatible with Axess session, factor, and method builders for realistic test scenarios.
//! - Supports DST (Deterministic Simulation Testing) and parallel test execution.
//!
//! # Usage
//! ```rust
//! use axess_core::utils::testing::mock_backend::MockBackend;
//! use axess_core::authn::backend::AuthnBackend;
//!
//! #[tokio::test]
//! async fn test_guest_user_creation() {
//!     let backend = MockBackend::default();
//!     let guest = backend.get_new_guest_user(None).await.unwrap();
//!     assert_eq!(guest.get_user_state().to_string(), "Guest");
//! }
//! ```
//!
//! See also: [`mock_entities`](mock_entities.rs), [`mock_authn`](mock_authn.rs), [`mock_form`](mock_form.rs)

#[cfg(feature = "admin")]
use crate::authn::backend::admin::AuthnAdminBackend;
use crate::{
    authn::{
        backend::{AuthTenant, AuthUser, AuthnBackend, EntityState}, errors::AuthError, methods::{
            MethodStateChange,
            factor::FactorStateChange,
            form::{FactorForm, FactorFormExt, FormField, Action},
            scope::{AuthnScope, EnablementState},
        }, session::state::{AuthEvent, AuthEventRecord, AuthEventStatus, AuthEventType}, types::{AuthFactor, AuthFactorState, AuthMethod, AuthMethodState} // workflows::{Workflow, WorkflowState, WorkflowStep, WorkflowStepKind},
    },
    utils::testing::{
        mock_authn::{MockAuthFactor, MockAuthFactorState, MockAuthMethod, MockAuthMethodState},
        mock_entities::{
            DEFAULT_TENANT_ID, MockTenant, MockUser, SYSTEM_SUPER_USER_ID,
            TENANT_SUPER_USER_ID, TestTenantId, TestUserId,
        },
    },
};

use async_trait::async_trait;
use chrono::Utc;
use dashmap::DashMap;
use tracing::{debug, info};
// use serde::{Deserialize, Serialize};
// use std::{fmt::Debug, hash::Hash};
use std::fmt::Debug;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MockBackendError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Other error: {0}")]
    Other(String),
}

// TODO: Consider letting the mock backend be an in-memory SQLite database
// use sqlx::SqlitePool;

// async fn create_test_backend() -> OurBackend {
//     let pool = SqlitePool::connect(":memory:").await.unwrap();
//     OurBackend::new(pool)
// }

// #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Hash)]
// pub struct MockWorkflow;

// impl MockWorkflow {
//     // pub fn new() -> Self {
//     //     MockWorkflow
//     // }

//     fn start_workflow<M>(&mut self, _method: &M) -> Result<WorkflowState, WorkflowError> {
//         // For mock, return a default state with required fields
//         Ok(WorkflowState {
//             steps: vec![WorkflowStep {
//                 kind: WorkflowStepKind::Custom("mock_step".to_string()),
//                 description: "Mock step for testing".to_string(),
//                 completed: false,
//                 completed_at: None,
//                 metadata: None,
//             }],
//             current_step: 0,
//             started_at: chrono::Utc::now(),
//             last_updated: chrono::Utc::now(),
//             blocking: false,
//         })
//     }
// }

// impl std::fmt::Display for MockWorkflow {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(f, "MockWorkflow")
//     }
// }

// impl Workflow for MockWorkflow {
//     fn advance(&mut self) -> Result<(), WorkflowError> {
//         Ok(())
//     }

//     fn current_step(&self) -> String {
//         "complete".to_string()
//     }

//     fn is_blocking(&self) -> bool {
//         false
//     }

//     fn is_complete(&self) -> bool {
//         true
//     }

//     fn blocking_reason(&self) -> Option<String> {
//         None
//     }
// }

pub struct MockBackend {
    pub users: DashMap<TestUserId, MockUser>,
    pub tenants: DashMap<TestTenantId, MockTenant>,
    pub auth_factors: DashMap<String, MockAuthFactor>,
    pub auth_factor_states: DashMap<String, MockAuthFactorState>,
    pub auth_methods: DashMap<String, MockAuthMethod>,
    pub auth_method_states: DashMap<String, MockAuthMethodState>,
    pub authn_history: DashMap<String, Vec<AuthEvent<Self>>>,
}

impl std::fmt::Debug for MockBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MockBackend {{ ... }}")
    }
}

impl Clone for MockBackend {
    fn clone(&self) -> Self {
        let users = self.users.clone();
        let tenants = self.tenants.clone();
        let auth_factors = self.auth_factors.clone();
        let auth_factor_states = self.auth_factor_states.clone();
        let auth_methods = self.auth_methods.clone();
        let auth_method_states = self.auth_method_states.clone();
        let authn_history = self.authn_history.clone();

        Self {
            users,
            tenants,
            auth_factors,
            auth_factor_states,
            auth_methods,
            auth_method_states,
            authn_history,
        }
    }
}

#[async_trait]
// Removed duplicate and incomplete impl AuthnBackend for MockBackend

impl Default for MockBackend {
    fn default() -> Self {
        Self {
            users: DashMap::new(),
            tenants: DashMap::new(),
            auth_factors: DashMap::new(),
            auth_factor_states: DashMap::new(),
            auth_methods: DashMap::new(),
            auth_method_states: DashMap::new(),
            authn_history: DashMap::new(),
        }
    }
}

#[async_trait]
impl AuthnBackend for MockBackend {
    type User = MockUser;
    type UserId = TestUserId;
    type Tenant = MockTenant;
    type TenantId = TestTenantId;
    type AuthId = String;
    type Error = MockBackendError;

    async fn get_default_protected_route(
        &self,
        _tenant_id: Self::TenantId,
        _user_id: Self::UserId,
    ) -> Result<String, Self::Error> {
        Ok("/dashboard".to_string())
    }

    async fn get_tenant(&self, tenant_id: &Self::TenantId) -> Result<Self::Tenant, Self::Error> {
        self.tenants
            .get(tenant_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| MockBackendError::NotFound("Tenant not found".to_string()))
    }

    async fn get_tenant_by_name(&self, name: &str) -> Result<Self::Tenant, Self::Error> {
        self.tenants
            .iter()
            .find(|entry| entry.value().name == name)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| MockBackendError::NotFound("Tenant not found".to_string()))
    }

    async fn get_default_tenant_id(&self) -> Result<Self::TenantId, Self::Error> {
        Ok(MockTenant::default().id())
    }

    async fn get_user(&self, user_id: &Self::UserId) -> Result<Self::User, Self::Error> {
        self.users
            .get(user_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| MockBackendError::NotFound("User not found".to_string()))
    }

    async fn get_user_by_name(
        &self,
        tenant_id: &Self::TenantId,
        username: &str,
    ) -> Result<Self::User, Self::Error> {
        self.users
            .iter()
            .find(|entry| entry.value().tenant_id == *tenant_id && entry.value().id.0 == username)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| MockBackendError::NotFound("User not found".to_string()))
    }

    async fn get_system_user_id(
        &self,
        tenant_id: Option<&Self::TenantId>,
    ) -> Result<Self::UserId, Self::Error> {
        match tenant_id {
            // Compare the inner string explicitly to avoid ambiguous `Into`/`From<&str>` impls
            Some(tid) if tid.0.as_str() == DEFAULT_TENANT_ID => {
                Ok(TestUserId(TENANT_SUPER_USER_ID.to_string()))
            }
            Some(_) => Err(MockBackendError::NotFound("User not found".to_string())),
            None => Ok(TestUserId(SYSTEM_SUPER_USER_ID.to_string())),
        }
    }

    async fn create_new_user<F>(
        &self,
        form: &F,
    ) -> Result<Self::User, Self::Error>
    where
        F: crate::authn::methods::form::FactorForm + Send + Sync,
    {
        if form.validate_form().is_err() {
            return Err(MockBackendError::Other(
                "Form validation failed".to_string(),
            ));
        }
        // For the mock, generate a user from the form (if possible) or use defaults
        let fields = form.fields();
        let tenant_name: String = fields
            .get(&FormField::TenantName)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| MockTenant::default().name());
        let tenant_id = self.get_tenant_by_name(&tenant_name).await?.id();
        let user_name: String = form
            .fields()
            .get(&FormField::UserName)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| MockUser::default().id.0.clone());
        let user = self.get_user_by_name(&tenant_id, &user_name).await?;
        let user_id = user.id();
        let state = EntityState::Active;
        let user = MockUser {
            id: user_id.clone(),
            tenant_id: tenant_id.clone(),
            state,
        };
        self.users.insert(user_id.clone(), user.clone());
        Ok(user)
    }

    async fn set_user_state(
        &self,
        user_id: &Self::UserId,
        new_state: EntityState,
        _actor: Self::UserId,
    ) -> Result<Self::User, Self::Error> {
        if let Some(mut entry) = self.users.get_mut(user_id) {
            entry.state = new_state;
            // entry.updated_at = Utc::now();
            // entry.updated_by = actor;
            Ok(entry.clone())
        } else {
            Err(MockBackendError::NotFound("User not found".to_string()))
        }
    }

    async fn get_new_guest_user(
        &self,
        tenant_id: Option<&Self::TenantId>,
    ) -> Result<Self::User, Self::Error> {
        Ok(MockUser {
            id: TestUserId("guest".to_string()),
            tenant_id: tenant_id
                .cloned()
                .unwrap_or(TestTenantId("default".to_string())),
            state: EntityState::Guest,
        })
    }

    async fn get_auth_method(
        &self,
        method_id: &Self::AuthId,
    ) -> Result<AuthMethod<Self>, Self::Error> {
        self.auth_methods
            .get(method_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| MockBackendError::NotFound("Method not found".to_string()))
    }

    /// Get the authentication method by its name, optionally filtered on enablement state(s) and scope.
    /// An empty array of enablement states means that all states are acceptable (i.e. no filtering).
    async fn get_auth_method_by_name(
        &self,
        name: &str,
        scope: AuthnScope<Self::TenantId, Self::UserId>,
        states: Vec<EnablementState>,
    ) -> Result<AuthMethod<Self>, Self::Error> {
        // 1. Find all methods with the given name
        let methods: Vec<_> = self
            .auth_methods
            .iter()
            .filter(|entry| entry.value().name == name)
            .map(|entry| entry.value().clone())
            .collect();

        // 2. For each method, check if there is a matching state for the scope and enablement state
        for method in methods {
            let method_states: Vec<_> = self
                .auth_method_states
                .iter()
                .filter(|entry| {
                    entry.value().method_id == method.id
                        && match &scope {
                            AuthnScope::Global | AuthnScope::Any => true,
                            AuthnScope::Tenant(tenant_id) => {
                                entry.value().tenant_id.as_ref().map(|t| t.as_str())
                                    == Some(tenant_id.0.as_str())
                            }
                            AuthnScope::User(tenant_id, user_id) => {
                                entry.value().tenant_id.as_ref().map(|t| t.as_str())
                                    == Some(tenant_id.0.as_str())
                                    && entry.value().user_id.as_ref().map(|u| u.as_str())
                                        == Some(user_id.0.as_str())
                            }
                        }
                        && (states.is_empty() || states.contains(&entry.value().state))
                })
                .collect();

            if !method_states.is_empty() {
                return Ok(method);
            }
        }

        Err(MockBackendError::NotFound(format!(
            "Method '{}' not found for scope and state",
            name
        )))
    }

    async fn get_scoped_auth_methods(
        &self,
        _scope: AuthnScope<Self::TenantId, Self::UserId>,
        _states: Vec<EnablementState>,
    ) -> Result<Vec<AuthMethod<Self>>, Self::Error> {
        Ok(self
            .auth_methods
            .iter()
            .map(|entry| entry.value().clone())
            .collect())
    }

    async fn get_method_states(
        &self,
        method_id: &Self::AuthId,
        scope: AuthnScope<Self::TenantId, Self::UserId>,
    ) -> Result<Vec<AuthMethodState<Self>>, Self::Error> {
        Ok(self
            .auth_method_states
            .iter()
            .filter(|entry| {
                &entry.value().method_id == method_id
                    && match &scope {
                        AuthnScope::Global | AuthnScope::Any => true,
                        AuthnScope::Tenant(tenant_id) => {
                            entry.value().tenant_id.as_ref().map(|t| t.as_str())
                                == Some(tenant_id.0.as_str())
                        }
                        AuthnScope::User(tenant_id, user_id) => {
                            entry.value().tenant_id.as_ref().map(|t| t.as_str())
                                == Some(tenant_id.0.as_str())
                                && entry.value().user_id.as_ref().map(|u| u.as_str())
                                    == Some(user_id.0.as_str())
                        }
                    }
            })
            .map(|entry| entry.value().clone())
            .collect())
    }

    /// Upserts (inserts or updates) the authentication method state for the given method.
    /// If a state for the method already exists, it will be updated; otherwise, it will be inserted.
    async fn upsert_method_state(
        &self,
        change: MethodStateChange<Self::AuthId, Self::TenantId, Self::UserId>,
        actor: Self::UserId,
    ) -> Result<AuthMethodState<Self>, Self::Error> {
        // Create natural key from method_id, tenant_id, user_id
        let key = format!(
            "{}:{}:{}",
            change.method_id,
            change
                .tenant_id
                .as_ref()
                .map(|t| t.to_string())
                .unwrap_or_else(|| "null".to_string()),
            change
                .user_id
                .as_ref()
                .map(|u| u.to_string())
                .unwrap_or_else(|| "null".to_string())
        );

        let now = Utc::now();

        // Check if state exists first (borrow only)
        let existing_id_and_audit = self.auth_method_states.get(&key).map(|existing| {
            (
                existing.id.clone(),
                existing.created_at,
                existing.created_by.clone(),
            )
        });

        // Build method state based on whether it exists
        let method_state = if let Some((id, created_at, created_by)) = existing_id_and_audit {
            // Update: preserve existing audit trail
            AuthMethodState::<MockBackend> {
                id,
                method_id: change.method_id,
                tenant_id: change.tenant_id,
                user_id: change.user_id,
                state: change.state,
                created_at,
                created_by,
                updated_at: now,
                updated_by: actor,
            }
        } else {
            // Insert: generate new ID
            let id = format!("method_state_{}", self.auth_method_states.len());

            AuthMethodState::<MockBackend> {
                id,
                method_id: change.method_id,
                tenant_id: change.tenant_id,
                user_id: change.user_id,
                state: change.state,
                created_at: now,
                created_by: change.updated_by.clone(),
                updated_at: now,
                updated_by: actor,
            }
        };

        // Store and return
        self.auth_method_states.insert(key, method_state.clone());
        Ok(method_state)
    }

    async fn get_auth_factor(
        &self,
        factor_id: &Self::AuthId,
    ) -> Result<AuthFactor<Self>, Self::Error> {
        self.auth_factors
            .get(factor_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| MockBackendError::NotFound("Factor not found".to_string()))
    }

    /// Get the authentication factor by its name, optionally filtered on enablement state(s) and scope.
    /// An empty array of enablement states means that all states are acceptable (i.e. no filtering).
    async fn get_auth_factor_by_name(
        &self,
        name: &str,
        scope: AuthnScope<Self::TenantId, Self::UserId>,
        states: Vec<EnablementState>,
    ) -> Result<AuthFactor<Self>, Self::Error> {
        // 1. Find all factors with the given name
        let factors: Vec<_> = self
            .auth_factors
            .iter()
            .filter(|entry| entry.value().name == name)
            .map(|entry| entry.value().clone())
            .collect();

        // 2. For each factor, check if there is a matching state for the scope and enablement state
        for factor in factors {
            let factor_states: Vec<_> = self
                .auth_factor_states
                .iter()
                .filter(|entry| {
                    entry.value().factor_id == factor.id
                        && match &scope {
                            AuthnScope::Tenant(tenant_id) => entry
                                .value()
                                .tenant_id
                                .as_ref()
                                .map(|t| t == tenant_id)
                                .unwrap_or(false),
                            AuthnScope::User(tenant_id, user_id) => {
                                entry.value().tenant_id.as_ref() == Some(tenant_id)
                                    && entry.value().user_id.as_ref() == Some(user_id)
                            }
                            _ => true,
                        }
                        && (states.is_empty() || states.contains(&entry.value().state))
                })
                .collect();

            if !factor_states.is_empty() {
                return Ok(factor);
            }
        }

        Err(MockBackendError::NotFound(format!(
            "Factor '{}' not found for scope and state",
            name
        )))
    }

    async fn get_scoped_auth_factors(
        &self,
        _scope: AuthnScope<Self::TenantId, Self::UserId>,
        _states: Vec<EnablementState>,
    ) -> Result<Vec<AuthFactor<Self>>, Self::Error> {
        Ok(self
            .auth_factors
            .iter()
            .map(|entry| entry.value().clone())
            .collect())
    }

    async fn get_factor_states(
        &self,
        factor_id: &Self::AuthId,
        scope: AuthnScope<Self::TenantId, Self::UserId>,
    ) -> Result<Vec<AuthFactorState<Self>>, Self::Error> {
        Ok(self
            .auth_factor_states
            .iter()
            .filter(|entry| {
                &entry.value().factor_id == factor_id
                    && match &scope {
                        AuthnScope::Global | AuthnScope::Any => true,
                        AuthnScope::Tenant(tenant_id) => {
                            entry.value().tenant_id.as_ref().map(|t| t.as_str())
                                == Some(tenant_id.0.as_str())
                        }
                        AuthnScope::User(tenant_id, user_id) => {
                            entry.value().tenant_id.as_ref().map(|t| t.as_str())
                                == Some(tenant_id.0.as_str())
                                && entry.value().user_id.as_ref().map(|u| u.as_str())
                                    == Some(user_id.0.as_str())
                        }
                    }
            })
            .map(|entry| entry.value().clone())
            .collect())
    }

    async fn upsert_factor_state(
        &self,
        change: FactorStateChange<Self::AuthId, Self::TenantId, Self::UserId>,
        actor: Self::UserId,
    ) -> Result<AuthFactorState<Self>, Self::Error> {
        // Create natural key from factor_id, tenant_id, user_id
        let key = format!(
            "{}:{}:{}",
            change.factor_id,
            change
                .tenant_id
                .as_ref()
                .map(|t| t.to_string())
                .unwrap_or_else(|| "null".to_string()),
            change
                .user_id
                .as_ref()
                .map(|u| u.to_string())
                .unwrap_or_else(|| "null".to_string())
        );

        let now = Utc::now();

        // Check if state exists first (borrow only)
        let existing_id_and_audit = self.auth_factor_states.get(&key).map(|existing| {
            (
                existing.id.clone(),
                existing.created_at,
                existing.created_by.clone(),
            )
        });

        // Build factor state based on whether it exists
        let factor_state = if let Some((id, created_at, created_by)) = existing_id_and_audit {
            // Update: preserve existing audit trail
            // AuthFactorState type params: <AuthId, UserId, TenantId>
            AuthFactorState::<MockBackend> {
                id,
                factor_id: change.factor_id,
                tenant_id: change.tenant_id,
                user_id: change.user_id,
                state: change.state,
                config: change.config,
                created_at,
                created_by,
                updated_at: now,
                updated_by: actor,
            }
        } else {
            // Insert: generate new ID
            let id = format!("factor_state_{}", self.auth_factor_states.len());

            AuthFactorState::<MockBackend> {
                id,
                factor_id: change.factor_id,
                tenant_id: change.tenant_id,
                user_id: change.user_id,
                state: change.state,
                config: change.config,
                created_at: now,
                created_by: actor.clone(),
                updated_at: now,
                updated_by: actor,
            }
        };

        // Store and return
        self.auth_factor_states.insert(key, factor_state.clone());
        Ok(factor_state)
    }

    async fn get_auth_history(
        &self,
        user_id: &Self::UserId,
        event_type: Option<AuthEventType>,
        event_status: Option<AuthEventStatus>,
        limit: Option<usize>,
    ) -> Result<Vec<AuthEvent<Self>>, Self::Error> {
        let key = user_id.0.as_str();

        // Take references to the optional filters so we can use them inside the closure
        let filter_type = event_type.as_ref();
        let filter_status = event_status.as_ref();

        match self.authn_history.get(key) {
            Some(entry) => {
                // Filter by optional event_type and event_status
                let mut filtered: Vec<AuthEvent<MockBackend>> = entry
                    .value()
                    .iter()
                    .filter(|evt| {
                        if let Some(t) = filter_type {
                            if &evt.event_type != t {
                                return false;
                            }
                        }
                        if let Some(s) = filter_status {
                            if &evt.event_status != s {
                                return false;
                            }
                        }
                        true
                    })
                    .cloned()
                    .collect();

                // Sort by event_time (most recent first)
                filtered.sort_by(|a, b| b.event_time.cmp(&a.event_time));

                // Apply limit if requested
                let result = match limit {
                    None => filtered,
                    Some(0) => Vec::new(),
                    Some(l) => {
                        if l >= filtered.len() {
                            filtered
                        } else {
                            filtered.into_iter().take(l).collect()
                        }
                    }
                };

                Ok(result)
            }
            // No history -> return empty vec rather than an error, to simplify for callers.
            None => Ok(Vec::new()),
        }
    }
    async fn get_last_login(
        &self,
        user_id: &Self::UserId,
    ) -> Result<Option<chrono::DateTime<Utc>>, Self::Error> {
        // Reuse get_auth_history to keep filtering/sorting logic in one place.
        let events = self
            .get_auth_history(
                user_id,
                Some(AuthEventType::LoginAttempt),
                Some(AuthEventStatus::Success),
                Some(1),
            )
            .await?;
        Ok(events.into_iter().next().map(|e| e.event_time))
    }

    async fn record_auth_event(&self, event: AuthEventRecord<'_, Self>) -> Result<(), Self::Error> {
        // Read the record fields explicitly to avoid type-inference issues with backend-associated types
        let user_id = event.user_id.clone();
        let tenant_id = event.tenant_id.clone();
        let session_id = event.session_id.map(|s| s.to_string());
        let event_type = event.event_type;
        let event_status = event.event_status;
        let method_id = event.method_id.map(|m| m.to_string());
        let factor_id = event.factor_id.map(|f| f.to_string());
        let factor_kind = event.factor_kind;
        let ip_address = event.ip_address.map(|s| s.to_string());
        let user_agent = event.user_agent.map(|s| s.to_string());
        let error_message = event.error_message.map(|s| s.to_string());

        // Use the user's id string as the map key before moving `user_id` into `stored`
        let key = user_id.as_ref().to_string();

        // Build the stored event (assign id and timestamp here)
        let stored = AuthEvent::<MockBackend> {
            id: format!("event_{}", self.authn_history.len()),
            user_id,
            tenant_id,
            session_id,
            event_type,
            event_status,
            method_id,
            factor_id,
            factor_kind,
            event_time: Utc::now(),
            ip_address,
            user_agent,
            error_message,
        };

        // Push into existing history vector or insert a new one
        if let Some(mut vec_ref) = self.authn_history.get_mut(&key) {
            vec_ref.push(stored);
        } else {
            self.authn_history.insert(key, vec![stored]);
        }

        Ok(())
    }

    async fn authenticate<'a, F>(&self, form: &'a F) -> Result<Self::User, AuthError<MockBackend>>
    where
        F: FactorForm + Send + Sync,
    {
        // 1. Validate form and action
        if form.validate_form().is_err() {
            return Err(AuthError::UnexpectedFormContent);
        } else if form.action() != Action::Verify {
            return Err(AuthError::UnexpectedFormAction);
        }

        // 2. Get tenant ID from form
        let tenant_id = match form.get_string_field(FormField::TenantName) {
            Some(name) => {
                self.get_tenant_by_name(&name.to_string())
                    .await
                    .map_err(|_| AuthError::<Self>::TenantNotFound)
                    .unwrap()
                    .id
            }
            None => {
                // If no tenant name is provided, fall back to the backend's default tenant ID
                debug!("No tenant name provided in form; using default tenant ID");
                self.get_default_tenant_id()
                    .await
                    .map_err(|_| AuthError::<Self>::TenantNotFound)?
            }
        };

        // 3. Get user by name from form and together with tenant ID then fetch user from backend
        let db_user = match form.get_string_field(FormField::UserName) {
            Some(name) => self
                .get_user_by_name(&tenant_id, &name.to_string())
                .await
                .map_err(|_| {
                    info!("User not found: {} in tenant {}", name, tenant_id);
                    return AuthError::<Self>::UserNotFound;
                })
                .unwrap(),
            None => return Err(AuthError::<Self>::UserNotFound),
        };

        // 4. Check user state and return appropriate error if not active
        let user_state = db_user.get_user_state();
        if !user_state.is_deactivated() {
            info!("User {} is {:?}", db_user.id, user_state);
            return Err(AuthError::UserDeactivated(Box::new(user_state)));
        } else if user_state == EntityState::Guest {
            info!("Guest users cannot authenticate: {}", db_user.id);
            return Err(AuthError::UnexpectedUserState);
        }

        // 5. For the mock, we currently assume authentication is always successful if we reach this point
        // TODO: Consider adding a bit more mocking logic for processing of form.

        // Otherwise, return a valid user
        Ok(MockUser::default())
    }
}

#[cfg(feature = "admin")]
#[async_trait]
impl AuthnAdminBackend for MockBackend {
    async fn upsert_user(
        &self,
        user: Self::User,
        _actor: Self::UserId,
    ) -> Result<Self::User, Self::Error> {
        self.users.insert(user.id.clone(), user.clone());
        Ok(user)
    }

    async fn delete_user(
        &self,
        user_id: &Self::UserId,
        _actor: Self::UserId,
    ) -> Result<(), Self::Error> {
        self.users.remove(user_id);
        Ok(())
    }

    async fn upsert_tenant(
        &self,
        tenant: Self::Tenant,
        _actor: Self::UserId,
    ) -> Result<Self::Tenant, Self::Error> {
        self.tenants.insert(tenant.id.clone(), tenant.clone());
        Ok(tenant)
    }

    async fn delete_tenant(
        &self,
        tenant_id: &Self::TenantId,
        _actor: Self::UserId,
    ) -> Result<(), Self::Error> {
        // Only return Ok if the tenant existed and was removed
        if self.tenants.remove(tenant_id).is_some() {
            Ok(())
        } else {
            Err(MockBackendError::NotFound("Tenant not found".to_string()))
        }
    }

    async fn delete_method_state(
        &self,
        method_state_id: &Self::AuthId,
        _actor: Self::UserId,
    ) -> Result<(), Self::Error> {
        self.auth_method_states.remove(method_state_id);
        Ok(())
    }

    async fn upsert_auth_method(
        &self,
        method: AuthMethod<Self>,
        _actor: Self::UserId,
    ) -> Result<AuthMethod<Self>, Self::Error> {
        // Use the method's actual ID instead of generating a new one
        self.auth_methods.insert(method.id.clone(), method.clone());
        Ok(method)
    }

    async fn delete_auth_method(
        &self,
        method_id: &Self::AuthId,
        _actor: Self::UserId,
    ) -> Result<(), Self::Error> {
        self.auth_methods.remove(method_id);
        Ok(())
    }

    async fn delete_factor_state(
        &self,
        factor_state_id: &Self::AuthId,
        _actor: Self::UserId,
    ) -> Result<(), Self::Error> {
        self.auth_factor_states.remove(factor_state_id);
        Ok(())
    }

    async fn upsert_auth_factor(
        &self,
        factor: AuthFactor<Self>,
        _actor: Self::UserId,
    ) -> Result<AuthFactor<Self>, Self::Error> {
        // Use the factor's actual ID instead of generating a new one
        self.auth_factors.insert(factor.id.clone(), factor.clone());
        Ok(factor)
    }

    async fn delete_auth_factor(
        &self,
        factor_id: &Self::AuthId,
        _actor: Self::UserId,
    ) -> Result<(), Self::Error> {
        self.auth_factors.remove(factor_id);
        Ok(())
    }
}

impl PartialEq for MockBackend {
    fn eq(&self, other: &Self) -> bool {
        // Compare users
        if self.users.len() != other.users.len() {
            return false;
        }
        for entry in self.users.iter() {
            let key = entry.key();
            match other.users.get(key) {
                Some(other_entry) => {
                    if entry.value() != other_entry.value() {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // Compare tenants
        if self.tenants.len() != other.tenants.len() {
            return false;
        }
        for entry in self.tenants.iter() {
            let key = entry.key();
            match other.tenants.get(key) {
                Some(other_entry) => {
                    if entry.value() != other_entry.value() {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // Compare auth_factors
        if self.auth_factors.len() != other.auth_factors.len() {
            return false;
        }
        for entry in self.auth_factors.iter() {
            let key = entry.key();
            match other.auth_factors.get(key) {
                Some(other_entry) => {
                    if entry.value() != other_entry.value() {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // Compare auth_factor_states
        if self.auth_factor_states.len() != other.auth_factor_states.len() {
            return false;
        }
        for entry in self.auth_factor_states.iter() {
            let key = entry.key();
            match other.auth_factor_states.get(key) {
                Some(other_entry) => {
                    if entry.value() != other_entry.value() {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // Compare auth_methods
        if self.auth_methods.len() != other.auth_methods.len() {
            return false;
        }
        for entry in self.auth_methods.iter() {
            let key = entry.key();
            match other.auth_methods.get(key) {
                Some(other_entry) => {
                    if entry.value() != other_entry.value() {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // Compare auth_method_states
        if self.auth_method_states.len() != other.auth_method_states.len() {
            return false;
        }
        for entry in self.auth_method_states.iter() {
            let key = entry.key();
            match other.auth_method_states.get(key) {
                Some(other_entry) => {
                    if entry.value() != other_entry.value() {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // Compare authn_history (Vec<AuthEvent<MockBackend>>)
        if self.authn_history.len() != other.authn_history.len() {
            return false;
        }
        for entry in self.authn_history.iter() {
            let key = entry.key();
            match other.authn_history.get(key) {
                Some(other_entry) => {
                    if entry.value() != other_entry.value() {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }
}

impl Eq for MockBackend {}
