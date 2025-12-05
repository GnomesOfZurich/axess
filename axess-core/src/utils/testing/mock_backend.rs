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
        backend::{AuthTenant, AuthnBackend, EntityState},
        methods::{
            MethodStateChange,
            factor::FactorStateChange,
            form::FactorForm,
            scope::{EnablementState, PermissionScope},
        },
        session::state::{AuthEvent, AuthEventRecord, AuthEventStatus, AuthEventType},
        types::{AuthFactor, AuthFactorState, AuthMethod, AuthMethodState}, // workflows::{Workflow, WorkflowState, WorkflowStep, WorkflowStepKind},
    },
    utils::testing::{
        mock_authn::{MockAuthFactor, MockAuthFactorState, MockAuthMethod, MockAuthMethodState},
        mock_entities::{
            DEFAULT_TENANT_ID, DEFAULT_USER_ID, MockTenant, MockUser, SYSTEM_SUPER_USER_ID,
            TENANT_SUPER_USER_ID, TestTenantId, TestUserId,
        },
        mock_form::DummyFailingForm,
    },
};

use async_trait::async_trait;
use chrono::Utc;
use dashmap::DashMap;
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
    type MethodId = String;
    type FactorId = String;
    type DataId = String;
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
        method_id: &Self::MethodId,
    ) -> Result<AuthMethod<Self>, Self::Error> {
        self.auth_methods
            .get(method_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| MockBackendError::NotFound("Method not found".to_string()))
    }

    async fn get_all_auth_methods(&self) -> Result<Vec<AuthMethod<Self>>, Self::Error> {
        Ok(self
            .auth_methods
            .iter()
            .map(|entry| entry.value().clone())
            .collect())
    }

    async fn get_scoped_auth_methods(
        &self,
        _scope: PermissionScope<Self::TenantId, Self::UserId>,
        _state: EnablementState,
    ) -> Result<Vec<AuthMethod<Self>>, Self::Error> {
        Ok(self
            .auth_methods
            .iter()
            .map(|entry| entry.value().clone())
            .collect())
    }

    async fn get_method_states(
        &self,
        method_id: &Self::MethodId,
        scope: PermissionScope<Self::TenantId, Self::UserId>,
    ) -> Result<Vec<AuthMethodState<Self>>, Self::Error> {
        Ok(self
            .auth_method_states
            .iter()
            .filter(|entry| {
                &entry.value().method_id == method_id
                    && match &scope {
                        PermissionScope::Global | PermissionScope::Any => true,
                        PermissionScope::Tenant(tenant_id) => {
                            entry.value().tenant_id.as_ref().map(|t| t.as_str())
                                == Some(tenant_id.0.as_str())
                        }
                        PermissionScope::User(tenant_id, user_id) => {
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
        change: MethodStateChange<Self::MethodId, Self::TenantId, Self::UserId>,
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
        factor_id: &Self::FactorId,
    ) -> Result<AuthFactor<Self>, Self::Error> {
        self.auth_factors
            .get(factor_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| MockBackendError::NotFound("Factor not found".to_string()))
    }

    async fn get_all_auth_factors(&self) -> Result<Vec<AuthFactor<Self>>, Self::Error> {
        Ok(self
            .auth_factors
            .iter()
            .map(|entry| entry.value().clone())
            .collect())
    }

    async fn get_scoped_auth_factors(
        &self,
        _scope: PermissionScope<Self::TenantId, Self::UserId>,
        _state: Vec<EnablementState>,
    ) -> Result<Vec<AuthFactor<Self>>, Self::Error> {
        // For mock implementation, return empty vector
        Ok(Vec::new())
    }

    async fn get_factor_states(
        &self,
        factor_id: &Self::FactorId,
        scope: PermissionScope<Self::TenantId, Self::UserId>,
    ) -> Result<Vec<AuthFactorState<Self>>, Self::Error> {
        Ok(self
            .auth_factor_states
            .iter()
            .filter(|entry| {
                &entry.value().factor_id == factor_id
                    && match &scope {
                        PermissionScope::Global | PermissionScope::Any => true,
                        PermissionScope::Tenant(tenant_id) => {
                            entry.value().tenant_id.as_ref().map(|t| t.as_str())
                                == Some(tenant_id.0.as_str())
                        }
                        PermissionScope::User(tenant_id, user_id) => {
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
        change: FactorStateChange<Self::FactorId, Self::TenantId, Self::UserId>,
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
            // AuthFactorState type params: <DataId, FactorId, UserId, TenantId>
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

    async fn authenticate<'a, F>(&self, creds: &'a F) -> Result<Self::User, Self::Error>
    where
        F: FactorForm + Send + Sync,
    {
        // If the form is DummyFailingForm, return an error
        if std::any::type_name_of_val(creds) == std::any::type_name::<DummyFailingForm>() {
            return Err(MockBackendError::Other("Invalid credentials".to_string()));
        }

        // If there are no users, or only a guest user, fail authentication
        let only_guest = self.users.len() == 1
            && self
                .users
                .get(&TestUserId("guest".to_string()))
                .map(|u| u.state == EntityState::Guest)
                .unwrap_or(false);

        let no_users = self.users.is_empty();

        if only_guest || no_users {
            return Err(MockBackendError::Other(
                "Guest users cannot authenticate".to_string(),
            ));
        }

        // If a user with id "guest" exists and is a guest, fail authentication
        if let Some(user) = self.users.get(&TestUserId("guest".to_string())) {
            if user.state == EntityState::Guest {
                return Err(MockBackendError::Other(
                    "Guest users cannot authenticate".to_string(),
                ));
            }
        }

        // Otherwise, return a valid user
        Ok(MockUser {
            id: DEFAULT_USER_ID.into(),
            tenant_id: DEFAULT_TENANT_ID.into(),
            state: EntityState::Active,
        })
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
        method_state_id: &Self::DataId,
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
        method_id: &Self::MethodId,
        _actor: Self::UserId,
    ) -> Result<(), Self::Error> {
        self.auth_methods.remove(method_id);
        Ok(())
    }

    async fn delete_factor_state(
        &self,
        factor_state_id: &Self::FactorId,
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
        factor_id: &Self::FactorId,
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
