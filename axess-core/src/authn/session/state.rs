use crate::authn::{
    backend::{AuthnBackend, EntityState, FactorId, MethodId, TenantId, UserId},
    methods::{
        factor::{AuthFactorKind, FactorInstance},
        method::MethodInstance,
    },
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value as JsonValue;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound(
    serialize = "M: Serialize, F: Serialize, U: Serialize",
    deserialize = "M: DeserializeOwned, F: DeserializeOwned, U: DeserializeOwned"
))]
pub struct PartialAuthState<M, F, U>
where
    M: MethodId + serde::de::DeserializeOwned + serde::Serialize,
    F: FactorId + serde::de::DeserializeOwned + serde::Serialize,
    U: UserId + serde::de::DeserializeOwned + serde::Serialize,
{
    pub current_method: MethodInstance<M, F, U>,
    pub remaining_factors: Vec<F>,
    pub attempt_count: u32,
    pub last_attempt: Option<DateTime<Utc>>,
}

impl<M, F, U> PartialAuthState<M, F, U>
where
    M: MethodId,
    F: FactorId,
    U: UserId,
{
    pub fn new(method: MethodInstance<M, F, U>) -> Self {
        Self {
            current_method: method,
            remaining_factors: Vec::new(),
            attempt_count: 0,
            last_attempt: None,
        }
    }

    /// Marks the given factor as applied by removing it from remaining_factors.
    pub fn apply_factor(&mut self, factor_id: &F) -> Self {
        self.remaining_factors.retain(|f| f != factor_id);
        self.clone()
    }

    /// Returns the kind of the next required factor, if any.
    pub fn next_factor_kind(&self) -> Option<AuthFactorKind> {
        self.next_factor().map(|factor| factor.kind.clone())
    }

    /// Returns the id of the next required factor, if any.
    pub fn next_factor_id(&self) -> Option<&F> {
        self.remaining_factors.first()
    }

    pub fn next_factor(&self) -> Option<&FactorInstance<F, U>> {
        self.next_factor_id().and_then(|factor_id| {
            self.current_method
                .factors
                .iter()
                .find(|factor_instance| &factor_instance.id == factor_id)
        })
    }

    pub fn is_complete(&self) -> bool {
        self.remaining_factors.is_empty()
    }

    pub fn increment_attempt(&mut self) -> Self {
        self.attempt_count += 1;
        self.last_attempt = Some(Utc::now());
        self.clone()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(bound(
    serialize = "M: Serialize, F: Serialize, U: Serialize",
    deserialize = "M: DeserializeOwned, F: DeserializeOwned, U: DeserializeOwned"
))]
pub enum AuthState<M, F, U>
where
    M: MethodId,
    F: FactorId,
    U: UserId,
{
    #[default]
    NotAuthenticated,
    PartialAuthn(PartialAuthState<M, F, U>),
    Authenticated,
}

impl<M, F, U> AuthState<M, F, U>
where
    M: MethodId,
    F: FactorId,
    U: UserId,
{
    pub fn new_partial(method: MethodInstance<M, F, U>) -> Self {
        let mut partial = PartialAuthState::new(method);
        partial.remaining_factors = partial
            .current_method
            .factors
            .iter()
            .map(|factor| factor.id.clone())
            .collect();
        AuthState::PartialAuthn(partial)
    }

    pub fn with_attempt(self, attempt: u32) -> Self {
        match self {
            AuthState::PartialAuthn(mut partial) => {
                partial.attempt_count = attempt;
                AuthState::PartialAuthn(partial)
            }
            _ => self,
        }
    }

    // pub fn increment_attempt(self) -> Self {
    //     match self {
    //         AuthState::PartialAuthn(mut partial) => {
    //             partial = partial.increment_attempt();
    //             AuthState::PartialAuthn(partial)
    //         }
    //         _ => self,
    //     }
    // }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(bound(
    serialize = "M: Serialize, F: Serialize, U: Serialize, T: Serialize",
    deserialize = "M: DeserializeOwned, F: DeserializeOwned, U: DeserializeOwned, T: DeserializeOwned"
))]
pub struct Data<M, F, U, T>
where
    M: MethodId,
    F: FactorId,
    U: UserId,
    T: TenantId,
{
    pub tenant_id: Option<T>,                    // Tenant ID if applicable
    pub user_id: Option<U>,                      // User ID if authenticated
    pub user_state: EntityState,                 // Current user state
    pub auth_state: AuthState<M, F, U>,          // Current authentication state
    pub auth_hash: Option<String>,               // Hash of the authentication state
    pub custom_data: HashMap<String, JsonValue>, // Additional custom session data
}

impl<M, F, U, T> Data<M, F, U, T>
where
    M: MethodId,
    F: FactorId,
    U: UserId,
    T: TenantId,
{
    pub fn new(
        tenant_id: Option<T>,
        user_id: Option<U>,
        user_state: EntityState,
        auth_state: AuthState<M, F, U>,
        auth_hash: Option<String>,
        custom_data: HashMap<String, JsonValue>,
    ) -> Self {
        Self {
            tenant_id,
            user_id,
            user_state,
            auth_state,
            auth_hash,
            custom_data,
        }
    }
}

impl<M, F, U, T> Default for Data<M, F, U, T>
where
    M: MethodId,
    F: FactorId,
    U: UserId,
    T: TenantId,
{
    fn default() -> Self {
        Self {
            tenant_id: None,                                    // Default tenant ID
            user_id: None,                                      // Default user ID
            user_state: EntityState::Guest,                     // Default user state
            auth_state: AuthState::<M, F, U>::NotAuthenticated, // Default authentication state
            auth_hash: None,
            custom_data: HashMap::new(), // Default empty custom data
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuthEventType {
    Authenticated,
    LoginAttempt,
    LogoutAttempt,
    FactorVerified,
    FactorSetup,
    FactorEnabled,
    FactorDisabled,
    MethodEnabled,
    MethodDisabled,
    PasswordReset,
    SessionExpired,
    SessionInvalidated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuthEventStatus {
    Success,
    Failure,
    Locked,
    Expired,
    Suspicious,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "B::DataId: Serialize, B::UserId: Serialize, B::TenantId: Serialize, B::MethodId: Serialize, B::FactorId: Serialize",
    deserialize = "B::DataId: DeserializeOwned, B::UserId: DeserializeOwned, B::TenantId: DeserializeOwned, B::MethodId: DeserializeOwned, B::FactorId: DeserializeOwned"
))]
pub struct AuthEvent<B>
where
    B: AuthnBackend,
{
    // Core identifiers
    pub id: B::DataId,
    pub user_id: B::UserId,
    pub tenant_id: B::TenantId,
    pub session_id: Option<String>,

    // What happened and when
    pub event_type: AuthEventType,
    pub event_status: AuthEventStatus,
    pub event_time: DateTime<Utc>,

    // Authentication context (as separate queryable fields)
    pub method_id: Option<B::MethodId>,
    pub factor_id: Option<B::FactorId>,
    pub factor_kind: Option<AuthFactorKind>,

    // Request context (authentication-related)
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,

    // Error details (for failures)
    pub error_message: Option<String>,
}

// impl<B> AuthEvent<B>
// where
//     B: AuthnBackend
// {
//     pub fn new(
//             &self, user_id: &B::UserId, tenant_id: &B::TenantId, event_type: AuthEventType, event_status: AuthEventStatus,
//             session_id: Option<&str>, ip_address: Option<&str>, user_agent: Option<&str>,
//         ) -> Self {
//         Self {
//             id: B::DataId::new(),
//             user_id: user_id.clone(),
//             tenant_id: tenant_id.clone(),
//             event_type,
//             event_status,
//             event_time: Utc::now(),
//             session_id: session_id.map(|s| s.to_string()),
//             ip_address: ip_address.map(|s| s.to_string()),
//             user_agent: user_agent.map(|s| s.to_string()),
//         }
//     }
// }

/// Parameters for recording an authentication event.
///
/// This struct groups related authentication event data to avoid
/// passing too many individual parameters to `record_auth_event`.
#[derive(Debug, Clone)]
pub struct AuthEventBuilder<'a, M, F, T, U>
where
    M: MethodId,
    F: FactorId,
    T: TenantId,
    U: UserId,
{
    pub user_id: &'a U,
    pub tenant_id: &'a T,
    pub session_id: Option<&'a str>,
    pub event_type: AuthEventType,
    pub event_status: AuthEventStatus,
    pub method_id: Option<&'a M>,
    pub factor_id: Option<&'a F>,
    pub factor_kind: Option<AuthFactorKind>,
    pub ip_address: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub error_message: Option<&'a str>,
}

impl<'a, M, F, T, U> AuthEventBuilder<'a, M, F, T, U>
where
    M: MethodId,
    F: FactorId,
    T: TenantId,
    U: UserId,
{
    pub fn new(
        user_id: &'a U,
        tenant_id: &'a T,
        event_type: AuthEventType,
        event_status: AuthEventStatus,
    ) -> Self {
        Self {
            user_id,
            tenant_id,
            session_id: None,
            event_type,
            event_status,
            method_id: None,
            factor_id: None,
            factor_kind: None,
            ip_address: None,
            user_agent: None,
            error_message: None,
        }
    }
    /// Builder method to set session ID
    pub fn with_session_id(mut self, session_id: &'a str) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Builder method to set method ID
    pub fn with_method_id(mut self, method_id: &'a M) -> Self {
        self.method_id = Some(method_id);
        self
    }

    /// Builder method to set factor ID
    pub fn with_factor_id(mut self, factor_id: &'a F) -> Self {
        self.factor_id = Some(factor_id);
        self
    }

    /// Builder method to set factor kind
    pub fn with_factor_kind(mut self, factor_kind: AuthFactorKind) -> Self {
        self.factor_kind = Some(factor_kind);
        self
    }

    /// Builder method to set IP address
    pub fn with_ip_address(mut self, ip_address: &'a str) -> Self {
        self.ip_address = Some(ip_address);
        self
    }

    /// Builder method to set user agent
    pub fn with_user_agent(mut self, user_agent: &'a str) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    /// Builder method to set error message
    pub fn with_error_message(mut self, error_message: &'a str) -> Self {
        self.error_message = Some(error_message);
        self
    }
}

pub type AuthEventRecord<'a, B> = AuthEventBuilder<
    'a,
    <B as AuthnBackend>::MethodId,
    <B as AuthnBackend>::FactorId,
    <B as AuthnBackend>::TenantId,
    <B as AuthnBackend>::UserId,
>;
