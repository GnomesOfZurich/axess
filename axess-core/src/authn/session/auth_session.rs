use crate::{
    authn::{
        backend::{AuthTenant, AuthUser, AuthnBackend, EntityState},
        errors::AuthError,
        methods::{
            EnablementState,
            factor::{AuthFactorKind, FactorInstance, FactorState},
            form::{FactorForm, FactorFormKind},
            method::{MethodInstance, MethodState},
            scope::PermissionScope,
        },
        session::state::{AuthState, Data, PartialAuthState},
    },
    axum::{
        extract::{Form, Json},
        http::StatusCode,
        response::{IntoResponse, Redirect},
    },
    // storage::session_registry::{
    //     // SessionRegistry,
    //     // SessionRegistryError,
    // },
    tracing::{debug, error, warn},
};
use std::{
    // collections::HashMap,
    // char::MAX,
    fmt::{Debug, Display}, // sync::Arc
};

use tower_sessions::{
    Session,
    // session::Error as SessionError,
    // session_store::Error as StoreError,
};

// TODO: Make the maximum number of attempts per factor and session configurable.
const MAX_ATTEMPTS: u32 = 5; // Maximum number of attempts for authentication

// const SESSION_TIMEOUT_SECS: i64 = 30 * 60; // 30 minutes in seconds
// const SESSION_TIMEOUT: Duration = Duration::seconds(SESSION_TIMEOUT_SECS);

#[derive(Clone)]
pub struct AuthSession<B>
where
    B: AuthnBackend,
{
    pub state: SessionState<B>,

    /// The user associated by the backend or a guest user.
    pub user: B::User,

    /// The authentication and authorization backend.
    pub backend: B,

    /// The underlying session.
    pub session: Session,

    data: SessionData<B>,
    data_key: &'static str,
    // session_registry: Option<Arc<R>>,
}

impl<B> Debug for AuthSession<B>
where
    B: AuthnBackend + Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthSession")
            .field("state", &self.state)
            .field("user", &self.user)
            .field("backend", &self.backend)
            .field("session", &self.session)
            .field("data", &self.data)
            .field("data_key", &self.data_key)
            // .field("session_registry", &self.session_registry.is_some())
            .finish()
    }
}

/// Methods for authenticating the session and logging a user in are provided.
///
/// Generally this session will be used in the context of some authentication
/// workflow, for example via a frontend login form. There a user would provide
/// their credentials, such as username and password, and via the backend
/// the session would authenticate those credentials.
impl<B> AuthSession<B>
where
    B: AuthnBackend + Debug + PartialEq,
    B::TenantId: From<<B::User as AuthUser>::TenantId>,
    B::UserId: From<<B::User as AuthUser>::Id>,
    <B as AuthnBackend>::TenantId: From<<<B as AuthnBackend>::Tenant as AuthTenant>::Id>,
{
    pub async fn from_session(
        session: Session,
        backend: B,
        data_key: &'static str,
        // session_registry: Option<Arc<R>>,
    ) -> Result<Self, AuthError<B>>
    where
        B::User: Clone,
        B::UserId: Clone,
        B::TenantId: Clone,
        // R: SessionRegistry + Send + Sync + 'static,
    {
        // 1. Load session data from the session store
        let mut data: SessionData<B> = session
            .get(data_key)
            .await
            .map_err(AuthError::SessionError)?
            .unwrap_or_default();

        // 2. Load the user based on the session data.
        let user = if data.user_state == EntityState::Guest {
            backend
                .get_new_guest_user(data.tenant_id.as_ref())
                .await
                .map_err(AuthError::BackendError)?
        } else {
            match data.user_id.as_ref() {
                Some(user_id) => {
                    let user = backend
                        .get_user(user_id)
                        .await
                        .map_err(AuthError::BackendError)?;
                    if user.get_user_state() == EntityState::Active {
                        if data.user_state != EntityState::Active {
                            debug!("Updating user state to Active in Session Data");
                            data.user_state = EntityState::Active;
                        }
                        user
                    } else {
                        warn!("User is not active, cannot authenticate");
                        return Err(AuthError::UserNotActive);
                    }
                }
                None => return Err(AuthError::UserNotFound),
            }
        };

        let auth_state = data.auth_state.clone();

        Ok(AuthSession {
            state: auth_state,
            user,
            backend,
            session,
            data,
            data_key,
            // session_registry,
        })
    }

    pub fn user(&self) -> Result<B::User, AuthError<B>> {
        Ok(self.user.clone())
    }

    pub fn get_user_state(&self) -> Option<EntityState> {
        Some(self.data.user_state.clone())
    }

    pub async fn set_user_state(&mut self, new_state: EntityState) -> Result<(), AuthError<B>>
    where
        B: AuthnBackend,
    {
        self.data.user_state = new_state;
        self.session
            .insert(self.data_key, &self.data)
            .await
            .map_err(AuthError::SessionError)?;
        Ok(())
    }

    /// Get the user ID associated with the session.
    /// Returns `None` if the session is not associated with a user.
    pub fn get_user_id(&self) -> Option<&B::UserId> {
        self.data.user_id.as_ref()
    }

    /// Get the tenant ID associated with the session.
    /// Returns `None` if the session is not associated with a tenant.
    pub fn get_tenant_id(&self) -> Option<&B::TenantId> {
        self.data.tenant_id.as_ref()
    }

    /// Get the authentication state of the session.
    /// This will return the current authentication state, which can be
    /// `NotAuthenticated`, `PartialAuthn`, or `Authenticated`.
    pub fn get_auth_state(&self) -> &SessionState<B> {
        &self.state
    }

    /// Get the user associated with the session.
    /// This will return the user if authenticated, or a guest user if not.
    /// Return reference to avoid move
    pub fn get_user(&self) -> &B::User {
        &self.user
    }

    /// Get the partial authentication state if it exists.
    /// This will return `Some(PartialAuthState)` if the session is in a partial authentication state,
    ///  or `None` if it is not.
    pub fn get_partial_inner_state(&self) -> Option<&PartialState<B>> {
        match self.state {
            SessionState::<B>::PartialAuthn(ref partial_state) => Some(partial_state),
            _ => None,
        }
    }

    /// Check if the session is in a partial authentication state.
    /// This will return `true` if the session is in a partial authentication state,
    /// or `false` if it is not.
    pub fn is_partial_authn(&self) -> bool {
        matches!(self.state, SessionState::<B>::PartialAuthn(_))
    }

    /// Check if the session is authenticated.
    /// This will return `true` if the session is authenticated,
    /// or `false` if it is not.
    pub fn is_authenticated(&self) -> bool {
        matches!(self.state, SessionState::<B>::Authenticated)
    }

    pub async fn initiate_auth_from_form<F>(
        &mut self,
        form: Form<F>,
    ) -> Result<impl IntoResponse, StatusCode>
    where
        F: FactorForm + Send + Sync + 'static,
    {
        self.initiate_auth_flow(form.0)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    }

    pub async fn initiate_auth_from_json<F>(
        &mut self,
        json: Json<F>,
    ) -> Result<impl IntoResponse, StatusCode>
    where
        F: FactorForm + Send + Sync + 'static,
    {
        self.initiate_auth_flow(json.0)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    }

    /// Initiate an authentication flow based on the submitted factor form.
    pub async fn initiate_auth_flow<F>(&mut self, form: F) -> Result<impl IntoResponse, StatusCode>
    where
        F: FactorForm + Send + Sync + 'static,
    {
        // Increment the attempt count and update last attempt time
        match &mut self.state {
            SessionState::<B>::PartialAuthn(partial_state) => {
                // Increment the attempt count and update last attempt time
                let updated_partial_state = partial_state.increment_attempt().clone();
                if updated_partial_state.attempt_count > MAX_ATTEMPTS {
                    // TODO: Handle too many attempts gracefully, e.g. capture IP addresses and store on user in the backend as locked out...)
                    error!("Too many authentication attempts, locking out session");
                    return Err(StatusCode::TOO_MANY_REQUESTS);
                }
                self.state = SessionState::<B>::PartialAuthn(updated_partial_state.clone());
                // updated_partial_state
            }
            _ => {
                error!("Session is not in partial authentication state");
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }

        let factor_kind = form.factor_kind();
        let form_kind = form.form_kind();
        if form_kind == FactorFormKind::Verify
            && let Some(partial_state) = self.get_partial_inner_state()
        {
            let expected_kind = partial_state.next_factor_kind();
            if expected_kind != Some(factor_kind.clone()) {
                tracing::warn!(
                    "Submitted factor kind {:?} does not match expected next factor {:?}",
                    form.factor_kind(),
                    expected_kind
                );
                return Err(StatusCode::BAD_REQUEST);
            }
        }

        // Determine desired factor state(s) based on form kind
        let desired_state = match form_kind {
            FactorFormKind::Setup => Some(EnablementState::Pending),
            FactorFormKind::Verify => Some(EnablementState::Active),
        };

        let fields = form.fields_map();

        // --- OAuth flow: handle OAuth factor kind ---
        if factor_kind == AuthFactorKind::Oauth {
            // Extract provider and tenant from form fields
            let provider_name = fields.get("provider").cloned().ok_or_else(|| {
                error!("No OAuth provider specified in form");
                StatusCode::BAD_REQUEST
            })?;

            // Resolve tenant_id from form, session, or backend default
            let tenant_id: B::TenantId = if let Some(tenant_name) = fields.get("tenant") {
                match self.backend.get_tenant_by_name(tenant_name).await {
                    Ok(tenant) => tenant.id().clone().into(),
                    Err(e) => {
                        warn!("Failed to resolve tenant name '{}': {:?}", tenant_name, e);
                        match self.backend.get_default_tenant_id().await {
                            Ok(default_id) => default_id,
                            Err(e) => {
                                error!(
                                    "Failed to fetch default tenant id after tenant name resolution failed: {:?}",
                                    e
                                );
                                return Err(StatusCode::INTERNAL_SERVER_ERROR);
                            }
                        }
                    }
                }
            } else if let Some(tid) = self.get_tenant_id().cloned() {
                tid
            } else {
                match self.backend.get_default_tenant_id().await {
                    Ok(id) => id,
                    Err(e) => {
                        error!("Failed to fetch default tenant id: {:?}", e);
                        return Err(StatusCode::INTERNAL_SERVER_ERROR);
                    }
                }
            };

            // Build the permission scope for OAuth provider lookup
            let scope = PermissionScope::Tenant(&tenant_id);

            // Get the OAuth provider configuration from backend
            // Get all factors for this tenant and provider
            let factors = self
                .backend
                .get_scoped_auth_factors(scope, Some(EnablementState::Active))
                .await
                .map_err(|e| {
                    error!("Failed to get scoped auth factors: {:?}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

            // Filter for OAuth factors matching the provider name
            let matching_factors: Vec<_> = factors
                .iter()
                .filter(|f| f.kind == AuthFactorKind::Oauth && f.name == provider_name)
                .collect();

            let factor = match matching_factors.len() {
                1 => matching_factors[0],
                0 => {
                    error!("No OAuth factor found for provider '{}'", provider_name);
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
                _ => {
                    warn!(
                        "Multiple OAuth factors found for provider '{}' and tenant '{:?}': {:?}",
                        provider_name, tenant_id, matching_factors
                    );
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            };

            // Fetch the factor state for this factor
            let factor_states = self
                .backend
                .get_factor_states(&factor.id, PermissionScope::Tenant(&tenant_id))
                .await
                .map_err(|e| {
                    error!(
                        "Failed to fetch factor state for OAuth factor '{:?}': {:?}",
                        factor.id, e
                    );
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;
            if factor_states.len() != 1
                || factor_states.first().map(|fs| &fs.state) != Some(&EnablementState::Active)
            {
                error!(
                    "Expected exactly one active factor state for OAuth factor '{:?}', found: {}",
                    factor.id,
                    factor_states.len()
                );
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }

            // Get the first factor state (assuming there's at least one)
            let factor_state = factor_states.first().ok_or_else(|| {
                error!("No factor state found for OAuth factor '{:?}'", factor.id);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            // Extract the authorization URL from the factor state's config
            let auth_url: &str = factor_state
                .config
                .get("auth_url")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    error!("Missing OAuth provider authorization URL in factor state config");
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

            // Store provider and tenant in session for later callback handling
            self.session
                .insert("oauth_provider", &provider_name)
                .await
                .map_err(|e| {
                    error!("Failed to store oauth_provider in session: {:?}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;
            self.session
                .insert("oauth_tenant_id", &tenant_id)
                .await
                .map_err(|e| {
                    error!("Failed to store oauth_tenant_id in session: {:?}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

            // Redirect user to the OAuth provider's authorization URL
            return Ok(Redirect::temporary(auth_url).into_response());
        }

        // --- Non-OAuth flow: robust and ergonomic ---
        let tenant_id: B::TenantId = if let Some(tenant_name) = fields.get("tenant") {
            match self.backend.get_tenant_by_name(tenant_name).await {
                Ok(tenant) => tenant.id().clone().into(),
                Err(e) => {
                    error!("Failed to resolve tenant name '{}': {:?}", tenant_name, e);
                    return Err(StatusCode::BAD_REQUEST);
                }
            }
        } else if let Some(tid) = self.get_tenant_id().cloned() {
            tid
        } else {
            match self.backend.get_default_tenant_id().await {
                Ok(id) => id,
                Err(e) => {
                    error!("Failed to fetch default tenant id: {:?}", e);
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            }
        };

        // Load user if guest
        let mut user = self.get_user().clone();
        if user.get_user_state() == EntityState::Guest {
            if let Some(username) = fields.get("username") {
                match self.backend.get_user_by_name(&tenant_id, username).await {
                    Ok(loaded_user) => user = loaded_user,
                    Err(e) => {
                        error!("Failed to load user '{}': {:?}", username, e);
                        return Err(StatusCode::BAD_REQUEST);
                    }
                }
            } else {
                error!("No username provided for non-OAuth authentication");
                return Err(StatusCode::BAD_REQUEST);
            }
        }

        let user_id: B::UserId = user.id().clone().into();
        let scope = PermissionScope::User(&tenant_id, &user_id);

        // Fetch all methods for this user and state
        let methods = self
            .backend
            .get_scoped_auth_methods(scope, desired_state)
            .await
            .map_err(|e| {
                error!("Failed to get scoped auth methods: {:?}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        // Find a method where the next required factor matches the submitted kind
        let factor_kind = form.factor_kind();
        let mut matched_method = None;
        for method in &methods {
            if let Some(next_factor_id) = method.factors.first() {
                let factor = self.backend.get_auth_factor(next_factor_id).await.ok();
                if let Some(factor) = factor
                    && factor.kind == factor_kind
                {
                    matched_method = Some(method.clone());
                    break;
                }
            }
        }
        let method = matched_method.ok_or_else(|| {
            error!(
                "No matching method for submitted factor kind: {:?}",
                factor_kind
            );
            StatusCode::BAD_REQUEST
        })?;

        // Fetch all factor instances for this method (MFA chain)
        let mut factor_instances = Vec::new();
        for factor_id in &method.factors {
            let factor = self.backend.get_auth_factor(factor_id).await.map_err(|e| {
                error!("Failed to fetch factor {:?}: {:?}", factor_id, e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
            factor_instances.push(factor);
        }

        // Build PartialAuthState with all factors (remaining_factors)
        let mut partial_state = PartialAuthState {
            current_method: method.clone(),
            remaining_factors: factor_instances,
            attempt_count: 0,
            last_attempt: None,
        };

        // Remove the just-submitted factor from remaining_factors
        if let Some(first_factor) = partial_state.remaining_factors.first()
            && first_factor.kind == factor_kind
        {
            partial_state.remaining_factors.remove(0);
        }

        self.state = AuthState::PartialAuthn(partial_state.clone());
        self.save_session_data().await.map_err(|e| {
            error!("Failed to save session data: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let next_factor_kind = partial_state.next_factor_kind();
        let next_factor_id = partial_state.next_factor_id().cloned();

        Ok(Json(serde_json::json!({
            "status": "auth_flow_initiated",
            "method_id": method.id,
            "next_factor_kind": next_factor_kind,
            "next_factor_id": next_factor_id,
        }))
        .into_response())
    }

    pub async fn start_authentication(
        &mut self,
        method: AuthMethod<B>,
    ) -> Result<(), AuthError<B>> {
        match &mut self.state {
            SessionState::<B>::Authenticated => {
                debug!("User is already authenticated, skipping authentication");
                Err(AuthError::InvalidStateTransition)
            }
            SessionState::<B>::PartialAuthn(partial_state) => {
                if partial_state.current_method == method {
                    debug!(
                        "Authentication already in progress for method: {:?}",
                        method
                    );
                    Ok(())
                } else {
                    debug!("Another authentication already in progress, cannot start a new one");
                    Err(AuthError::InvalidStateTransition)
                }
            }
            SessionState::<B>::NotAuthenticated => {
                debug!("Starting authentication for method: {:?}", method);
                if self.data.user_state == EntityState::Guest {
                    debug!("No user associated with session, cannot start authentication");
                    // TODO: Convert Guest user to a real user ???
                    return Err(AuthError::UserNotFound);
                }

                let user = &self.user;
                let user_id: B::UserId = user.id().clone().into();
                let tenant_id: B::TenantId = user.tenant_id().clone().into();

                let scope = PermissionScope::User(&tenant_id, &user_id);
                let methods_available = self
                    .backend
                    .get_scoped_auth_methods(scope, Some(EnablementState::Active))
                    .await
                    .map_err(AuthError::BackendError)?;
                if !methods_available.contains(&method) {
                    debug!("Method {:?} not available for user {:?}", method, user_id);
                    return Err(AuthError::MethodNotSupported);
                }
                let partial_state = PartialState::<B>::new(method);
                self.state = SessionState::<B>::PartialAuthn(partial_state);
                Ok(())
            }
        }
    }

    /// Authenticates the session using the provided credentials and backend.
    pub async fn submit_credentials<F>(&mut self, creds: &F) -> Result<B::User, AuthError<B>>
    where
        F: FactorForm + Send + Sync,
    {
        let user = self
            .backend
            .authenticate(creds)
            .await
            .map_err(AuthError::BackendError)?;
        self.user = user.clone();
        self.state = SessionState::<B>::Authenticated;
        Ok(user)
    }

    pub async fn get_session_data(&self) -> Result<SessionData<B>, AuthError<B>> {
        let session_data_opt: Option<SessionData<B>> = self
            .session
            .get(self.data_key)
            .await
            .map_err(AuthError::SessionError)?;
        match session_data_opt {
            Some(session_data) => Ok(session_data),
            None => Err(AuthError::SessionNotFound),
        }
    }

    // async fn update_session(&mut self) -> Result<(), AuthError<B>> {
    //     self.session
    //         .insert(self.data_key, &self.data)
    //         .await
    //         .map_err(AuthError::SessionError)?;
    //     Ok(())
    // }

    /// Update last activity time stamp and save the current session data to the session store.
    pub async fn save_session_data(&mut self) -> Result<(), AuthError<B>> {
        // Update last_activity timestamp
        // let mut data = self.data.clone();
        // data.last_activity = Utc::now();
        self.session
            .insert(self.data_key, &self.data)
            .await
            .map_err(AuthError::SessionError)?;

        Ok(())
    }

    pub async fn complete_authentication(&mut self) -> Result<(), AuthError<B>>
    where
        // R: SessionRegistry + Send + Sync + 'static,
        B::UserId: Display,
        B::TenantId: Display,
    {
        self.state = SessionState::<B>::Authenticated;
        self.session
            .cycle_id()
            .await
            .map_err(AuthError::SessionError)?; // Cycle session ID to prevent replay attacks

        // // Register session for user/tenant using the session registry
        // if let Some(registry) = &self.session_registry {
        //     if let Some(session_id) = self.session.id() {
        //         let session_id_str = session_id.to_string();
        //         let user_id = self.get_user_id().map(|id| id.to_string());
        //         let tenant_id = self.get_tenant_id().map(|id| id.to_string());

        //         if let Err(e) = registry
        //             .register_session(&session_id_str, user_id.as_ref(), tenant_id.as_ref())
        //             .await
        //         {
        //             tracing::error!("Failed to register session in registry: {}", e);
        //         }
        //     }
        // }

        self.save_session_data().await
    }

    pub async fn logout(&mut self) -> Result<Option<B::User>, AuthError<B>>
// where
    //     R: SessionRegistry + Send + Sync + 'static,
    {
        // // Use registry to invalidate if available
        // if let Some(registry) = &self.session_registry {
        //     if let Some(session_id) = self.session.id() {
        //         let session_id_str = session_id.to_string();
        //         if let Err(e) = registry.invalidate_session(&session_id_str).await {
        //             // Log error but continue with local logout
        //             tracing::error!("Failed to invalidate session in registry: {}", e);
        //         }
        //     }
        // }

        // Existing logout logic
        self.session.clear().await;
        self.session
            .cycle_id()
            .await
            .map_err(AuthError::SessionError)?;

        // Clear user and state
        let user = Some(self.user.clone());
        self.state = SessionState::<B>::NotAuthenticated;

        // Clear session data
        self.data = SessionData::<B>::default();
        self.save_session_data().await?;

        Ok(user)
    }

    // // Add method to register the session after successful authentication
    // pub async fn register_session(&self) -> Result<(), AuthError<B>>
    // where
    //     R: SessionRegistry + Send + Sync + 'static,
    //     <B::User as AuthUser>::Id: Display,
    //     <B::User as AuthUser>::TenantId: Display,
    // {
    //     if let Some(registry) = &self.session_registry {
    //         if let Some(session_id) = self.session.id() {
    //             let session_id_str = session_id.to_string();
    //             let user_id = self.user.id().to_string();
    //             let tenant_id = self.user.tenant_id().to_string();
    //             registry
    //                 .register_session(&session_id_str, Some(&user_id), Some(&tenant_id))
    //                 .await
    //                 .map_err(|e| AuthError::SessionRegistryError(e))?;
    //         }
    //     }

    //     Ok(())
    // }
}

pub type AuthFactor<B> = FactorInstance<<B as AuthnBackend>::FactorId, <B as AuthnBackend>::UserId>;

pub type AuthFactorState<B> = FactorState<
    <B as AuthnBackend>::FactorId,
    <B as AuthnBackend>::UserId,
    <B as AuthnBackend>::MethodId,
    <B as AuthnBackend>::TenantId,
>;

pub type AuthMethod<B> = MethodInstance<
    <B as AuthnBackend>::MethodId,
    <B as AuthnBackend>::FactorId,
    <B as AuthnBackend>::UserId,
>;

pub type AuthMethodState<B> = MethodState<
    <B as AuthnBackend>::MethodId,
    <B as AuthnBackend>::FactorId,
    <B as AuthnBackend>::UserId,
    <B as AuthnBackend>::TenantId,
>;

pub type PartialState<B> = PartialAuthState<
    <B as AuthnBackend>::MethodId,
    <B as AuthnBackend>::FactorId,
    <B as AuthnBackend>::UserId,
>;

pub type SessionState<B> = AuthState<
    <B as AuthnBackend>::MethodId,
    <B as AuthnBackend>::FactorId,
    <B as AuthnBackend>::UserId,
>;

pub type SessionData<B> = Data<
    <B as AuthnBackend>::MethodId,
    <B as AuthnBackend>::FactorId,
    <B as AuthnBackend>::UserId,
    <B as AuthnBackend>::TenantId,
>;
