use crate::{
    authn::{
        backend::{AuthTenant, AuthUser, AuthnBackend, EntityState},
        errors::{AuthError, FactorKindError},
        methods::{
            EnablementState,
            factor::{AuthFactorKind, FactorInstance, FactorState, FactorStateChange},
            form::{FactorForm, FactorFormKind},
            method::{MethodInstance, MethodState},
            scope::PermissionScope,
        },
        session::state::{AuthState, Data, PartialAuthState},
    },
    axum::{
        extract::{Form, Json},
        // http::StatusCode,
        response::{IntoResponse, Redirect, Response},
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
    fmt::Debug, // sync::Arc
};

use tower_sessions::{
    Session,
    // session::Error as SessionError,
    // session_store::Error as StoreError,
};

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

    /// Validates that the provided scope matches the current session
    fn validate_scope(&self, scope: &PermissionScope<B::TenantId, B::UserId>) 
        -> Result<(), AuthError<B>> 
    {
        let (tid, uid) = match scope {
            PermissionScope::User(tid, uid) => (tid, uid),
            _ => {
                error!("Need User scope to check method and factor states");
                return Err(AuthError::MethodNotFound);
            }
        };

        // Validate that scope matches session
        if Some(tid) != self.get_tenant_id() || Some(uid) != self.get_user_id() {
            error!("Scope does not match session's tenant/user IDs");
            return Err(AuthError::Unauthorized);
        }

        Ok(())
    }

    /// Validates that the user is in an acceptable state for authentication
    fn validate_user_state(&self) -> Result<(), AuthError<B>> {
        match self.get_user_state() {
            EntityState::Active | EntityState::Pending(_) => Ok(()),
            state => {
                error!("User is not active or pending: {:?}", state);
                Err(AuthError::UserNotActive)
            }
        }
    }

    /// Validate that a factor has the expected state in the given scope
    async fn validate_factor_state(
        &self,
        factor_id: &B::FactorId,
        scope: &PermissionScope<B::TenantId, B::UserId>,
        expected_state: &EnablementState,
    ) -> Result<bool, AuthError<B>> {
        let factor_states = self
            .backend
            .get_factor_states(factor_id, scope.clone())
            .await
            .map_err(|e| {
                error!("Failed to fetch factor states: {:?}", e);
                AuthError::BackendError(e)
            })?;

        if factor_states.is_empty() {
            debug!("No factor states found for factor {:?}", factor_id);
            return Ok(false);
        }

        Ok(factor_states.iter().any(|fs| fs.state == *expected_state))
    }

    /// Find a suitable method for a given action/factor.
    /// Returns a reference to avoid cloning in the loop; caller clones once if needed.
    async fn select_method_for_action<'a>(
        &'a self,
        methods: &'a [AuthMethod<B>],
        factor_kind: &AuthFactorKind,
        action_kind: FactorFormKind,
        scope: &PermissionScope<B::TenantId, B::UserId>,
    ) -> Result<Option<&'a AuthMethod<B>>, AuthError<B>> {
        let expected_state = match action_kind {
            FactorFormKind::Setup => EnablementState::Pending,
            FactorFormKind::Verify => EnablementState::Active,
        };

        for method in methods {
            let Some(first_factor) = method.factors.first() else {
                warn!("Method {:?} has no factors, skipping", method.id);
                continue;
            };

            if first_factor.kind != *factor_kind {
                continue;
            }

            if self
                .validate_factor_state(&first_factor.id, scope, &expected_state)
                .await?
            {
                debug!(
                    "Found method {:?} with factor {:?} in expected state {:?}",
                    method.id, first_factor.id, expected_state
                );
                return Ok(Some(method));
            }
        }

        Ok(None) // Return None instead of Err when no method matches
    }

    /// Finds an authentication method suitable for the current session state.
    ///
    /// # Arguments
    /// * `scope` - Must be `PermissionScope::User` containing the tenant and user IDs
    /// * `factor_kind` - The type of authentication factor (Password, TOTP, OAuth)
    /// * `action_kind` - Whether this is for Setup (Pending) or Verify (Active)
    ///
    /// # Errors
    /// Returns `AuthError::MethodNotFound` if:
    /// - No methods exist for the scope
    /// - No method has a first factor matching `factor_kind`
    /// - No method's first factor is in the required state
    ///
    /// Returns `AuthError::Unauthorized` if the scope doesn't match the session
    pub async fn get_assumed_auth_method(
        &self,
        scope: PermissionScope<B::TenantId, B::UserId>,
        factor_kind: AuthFactorKind,
        action_kind: FactorFormKind,
    ) -> Result<AuthMethod<B>, AuthError<B>> {
        debug!(
            "Looking for auth method with factor {:?} and action {:?} in scope {:?}",
            factor_kind, action_kind, scope
        );
        // Validate scope and user state first
        self.validate_scope(&scope)?;
        self.validate_user_state()?;

        // Fetch all relevant authentication methods for the given scope
        let methods: Vec<AuthMethod<B>> = self
            .backend
            .get_scoped_auth_methods(scope.clone(), EnablementState::Active)
            .await
            .map_err(|e| {
                error!("Failed to fetch scoped auth methods from backend: {:?}", e);
                AuthError::BackendError(e)
            })?;
            
        if methods.is_empty() {
            error!("No authentication methods found for scope {:?}", scope);
            return Err(AuthError::MethodNotFound);
        }
        // For the found methods, check the state of the first factor using get_factor_states.
        // If action_kind is Setup, accept Pending (user scope) or Active (tenant/global
        if let Some(m_ref) = self
            .select_method_for_action(&methods, &factor_kind, action_kind, &scope)
            .await?
        {
            return Ok(m_ref.clone());
        }

        error!(
            "No authentication method found with first factor kind {:?} for scope {:?}",
            factor_kind, scope
        );
        Err(AuthError::MethodNotFound)
    }

    pub fn user(&self) -> Result<B::User, AuthError<B>> {
        Ok(self.user.clone())
    }

    pub fn get_user_state(&self) -> EntityState {
        self.data.user_state.clone()
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

    /// Set the authentication state of the session.
    pub async fn set_auth_state(&mut self, new_state: SessionState<B>) -> Result<(), AuthError<B>> {
        self.state = new_state;
        self.data.auth_state = self.state.clone();
        self.session
            .insert(self.data_key, &self.data)
            .await
            .map_err(AuthError::SessionError)?;
        Ok(())
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

    pub async fn authenticate_from_form<F>(
        &mut self,
        form: Form<F>,
    ) -> Result<Response, AuthError<B>>
    // Return AuthError directly
    where
        F: FactorForm + Send + Sync + 'static,
    {
        self.authenticate(form.0).await
    }

    pub async fn authenticate_from_json<F>(
        &mut self,
        json: Json<F>,
    ) -> Result<Response, AuthError<B>>
    // Return AuthError directly
    where
        F: FactorForm + Send + Sync + 'static,
    {
        self.authenticate(json.0).await
    }

    /// Initiate an authentication flow based on the submitted factor form.
    pub async fn authenticate<F>(&mut self, form: F) -> Result<Response, AuthError<B>>
    where
        F: FactorForm + Send + Sync + 'static,
    {
        debug!("Starting authentication process from form");

        form.validate_form()
            .map_err(|_| AuthError::InvalidCredentials)?;

        let form_kind = form.form_kind();
        let factor_kind = form.factor_kind();

        match (&self.state, &form_kind) {
            (SessionState::<B>::NotAuthenticated, FactorFormKind::Verify) => {
                self.handle_initial_authentication(&form, factor_kind, form_kind)
                    .await
            }
            (SessionState::<B>::PartialAuthn(partial_state), FactorFormKind::Verify) => {
                self.handle_partial_authentication(&form, partial_state.clone())
                    .await
            }
            (SessionState::<B>::Authenticated, FactorFormKind::Setup) => {
                self.handle_factor_setup(&form, factor_kind).await
            }
            (SessionState::<B>::NotAuthenticated, FactorFormKind::Setup) => {
                error!("Cannot setup factors without authentication");
                Err(AuthError::InvalidStateTransition)
            }
            (SessionState::<B>::Authenticated, FactorFormKind::Verify) => {
                error!("Already authenticated");
                Err(AuthError::AlreadyAuthenticated)
            }
            (SessionState::<B>::PartialAuthn(_), FactorFormKind::Setup) => {
                error!("Cannot setup factors during partial authentication");
                Err(AuthError::InvalidStateTransition)
            }
        }
    }

    /// Resolve user and tenant from form fields
    async fn resolve_user_and_scope<F>(
        &mut self,
        form: &F,
    ) -> Result<PermissionScope<B::TenantId, B::UserId>, AuthError<B>>
    where
        F: FactorForm + Send + Sync,
    {
        let fields = form.fields_map();
        let username = fields.get("username").ok_or(AuthError::UserNotFound)?;

        // Resolve tenant
        let tenant_id = if let Some(name) = fields.get("tenant") {
            self.backend
                .get_tenant_by_name(name)
                .await
                .map_err(AuthError::BackendError)?
                .id()
                .clone()
                .into()
        } else {
            self.get_tenant_id()
                .cloned()
                .ok_or(AuthError::UserNotFound)?
        };

        // Look up user by username and tenant
        let user = self
            .backend
            .get_user_by_name(&tenant_id, username)
            .await
            .map_err(AuthError::BackendError)?;

        let user_id: B::UserId = user.id().clone().into();

        // Update session state
        self.user = user;
        self.data.user_id = Some(user_id.clone());
        self.data.tenant_id = Some(tenant_id.clone());
        self.data.user_state = EntityState::Active;

        Ok(PermissionScope::User(tenant_id, user_id))
    }

    /// applies a given approved factor to the current method and determines next action
    /// if all factors are applied, completes authentication.
    async fn apply_factor(
        &mut self,
        factor_id: &B::FactorId,
        next: Option<String>,
    ) -> Result<Response, AuthError<B>> {
        // Extract state without cloning
        let mut partial_state = match std::mem::replace(
            &mut self.state,
            SessionState::<B>::NotAuthenticated
        ) {
            SessionState::<B>::PartialAuthn(ps) => ps,
            other => {
                self.state = other; // Restore if not partial
                error!("Session is not in PartialAuthn state");
                return Err(AuthError::UnexpectedAuthState);
            }
        };

        partial_state.apply_factor(factor_id);

        // Check if authentication is complete
        if partial_state.remaining_factors.is_empty() {
            self.complete_authentication().await?;
            let redirect_url = self.get_next_route(next).await;
            Ok(Redirect::to(&redirect_url).into_response())
        } else {
            let next_factor = partial_state.remaining_factors.first()
                .cloned()
                .ok_or(AuthError::FactorNotFound)?;

            self.set_auth_state(SessionState::<B>::PartialAuthn(partial_state)).await?;

            // Return info about next factor
            Ok(Json(serde_json::json!({
                "status": "partial",
                "next_factor": next_factor
            })).into_response())
        }
    }

    async fn handle_initial_authentication<F>(
        &mut self,
        form: &F,
        factor_kind: AuthFactorKind,
        form_kind: FactorFormKind,
    ) -> Result<Response, AuthError<B>>
    // Changed from StatusCode to AuthError
    where
        F: FactorForm + Send + Sync,
    {
        // 1. Only allow verify forms for initial authentication
        if form_kind != FactorFormKind::Verify {
            error!("Cannot setup factors without authentication");
            return Err(AuthError::InvalidStateTransition);
        }

        // 2. Resolve user and scope
        let scope = self.resolve_user_and_scope(form).await?;

        // 3. Find authentication method
        let method = self
            .get_assumed_auth_method(scope.clone(), factor_kind, form_kind)
            .await?;

        // 4. Start authentication flow
        self.start_authentication(method.clone()).await?;

        // 5. Get the first factor ID
        let factor_id = method
            .get_first_factor_id()
            .ok_or(AuthError::FactorNotFound)?;

        // 6. Verify first factor
        debug!("First factor ID to verify: {:?}", factor_id);
        match self.verify_factor(form, &factor_id).await {
            Ok(()) => {
                debug!("First factor verified successfully");
                let requested_next_route = form.fields_map().get("next").cloned();
                self.apply_factor(&factor_id, requested_next_route).await
            }
            Err(_) => {
                error!("First factor verification failed");
                Err(AuthError::InvalidCredentials)
            }
        }
    }

    async fn handle_partial_authentication<F>(
        &mut self,
        form: &F,
        mut partial_state: PartialState<B>,
    ) -> Result<Response, AuthError<B>>
    // Changed from StatusCode
    where
        F: FactorForm + Send + Sync,
    {
        // Check attempt count
        partial_state.attempt_count += 1;
        partial_state.last_attempt = Some(chrono::Utc::now());

        if partial_state.attempt_count > self.backend.max_auth_attempts() {
            error!("Too many authentication attempts");
            self.logout().await?;
            return Err(AuthError::TooManyAttempts);
        }

        // Verify the next expected factor
        let next_factor_id = partial_state
            .remaining_factors
            .first()
            .ok_or(AuthError::FactorNotFound)?;

        let factor = self
            .backend
            .get_auth_factor(next_factor_id)
            .await
            .map_err(AuthError::BackendError)?;

        // Verify factor matches form
        if factor.kind != form.factor_kind() {
            error!("Unexpected factor type");
            return Err(AuthError::UnexpectedFactorKind(
                FactorKindError::UnexpectedValue(format!("{:?}", form.factor_kind())),
            ));
        }

        // Verify the factor
        self.verify_factor(form, &factor.id).await?;

        // Apply the factor to the current state and determine next step (partial or authenticated)
        let requested_next_route = form.fields_map().get("next").cloned();
        self.apply_factor(&factor.id, requested_next_route).await
    }

    async fn verify_factor<F>(
        &mut self,
        form: &F,
        factor_id: &B::FactorId,
    ) -> Result<(), AuthError<B>>
    // Changed from StatusCode
    where
        F: FactorForm + Send + Sync,
    {
        // Create scope from session data
        let scope = PermissionScope::User(
            self.get_tenant_id()
                .cloned()
                .ok_or(AuthError::Unauthorized)?,
            self.get_user_id().cloned().ok_or(AuthError::Unauthorized)?,
        );

        let factor_states = self
            .backend
            .get_factor_states(factor_id, scope)
            .await
            .map_err(AuthError::BackendError)?;

        let factor_state = factor_states.first().ok_or(AuthError::FactorNotFound)?;

        // Verify form against config
        // factor_state.config is a HashMap<String, serde_json::Value>, but
        // verify_against_config expects a &serde_json::Value, so convert it
        // into a serde_json::Value::Object.
        let config_value = serde_json::Value::Object(
            factor_state
                .config
                .clone()
                .into_iter()
                .collect::<serde_json::Map<String, serde_json::Value>>(),
        );

        form.verify_against_config(&config_value)
            .map_err(|_| AuthError::InvalidCredentials)?;

        Ok(())
    }

    pub async fn start_authentication(
        &mut self,
        method: AuthMethod<B>,
    ) -> Result<(), AuthError<B>> {
        match &mut self.state {
            SessionState::<B>::Authenticated => {
                debug!("User is already authenticated, skipping authentication");
                Err(AuthError::AlreadyAuthenticated)
            }
            SessionState::<B>::PartialAuthn(partial_state) => {
                if partial_state.current_method == method {
                    debug!(
                        "Authentication already in progress for method: {:?}",
                        method
                    );
                } else {
                    warn!(
                        "Another authentication already in progress, attempt to restart with a different method"
                    );
                    let current_attempt = partial_state.attempt_count;
                    self.state = SessionState::<B>::PartialAuthn(PartialState::<B> {
                        current_method: method.clone(),
                        remaining_factors: method.get_factor_ids(),
                        attempt_count: current_attempt + 1,
                        last_attempt: Some(chrono::Utc::now()),
                    });
                }
                Ok(())
            }
            SessionState::<B>::NotAuthenticated => {
                debug!("Starting authentication for method: {:?}", method);
                
                if self.data.user_state == EntityState::Guest {
                    debug!("No user associated with session, cannot start authentication");
                    // TODO: Convert Guest user to a real user ???
                    return Err(AuthError::UserNotFound);
                }

                // Add user state validation here:
                self.validate_user_state()?;

                let user = &self.user;
                let user_id: B::UserId = user.id().clone().into();
                let tenant_id: B::TenantId = user.tenant_id().clone().into();

                let scope = PermissionScope::User(tenant_id, user_id.clone());
                
                let methods_available = self
                    .backend
                    .get_scoped_auth_methods(scope, EnablementState::Active)
                    .await
                    .map_err(AuthError::BackendError)?;
                    
                if !methods_available.contains(&method) {
                    debug!(
                        "Method {:?} not available for user {:?}",
                        method, user_id
                    );
                    return Err(AuthError::MethodNotSupported);
                }
                
                let partial_state = PartialState::<B> {
                    current_method: method.clone(),
                    remaining_factors: method.get_factor_ids(),
                    attempt_count: 0,
                    last_attempt: None,
                };
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
// where
    //     // R: SessionRegistry + Send + Sync + 'static,
    //     B::UserId: Display,
    //     B::TenantId: Display,
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

    pub async fn get_next_route(&self, next: Option<String>) -> String {
        if let Some(route) = next {
            if route.starts_with('/') && !route.contains("//") && route.len() < 2048 {
                return route;
            } else {
                warn!("Invalid next route provided: {}", route);
            }
        }
        let tid = self.get_tenant_id().cloned();
        let uid = self.get_user_id().cloned();
        
        match (tid, uid) {
            (Some(tenant_id), Some(user_id)) => {
                self.backend.get_default_protected_route(tenant_id, user_id).await
                    .unwrap_or_else(|_| "/".to_string())
            }
            _ => "/".to_string()
        }
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

    /// Handle factor setup for authenticated users.
    /// This allows users to add/configure new authentication factors after logging in.
    async fn handle_factor_setup<F>(
        &mut self,
        form: &F,
        factor_kind: AuthFactorKind,
    ) -> Result<Response, AuthError<B>>
    // Changed from StatusCode
    where
        F: FactorForm + Send + Sync,
    {
        // 1. Ensure user is authenticated
        if !self.is_authenticated() {
            error!("Cannot setup factor without authentication");
            return Err(AuthError::NotAuthenticated);
        }
        // 2. Ensure form is for setup
        if form.form_kind() != FactorFormKind::Setup {
            error!("Form kind must be Setup for factor setup");
            return Err(AuthError::InvalidStateTransition);
        }
        // 3. Validate form
        form.validate_form()
            .map_err(|_| AuthError::InvalidCredentials)?;

        // 4. Validate user state
        self.validate_user_state()?;

        let tenant_id = self
            .get_tenant_id()
            .cloned()
            .ok_or(AuthError::InvalidScope)?;

        let user_id = self.get_user_id().cloned().ok_or(AuthError::UserNotFound)?;

        let scope = PermissionScope::User(tenant_id.clone(), user_id.clone());

        let method = self
            .get_assumed_auth_method(scope.clone(), factor_kind.clone(), FactorFormKind::Setup)
            .await?;

        let factor = method.factors.first().ok_or(AuthError::FactorNotFound)?;

        let credential = form.credential().ok_or(AuthError::InvalidCredentials)?;

        let mut config = std::collections::HashMap::new();
        match factor_kind {
            AuthFactorKind::Password => {
                // Hash the password before storing
                let password_hash = password_auth::generate_hash(credential);
                config.insert(
                    "password_hash".to_string(),
                    serde_json::json!(password_hash),
                );
            }
            AuthFactorKind::Totp => {
                // Store the TOTP secret
                config.insert("totp_secret".to_string(), serde_json::json!(credential));
            }
            AuthFactorKind::Oauth => {
                // Store OAuth provider configuration
                config.insert("provider".to_string(), serde_json::json!(credential));
            }
        }

        // 6. Create FactorStateChange to enable the factor
        let change = FactorStateChange::new(factor.id.clone(), user_id.clone())
            .with_scope(scope)
            .with_state(EnablementState::Active)
            .with_config(config);

        // 7. Upsert - backend handles all the logic
        self.backend
            .upsert_factor_state(change)
            .await
            .map_err(AuthError::BackendError)?;

        debug!("Factor setup successful");

        // 8. Return success response
        let fields = form.fields_map();
        let next = fields.get("next").cloned();
        let redirect_url = self.get_next_route(next).await;

        Ok(Redirect::to(&redirect_url).into_response())
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
    <B as AuthnBackend>::DataId,
    <B as AuthnBackend>::FactorId,
    <B as AuthnBackend>::TenantId,
    <B as AuthnBackend>::UserId,
>;

pub type AuthMethod<B> = MethodInstance<
    <B as AuthnBackend>::MethodId,
    <B as AuthnBackend>::FactorId,
    <B as AuthnBackend>::UserId,
>;

pub type AuthMethodState<B> = MethodState<
    <B as AuthnBackend>::MethodId,
    <B as AuthnBackend>::FactorId,
    <B as AuthnBackend>::TenantId,
    <B as AuthnBackend>::UserId,
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
