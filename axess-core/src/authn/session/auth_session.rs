use crate::{
    authn::{
        backend::{AuthTenant, AuthUser, AuthnBackend, EntityState},
        errors::{AuthError, FactorKindError},
        methods::{
            EnablementState,
            factor::{AuthFactorKind, FactorStateChange},
            form::{FactorForm, FactorFormExt, FactorFormKind, FormField},
            scope::PermissionScope,
        },
        session::SessionRegistry,
        types::{AuthFactorState, AuthMethod, PartialState, SessionData, SessionState},
    },
    axum::{
        extract::{Form, Json},
        response::{IntoResponse, Redirect, Response},
    },
    tracing::{debug, error, warn},
    utils::{
        random::{SecureRng, SystemRng},
        validation::OtpType,
    },
};
use axess_factors::{generate_password_hash, verify_hotp};
use sha2::{Digest, Sha256};
use std::{fmt::Debug, sync::Arc};
use tower_sessions::Session;

/// `AuthSession` orchestrates authentication workflows for a user session. It handles factor
/// verification, state transitions, session persistence, and registry bookkeeping.
///
/// # Deterministic Simulation Testing (DST)
/// To keep authentication flows reproducible in tests while remaining secure in production,
/// the session takes two injectable components:
/// - `Rng`: any implementor of [`SecureRng`](crate::utils::random::SecureRng). Production code
///   uses [`SystemRng`](crate::utils::random::SystemRng); tests can provide
///   [`MockRng`](crate::utils::testing::mock_random::MockRng) for deterministic output.
/// - `SessionRegistry`: an optional [`SessionRegistry`](crate::authn::session::SessionRegistry)
///   allowing tests to swap the backing store (see
///   [`SessionRegistryStore`](crate::authn::session::registry::SessionRegistryStore)) or skip it
///   entirely for guest scenarios.
///
/// Both parameters are injected via [`AuthSession::from_session_with_rng`](self::AuthSession::from_session_with_rng),
/// ensuring contributors can control randomness and persistence when writing DST-oriented tests.
#[derive(Clone)]
pub struct AuthSession<B, R, Rng>
where
    B: AuthnBackend,
    R: SessionRegistry,
    Rng: SecureRng,
{
    pub state: SessionState<B>,

    /// The user associated by the backend or a guest user.
    pub user: B::User,

    /// Shared reference to the authentication backend (cheap to clone).
    pub backend: Arc<B>,

    /// The underlying session.
    pub session: Session,

    data: SessionData<B>,
    data_key: &'static str,
    session_registry: Option<Arc<R>>,
    rng: Rng, // Add RNG field
}

impl<B, R, Rng> Debug for AuthSession<B, R, Rng>
where
    B: AuthnBackend + Debug,
    R: SessionRegistry + Debug,
    Rng: SecureRng,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthSession")
            .field("state", &self.state)
            .field("user", &self.user)
            .field("backend", &self.backend)
            .field("session", &self.session)
            .field("data", &self.data)
            .field("data_key", &self.data_key)
            .field("session_registry", &self.session_registry.is_some())
            .finish_non_exhaustive() // Don't debug RNG
    }
}

impl<B, R> AuthSession<B, R, SystemRng>
where
    B: AuthnBackend + Debug,
    B::TenantId: From<<B::User as AuthUser>::TenantId>,
    B::UserId: From<<B::User as AuthUser>::Id>,
    <B as AuthnBackend>::TenantId: From<<<B as AuthnBackend>::Tenant as AuthTenant>::Id>,
    R: SessionRegistry + Send + Sync + 'static,
{
    pub async fn from_session(
        session: Session,
        backend: Arc<B>,
        data_key: &'static str,
        session_registry: Option<Arc<R>>,
    ) -> Result<Self, AuthError<B>>
    where
        B::User: Clone,
        B::UserId: Clone,
        B::TenantId: Clone,
    {
        Self::from_session_with_rng(session, backend, data_key, session_registry, SystemRng).await
    }
}

impl<B, R, Rng> AuthSession<B, R, Rng>
where
    B: AuthnBackend + Debug,
    B::TenantId: From<<B::User as AuthUser>::TenantId>,
    B::UserId: From<<B::User as AuthUser>::Id>,
    <B as AuthnBackend>::TenantId: From<<<B as AuthnBackend>::Tenant as AuthTenant>::Id>,
    R: SessionRegistry + Send + Sync + 'static,
    Rng: SecureRng,
{
    /// Create AuthSession with custom RNG (for testing)
    pub async fn from_session_with_rng(
        session: Session,
        backend: Arc<B>,
        data_key: &'static str,
        session_registry: Option<Arc<R>>,
        rng: Rng,
    ) -> Result<Self, AuthError<B>>
    where
        B::User: Clone,
        B::UserId: Clone,
        B::TenantId: Clone,
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
            session_registry,
            rng,
        })
    }

    /// Validates that the provided scope matches the current session
    fn validate_scope(
        &self,
        scope: &PermissionScope<B::TenantId, B::UserId>,
    ) -> Result<(), AuthError<B>> {
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

    /// Validates session is still registered and hash matches
    async fn validate_session_binding(&self) -> Result<(), AuthError<B>> {
        let Some(registry) = &self.session_registry else {
            // No registry configured - skip validation
            return Ok(());
        };

        let Some(session_id) = self.session.id() else {
            error!("Session has no ID");
            return Err(AuthError::SessionInvalid);
        };

        let Some(session_hash) = &self.data.auth_hash else {
            // Session not yet authenticated - skip validation
            return Ok(());
        };

        let session_id_str = session_id.to_string();

        match registry
            .validate_session(&session_id_str, session_hash)
            .await
        {
            Ok(true) => {
                // Update last activity (best effort)
                if let Err(e) = registry.touch_session(&session_id_str).await {
                    debug!(
                        session_id = %session_id_str,
                        error = ?e,
                        "Failed to update session activity timestamp (non-fatal)"
                    );
                }
                Ok(())
            }
            Ok(false) => {
                error!(
                    session_id = ?session_id,
                    "Session validation failed - not in registry or hash mismatch"
                );
                Err(AuthError::SessionInvalid)
            }
            Err(e) => {
                error!(
                    session_id = ?session_id,
                    error = ?e,
                    "Registry error during session validation"
                );
                Err(AuthError::SessionRegistryError(e))
            }
        }
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
        // Prefer username lookup (core-friendly, backend-agnostic)
        let username = form
            .get_string_field(FormField::Username)
            .ok_or(AuthError::UserNotFound)?;

        // Resolve tenant: prefer explicit tenant name in form -> session tenant -> backend default.
        // If session already has a tenant/user, do not allow a different tenant to be selected via form.
        let tenant_id = if let Some(tenant_name) = form.get_string_field(FormField::Tenant) {
            // If session already associated with a tenant, ensure it matches the supplied tenant.
            if let Some(current_tid) = self.get_tenant_id() {
                // Look up the named tenant to compare ids
                let named = self
                    .backend
                    .get_tenant_by_name(&tenant_name)
                    .await
                    .map_err(AuthError::BackendError)?;
                // convert tenant::Id -> backend::TenantId (From bound exists)
                let named_tid: B::TenantId = named.id().clone().into();
                if &named_tid != current_tid {
                    // Session already tied to another tenant — treat as invalid scope
                    error!(
                        "Tenant in form ({}) does not match session tenant ({:?})",
                        tenant_name, current_tid
                    );
                    return Err(AuthError::InvalidScope);
                }
                // Use current session tenant
                current_tid.clone()
            } else {
                // No session tenant — use the tenant named in the form
                let named = self
                    .backend
                    .get_tenant_by_name(&tenant_name)
                    .await
                    .map_err(AuthError::BackendError)?;
                // convert and return backend TenantId
                named.id().clone().into()
            }
        } else if let Some(tid) = self.get_tenant_id() {
            // Use tenant from session if present
            tid.clone()
        } else {
            // Fallback to backend default tenant
            self.backend
                .get_default_tenant_id()
                .await
                .map_err(AuthError::BackendError)?
        };

        // Lookup user by tenant + username (backend-agnostic)
        let user = self
            .backend
            .get_user_by_name(&tenant_id, &username)
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
        let mut partial_state =
            match std::mem::replace(&mut self.state, SessionState::<B>::NotAuthenticated) {
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
            // ✅ Session already registered in start_authentication, just update hash if needed
            if self.data.auth_hash.is_none() {
                let session_hash = self.generate_session_hash();
                self.data.auth_hash = Some(session_hash);
                // Re-register with new hash (update operation)
                self.ensure_session_registered().await?;
            }

            let next_factor = partial_state
                .remaining_factors
                .first()
                .cloned()
                .ok_or(AuthError::FactorNotFound)?;

            self.set_auth_state(SessionState::<B>::PartialAuthn(partial_state))
                .await?;

            Ok(Json(serde_json::json!({
                "status": "partial",
                "next_factor": next_factor
            }))
            .into_response())
        }
    }

    async fn process_hotp_success<F>(
        &mut self,
        form: &F,
        factor_state: &AuthFactorState<B>,
        scope: &PermissionScope<B::TenantId, B::UserId>,
        config: &serde_json::Value,
    ) -> Result<(), AuthError<B>>
    where
        F: FactorForm,
    {
        let otp_code = form.credential().ok_or(AuthError::InvalidCredentials)?;

        let secret = config
            .get("otp_secret")
            .and_then(|value| value.as_str())
            .ok_or(AuthError::InvalidCredentials)?;

        let counter = config
            .get("counter")
            .and_then(|value| value.as_u64())
            .ok_or(AuthError::InvalidCredentials)?;

        let digits = config
            .get("digits")
            .and_then(|value| value.as_u64())
            .unwrap_or(6) as usize;

        let window = config
            .get("window")
            .and_then(|value| value.as_u64())
            .unwrap_or(5);

        let used_counter = verify_hotp(secret, otp_code, counter, digits, window)
            .ok_or(AuthError::InvalidCredentials)?;

        let mut updated_config = factor_state.config.clone();
        updated_config.insert("counter".to_string(), serde_json::json!(used_counter + 1));

        let updated_by = self.get_user_id().cloned().ok_or(AuthError::UserNotFound)?;

        let change = FactorStateChange::new(factor_state.factor_id.clone(), updated_by)
            .with_scope(scope.clone())
            .with_state(factor_state.state.clone())
            .with_config(updated_config);

        self.backend
            .upsert_factor_state(change)
            .await
            .map_err(AuthError::BackendError)?;

        Ok(())
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
        let scope = PermissionScope::User(
            self.get_tenant_id()
                .cloned()
                .ok_or(AuthError::Unauthorized)?,
            self.get_user_id().cloned().ok_or(AuthError::Unauthorized)?,
        );

        let factor_states = self
            .backend
            .get_factor_states(factor_id, scope.clone())
            .await
            .map_err(AuthError::BackendError)?;

        let factor_state = factor_states.first().ok_or(AuthError::FactorNotFound)?;

        let config_value = serde_json::Value::Object(
            factor_state
                .config
                .clone()
                .into_iter()
                .collect::<serde_json::Map<String, serde_json::Value>>(),
        );

        // Form handles all verification logic
        form.verify_against_config(&config_value)
            .map_err(|_| AuthError::InvalidCredentials)?;

        // ✅ Only check otp_mode for OTP factors
        if form.factor_kind() == AuthFactorKind::Otp {
            let otp_type: OtpType = config_value
                .get("otp_type")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or(OtpType::Totp);

            if matches!(otp_type, OtpType::Hotp) {
                self.process_hotp_success(form, factor_state, &scope, &config_value)
                    .await?;
            }
        }

        Ok(())
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
                let requested_next_route = form.get_string_field(FormField::Next);
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
        let requested_next_route = form.get_string_field(FormField::Next);
        self.apply_factor(&factor.id, requested_next_route).await
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
                        "Another authentication already in progress, restarting with different method"
                    );
                    self.state = SessionState::<B>::new_partial(method)
                        .with_attempt(partial_state.attempt_count + 1);
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
                    debug!("Method {:?} not available for user {:?}", method, user_id);
                    return Err(AuthError::MethodNotSupported);
                }

                self.state = SessionState::<B>::new_partial(method);

                // ✅ Register session when entering PartialAuthn
                self.ensure_session_registered().await?;

                Ok(())
            }
        }
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

    /// Generates a cryptographically secure hash binding this authentication to a specific session
    fn generate_session_hash(&mut self) -> String {
        let mut hasher = Sha256::new();

        // Session ID
        if let Some(session_id) = self.session.id() {
            hasher.update(session_id.to_string().as_bytes());
        }

        // User ID
        hasher.update(format!("{:?}", self.user.id()).as_bytes());

        // Tenant ID
        hasher.update(format!("{:?}", self.user.tenant_id()).as_bytes());

        // High-precision timestamp
        let now = chrono::Utc::now();
        hasher.update(now.timestamp().to_string().as_bytes());
        hasher.update(now.timestamp_subsec_nanos().to_string().as_bytes());

        // Cryptographically secure random nonce (32 bytes)
        let mut nonce = [0u8; 32];
        SecureRng::fill_bytes(&mut self.rng, &mut nonce);
        hasher.update(nonce);

        format!("{:x}", hasher.finalize())
    }

    /// Update and save the current session data to the session store.
    pub async fn save_session_data(&mut self) -> Result<(), AuthError<B>> {
        // Insert session data
        self.session
            .insert(self.data_key, &self.data)
            .await
            .map_err(AuthError::SessionError)?;

        // ✅ Always save the session record to persist all changes
        self.session.save().await.map_err(AuthError::SessionError)?;

        Ok(())
    }

    pub async fn complete_authentication(&mut self) -> Result<(), AuthError<B>> {
        self.state = SessionState::<B>::Authenticated;

        // Store old session ID before cycling
        let old_session_id = self.session.id().map(|id| id.to_string());

        // Cycle session ID for security
        self.session
            .cycle_id()
            .await
            .map_err(AuthError::SessionError)?;

        // Invalidate old session in registry if it exists
        if let (Some(registry), Some(old_id)) = (&self.session_registry, old_session_id)
            && let Err(e) = registry.invalidate_session(&old_id).await
        {
            debug!(
                old_session_id = %old_id,
                error = ?e,
                "Failed to invalidate old session (non-fatal)"
            );
        }

        // Generate fresh hash after session ID cycle
        let session_hash = self.generate_session_hash();
        self.data.auth_hash = Some(session_hash);
        self.data.auth_state = self.state.clone();

        // Save session data (this now also saves the session record)
        self.save_session_data().await?;

        // Now register the new session ID
        self.ensure_session_registered().await?;

        Ok(())
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
            (Some(tenant_id), Some(user_id)) => self
                .backend
                .get_default_protected_route(tenant_id, user_id)
                .await
                .unwrap_or_else(|_| "/".to_string()),
            _ => "/".to_string(),
        }
    }

    /// Unregisters the session from the session registry (best effort) and clears out the currentsession.
    pub async fn logout(&mut self) -> Result<Option<B::User>, AuthError<B>> {
        // Unregister session (best effort)
        if let Err(e) = self.unregister_session().await {
            tracing::warn!("Failed to unregister session during logout: {:?}", e);
        }

        // Clear session
        self.session.clear().await;
        self.session
            .cycle_id()
            .await
            .map_err(AuthError::SessionError)?;

        let user = Some(self.user.clone());
        self.state = SessionState::<B>::NotAuthenticated;
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
        F: FactorForm + Send + Sync + 'static,
    {
        // 1. Ensure user is authenticated
        if !self.is_authenticated() {
            error!("Cannot setup factor without authentication");
            return Err(AuthError::NotAuthenticated);
        }

        // 2. Validate session is still registered
        self.validate_session_binding().await?;

        // 3. Ensure form is for setup
        if form.form_kind() != FactorFormKind::Setup {
            error!("Form kind must be Setup for factor setup");
            return Err(AuthError::InvalidStateTransition);
        }
        // 4. Validate form
        form.validate_form()
            .map_err(|_| AuthError::InvalidCredentials)?;

        // 5. Validate user state
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
                let password_hash = generate_password_hash(credential);
                config.insert(
                    "password_hash".to_string(),
                    serde_json::json!(password_hash),
                );
            }
            AuthFactorKind::Otp => {
                config = self
                    .backend
                    .get_factor_states(&factor.id, scope.clone())
                    .await
                    .map_err(AuthError::BackendError)?
                    .into_iter()
                    .find(|state| state.state == EnablementState::Pending)
                    .map(|state| state.config)
                    .unwrap_or_default();

                let otp_type = config
                    .get("otp_type")
                    .cloned()
                    .and_then(|raw| serde_json::from_value::<OtpType>(raw).ok())
                    .unwrap_or(OtpType::Totp);

                config.insert("otp_type".to_string(), serde_json::json!(otp_type.as_str()));
                config.insert("otp_secret".to_string(), serde_json::json!(credential));

                if matches!(otp_type, OtpType::Hotp) && !config.contains_key("counter") {
                    config.insert("counter".to_string(), serde_json::json!(0u64));
                }
            }
            AuthFactorKind::Oauth => {
                // Store OAuth provider configuration
                config.insert("provider".to_string(), serde_json::json!(credential));
            }
            AuthFactorKind::Custom(_) => {
                // For custom factors, store credential as-is
                config.insert("credential".to_string(), serde_json::json!(credential));
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
        let next = form.get_string_field(FormField::Next);
        let redirect_url = self.get_next_route(next).await;

        Ok(Redirect::to(&redirect_url).into_response())
    }

    /// Ensures session is registered starting from PartialAuthn state
    async fn ensure_session_registered(&mut self) -> Result<(), AuthError<B>> {
        // Clone ownership of the optional registry so we don't hold an immutable borrow of self
        // while we later need a mutable borrow for generating a session hash.
        let registry_opt = self.session_registry.clone();
        let Some(registry) = registry_opt else {
            // No registry configured - this is OK for guest sessions
            // but consider warning if not guest
            if !matches!(self.data.user_state, EntityState::Guest) {
                warn!("No session registry configured for authenticated session");
            }
            return Ok(());
        };

        // Capture the session id as an owned String so the borrow ends immediately.
        let session_id_str = match self.session.id() {
            Some(id) => id.to_string(),
            None => {
                error!("Cannot register session without ID");
                return Err(AuthError::SessionInvalid);
            }
        };

        // Only register if user is identified (not guest)
        if matches!(self.data.user_state, EntityState::Guest) {
            debug!("Skipping registration for guest session");
            return Ok(());
        }

        // Ensure hash exists; if not, generate and persist it (best-effort).
        // This block may call &mut self methods, so previous borrows must have ended.
        let session_hash = if let Some(h) = self.data.auth_hash.as_ref() {
            h.clone()
        } else {
            let new_hash = self.generate_session_hash();
            self.data.auth_hash = Some(new_hash.clone());
            // Best-effort persist the new hash into the session store (don't fail the flow).
            if let Err(e) = self.session.insert(self.data_key, &self.data).await {
                debug!(
                    error = ?e,
                    "Failed to persist regenerated auth_hash into session (non-fatal)"
                );
            }
            new_hash
        };

        let user_id = self.get_user_id().map(|id| id.to_string());
        let tenant_id = self.get_tenant_id().map(|id| id.to_string());

        registry
            .register_session(
                &session_id_str,
                user_id.as_ref(),
                tenant_id.as_ref(),
                session_hash,
            )
            .await
            .map_err(|e| {
                error!(
                    session_id = %session_id_str,
                    error = ?e,
                    "Failed to register session in registry"
                );
                AuthError::SessionRegistryError(e)
            })
    }

    /// Removes session from registry (best effort)
    async fn unregister_session(&self) -> Result<(), AuthError<B>> {
        let Some(registry) = &self.session_registry else {
            return Ok(());
        };

        if let Some(session_id) = self.session.id() {
            let session_id_str = session_id.to_string();
            registry
                .invalidate_session(&session_id_str)
                .await
                .map_err(|e| {
                    warn!(
                        session_id = %session_id_str,
                        error = ?e,
                        "Failed to unregister session (non-fatal)"
                    );
                    AuthError::SessionRegistryError(e)
                })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authn::{
            admin::AuthnAdminBackend, methods::method::MethodInstance,
            session::registry::SessionRegistryStore,
        },
        utils::testing::{
            mock_backend::{MockBackend, MockUser, TestTenantId, TestUserId},
            mock_form::{DummyFailingForm, DummyOkForm},
            mock_random::MockRng,
        },
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tower_sessions::{
        MemoryStore, SessionStore,
        session::{Id, Record},
    };

    fn mock_method() -> AuthMethod<MockBackend> {
        MethodInstance {
            id: "method1".to_string(),
            name: "Test Method".to_string(),
            factors: vec![],
            description: "Test authentication method".to_string(),
            created_at: chrono::Utc::now(),
            created_by: TestUserId("system".to_string()),
            updated_at: chrono::Utc::now(),
            updated_by: TestUserId("system".to_string()),
        }
    }

    /// Helper to create a session that's properly initialized in the store
    async fn create_initialized_session(store: MemoryStore) -> Session {
        // Bring the SessionStore trait into scope so its async methods are available.

        // Generate a new session ID
        let session_id = Id::default();

        // Create a record with the ID and empty data (mutable because create expects &mut Record)
        let mut record = Record {
            id: session_id.clone(),
            data: Default::default(),
            expiry_date: time::OffsetDateTime::now_utc() + time::Duration::hours(24),
        };

        // Save the record to the store (pass a mutable reference)
        store
            .create(&mut record)
            .await
            .expect("Failed to create session record in store");

        // Create Session with this ID - it will be able to load from store
        Session::new(Some(session_id), std::sync::Arc::new(store), None)
    }

    async fn create_test_session() -> Result<
        (
            AuthSession<MockBackend, SessionRegistryStore<MemoryStore>, MockRng>,
            Arc<SessionRegistryStore<MemoryStore>>,
        ),
        AuthError<MockBackend>,
    > {
        let backend = Arc::new(MockBackend::default());
        let store = MemoryStore::default();

        // Create and initialize session (pass a cloned MemoryStore value)
        let session = create_initialized_session(store.clone()).await;

        let registry = Arc::new(SessionRegistryStore::new(store, 0));

        // Configure backend with test method
        let method = mock_method();
        backend
            .upsert_auth_method(method.clone())
            .await
            .map_err(AuthError::BackendError)?;

        let rng = MockRng::new(42);
        let auth_session = AuthSession::from_session_with_rng(
            session,
            backend.clone(),
            "test.data",
            Some(registry.clone()),
            rng,
        )
        .await?;

        Ok((auth_session, registry))
    }

    /// Helper to create a test session with a custom RNG
    async fn create_test_session_with_custom_rng(
        rng: MockRng,
    ) -> Result<
        (
            AuthSession<MockBackend, SessionRegistryStore<MemoryStore>, MockRng>,
            Arc<SessionRegistryStore<MemoryStore>>,
        ),
        AuthError<MockBackend>,
    > {
        let backend = Arc::new(MockBackend::default());
        let store = MemoryStore::default();

        // Create and initialize session (pass a cloned MemoryStore value)
        let session = create_initialized_session(store.clone()).await;

        let registry = Arc::new(SessionRegistryStore::new(store, 0));

        // Configure backend with test method
        let method = mock_method();
        backend
            .upsert_auth_method(method.clone())
            .await
            .map_err(AuthError::BackendError)?;

        let auth_session = AuthSession::from_session_with_rng(
            session,
            backend.clone(),
            "test.data",
            Some(registry.clone()),
            rng,
        )
        .await?;

        Ok((auth_session, registry))
    }

    #[tokio::test]
    /// Test that session hash is generated and stored during partial authentication
    async fn test_session_hash_generation_on_partial_auth() -> Result<(), AuthError<MockBackend>> {
        let (mut auth_session, registry) = create_test_session().await?;

        // Setup user
        let user = MockUser {
            id: TestUserId("user1".to_string()),
            tenant_id: TestTenantId("tenant1".to_string()),
            state: EntityState::Active,
        };
        auth_session.user = user;
        auth_session.data.user_id = Some(TestUserId("user1".to_string()));
        auth_session.data.tenant_id = Some(TestTenantId("tenant1".to_string()));
        auth_session.data.user_state = EntityState::Active;

        // Get the method that backend knows about (handle backend error explicitly)
        let methods_res = auth_session
            .backend
            .get_scoped_auth_methods(
                PermissionScope::User(
                    TestTenantId("tenant1".to_string()),
                    TestUserId("user1".to_string()),
                ),
                EnablementState::Active,
            )
            .await;

        let methods = match methods_res {
            Ok(m) => m,
            Err(e) => panic!("Failed to fetch scoped auth methods from backend: {:?}", e),
        };

        assert!(
            !methods.is_empty(),
            "Backend should have at least one method configured"
        );

        // Safely take the first method without unwrap
        let method = methods[0].clone();

        // Start authentication (handle error explicitly)
        if let Err(e) = auth_session.start_authentication(method).await {
            panic!("start_authentication failed: {:?}", e);
        }

        // Verify hash was generated
        assert!(
            auth_session.data.auth_hash.is_some(),
            "Session hash should be generated during partial authentication"
        );

        // Verify session was registered
        if let Some(session_id) = auth_session.session.id() {
            let registered = registry
                .get_user_sessions(&"user1")
                .await
                .expect("Should retrieve user sessions");
            assert_eq!(
                registered.len(),
                1,
                "Exactly one session should be registered"
            );
            assert_eq!(
                registered[0],
                session_id.to_string(),
                "Registered session ID should match"
            );
        } else {
            panic!("Session should have an ID");
        }

        Ok(())
    }

    #[tokio::test]
    /// Test that session hash is regenerated after complete authentication
    async fn test_session_hash_regenerated_on_complete() -> Result<(), AuthError<MockBackend>> {
        let (mut auth_session, registry) = create_test_session().await?;

        // Setup user for authenticated state
        let user = MockUser {
            id: TestUserId("user1".to_string()),
            tenant_id: TestTenantId("tenant1".to_string()),
            state: EntityState::Active,
        };
        auth_session.user = user;
        auth_session.data.user_id = Some(TestUserId("user1".to_string()));
        auth_session.data.tenant_id = Some(TestTenantId("tenant1".to_string()));
        auth_session.data.user_state = EntityState::Active;

        // Set partial auth state with initial hash
        let initial_hash = "initial_hash".to_string();
        let method = mock_method();

        auth_session.state = SessionState::<MockBackend>::new_partial(method.clone());
        auth_session.data.auth_hash = Some(initial_hash.clone());
        auth_session.data.auth_state = auth_session.state.clone();

        // Save current session state before completing
        auth_session.save_session_data().await?;

        // Register initial session (simulate partial auth flow)
        auth_session.ensure_session_registered().await?;

        // Store the original session ID before cycling
        let original_session_id = auth_session
            .session
            .id()
            .map(|id| id.to_string())
            .ok_or(AuthError::SessionInvalid)?;

        // Complete authentication (this will cycle the session ID)
        auth_session.complete_authentication().await?;

        // Get the new session ID after cycling
        let new_session_id = auth_session
            .session
            .id()
            .map(|id| id.to_string())
            .ok_or(AuthError::SessionInvalid)?;

        // Verify session ID was cycled
        assert_ne!(
            original_session_id, new_session_id,
            "Session ID should change after complete_authentication"
        );

        // Verify hash was regenerated
        let new_hash = auth_session
            .data
            .auth_hash
            .as_ref()
            .ok_or(AuthError::SessionInvalid)?;
        assert_ne!(
            new_hash, &initial_hash,
            "Session hash should be regenerated (different from initial)"
        );

        // Verify state is now authenticated
        assert!(
            matches!(
                auth_session.state,
                SessionState::<MockBackend>::Authenticated
            ),
            "Session should be in Authenticated state"
        );

        // Verify the new session is registered in the registry
        let user_sessions = registry
            .get_user_sessions(&"user1")
            .await
            .map_err(|e| AuthError::SessionRegistryError(e))?;

        // The old session should be replaced by the new one
        assert_eq!(
            user_sessions.len(),
            1,
            "Should have exactly one registered session after completion"
        );
        assert_eq!(
            user_sessions[0], new_session_id,
            "Registered session should be the new (cycled) session ID"
        );

        Ok(())
    }

    #[tokio::test]
    /// Test session validation fails with wrong hash
    async fn test_session_validation_fails_with_wrong_hash() -> Result<(), AuthError<MockBackend>> {
        let (mut auth_session, registry) = create_test_session().await?;

        // Register session with one hash
        let session_id = auth_session
            .session
            .id()
            .ok_or(AuthError::SessionInvalid)?
            .to_string();

        registry
            .register_session(
                &session_id,
                Some(&"user1"),
                Some(&"tenant1"),
                "correct_hash".to_string(),
            )
            .await
            .map_err(|e| AuthError::SessionRegistryError(e))?;

        // Set different hash in session
        auth_session.data.auth_hash = Some("wrong_hash".to_string());
        auth_session.data.user_state = EntityState::Active;

        // Validation should fail
        let result = auth_session.validate_session_binding().await;
        assert!(result.is_err(), "Validation should fail with wrong hash");
        assert!(
            matches!(result.unwrap_err(), AuthError::SessionInvalid),
            "Error should be SessionInvalid"
        );

        Ok(())
    }

    #[tokio::test]
    /// Test concurrent session handling
    async fn test_concurrent_sessions_for_same_user() -> Result<(), AuthError<MockBackend>> {
        let store = MemoryStore::default();
        let registry = Arc::new(SessionRegistryStore::new(store.clone(), 0));
        let backend = Arc::new(MockBackend::default());

        // Create two initialized sessions
        let session1 = create_initialized_session(store.clone()).await;
        let session2 = create_initialized_session(store.clone()).await;

        // Verify both have IDs
        assert!(session1.id().is_some(), "Session1 should have ID");
        assert!(session2.id().is_some(), "Session2 should have ID");

        let mut auth_session1 = AuthSession::from_session(
            session1,
            backend.clone(),
            "test.data",
            Some(registry.clone()),
        )
        .await?;

        let mut auth_session2 = AuthSession::from_session(
            session2,
            backend.clone(),
            "test.data",
            Some(registry.clone()),
        )
        .await?;

        // Setup both with same user
        let user = MockUser {
            id: TestUserId("user1".to_string()),
            tenant_id: TestTenantId("tenant1".to_string()),
            state: EntityState::Active,
        };

        auth_session1.user = user.clone();
        auth_session1.data.user_id = Some(TestUserId("user1".to_string()));
        auth_session1.data.tenant_id = Some(TestTenantId("tenant1".to_string()));
        auth_session1.data.user_state = EntityState::Active;

        auth_session2.user = user;
        auth_session2.data.user_id = Some(TestUserId("user1".to_string()));
        auth_session2.data.tenant_id = Some(TestTenantId("tenant1".to_string()));
        auth_session2.data.user_state = EntityState::Active;

        // Register both sessions
        auth_session1.ensure_session_registered().await?;
        auth_session2.ensure_session_registered().await?;

        // Verify both are registered
        let user_sessions = registry
            .get_user_sessions(&"user1")
            .await
            .map_err(AuthError::SessionRegistryError)?;
        assert_eq!(user_sessions.len(), 2, "Both sessions should be registered");

        // Logout session1
        auth_session1.logout().await?;

        // Verify only session2 remains
        let user_sessions = registry
            .get_user_sessions(&"user1")
            .await
            .map_err(AuthError::SessionRegistryError)?;
        assert_eq!(
            user_sessions.len(),
            1,
            "Only one session should remain after logout"
        );

        Ok(())
    }

    #[tokio::test]
    /// Test guest sessions are not registered
    async fn test_guest_sessions_not_registered() -> Result<(), AuthError<MockBackend>> {
        let (mut auth_session, registry) = create_test_session().await?;

        // Ensure session is in guest state
        assert_eq!(
            auth_session.data.user_state,
            EntityState::Guest,
            "Session should start as guest"
        );

        // Try to register (should be a no-op and not error)
        auth_session.ensure_session_registered().await?;

        // Verify no sessions registered for any user
        if let Some(session_id) = auth_session.session.id() {
            let session_id_str = session_id.to_string();

            // Try to get sessions for a non-existent user - should be empty
            let all_sessions = registry
                .get_user_sessions(&"nonexistent_user")
                .await
                .map_err(AuthError::SessionRegistryError)?;

            assert!(
                !all_sessions.contains(&session_id_str),
                "Guest session should not be registered under any user"
            );
        }

        Ok(())
    }

    #[tokio::test]
    /// Test from_session_with_rng uses injected RNG
    async fn test_from_session_with_rng_uses_injected_rng() -> Result<(), AuthError<MockBackend>> {
        let counter = Arc::new(AtomicUsize::new(0));
        let rng = MockRng::with_counter(42, counter.clone());
        let (mut auth_session, _) = create_test_session_with_custom_rng(rng).await?;

        auth_session.user = MockUser {
            id: TestUserId("user_rng".to_string()),
            tenant_id: TestTenantId("tenant_rng".to_string()),
            state: EntityState::Active,
        };
        auth_session.data.user_id = Some(TestUserId("user_rng".to_string()));
        auth_session.data.tenant_id = Some(TestTenantId("tenant_rng".to_string()));
        auth_session.data.user_state = EntityState::Active;

        let first = auth_session.generate_session_hash();
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "Injected RNG should be invoked for hash generation"
        );

        let second = auth_session.generate_session_hash();
        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "Injected RNG should be called each time a hash is generated"
        );

        assert_ne!(
            first, second,
            "Hashes should differ because timestamps change"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_factor_returns_factor_not_found() -> Result<(), AuthError<MockBackend>> {
        let rng = MockRng::new(42);
        let (mut auth_session, _) = create_test_session_with_custom_rng(rng).await?;

        auth_session.user = MockUser {
            id: TestUserId("user-factor-missing".into()),
            tenant_id: TestTenantId("tenant-factor-missing".into()),
            state: EntityState::Active,
        };
        auth_session.data.user_id = Some(TestUserId("user-factor-missing".into()));
        auth_session.data.tenant_id = Some(TestTenantId("tenant-factor-missing".into()));
        auth_session.data.user_state = EntityState::Active;

        let form = DummyOkForm::default();
        let factor_id = "missing-factor".to_string();

        let result = auth_session.verify_factor(&form, &factor_id).await;
        assert!(matches!(result, Err(AuthError::FactorNotFound)));
        Ok(())
    }
    #[tokio::test]
    async fn test_verify_factor_invalid_credentials_when_form_verification_fails()
    -> Result<(), AuthError<MockBackend>> {
        use std::collections::HashMap;

        let rng = MockRng::new(42);
        let (mut auth_session, _) = create_test_session_with_custom_rng(rng).await?;

        let user_id = TestUserId("user-form-fail".into());
        let tenant_id = TestTenantId("tenant-form-fail".into());
        auth_session.user = MockUser {
            id: user_id.clone(),
            tenant_id: tenant_id.clone(),
            state: EntityState::Active,
        };
        auth_session.data.user_id = Some(user_id.clone());
        auth_session.data.tenant_id = Some(tenant_id.clone());
        auth_session.data.user_state = EntityState::Active;

        let factor_id = "password-factor".to_string();
        let scope = PermissionScope::User(tenant_id.clone(), user_id.clone());

        let change = FactorStateChange::new(factor_id.clone(), user_id.clone())
            .with_scope(scope.clone())
            .with_state(EnablementState::Active)
            .with_config(HashMap::new());

        auth_session
            .backend
            .upsert_factor_state(change)
            .await
            .expect("mock backend upsert should succeed");

        let form = DummyFailingForm::default();
        let result = auth_session.verify_factor(&form, &factor_id).await;
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
        Ok(())
    }
}
