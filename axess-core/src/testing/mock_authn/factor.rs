//! The in-memory factor store and the pre-wired login fixture.

use super::{CallLog, MockIdentityStore, MockStoreError, note};
use crate::authn::{
    factor::{FactorConfig, FactorKind},
    ids::{TenantId, UserId},
    store::{AuthMethod, FactorStore},
    types::AuthnScope,
};
use dashmap::DashMap;
use std::sync::Arc;

/// In-memory [`FactorStore`] for unit tests.
///
/// Pre-load factor configs and auth methods using builder methods.
#[derive(Clone, Default)]
pub struct MockFactorStore {
    /// Shared call record; see [`CallLog`].
    call_log: Option<CallLog>,
    /// `scope_key::factor_kind_str` -> FactorConfig
    configs: Arc<DashMap<String, FactorConfig>>,
    /// `user_id -> Vec<AuthMethod>` (legacy test fixture keyed by user)
    methods: Arc<DashMap<String, Vec<AuthMethod>>>,
    /// `scope.key()` -> Vec<(method, enabled)>: storage for
    /// `save_method` / `remove_method` / `set_method_enabled`.
    scoped_methods: Arc<DashMap<String, Vec<(AuthMethod, bool)>>>,
    /// Number of upcoming `compare_and_save_factor` calls that must
    /// report a CAS loss regardless of stored state. Lets tests
    /// exercise the retry/reload path inside
    /// `persist_fail_with_update`.
    cas_failures_remaining: Arc<std::sync::atomic::AtomicUsize>,
    /// Number of `compare_and_save_factor` calls that go through normally
    /// before the armed losses begin; see
    /// [`arm_cas_failures_after`](Self::arm_cas_failures_after).
    cas_skip_remaining: Arc<std::sync::atomic::AtomicUsize>,
    /// Number of upcoming `load_factor` calls that report no row even
    /// when one exists: a read that happened before a concurrent first
    /// write landed. Unit-test only.
    #[cfg(test)]
    blind_loads_remaining: Arc<std::sync::atomic::AtomicUsize>,
}

impl MockFactorStore {
    /// Create an empty mock factor store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record this store's method lookups into `log`.
    pub fn with_call_log(mut self, log: &CallLog) -> Self {
        self.call_log = Some(log.clone());
        self
    }

    fn config_key(scope: &AuthnScope, kind: &FactorKind) -> String {
        format!("{}::{}", scope.key(), kind.as_str())
    }

    /// The next `n` `load_factor` calls report no row, as a read that
    /// raced ahead of a concurrent first write would.
    #[cfg(test)]
    pub(crate) fn arm_blind_loads(&self, n: usize) {
        self.blind_loads_remaining
            .store(n, std::sync::atomic::Ordering::SeqCst);
    }

    /// Register a factor configuration for a given scope.
    pub fn with_factor(self, scope: AuthnScope, config: FactorConfig) -> Self {
        let key = Self::config_key(&scope, &config.kind());
        self.configs.insert(key, config);
        self
    }

    /// Register the available authentication methods for a user.
    pub fn with_method(self, user_id: &UserId, method: AuthMethod) -> Self {
        self.methods
            .entry(user_id.to_string())
            .or_default()
            .push(method);
        self
    }

    /// Drop every factor config and auth method held for one user: the
    /// `AuthnScope::User` rows and the per-user fixture methods.
    pub(crate) fn forget_user(&self, tenant_id: &TenantId, user_id: &UserId) {
        let scope_key = AuthnScope::User {
            tenant_id: *tenant_id,
            user_id: *user_id,
        }
        .key();
        let prefix = format!("{scope_key}::");
        self.configs.retain(|k, _| !k.starts_with(&prefix));
        self.scoped_methods.remove(&scope_key);
        self.methods.remove(user_id.to_string().as_str());
    }

    /// Arm the CAS-contention failure mode: the next `n` calls to
    /// [`crate::authn::store::FactorStore::compare_and_save_factor`]
    /// return `Ok(false)` regardless of whether the stored value matches
    /// `prior`. Lets tests drive the retry/reload path inside
    /// `persist_fail_with_update` without a real concurrent writer.
    pub fn arm_cas_failures(&self, n: usize) {
        self.cas_failures_remaining
            .store(n, std::sync::atomic::Ordering::SeqCst);
    }

    /// Like [`arm_cas_failures`](Self::arm_cas_failures), but the first
    /// `skip` calls to `compare_and_save_factor` behave normally. Lets a
    /// test lose the second swap of a two-swap flow.
    pub fn arm_cas_failures_after(&self, skip: usize, n: usize) {
        self.cas_skip_remaining
            .store(skip, std::sync::atomic::Ordering::SeqCst);
        self.cas_failures_remaining
            .store(n, std::sync::atomic::Ordering::SeqCst);
    }
}

impl FactorStore for MockFactorStore {
    type Error = MockStoreError;

    async fn resolve_factor(
        &self,
        scope: &AuthnScope,
        kind: FactorKind,
    ) -> Result<Option<crate::authn::store::ResolvedFactor>, Self::Error> {
        for candidate in scope.resolution_chain() {
            let key = Self::config_key(&candidate, &kind);
            if let Some(cfg) = self.configs.get(&key).map(|r| r.clone()) {
                return Ok(Some(crate::authn::store::ResolvedFactor {
                    config: cfg,
                    resolved_from: candidate,
                }));
            }
        }
        Ok(None)
    }

    async fn load_factor(
        &self,
        scope: &AuthnScope,
        kind: FactorKind,
    ) -> Result<Option<FactorConfig>, Self::Error> {
        #[cfg(test)]
        {
            use std::sync::atomic::Ordering;
            let left = self.blind_loads_remaining.load(Ordering::SeqCst);
            if left > 0 {
                self.blind_loads_remaining.store(left - 1, Ordering::SeqCst);
                return Ok(None);
            }
        }
        let key = Self::config_key(scope, &kind);
        Ok(self.configs.get(&key).map(|r| r.clone()))
    }

    async fn save_factor(
        &self,
        scope: &AuthnScope,
        config: FactorConfig,
    ) -> Result<(), Self::Error> {
        let key = Self::config_key(scope, &config.kind());
        self.configs.insert(key, config);
        Ok(())
    }

    async fn compare_and_save_factor(
        &self,
        scope: &AuthnScope,
        prior: &FactorConfig,
        updated: FactorConfig,
    ) -> Result<bool, Self::Error> {
        // Tests can pre-arm a sequence of CAS losses to drive the
        // retry/reload path without a real concurrent writer.
        let skip = self
            .cas_skip_remaining
            .load(std::sync::atomic::Ordering::SeqCst);
        if skip > 0 {
            self.cas_skip_remaining
                .store(skip - 1, std::sync::atomic::Ordering::SeqCst);
        }
        let remaining = if skip > 0 {
            0
        } else {
            self.cas_failures_remaining
                .load(std::sync::atomic::Ordering::SeqCst)
        };
        if remaining > 0 {
            self.cas_failures_remaining
                .store(remaining - 1, std::sync::atomic::Ordering::SeqCst);
            return Ok(false);
        }

        let key = Self::config_key(scope, &prior.kind());
        // FactorConfig has no PartialEq derive; compare via canonical JSON.
        // serde_json::to_value never fails for FactorConfig (no map-key shape
        // violations), so a None result here means "treat as mismatch."
        let prior_json = serde_json::to_value(prior).ok();
        if prior_json.is_none() {
            return Ok(false);
        }
        let mut swapped = false;
        let updated_for_swap = updated.clone();
        self.configs.entry(key).and_modify(|stored| {
            if serde_json::to_value(&*stored).ok() == prior_json {
                *stored = updated_for_swap.clone();
                swapped = true;
            }
        });
        Ok(swapped)
    }

    async fn insert_factor_if_absent(
        &self,
        scope: &AuthnScope,
        config: FactorConfig,
    ) -> Result<bool, Self::Error> {
        let key = Self::config_key(scope, &config.kind());
        match self.configs.entry(key) {
            dashmap::mapref::entry::Entry::Vacant(v) => {
                v.insert(config);
                Ok(true)
            }
            dashmap::mapref::entry::Entry::Occupied(_) => Ok(false),
        }
    }

    async fn available_methods(
        &self,
        user_id: &UserId,
        tenant_id: &TenantId,
    ) -> Result<Vec<AuthMethod>, Self::Error> {
        note(&self.call_log, "available_methods");
        let mut out: Vec<AuthMethod> = self
            .methods
            .get(user_id.to_string().as_str())
            .map(|r| r.clone())
            .unwrap_or_default();

        // Scoped storage: user-scope first, then tenant-scope. Only
        // enabled rows are returned.
        let user_key = AuthnScope::User {
            user_id: *user_id,
            tenant_id: *tenant_id,
        }
        .key();
        if let Some(rows) = self.scoped_methods.get(&user_key) {
            out.extend(rows.iter().filter(|(_, en)| *en).map(|(m, _)| m.clone()));
        }

        let tenant_key = AuthnScope::Tenant(*tenant_id).key();
        if let Some(rows) = self.scoped_methods.get(&tenant_key) {
            out.extend(rows.iter().filter(|(_, en)| *en).map(|(m, _)| m.clone()));
        }

        Ok(out)
    }

    async fn save_method(&self, scope: &AuthnScope, method: AuthMethod) -> Result<(), Self::Error> {
        if matches!(scope, AuthnScope::System) {
            // Consistent with the example backend: auth methods are a
            // tenant-or-user-scoped concept.
            return Err(MockStoreError::InvalidSystemMethod);
        }
        let key = scope.key();
        let mut entry = self.scoped_methods.entry(key).or_default();
        if let Some(existing) = entry.iter_mut().find(|(m, _)| m.name == method.name) {
            *existing = (method, true);
        } else {
            entry.push((method, true));
        }
        Ok(())
    }

    async fn remove_method(&self, scope: &AuthnScope, name: &str) -> Result<(), Self::Error> {
        if matches!(scope, AuthnScope::System) {
            return Err(MockStoreError::InvalidSystemMethod);
        }
        if let Some(mut entry) = self.scoped_methods.get_mut(&scope.key()) {
            entry.retain(|(m, _)| m.name.as_ref() != name);
        }
        Ok(())
    }

    async fn set_method_enabled(
        &self,
        scope: &AuthnScope,
        name: &str,
        enabled: bool,
    ) -> Result<bool, Self::Error> {
        if matches!(scope, AuthnScope::System) {
            return Err(MockStoreError::InvalidSystemMethod);
        }
        if let Some(mut entry) = self.scoped_methods.get_mut(&scope.key()) {
            for (m, en) in entry.iter_mut() {
                if m.name.as_ref() == name {
                    *en = enabled;
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

/// Assemble a ready-to-login [`RequestAuthnService`](crate::authn::service::RequestAuthnService)
/// holding a single password-authenticated user under tenant `"t1"`.
///
/// The handle carries an empty [`AuditContext`](crate::authn::event::AuditContext),
/// which is the honest fixture for a test whose subject is not the client:
/// the rows it writes record no address and say so. Tests about the address
/// itself derive their own handle with
/// [`with_audit_context`](crate::authn::service::AuthnService::with_audit_context),
/// which this one derefs to.
///
/// Use this in tests whose subject is the surface around login (lockout,
/// session id rotation, custom-data limits) rather than the factor-chain
/// composition itself. The user id and identifier are taken separately so
/// tests can assert on both: `user_label` drives the deterministic UUID v5
/// via [`crate::testing::user_record`], while `identifier` is the
/// human-readable login string (e.g. an email).
///
/// ```ignore
/// use axess_core::testing::mock_authn::make_password_service;
/// let svc = make_password_service("u1", "alice@example.com", "hunter2");
/// // ... drive svc.begin_login("alice@example.com", "t1", &session) ...
/// ```
pub fn make_password_service(
    user_label: &str,
    identifier: &str,
    password: &str,
) -> crate::authn::service::RequestAuthnService<MockIdentityStore, MockFactorStore> {
    use crate::authn::event::AuditContext;
    use crate::authn::factor::{PasswordConfig, PasswordRules, ZeroizedString};
    use crate::authn::service::AuthnService;
    use crate::testing::{tenant_record, user_record};

    let mut user = user_record(user_label, "t1");
    user.identifier = identifier.into();
    user.display_name = identifier.into();
    let tenant = tenant_record("t1");
    let scope = AuthnScope::User {
        tenant_id: tenant.id,
        user_id: user.id,
    };

    let pw_config = FactorConfig::Password(PasswordConfig {
        hash: ZeroizedString::new(axess_factors::generate_password_hash(password)),
        rules: PasswordRules::default(),
    });

    let user_id = user.id;
    let identity = MockIdentityStore::new().with_tenant(tenant).with_user(user);
    let factors = MockFactorStore::new()
        .with_factor(scope.clone(), pw_config)
        .with_method(
            &user_id,
            AuthMethod::sequential("password", vec![FactorKind::Password], scope),
        );

    AuthnService::new(identity, factors).with_audit_context(AuditContext::default())
}
