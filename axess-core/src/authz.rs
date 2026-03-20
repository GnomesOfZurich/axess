use cedar_policy::{Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, Schema};
use std::str::FromStr;
use tracing::warn;

/// System role names — must match the Cedar policy file and the DB seed.
pub const ROLE_PLATFORM_ADMIN: &str = "platform-admin";
pub const ROLE_FINANCE_VIEWER: &str = "finance-viewer";
pub const ROLE_FINANCE_MEMBER: &str = "finance-member";
pub const ROLE_FINANCE_ADMIN: &str = "finance-admin";
pub const ROLE_DOC_VIEWER: &str = "doc-viewer";
pub const ROLE_DOC_MEMBER: &str = "doc-member";
pub const ROLE_DOC_ADMIN: &str = "doc-admin";

/// All system role names in canonical order.
pub const SYSTEM_ROLES: &[(&str, &str)] = &[
    (ROLE_PLATFORM_ADMIN, "Full access to all modules and platform management"),
    (ROLE_FINANCE_VIEWER, "Read-only access to ledgers and journal entries"),
    (ROLE_FINANCE_MEMBER, "View and post journal entries"),
    (ROLE_FINANCE_ADMIN, "Full finance access including chart-of-accounts management"),
    (ROLE_DOC_VIEWER, "Read-only access to documents"),
    (ROLE_DOC_MEMBER, "Read and write documents"),
    (ROLE_DOC_ADMIN, "Full document access including delete"),
];

// ── Cedar entity namespace ───────────────────────────────────────────────────

pub const NS: &str = "Ekekrantz";

pub fn user_uid(id: &str) -> Result<EntityUid, AuthzError> {
    EntityUid::from_str(&format!(r#"{}::User::"{id}""#, NS))
        .map_err(|e| AuthzError::InvalidEntityUid(format!("User/{id}: {e:?}")))
}

pub fn role_uid(name: &str) -> Result<EntityUid, AuthzError> {
    EntityUid::from_str(&format!(r#"{}::Role::"{name}""#, NS))
        .map_err(|e| AuthzError::InvalidEntityUid(format!("Role/{name}: {e:?}")))
}

pub fn ledger_uid(id: &str) -> Result<EntityUid, AuthzError> {
    EntityUid::from_str(&format!(r#"{}::Ledger::"{id}""#, NS))
        .map_err(|e| AuthzError::InvalidEntityUid(format!("Ledger/{id}: {e:?}")))
}

pub fn document_uid(id: &str) -> Result<EntityUid, AuthzError> {
    EntityUid::from_str(&format!(r#"{}::Document::"{id}""#, NS))
        .map_err(|e| AuthzError::InvalidEntityUid(format!("Document/{id}: {e:?}")))
}

pub fn platform_uid(tenant_id: &str) -> Result<EntityUid, AuthzError> {
    EntityUid::from_str(&format!(r#"{}::Platform::"{tenant_id}""#, NS))
        .map_err(|e| AuthzError::InvalidEntityUid(format!("Platform/{tenant_id}: {e:?}")))
}

pub fn action_uid(name: &str) -> Result<EntityUid, AuthzError> {
    EntityUid::from_str(&format!(r#"{}::Action::"{name}""#, NS))
        .map_err(|e| AuthzError::InvalidEntityUid(format!("Action/{name}: {e:?}")))
}

// ── PolicyStore ──────────────────────────────────────────────────────────────

/// Compiled, immutable policy set + schema + authorizer. Arc-wrap at the call site.
pub struct PolicyStore {
    policy_set: PolicySet,
    schema: Schema,
    authorizer: Authorizer,
}

impl PolicyStore {
    /// Load from Cedar policy text and JSON schema string.
    pub fn from_text(policy_text: &str, schema_json: &str) -> Result<Self, AuthzError> {
        let policy_set = PolicySet::from_str(policy_text)
            .map_err(|e| AuthzError::PolicyParse(format!("{e:?}")))?;

        let schema = Schema::from_json_str(schema_json)
            .map_err(|e| AuthzError::SchemaParse(format!("{e:?}")))?;

        Ok(Self {
            policy_set,
            schema,
            authorizer: Authorizer::new(),
        })
    }

    pub fn schema(&self) -> &Schema {
        &self.schema
    }
}

// ── AuthzRequest ─────────────────────────────────────────────────────────────

/// Per-request authorization inputs.
pub struct AuthzRequest {
    pub principal: EntityUid,
    pub action: EntityUid,
    pub resource: EntityUid,
}

// ── AuthzDecision ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzDecision {
    Allow,
    Deny,
}

// ── is_authorized ─────────────────────────────────────────────────────────────

/// Evaluate `req` against the policy store using the supplied entity set.
/// Returns `Allow` only when Cedar returns `Allow`; any error → `Deny`.
pub fn is_authorized(store: &PolicyStore, entities: Entities, req: &AuthzRequest) -> AuthzDecision {
    let cedar_req = match Request::new(
        req.principal.clone(),
        req.action.clone(),
        req.resource.clone(),
        Context::empty(),
        Some(&store.schema),
    ) {
        Ok(r) => r,
        Err(e) => {
            warn!("Cedar request validation failed: {e:?}");
            return AuthzDecision::Deny;
        }
    };

    let response = store
        .authorizer
        .is_authorized(&cedar_req, &store.policy_set, &entities);

    match response.decision() {
        Decision::Allow => AuthzDecision::Allow,
        Decision::Deny => AuthzDecision::Deny,
    }
}

// ── AuthzError ───────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum AuthzError {
    #[error("Failed to parse Cedar policy: {0}")]
    PolicyParse(String),

    #[error("Failed to parse Cedar schema: {0}")]
    SchemaParse(String),

    #[error("Invalid entity UID: {0}")]
    InvalidEntityUid(String),

    #[error("Failed to build Cedar entities: {0}")]
    EntityBuild(String),
}
