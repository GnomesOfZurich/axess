//! In-memory [`AuthzEntityProvider`] for the document management example.
//!
//! In a real application this would query a database. Here the data is
//! hardcoded to keep the example focused on Cedar authorization concepts.

use axess::authorization::{AuthzEntityProvider, AuthzError};
use cedar_policy::{Entities, Entity, EntityUid, RestrictedExpression, Schema};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

// ── Domain types ─────────────────────────────────────────────────────────────

/// A document in our example application.
#[derive(Clone)]
pub struct Document {
    pub id: String,
    pub title: String,
    pub owner_id: String,
}

/// In-memory data store; users, roles, and documents.
#[derive(Clone)]
pub struct AppData {
    /// user_id → list of role names
    pub user_roles: HashMap<String, Vec<String>>,
    /// doc_id → Document
    pub documents: HashMap<String, Document>,
}

impl AppData {
    /// Seed the example data.
    pub fn seed() -> Self {
        let mut user_roles = HashMap::new();
        user_roles.insert("alice".to_string(), vec!["admin".to_string()]);
        user_roles.insert("bob".to_string(), vec!["viewer".to_string()]);
        user_roles.insert("carol".to_string(), vec!["editor".to_string()]);

        let mut documents = HashMap::new();
        documents.insert(
            "doc-1".to_string(),
            Document {
                id: "doc-1".to_string(),
                title: "Q4 Financial Report".to_string(),
                owner_id: "carol".to_string(),
            },
        );
        documents.insert(
            "doc-2".to_string(),
            Document {
                id: "doc-2".to_string(),
                title: "Board Minutes".to_string(),
                owner_id: "alice".to_string(),
            },
        );
        documents.insert(
            "doc-3".to_string(),
            Document {
                id: "doc-3".to_string(),
                title: "Public Handbook".to_string(),
                owner_id: "bob".to_string(),
            },
        );

        Self {
            user_roles,
            documents,
        }
    }
}

// ── AuthzEntityProvider impl ─────────────────────────────────────────────────

/// The entity provider teaches Axess how to build Cedar entity graphs from
/// our application data.
pub struct DocEntityProvider {
    data: AppData,
    namespace: Arc<str>,
}

impl DocEntityProvider {
    pub fn new(data: AppData, namespace: impl Into<Arc<str>>) -> Self {
        Self {
            data,
            namespace: namespace.into(),
        }
    }

    fn make_uid(&self, type_name: &str, id: &str) -> Result<EntityUid, AuthzError> {
        EntityUid::from_str(&format!(r#"{}::{}::"{id}""#, self.namespace, type_name))
            .map_err(|e| AuthzError::InvalidEntityUid(format!("{e:?}")))
    }
}

/// Provider error.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("document not found: {0}")]
    NotFound(String),

    #[error("entity build error: {0}")]
    Build(String),
}

// `?` rather than a `map_err` closure at each of the nine fallible calls
// below. The conversions are uninteresting and repeating them inline buries
// the part worth reading, which is which entities get built and why.
impl From<AuthzError> for ProviderError {
    fn from(e: AuthzError) -> Self {
        Self::Build(e.to_string())
    }
}

impl From<cedar_policy::EntityAttrEvaluationError> for ProviderError {
    fn from(e: cedar_policy::EntityAttrEvaluationError) -> Self {
        Self::Build(format!("{e:?}"))
    }
}

impl From<cedar_policy::entities_errors::EntitiesError> for ProviderError {
    fn from(e: cedar_policy::entities_errors::EntitiesError) -> Self {
        Self::Build(format!("{e:?}"))
    }
}

// ANCHOR: provider
impl AuthzEntityProvider for DocEntityProvider {
    /// Resources are identified by document ID string.
    type ResourceId = String;
    type Error = ProviderError;

    /// Build the Cedar entity set for a single authorization check.
    ///
    /// Returns:
    /// - The User entity with its Role parents
    /// - The Role entities
    /// - The Document entity with its `owner` attribute
    async fn entities_for(
        &self,
        principal: &EntityUid,
        resource_id: &String,
        _action: &EntityUid,
    ) -> Result<Entities, Self::Error> {
        let mut entities = Vec::new();

        // 1. Extract user ID from the principal UID.
        let user_id = principal.id().as_ref();

        // 2. Build Role entities and collect parent UIDs for the user.
        //    The lookups here read an in-memory map so this example
        //    compiles with no database. A real provider issues the
        //    equivalent queries (`SELECT role_name FROM user_roles WHERE
        //    user_id = $1`) and the shape of what follows is unchanged.
        let role_names = self
            .data
            .user_roles
            .get(user_id)
            .cloned()
            .unwrap_or_default();

        let mut role_uids = HashSet::new();
        for role_name in &role_names {
            let role_uid = self.make_uid("Role", role_name)?;
            let role_entity = Entity::new(role_uid.clone(), HashMap::new(), HashSet::new())?;
            entities.push(role_entity);
            role_uids.insert(role_uid);
        }

        // 3. Build the User entity with Role parents.
        let user_entity = Entity::new(principal.clone(), HashMap::new(), role_uids)?;
        entities.push(user_entity);

        // 4. Build the Document entity with `owner` attribute.
        let doc = self
            .data
            .documents
            .get(resource_id.as_str())
            .ok_or_else(|| ProviderError::NotFound(resource_id.to_string()))?;

        let doc_uid = self.make_uid("Document", &doc.id)?;

        let owner_uid = self.make_uid("User", &doc.owner_id)?;

        let mut doc_attrs = HashMap::new();
        doc_attrs.insert(
            "owner".to_string(),
            RestrictedExpression::new_entity_uid(owner_uid.clone()),
        );

        let doc_entity = Entity::new(doc_uid, doc_attrs, HashSet::new())?;
        entities.push(doc_entity);

        // 5. The owner user entity must also be in the entity set if they
        //    are different from the requesting principal.
        //
        //    An entity a policy dereferences but the provider did not
        //    build is absent, and Cedar reads absent as deny, not error.
        if doc.owner_id != user_id {
            let owner_roles = self
                .data
                .user_roles
                .get(&doc.owner_id)
                .cloned()
                .unwrap_or_default();
            let owner_role_uids: HashSet<EntityUid> = owner_roles
                .iter()
                .filter_map(|r| self.make_uid("Role", r).ok())
                .collect();
            let owner_entity = Entity::new(owner_uid, HashMap::new(), owner_role_uids)?;
            entities.push(owner_entity);
        }

        Ok(Entities::from_entities(entities, None)?)
    }

    /// Build the Cedar entity UID for a document.
    fn resource_uid(&self, id: &String) -> Result<EntityUid, AuthzError> {
        self.make_uid("Document", id)
    }

    fn validate_schema(&self, schema: &Schema) -> Result<(), AuthzError> {
        // Example provider: trusts the loaded schema. Real providers cross-check
        // entity shapes against the schema here.
        tracing::trace!(
            target: "axess::example::authz",
            ?schema,
            "example provider: schema accepted without cross-checks",
        );
        Ok(())
    }
}
// ANCHOR_END: provider
