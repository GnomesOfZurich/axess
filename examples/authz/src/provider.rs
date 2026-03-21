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

/// In-memory data store — users, roles, and documents.
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
        let role_names = self
            .data
            .user_roles
            .get(user_id)
            .cloned()
            .unwrap_or_default();

        let mut role_uids = HashSet::new();
        for role_name in &role_names {
            let role_uid = self
                .make_uid("Role", role_name)
                .map_err(|e| ProviderError::Build(e.to_string()))?;
            let role_entity = Entity::new(role_uid.clone(), HashMap::new(), HashSet::new())
                .map_err(|e| ProviderError::Build(format!("{e:?}")))?;
            entities.push(role_entity);
            role_uids.insert(role_uid);
        }

        // 3. Build the User entity with Role parents.
        let user_entity = Entity::new(principal.clone(), HashMap::new(), role_uids)
            .map_err(|e| ProviderError::Build(format!("{e:?}")))?;
        entities.push(user_entity);

        // 4. Build the Document entity with `owner` attribute.
        let doc = self
            .data
            .documents
            .get(resource_id.as_str())
            .ok_or_else(|| ProviderError::NotFound(resource_id.to_string()))?;

        let doc_uid = self
            .make_uid("Document", &doc.id)
            .map_err(|e| ProviderError::Build(e.to_string()))?;

        let owner_uid = self
            .make_uid("User", &doc.owner_id)
            .map_err(|e| ProviderError::Build(e.to_string()))?;

        let mut doc_attrs = HashMap::new();
        doc_attrs.insert(
            "owner".to_string(),
            RestrictedExpression::new_entity_uid(owner_uid.clone()),
        );

        let doc_entity = Entity::new(doc_uid, doc_attrs, HashSet::new())
            .map_err(|e| ProviderError::Build(format!("{e:?}")))?;
        entities.push(doc_entity);

        // 5. The owner user entity must also be in the entity set if they
        //    are different from the requesting principal.
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
            let owner_entity = Entity::new(owner_uid, HashMap::new(), owner_role_uids)
                .map_err(|e| ProviderError::Build(format!("{e:?}")))?;
            entities.push(owner_entity);
        }

        Entities::from_entities(entities, None).map_err(|e| ProviderError::Build(format!("{e:?}")))
    }

    /// Build the Cedar entity UID for a document.
    fn resource_uid(&self, id: &String) -> Result<EntityUid, AuthzError> {
        self.make_uid("Document", id)
    }

    fn validate_against_schema(&self, _schema: &Schema) -> Result<(), AuthzError> {
        Ok(())
    }
}
