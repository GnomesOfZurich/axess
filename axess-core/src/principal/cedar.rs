//! Cedar bridge for [`Principal`].
//!
//! Emit `cedar_policy::Entity` values for human and workload
//! principals so adopter authorization policies can reason about them
//! symmetrically. Entity type names live under a stable `axess`
//! namespace (`axess::Human`, `axess::Workload`); adopter schemas
//! extend with their own resource entity types.
//!
//! [`Principal`] is defined in the leaf [`axess_identity`] crate so
//! the Cedar surface lives behind a [`ToCedarEntity`] trait here
//! instead of inherent methods. Call sites bring the trait into scope:
//!
//! ```ignore
//! use axess_core::ToCedarEntity;
//! let entity = principal.to_cedar_entity()?;
//! ```
//!
//! # Attribute shapes
//!
//! `axess::Human`:
//! - `user_id`: string
//! - `tenant_id`: string
//! - `session_id`: string (only present when the principal carries one)
//! - `impersonator`: string, the administrator's user id (only present for
//!   the principal of an impersonated session)
//! - any extra keys from [`HumanPrincipal::attributes`] map onto Cedar
//!   typed values via the JSON-to-Cedar rules documented on
//!   [`json_to_restricted_expression`].
//!
//! `axess::Workload`:
//! - `workload_id`: string (the SPIFFE URI)
//! - `trust_domain`: string
//! - `issuer`: string (lowercase variant name; `"cli"` today)
//! - `tenant_id`: string
//! - `tenant_slug`: string
//! - `service_name`: string
//! - extras from [`WorkloadPrincipal::attributes`] per the same rules
//!
//! # Conflict policy
//!
//! When [`HumanPrincipal::attributes`] or [`WorkloadPrincipal::attributes`]
//! contains a key that collides with a built-in attribute name
//! (e.g. `tenant_id`), the built-in attribute wins and the colliding key
//! is dropped with a warning. The names are reserved whether or not the
//! principal sets them: a caller cannot supply a `session_id` or an
//! `impersonator` the session does not carry. The built-ins (tenant, user, workload
//! identity) are what policies pin on, and the extra attributes can come
//! from token claims the caller influences, so they must never be able to
//! replace them. Use a different key for application attributes.

use std::collections::{HashMap, HashSet};

use axess_identity::{HumanPrincipal, Principal, WorkloadPrincipal};
use cedar_policy::{Entity, EntityUid, RestrictedExpression};

use crate::authz::{AuthzError, make_entity_uid};

/// Cedar namespace used for axess-emitted principal entities.
pub const PRINCIPAL_NAMESPACE: &str = "axess";

/// Cedar entity type name for human principals.
pub const HUMAN_ENTITY_TYPE: &str = "Human";

/// Cedar entity type name for workload principals.
pub const WORKLOAD_ENTITY_TYPE: &str = "Workload";

/// The attribute names of `axess::Human` the library owns, set or not.
const HUMAN_BUILT_INS: &[&str] = &["user_id", "tenant_id", "session_id", "impersonator"];

/// The attribute names of `axess::Workload` the library owns.
const WORKLOAD_BUILT_INS: &[&str] = &[
    "workload_id",
    "trust_domain",
    "issuer",
    "tenant_id",
    "tenant_slug",
    "service_name",
];

/// Trait surface for converting a [`Principal`] (or one of its
/// variants) into a `cedar_policy::Entity`. Bring this into scope to
/// call `to_cedar_entity()` on principals.
pub trait ToCedarEntity {
    /// Build the Cedar [`EntityUid`] for this principal without
    /// constructing the full entity. Useful when the caller only
    /// needs the UID for an authorization request (entity attributes
    /// supplied separately via an
    /// [`AuthzEntityProvider`](crate::AuthzEntityProvider)).
    fn cedar_entity_uid(&self) -> Result<EntityUid, AuthzError>;

    /// Build the full Cedar [`Entity`] for this principal: UID plus
    /// attribute record.
    fn to_cedar_entity(&self) -> Result<Entity, AuthzError>;
}

impl ToCedarEntity for Principal {
    fn cedar_entity_uid(&self) -> Result<EntityUid, AuthzError> {
        match self {
            Self::Human(h) => h.cedar_entity_uid(),
            Self::Workload(w) => w.cedar_entity_uid(),
        }
    }

    fn to_cedar_entity(&self) -> Result<Entity, AuthzError> {
        match self {
            Self::Human(h) => h.to_cedar_entity(),
            Self::Workload(w) => w.to_cedar_entity(),
        }
    }
}

impl ToCedarEntity for HumanPrincipal {
    fn cedar_entity_uid(&self) -> Result<EntityUid, AuthzError> {
        make_entity_uid(
            PRINCIPAL_NAMESPACE,
            HUMAN_ENTITY_TYPE,
            &self.user_id.to_string(),
        )
    }

    fn to_cedar_entity(&self) -> Result<Entity, AuthzError> {
        let uid = self.cedar_entity_uid()?;
        let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();
        attrs.insert(
            "user_id".to_string(),
            RestrictedExpression::new_string(self.user_id.to_string()),
        );
        attrs.insert(
            "tenant_id".to_string(),
            RestrictedExpression::new_string(self.tenant_id.to_string()),
        );
        if let Some(sid) = &self.session_id {
            attrs.insert(
                "session_id".to_string(),
                RestrictedExpression::new_string(sid.to_string()),
            );
        }
        if let Some(admin) = &self.impersonator {
            attrs.insert(
                "impersonator".to_string(),
                RestrictedExpression::new_string(admin.to_string()),
            );
        }
        merge_attribute_map(&mut attrs, HUMAN_BUILT_INS, &self.attributes);
        Entity::new(uid, attrs, HashSet::new())
            .map_err(|e| AuthzError::EntityBuild(format!("HumanPrincipal: {e:?}")))
    }
}

impl ToCedarEntity for WorkloadPrincipal {
    fn cedar_entity_uid(&self) -> Result<EntityUid, AuthzError> {
        make_entity_uid(
            PRINCIPAL_NAMESPACE,
            WORKLOAD_ENTITY_TYPE,
            self.workload_id.as_str(),
        )
    }

    fn to_cedar_entity(&self) -> Result<Entity, AuthzError> {
        let uid = self.cedar_entity_uid()?;
        let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();
        attrs.insert(
            "workload_id".to_string(),
            RestrictedExpression::new_string(self.workload_id.as_str().to_string()),
        );
        attrs.insert(
            "trust_domain".to_string(),
            RestrictedExpression::new_string(self.trust_domain.as_str().to_string()),
        );
        attrs.insert(
            "issuer".to_string(),
            RestrictedExpression::new_string(self.issuer.as_str().to_string()),
        );
        attrs.insert(
            "tenant_id".to_string(),
            RestrictedExpression::new_string(self.tenant_id.to_string()),
        );
        attrs.insert(
            "tenant_slug".to_string(),
            RestrictedExpression::new_string(self.tenant_slug.clone()),
        );
        attrs.insert(
            "service_name".to_string(),
            RestrictedExpression::new_string(self.service_name.clone()),
        );
        merge_attribute_map(&mut attrs, WORKLOAD_BUILT_INS, &self.attributes);
        Entity::new(uid, attrs, HashSet::new())
            .map_err(|e| AuthzError::EntityBuild(format!("WorkloadPrincipal: {e:?}")))
    }
}

/// Apply user-supplied attributes onto the built-in attribute map,
/// converting each `serde_json::Value` per
/// [`json_to_restricted_expression`]. A user key that collides with a
/// built-in, set or not, is dropped with a warning (see module-level
/// "Conflict policy"): `reserved` names every built-in of the entity type,
/// since one the principal does not carry (a session id, an impersonator)
/// must not be supplied by a caller either.
fn merge_attribute_map(
    attrs: &mut HashMap<String, RestrictedExpression>,
    reserved: &[&str],
    user: &std::collections::BTreeMap<String, serde_json::Value>,
) {
    for (k, v) in user {
        if attrs.contains_key(k) || reserved.contains(&k.as_str()) {
            tracing::warn!(
                attribute = %k,
                "principal attribute collides with a built-in Cedar attribute; the built-in value is kept"
            );
            continue;
        }
        attrs.insert(k.clone(), json_to_restricted_expression(v));
    }
}

/// Map a [`serde_json::Value`] onto a Cedar [`RestrictedExpression`].
///
/// Conversion rules:
/// - `Bool` → Cedar bool
/// - `String` → Cedar string
/// - `Number` → Cedar long when it fits in `i64`; string otherwise
///   (Cedar has no native floating-point or arbitrary-precision type)
/// - `Null`, `Array`, `Object` → JSON-encoded string
///
/// The string fallback for non-scalar shapes preserves the data so
/// adopter policies can `contains(...)`-test it; future iterations
/// may map arrays onto Cedar sets natively when a concrete use case
/// demands it.
pub fn json_to_restricted_expression(v: &serde_json::Value) -> RestrictedExpression {
    match v {
        serde_json::Value::Bool(b) => RestrictedExpression::new_bool(*b),
        serde_json::Value::String(s) => RestrictedExpression::new_string(s.clone()),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                RestrictedExpression::new_long(i)
            } else {
                RestrictedExpression::new_string(n.to_string())
            }
        }
        serde_json::Value::Null | serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            RestrictedExpression::new_string(v.to_string())
        }
    }
}

#[cfg(test)]
mod tests;
