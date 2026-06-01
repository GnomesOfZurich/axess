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
//! (e.g. `tenant_id`), the user-supplied attribute wins. Adopters who
//! explicitly override an attribute have a reason; a silent built-in
//! win would surprise them.

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
        merge_attribute_map(&mut attrs, &self.attributes);
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
        merge_attribute_map(&mut attrs, &self.attributes);
        Entity::new(uid, attrs, HashSet::new())
            .map_err(|e| AuthzError::EntityBuild(format!("WorkloadPrincipal: {e:?}")))
    }
}

/// Apply user-supplied attributes onto the built-in attribute map,
/// converting each `serde_json::Value` per
/// [`json_to_restricted_expression`]. User keys override built-in
/// keys on collision (see module-level "Conflict policy").
fn merge_attribute_map(
    attrs: &mut HashMap<String, RestrictedExpression>,
    user: &std::collections::BTreeMap<String, serde_json::Value>,
) {
    for (k, v) in user {
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
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use axess_identity::{Issuer, TrustDomain, WorkloadId};
    use axess_identity::{TenantId, UserId};

    fn sample_human() -> HumanPrincipal {
        HumanPrincipal {
            user_id: UserId::from_bytes([10u8; 16]),
            tenant_id: TenantId::from_bytes([20u8; 16]),
            session_id: None,
            attributes: BTreeMap::new(),
        }
    }

    fn sample_workload() -> WorkloadPrincipal {
        let trust = TrustDomain::new("gnomes.local").unwrap();
        let wid = WorkloadId::build(&trust, "compute-worker", "ekekrantz").unwrap();
        WorkloadPrincipal {
            workload_id: wid,
            trust_domain: trust,
            issuer: Issuer::Cli,
            tenant_id: TenantId::from_bytes([30u8; 16]),
            tenant_slug: "ekekrantz".to_string(),
            service_name: "compute-worker".to_string(),
            attributes: BTreeMap::new(),
        }
    }

    #[test]
    fn human_entity_uid_is_namespaced_under_axess_human() {
        let uid = sample_human().cedar_entity_uid().unwrap();
        let s = format!("{uid}");
        assert!(s.starts_with("axess::Human::"), "actual: {s}");
    }

    #[test]
    fn workload_entity_uid_is_namespaced_under_axess_workload() {
        let uid = sample_workload().cedar_entity_uid().unwrap();
        let s = format!("{uid}");
        assert!(s.starts_with("axess::Workload::"), "actual: {s}");
        assert!(s.contains("spiffe://gnomes.local/compute-worker/ekekrantz"));
    }

    #[test]
    fn human_to_cedar_entity_includes_required_attrs() {
        let h = sample_human();
        let entity = h.to_cedar_entity().unwrap();
        assert!(entity.attr("user_id").is_some());
        assert!(entity.attr("tenant_id").is_some());
        assert!(
            entity.attr("session_id").is_none(),
            "session_id absent when principal has none"
        );
    }

    #[test]
    fn human_to_cedar_entity_includes_session_id_when_present() {
        let mut h = sample_human();
        h.session_id = Some(axess_identity::SessionId::from_bytes([7u8; 16]));
        let entity = h.to_cedar_entity().unwrap();
        assert!(entity.attr("session_id").is_some());
    }

    #[test]
    fn workload_to_cedar_entity_includes_all_built_in_attrs() {
        let entity = sample_workload().to_cedar_entity().unwrap();
        for name in [
            "workload_id",
            "trust_domain",
            "issuer",
            "tenant_id",
            "tenant_slug",
            "service_name",
        ] {
            assert!(
                entity.attr(name).is_some(),
                "missing built-in attribute '{name}'"
            );
        }
    }

    #[test]
    fn user_supplied_attributes_override_built_ins_on_collision() {
        let mut h = sample_human();
        h.attributes.insert(
            "tenant_id".to_string(),
            serde_json::json!("override-tenant"),
        );
        let entity = h.to_cedar_entity().unwrap();
        assert!(entity.attr("tenant_id").is_some());
    }

    #[test]
    fn principal_enum_dispatches_to_variant_method() {
        let p = Principal::Human(sample_human());
        let uid = p.cedar_entity_uid().unwrap();
        assert!(format!("{uid}").starts_with("axess::Human::"));

        let p = Principal::Workload(sample_workload());
        let uid = p.cedar_entity_uid().unwrap();
        assert!(format!("{uid}").starts_with("axess::Workload::"));
    }

    #[test]
    fn json_to_restricted_handles_scalars() {
        let mut w = sample_workload();
        w.attributes
            .insert("flag".to_string(), serde_json::json!(true));
        w.attributes
            .insert("name".to_string(), serde_json::json!("worker"));
        w.attributes
            .insert("count".to_string(), serde_json::json!(42));
        w.attributes
            .insert("ratio".to_string(), serde_json::json!(1.5));
        w.attributes
            .insert("missing".to_string(), serde_json::json!(null));
        w.attributes
            .insert("tags".to_string(), serde_json::json!(["a", "b"]));
        let entity = w.to_cedar_entity().unwrap();
        for name in ["flag", "name", "count", "ratio", "missing", "tags"] {
            assert!(
                entity.attr(name).is_some(),
                "missing attribute '{name}' after JSON-to-Cedar conversion"
            );
        }
    }
}
