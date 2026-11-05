use std::collections::BTreeMap;

use super::*;
use axess_identity::{Issuer, TrustDomain, WorkloadId};
use axess_identity::{TenantId, UserId};

fn sample_human() -> HumanPrincipal {
    HumanPrincipal {
        user_id: UserId::from_bytes([10u8; 16]),
        tenant_id: TenantId::from_bytes([20u8; 16]),
        session_id: None,
        impersonator: None,
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

/// A built-in attribute name is reserved whether or not the principal
/// sets it: a caller attribute of that name cannot stand in for one the
/// principal does not carry.
#[test]
fn a_caller_attribute_cannot_take_an_unset_built_in_name() {
    let mut h = sample_human();
    for name in ["session_id", "impersonator"] {
        h.attributes
            .insert(name.to_string(), serde_json::json!("forged"));
    }
    let entity = h.to_cedar_entity().unwrap();
    assert!(entity.attr("session_id").is_none());
    assert!(entity.attr("impersonator").is_none());

    let mut w = sample_workload();
    w.attributes
        .insert("workload_id".to_string(), serde_json::json!("forged"));
    let entity = w.to_cedar_entity().unwrap();
    assert!(
        entity
            .attr("workload_id")
            .is_some_and(|v| format!("{v:?}").contains("spiffe://")),
        "the built-in value is kept"
    );
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

/// The reserved names are exactly the attributes the library writes: one
/// added to an entity and not to its list would let a caller forge it.
#[test]
fn the_reserved_names_are_the_attributes_the_library_writes() {
    let mut h = sample_human();
    h.session_id = Some(axess_identity::SessionId::from_bytes([7u8; 16]));
    h.impersonator = Some(UserId::from_bytes([30u8; 16]));
    let mut written: Vec<String> = h
        .to_cedar_entity()
        .unwrap()
        .attrs()
        .map(|(k, _)| k.to_string())
        .collect();
    written.sort();
    let mut reserved: Vec<String> = HUMAN_BUILT_INS.iter().map(|s| s.to_string()).collect();
    reserved.sort();
    assert_eq!(written, reserved, "human");

    let mut written: Vec<String> = sample_workload()
        .to_cedar_entity()
        .unwrap()
        .attrs()
        .map(|(k, _)| k.to_string())
        .collect();
    written.sort();
    let mut reserved: Vec<String> = WORKLOAD_BUILT_INS.iter().map(|s| s.to_string()).collect();
    reserved.sort();
    assert_eq!(written, reserved, "workload");
}

fn string_attr(entity: &Entity, name: &str) -> Option<String> {
    match entity.attr(name) {
        Some(Ok(cedar_policy::EvalResult::String(s))) => Some(s),
        _ => None,
    }
}

#[test]
fn user_supplied_attributes_cannot_replace_built_ins() {
    let mut h = sample_human();
    let expected = h.tenant_id.to_string();
    h.attributes.insert(
        "tenant_id".to_string(),
        serde_json::json!("override-tenant"),
    );
    h.attributes
        .insert("tier".to_string(), serde_json::json!("gold"));
    let entity = h.to_cedar_entity().unwrap();
    assert_eq!(string_attr(&entity, "tenant_id"), Some(expected));
    assert_eq!(string_attr(&entity, "tier").as_deref(), Some("gold"));

    let mut w = sample_workload();
    let workload_id = w.workload_id.as_str().to_string();
    w.attributes.insert(
        "workload_id".to_string(),
        serde_json::json!("spiffe://evil"),
    );
    w.attributes
        .insert("trust_domain".to_string(), serde_json::json!("evil"));
    let entity = w.to_cedar_entity().unwrap();
    assert_eq!(string_attr(&entity, "workload_id"), Some(workload_id));
    assert_eq!(
        string_attr(&entity, "trust_domain").as_deref(),
        Some("gnomes.local")
    );
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
