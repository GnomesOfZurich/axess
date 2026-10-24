use super::*;

fn sample_tenant() -> TenantId {
    TenantId::from_bytes([1u8; 16])
}

fn sample_user() -> UserId {
    UserId::from_bytes([2u8; 16])
}

#[test]
fn human_principal_tenant_id_accessor() {
    let tenant = sample_tenant();
    let human = HumanPrincipal {
        user_id: sample_user(),
        tenant_id: tenant,
        session_id: None,
        attributes: BTreeMap::new(),
    };
    let p = Principal::Human(human);
    assert_eq!(p.tenant_id(), &tenant);
}

#[test]
fn workload_principal_tenant_id_accessor() {
    let tenant = sample_tenant();
    let trust = TrustDomain::new("gnomes.local").unwrap();
    let wid = WorkloadId::build(&trust, "compute-worker", "ekekrantz").unwrap();
    let workload = WorkloadPrincipal {
        workload_id: wid,
        trust_domain: trust,
        issuer: Issuer::Cli,
        tenant_id: tenant,
        tenant_slug: "ekekrantz".to_string(),
        service_name: "compute-worker".to_string(),
        attributes: BTreeMap::new(),
    };
    let p = Principal::Workload(workload);
    assert_eq!(p.tenant_id(), &tenant);
}

#[test]
fn attributes_accessor_returns_empty_by_default() {
    let trust = TrustDomain::new("gnomes.local").unwrap();
    let wid = WorkloadId::build(&trust, "feed-worker", "ekekrantz").unwrap();
    let workload = WorkloadPrincipal {
        workload_id: wid,
        trust_domain: trust,
        issuer: Issuer::Cli,
        tenant_id: sample_tenant(),
        tenant_slug: "ekekrantz".to_string(),
        service_name: "feed-worker".to_string(),
        attributes: BTreeMap::new(),
    };
    let p = Principal::Workload(workload);
    assert!(p.attributes().is_empty());
}

/// `attributes()` returns the LIVE attribute map, not a fresh
/// empty one. The mutation `-> Box::leak(Box::new(BTreeMap::new()))`
/// would hide any populated attributes.
#[test]
fn attributes_accessor_returns_populated_human_map() {
    let mut attrs = BTreeMap::new();
    attrs.insert("amr".to_string(), serde_json::json!(["pwd", "mfa"]));
    let human = HumanPrincipal {
        user_id: sample_user(),
        tenant_id: sample_tenant(),
        session_id: None,
        attributes: attrs,
    };
    let p = Principal::Human(human);
    let seen = p.attributes();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen.get("amr"), Some(&serde_json::json!(["pwd", "mfa"])));
}

#[test]
fn attributes_accessor_returns_populated_workload_map() {
    let trust = TrustDomain::new("gnomes.local").unwrap();
    let wid = WorkloadId::build(&trust, "feed-worker", "ekekrantz").unwrap();
    let mut attrs = BTreeMap::new();
    attrs.insert("region".to_string(), serde_json::json!("eu-west-1"));
    let workload = WorkloadPrincipal {
        workload_id: wid,
        trust_domain: trust,
        issuer: Issuer::Cli,
        tenant_id: sample_tenant(),
        tenant_slug: "ekekrantz".to_string(),
        service_name: "feed-worker".to_string(),
        attributes: attrs,
    };
    let p = Principal::Workload(workload);
    assert_eq!(
        p.attributes().get("region"),
        Some(&serde_json::json!("eu-west-1"))
    );
}

#[test]
fn issuer_as_str_is_stable_lowercase() {
    assert_eq!(Issuer::Cli.as_str(), "cli");
    assert_eq!(Issuer::JwtSvid.as_str(), "jwt_svid");
    assert_eq!(Issuer::Mtls.as_str(), "mtls");
    assert_eq!(Issuer::OAuth.as_str(), "oauth");
    assert_eq!(
        Issuer::custom("github_actions").unwrap().as_str(),
        "github_actions"
    );
}

#[test]
fn issuer_custom_validation_rejects_bad_labels() {
    // Empty: rejected.
    assert!(Issuer::custom("").is_err());
    // Too long (>32): rejected.
    assert!(Issuer::custom("a".repeat(33)).is_err());
    // Uppercase: rejected.
    assert!(Issuer::custom("GitHubActions").is_err());
    // Dashes / dots / spaces: rejected.
    assert!(Issuer::custom("github-actions").is_err());
    assert!(Issuer::custom("github.actions").is_err());
    assert!(Issuer::custom("github actions").is_err());
    // Accepted shapes.
    assert!(Issuer::custom("k8s").is_ok());
    assert!(Issuer::custom("github_actions").is_ok());
    assert!(Issuer::custom("circleci_2_1").is_ok());
}

#[test]
fn issuer_custom_accepts_exactly_32_chars() {
    let label = "a".repeat(32);
    assert!(
        Issuer::custom(&label).is_ok(),
        "32-char label must be accepted (kills `> -> >=` boundary mutation)"
    );
    let too_long = "a".repeat(33);
    assert!(
        Issuer::custom(&too_long).is_err(),
        "33-char label must be rejected"
    );
}

#[cfg(feature = "serde")]
#[test]
fn principal_serde_round_trip_human() {
    let human = HumanPrincipal {
        user_id: sample_user(),
        tenant_id: sample_tenant(),
        session_id: None,
        attributes: BTreeMap::new(),
    };
    let p = Principal::Human(human);
    let json = serde_json::to_string(&p).unwrap();
    let back: Principal = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[cfg(feature = "serde")]
#[test]
fn principal_serde_round_trip_workload() {
    let trust = TrustDomain::new("gnomes.local").unwrap();
    let wid = WorkloadId::build(&trust, "market-worker", "world_cup").unwrap();
    let workload = WorkloadPrincipal {
        workload_id: wid,
        trust_domain: trust,
        issuer: Issuer::Cli,
        tenant_id: sample_tenant(),
        tenant_slug: "world_cup".to_string(),
        service_name: "market-worker".to_string(),
        attributes: BTreeMap::new(),
    };
    let p = Principal::Workload(workload);
    let json = serde_json::to_string(&p).unwrap();
    let back: Principal = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn issuer_custom_rejects_built_in_names() {
    for name in ["cli", "jwt_svid", "mtls", "oauth"] {
        assert!(Issuer::custom(name).is_err(), "{name} is reserved");
    }
}

#[cfg(feature = "serde")]
#[test]
fn issuer_serde_round_trips_every_variant() {
    for issuer in [
        Issuer::Cli,
        Issuer::JwtSvid,
        Issuer::Mtls,
        Issuer::OAuth,
        Issuer::custom("github_actions").unwrap(),
    ] {
        let json = serde_json::to_string(&issuer).expect("serialize");
        let back: Issuer = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(issuer, back, "{json}");
    }
    assert_eq!(
        serde_json::to_string(&Issuer::custom("k8s").unwrap()).unwrap(),
        r#"{"kind":"custom","label":"k8s"}"#
    );
    assert_eq!(
        serde_json::to_string(&Issuer::OAuth).unwrap(),
        r#"{"kind":"oauth"}"#
    );
}

#[cfg(feature = "serde")]
#[test]
fn issuer_deserialize_validates_custom_label() {
    for bad in ["oauth", "mtls", "Bad-Label", ""] {
        let json = format!(r#"{{"kind":"custom","label":"{bad}"}}"#);
        assert!(serde_json::from_str::<Issuer>(&json).is_err(), "{json}");
    }
}

#[cfg(feature = "serde")]
#[test]
fn workload_principal_with_custom_issuer_round_trips() {
    let trust = TrustDomain::new("gnomes.local").unwrap();
    let workload = WorkloadPrincipal {
        workload_id: WorkloadId::build(&trust, "ci", "acme").unwrap(),
        trust_domain: trust,
        issuer: Issuer::custom("github_actions").unwrap(),
        tenant_id: sample_tenant(),
        tenant_slug: "acme".to_string(),
        service_name: "ci".to_string(),
        attributes: BTreeMap::new(),
    };
    let p = Principal::Workload(workload);
    let json = serde_json::to_string(&p).expect("serialize");
    assert_eq!(serde_json::from_str::<Principal>(&json).unwrap(), p);
}
