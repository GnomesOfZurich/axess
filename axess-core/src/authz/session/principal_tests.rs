//! A session begun for a `Principal`: the policy of the principal chapter's
//! Cedar bridge section, word for word, admits a human and a workload of
//! tenant acme and refuses another tenant's workload.

use super::*;
use crate::authz::store::PolicyStore;
use crate::{HumanPrincipal, TenantId, TrustDomain, UserId, WorkloadId, WorkloadPrincipal};
use axess_identity::Issuer;
use cedar_policy::{RestrictedExpression, Schema};
use std::collections::{BTreeMap, HashSet};

/// The example of `docs/authentication/principal.md`, "The Cedar bridge".
const POLICY: &str = r#"permit (
  principal,
  action == Action::"read",
  resource in TenantData::"acme"
) when {
  principal.tenant_id == resource.tenant_id
};"#;

const SCHEMA: &str = r#"{
    "": {
        "entityTypes": {
            "TenantData": {},
            "Document": {
                "memberOfTypes": ["TenantData"],
                "shape": {
                    "type": "Record",
                    "attributes": { "tenant_id": { "type": "String" } }
                }
            }
        },
        "actions": {
            "read": {
                "appliesTo": {
                    "principalTypes": ["axess::Human", "axess::Workload"],
                    "resourceTypes": ["Document"]
                }
            }
        }
    },
    "axess": {
        "entityTypes": {
            "Human": {
                "shape": {
                    "type": "Record",
                    "attributes": {
                        "user_id": { "type": "String" },
                        "tenant_id": { "type": "String" },
                        "session_id": { "type": "String", "required": false },
                        "impersonator": { "type": "String", "required": false }
                    }
                }
            },
            "Workload": {
                "shape": {
                    "type": "Record",
                    "attributes": {
                        "workload_id": { "type": "String" },
                        "trust_domain": { "type": "String" },
                        "issuer": { "type": "String" },
                        "tenant_id": { "type": "String" },
                        "tenant_slug": { "type": "String" },
                        "service_name": { "type": "String" }
                    }
                }
            }
        },
        "actions": {}
    }
}"#;

fn acme() -> TenantId {
    TenantId::from_bytes([0xac; 16])
}

fn other_tenant() -> TenantId {
    TenantId::from_bytes([0x07; 16])
}

/// The documents of tenant acme's data, each holding acme's tenant id, and
/// what the session asked for. With `principal_entity` set, the provider
/// also supplies that entity under the principal's UID.
struct AcmeDocuments {
    tenants_seen: Mutex<Vec<Option<String>>>,
    principal_entity: Option<Entity>,
}

impl AcmeDocuments {
    fn new() -> Self {
        Self {
            tenants_seen: Mutex::new(Vec::new()),
            principal_entity: None,
        }
    }
}

impl AuthzEntityProvider for AcmeDocuments {
    type ResourceId = String;
    type Error = AuthzError;

    async fn entities_for(
        &self,
        principal: &EntityUid,
        resource_id: &Self::ResourceId,
        action: &EntityUid,
    ) -> Result<Entities, AuthzError> {
        self.entities_for_tenant(principal, None, resource_id, action)
            .await
    }

    async fn entities_for_tenant(
        &self,
        _: &EntityUid,
        tenant: Option<&str>,
        resource_id: &Self::ResourceId,
        _: &EntityUid,
    ) -> Result<Entities, AuthzError> {
        self.tenants_seen
            .lock()
            .unwrap()
            .push(tenant.map(str::to_string));
        let data = make_uid("", "TenantData", "acme")?;
        let document = Entity::new(
            self.resource_uid(resource_id)?,
            [(
                "tenant_id".to_string(),
                RestrictedExpression::new_string(acme().to_string()),
            )]
            .into_iter()
            .collect(),
            HashSet::from([data.clone()]),
        )
        .map_err(|e| AuthzError::EntityBuild(e.to_string()))?;
        let mut entities = vec![document, Entity::with_uid(data)];
        entities.extend(self.principal_entity.clone());
        Entities::from_entities(entities, None).map_err(|e| AuthzError::EntityBuild(e.to_string()))
    }

    fn resource_uid(&self, id: &Self::ResourceId) -> Result<EntityUid, AuthzError> {
        make_uid("", "Document", id)
    }

    fn validate_schema(&self, _: &Schema) -> Result<(), AuthzError> {
        Ok(())
    }
}

fn store(provider: AcmeDocuments) -> Arc<AuthzStore<AcmeDocuments>> {
    let evaluator: Arc<dyn PolicyEvaluator> =
        Arc::new(PolicyStore::from_text(POLICY, SCHEMA).expect("the page's policy validates"));
    Arc::new(AuthzStore::try_new(evaluator, Arc::new(provider), "").expect("a store"))
}

fn human(tenant: TenantId) -> Principal {
    Principal::Human(HumanPrincipal {
        user_id: UserId::from_bytes([1u8; 16]),
        tenant_id: tenant,
        session_id: None,
        impersonator: None,
        attributes: BTreeMap::new(),
    })
}

fn workload(tenant: TenantId, slug: &str) -> Principal {
    let trust_domain = TrustDomain::new("example.org").unwrap();
    Principal::Workload(WorkloadPrincipal {
        workload_id: WorkloadId::build(&trust_domain, "billing", slug).unwrap(),
        trust_domain,
        issuer: Issuer::Cli,
        tenant_id: tenant,
        tenant_slug: slug.to_string(),
        service_name: "billing".to_string(),
        attributes: BTreeMap::new(),
    })
}

#[tokio::test]
async fn the_pages_policy_admits_a_human_and_a_workload_of_acme_and_refuses_another_tenants_workload()
 {
    let store = store(AcmeDocuments::new());
    let document = "report-1".to_string();

    let person = store.for_principal(&human(acme())).unwrap();
    assert_eq!(
        person.principal().to_string(),
        format!(r#"axess::Human::"{}""#, UserId::from_bytes([1u8; 16]))
    );
    assert!(person.require("read", &document).await.is_ok());

    let worker = store.for_principal(&workload(acme(), "acme")).unwrap();
    assert_eq!(
        worker.principal().to_string(),
        r#"axess::Workload::"spiffe://example.org/billing/acme""#
    );
    assert!(worker.require("read", &document).await.is_ok());

    let stranger = store
        .for_principal(&workload(other_tenant(), "other"))
        .unwrap();
    assert!(stranger.require("read", &document).await.is_err());

    let other_person = store.for_principal(&human(other_tenant())).unwrap();
    assert!(!other_person.is_permitted("read", &document).await);
}

#[tokio::test]
async fn the_session_is_in_the_principals_tenant() {
    let store = store(AcmeDocuments::new());
    let session = store.for_principal(&workload(acme(), "acme")).unwrap();
    session
        .require("read", &"report-1".to_string())
        .await
        .unwrap();
    assert_eq!(
        *store.provider.tenants_seen.lock().unwrap(),
        vec![Some(acme().to_string())]
    );
}

#[tokio::test]
async fn a_provider_may_supply_the_principals_own_entity_but_no_other_under_its_uid() {
    let principal = workload(acme(), "acme");
    let same = AcmeDocuments {
        principal_entity: Some(principal.to_cedar_entity().unwrap()),
        ..AcmeDocuments::new()
    };
    let session = store(same).for_principal(&principal).unwrap();
    assert!(
        session
            .require("read", &"report-1".to_string())
            .await
            .is_ok()
    );

    // The provider's entity of the same UID names another tenant: the check
    // is denied rather than decided on either of the two.
    let forged = workload(other_tenant(), "acme").to_cedar_entity().unwrap();
    let conflicting = AcmeDocuments {
        principal_entity: Some(forged),
        ..AcmeDocuments::new()
    };
    let session = store(conflicting).for_principal(&principal).unwrap();
    assert!(
        session
            .require("read", &"report-1".to_string())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_user_id_session_is_the_user_case_and_brings_no_entity_of_its_own() {
    let store = store(AcmeDocuments::new());
    let session = store.for_user_in_tenant("u1", &acme().to_string()).unwrap();
    assert_eq!(session.principal().to_string(), r#"User::"u1""#);
    // `User` is not a principal type of this schema, and the provider
    // supplies no entity for it: the request is refused.
    assert!(
        session
            .require("read", &"report-1".to_string())
            .await
            .is_err()
    );
}
