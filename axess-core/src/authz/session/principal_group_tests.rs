//! Groups for a session begun for a `Principal`, as the principal chapter
//! says they come: the principal's entity is the library's and has no
//! parents, so the provider supplies the groups as entities of their own,
//! with their parent links between them and their members named on them.
//! A policy that reads a group's members admits a member; one that asks for
//! the principal's own parents is never satisfied; and a provider that
//! gives the principal's entity a parent denies the check.

use super::*;
use crate::authz::store::PolicyStore;
use crate::{HumanPrincipal, TenantId, UserId};
use cedar_policy::{RestrictedExpression, Schema};
use std::collections::{BTreeMap, HashSet};

/// The pattern of `docs/authentication/principal.md`, "Groups and other
/// parents": membership is read from the group, and the parent link
/// between two groups is the provider's.
const POLICY: &str = r#"permit (
  principal,
  action == Action::"read",
  resource
) when {
  principal in Group::"payroll".members && Group::"payroll" in Group::"finance"
};

permit (
  principal,
  action == Action::"write",
  resource
) when {
  principal in Group::"finance"
};"#;

const SCHEMA: &str = r#"{
    "": {
        "entityTypes": {
            "Group": {
                "memberOfTypes": ["Group"],
                "shape": {
                    "type": "Record",
                    "attributes": {
                        "members": {
                            "type": "Set",
                            "element": { "type": "Entity", "name": "axess::Human" }
                        }
                    }
                }
            },
            "Document": {}
        },
        "actions": {
            "read": {
                "appliesTo": {
                    "principalTypes": ["axess::Human"],
                    "resourceTypes": ["Document"]
                }
            },
            "write": {
                "appliesTo": {
                    "principalTypes": ["axess::Human"],
                    "resourceTypes": ["Document"]
                }
            }
        }
    },
    "axess": {
        "entityTypes": {
            "Human": {
                "memberOfTypes": ["Group"],
                "shape": {
                    "type": "Record",
                    "attributes": {
                        "user_id": { "type": "String" },
                        "tenant_id": { "type": "String" },
                        "session_id": { "type": "String", "required": false },
                        "impersonator": { "type": "String", "required": false }
                    }
                }
            }
        },
        "actions": {}
    }
}"#;

fn person(byte: u8) -> Principal {
    Principal::Human(HumanPrincipal {
        user_id: UserId::from_bytes([byte; 16]),
        tenant_id: TenantId::from_bytes([0xac; 16]),
        session_id: None,
        impersonator: None,
        attributes: BTreeMap::new(),
    })
}

/// Two groups, `payroll` within `finance`, with `member` the one member of
/// `payroll`; with `parent_on_principal`, the provider also supplies the
/// member's own entity with `finance` as its parent.
struct Groups {
    member: Principal,
    parent_on_principal: bool,
}

fn group(name: &str, members: &[&Principal], parents: &[&str]) -> Result<Entity, AuthzError> {
    let members = members
        .iter()
        .map(|p| {
            p.cedar_entity_uid()
                .map(RestrictedExpression::new_entity_uid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let parents = parents
        .iter()
        .map(|p| make_uid("", "Group", p))
        .collect::<Result<HashSet<_>, _>>()?;
    Entity::new(
        make_uid("", "Group", name)?,
        [(
            "members".to_string(),
            RestrictedExpression::new_set(members),
        )]
        .into_iter()
        .collect(),
        parents,
    )
    .map_err(|e| AuthzError::EntityBuild(e.to_string()))
}

impl AuthzEntityProvider for Groups {
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
        _: Option<&str>,
        resource_id: &Self::ResourceId,
        _: &EntityUid,
    ) -> Result<Entities, AuthzError> {
        let mut entities = vec![
            Entity::with_uid(self.resource_uid(resource_id)?),
            group("finance", &[], &[])?,
            group("payroll", &[&self.member], &["finance"])?,
        ];
        if self.parent_on_principal {
            let own = self.member.to_cedar_entity()?;
            let (uid, attrs, _) = own.into_inner();
            entities.push(
                Entity::new(
                    uid,
                    attrs,
                    HashSet::from([make_uid("", "Group", "finance")?]),
                )
                .map_err(|e| AuthzError::EntityBuild(e.to_string()))?,
            );
        }
        Entities::from_entities(entities, None).map_err(|e| AuthzError::EntityBuild(e.to_string()))
    }

    fn resource_uid(&self, id: &Self::ResourceId) -> Result<EntityUid, AuthzError> {
        make_uid("", "Document", id)
    }

    fn validate_schema(&self, _: &Schema) -> Result<(), AuthzError> {
        Ok(())
    }
}

fn store(provider: Groups) -> Arc<AuthzStore<Groups>> {
    let evaluator: Arc<dyn PolicyEvaluator> =
        Arc::new(PolicyStore::from_text(POLICY, SCHEMA).expect("the policies validate"));
    Arc::new(AuthzStore::try_new(evaluator, Arc::new(provider), "").expect("a store"))
}

#[tokio::test]
async fn a_group_the_provider_supplies_admits_its_members_and_no_one_else() {
    let member = person(1);
    let store = store(Groups {
        member: member.clone(),
        parent_on_principal: false,
    });
    let document = "report-1".to_string();

    let session = store.for_principal(&member).unwrap();
    assert!(session.is_permitted("read", &document).await);
    // The principal's entity has no parents, so a policy that asks for
    // them is not satisfied, whatever the groups say.
    assert!(!session.is_permitted("write", &document).await);

    let outsider = store.for_principal(&person(2)).unwrap();
    assert!(!outsider.is_permitted("read", &document).await);
}

#[tokio::test]
async fn a_provider_that_gives_the_principal_a_parent_denies_the_check() {
    let member = person(1);
    let store = store(Groups {
        member: member.clone(),
        parent_on_principal: true,
    });
    let session = store.for_principal(&member).unwrap();
    let document = "report-1".to_string();
    assert!(!session.is_permitted("read", &document).await);
    assert!(!session.is_permitted("write", &document).await);
}
