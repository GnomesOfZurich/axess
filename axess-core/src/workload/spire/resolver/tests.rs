//! The agent-validated resolver: what it makes of the agent's answer.

use serde_json::json;

use super::*;
use crate::testing::spire_agent::WorkloadApiMethod;
use crate::workload::spire::test_support::{World, within};

const ID: &str = "spiffe://example.org/billing/acme";
const AUDIENCE: &str = "https://api.example.org";

fn tenant() -> TenantId {
    TenantId::from_bytes([7u8; 16])
}

fn trust_domain(name: &str) -> TrustDomain {
    TrustDomain::new(name).expect("a trust domain")
}

fn resolver(world: &World, expected: &str) -> AgentJwtSvidResolver {
    AgentJwtSvidResolver::new(
        world.client("example.org"),
        AUDIENCE,
        trust_domain(expected),
        "header.payload.signature",
        |slug: &str| (slug == "acme").then(tenant),
    )
}

fn claims(value: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    value.as_object().expect("an object").clone()
}

#[tokio::test(start_paused = true)]
async fn a_token_the_agent_validates_resolves_to_a_workload() {
    let world = World::new();
    let agent = world.agent();
    agent.accept_validations(ID, &claims(json!({ "sub": ID, "aud": [AUDIENCE] })));

    let principal = within(resolver(&world, "example.org").resolve())
        .await
        .expect("a validated token");
    let Principal::Workload(workload) = principal else {
        panic!("a JWT SVID resolves to a workload");
    };
    assert_eq!(workload.workload_id.as_str(), ID);
    assert_eq!(workload.trust_domain.as_str(), "example.org");
    assert_eq!(workload.issuer, Issuer::JwtSvid);
    assert_eq!(workload.tenant_id, tenant());
    assert_eq!(workload.tenant_slug, "acme");
    assert_eq!(workload.service_name, "billing");
    assert!(workload.attributes.is_empty());
    // The agent was asked about this token, for this audience.
    assert_eq!(
        agent.validations(),
        [(AUDIENCE.to_owned(), "header.payload.signature".to_owned())]
    );
}

#[tokio::test(start_paused = true)]
async fn a_token_the_agent_refuses_is_not_authenticated() {
    let world = World::new();
    let agent = world.agent();
    // The method is not offered.
    assert!(matches!(
        within(resolver(&world, "example.org").resolve()).await,
        Err(IdentityError::NotAuthenticated)
    ));
    agent.refuse(WorkloadApiMethod::ValidateJwtSvid, 3, "token has expired");
    assert!(matches!(
        within(resolver(&world, "example.org").resolve()).await,
        Err(IdentityError::NotAuthenticated)
    ));
    assert_eq!(agent.calls(WorkloadApiMethod::ValidateJwtSvid), 2);
}

#[tokio::test(start_paused = true)]
async fn an_agent_that_cannot_be_reached_is_not_authenticated() {
    let world = World::new();
    assert!(matches!(
        within(resolver(&world, "example.org").resolve()).await,
        Err(IdentityError::NotAuthenticated)
    ));
}

#[tokio::test(start_paused = true)]
async fn a_token_of_another_trust_domain_is_refused_by_name() {
    let world = World::new();
    let agent = world.agent();
    // The agent validates the tokens of every trust domain it holds a
    // bundle for; admitting one is the resolver's decision.
    agent.accept_validations(
        "spiffe://partner.test/billing/acme",
        &claims(json!({ "sub": "spiffe://partner.test/billing/acme" })),
    );
    let outcome = within(resolver(&world, "example.org").resolve()).await;
    let Err(IdentityError::InvalidSpiffeId(text)) = outcome else {
        panic!("a federated token is refused where it was not admitted");
    };
    assert_eq!(
        text,
        "trust domain mismatch: expected example.org, presented partner.test"
    );
    // A resolver built for the partner's trust domain admits it.
    assert!(
        within(resolver(&world, "partner.test").resolve())
            .await
            .is_ok()
    );
}

#[tokio::test(start_paused = true)]
async fn a_spiffe_path_of_another_shape_is_refused() {
    let world = World::new();
    let agent = world.agent();
    for id in [
        "spiffe://example.org",
        "spiffe://example.org/billing",
        "spiffe://example.org/region/billing/acme",
    ] {
        agent.accept_validations(id, &claims(json!({ "sub": id })));
        assert!(
            matches!(
                within(resolver(&world, "example.org").resolve()).await,
                Err(IdentityError::InvalidSpiffeId(_))
            ),
            "{id} must be refused"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_tenant_the_registry_does_not_know_is_not_authenticated() {
    let world = World::new();
    let agent = world.agent();
    agent.accept_validations(
        "spiffe://example.org/billing/unknown",
        &claims(json!({ "sub": "spiffe://example.org/billing/unknown" })),
    );
    assert!(matches!(
        within(resolver(&world, "example.org").resolve()).await,
        Err(IdentityError::NotAuthenticated)
    ));
}

#[tokio::test(start_paused = true)]
async fn a_tid_claim_has_to_name_the_registrys_tenant() {
    let world = World::new();
    let agent = world.agent();

    agent.accept_validations(ID, &claims(json!({ "tid": tenant().to_string() })));
    assert!(
        within(resolver(&world, "example.org").resolve())
            .await
            .is_ok()
    );

    let other = TenantId::from_bytes([9u8; 16]);
    for tid in [json!(other.to_string()), json!("not a tenant id"), json!(7)] {
        agent.accept_validations(ID, &claims(json!({ "tid": tid })));
        assert!(matches!(
            within(resolver(&world, "example.org").resolve()).await,
            Err(IdentityError::NotAuthenticated)
        ));
    }
}

#[tokio::test(start_paused = true)]
async fn a_spiffe_id_that_is_not_of_the_platforms_shape_is_refused() {
    // The agent validates the token; the SPIFFE ID it names is valid and
    // has no service and tenant to read. The shape is read by
    // `WorkloadId::components`, as the in-process resolvers read it.
    for other in [
        "spiffe://example.org",
        "spiffe://example.org/billing",
        "spiffe://example.org/a/b/c",
    ] {
        let world = World::new();
        let agent = world.agent();
        agent.accept_validations(other, &claims(json!({ "sub": other })));
        let outcome = within(resolver(&world, "example.org").resolve()).await;
        let Err(IdentityError::InvalidSpiffeId(text)) = outcome else {
            panic!("{other} must be refused as not of the platform's shape");
        };
        assert_eq!(
            text,
            format!("SPIFFE path is not <service>/<tenant_slug>: {other}")
        );
    }
}
