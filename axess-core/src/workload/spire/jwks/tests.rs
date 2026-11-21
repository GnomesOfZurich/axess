//! Key sets for `JwtVerifier`, filled from the agent's JWT bundles.

use std::sync::{Arc, RwLock};

use jsonwebtoken::jwk::JwkSet;
use serde_json::json;

use super::KeySets;
use crate::metrics::WorkloadCredentialKind;
use crate::workload::spire::proto::RawBundles;
use crate::workload::spire::test_support::{World, within};
use crate::workload::spire::{JwtBundleSet, SpireError};

fn trust_domain(name: &str) -> axess_identity::TrustDomain {
    axess_identity::TrustDomain::new(name).expect("a trust domain")
}

/// The `kid` of every key in the set.
fn key_ids(key_set: &Arc<RwLock<JwkSet>>) -> Vec<String> {
    key_set
        .read()
        .expect("the key set's lock")
        .keys
        .iter()
        .filter_map(|key| key.common.key_id.clone())
        .collect()
}

fn ec_key(kid: &str) -> serde_json::Value {
    json!({
        "kty": "EC",
        "kid": kid,
        "crv": "P-256",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    })
}

fn bundle(keys: &[serde_json::Value]) -> Vec<u8> {
    json!({ "keys": keys }).to_string().into_bytes()
}

#[tokio::test(start_paused = true)]
async fn a_key_set_follows_the_agents_bundles() {
    let world = World::new();
    let agent = world.agent();
    let source = world
        .client("example.org")
        .watch_jwt_bundles()
        .expect("inside a runtime");
    let own = trust_domain("example.org");

    // Asked for before the agent has answered: no keys, so nothing verifies.
    let key_set = source.key_set(&own);
    assert!(key_ids(&key_set).is_empty());

    agent.set_jwt_bundles(&[("example.org", bundle(&[ec_key("k1")]).as_slice())]);
    within(source.ready()).await;
    assert_eq!(key_ids(&key_set), ["k1"]);

    // The agent rotates: the new key is published beside the old one, then
    // the old one is withdrawn. The same key set shows each step.
    agent.set_jwt_bundles(&[(
        "example.org",
        bundle(&[ec_key("k1"), ec_key("k2")]).as_slice(),
    )]);
    within(source.updated(1)).await;
    assert_eq!(key_ids(&key_set), ["k1", "k2"]);

    agent.set_jwt_bundles(&[("example.org", bundle(&[ec_key("k2")]).as_slice())]);
    within(source.updated(2)).await;
    assert_eq!(key_ids(&key_set), ["k2"]);

    // Asking again gives the same set, not a copy that would go stale.
    assert!(Arc::ptr_eq(&key_set, &source.key_set(&own)));
}

#[tokio::test(start_paused = true)]
async fn a_federated_trust_domain_has_a_key_set_of_its_own() {
    let world = World::new();
    let agent = world.agent();
    agent.set_jwt_bundles(&[
        ("example.org", bundle(&[ec_key("own")]).as_slice()),
        (
            "spiffe://partner.test",
            bundle(&[ec_key("theirs")]).as_slice(),
        ),
    ]);
    let source = world
        .client("example.org")
        .watch_jwt_bundles()
        .expect("inside a runtime");
    within(source.ready()).await;

    // Asked for after the bundles arrived: filled at once.
    let own = source.key_set(&trust_domain("example.org"));
    let partner = source.key_set(&trust_domain("partner.test"));
    assert_eq!(key_ids(&own), ["own"]);
    assert_eq!(key_ids(&partner), ["theirs"]);
    assert!(!Arc::ptr_eq(&own, &partner));

    // The federation ends: the partner's keys are gone, the own stay.
    agent.set_jwt_bundles(&[("example.org", bundle(&[ec_key("own")]).as_slice())]);
    within(source.updated(1)).await;
    assert!(key_ids(&partner).is_empty());
    assert_eq!(key_ids(&own), ["own"]);

    // A trust domain the agent never served has no keys.
    assert!(key_ids(&source.key_set(&trust_domain("stranger.test"))).is_empty());
}

#[tokio::test(start_paused = true)]
async fn spiffe_use_values_do_not_reach_the_jose_library() {
    let world = World::new();
    let agent = world.agent();
    let mut for_tokens = ec_key("for-tokens");
    for_tokens["use"] = json!("jwt-svid");
    let mut for_certificates = ec_key("for-certificates");
    for_certificates["use"] = json!("x509-svid");
    let unreadable = json!({ "kty": "FUTURE", "kid": "unreadable" });
    agent.set_jwt_bundles(&[(
        "example.org",
        bundle(&[for_tokens, for_certificates, unreadable, ec_key("plain")]).as_slice(),
    )]);
    let source = world
        .client("example.org")
        .watch_jwt_bundles()
        .expect("inside a runtime");
    within(source.ready()).await;

    let key_set = source.key_set(&trust_domain("example.org"));
    // The X.509 key is not a token key, and the key of an unknown type is
    // left out without taking the others with it.
    assert_eq!(key_ids(&key_set), ["for-tokens", "plain"]);
    let keys = key_set.read().expect("the key set's lock");
    assert!(
        keys.keys
            .iter()
            .all(|key| key.common.public_key_use.is_none()),
        "a `use` of jwt-svid would make a verifier refuse the key"
    );
}

#[tokio::test(start_paused = true)]
async fn a_stale_bundle_set_leaves_its_key_sets_with_no_keys() {
    let world = World::new();
    let agent = world.agent();
    let served = [
        ("example.org", bundle(&[ec_key("own")])),
        ("partner.test", bundle(&[ec_key("theirs")])),
    ];
    let borrowed: Vec<(&str, &[u8])> = served
        .iter()
        .map(|(name, bundle)| (*name, bundle.as_slice()))
        .collect();
    agent.set_jwt_bundles(&borrowed);
    // The default maximum bundle age: one hour.
    let source = world
        .client("example.org")
        .watch_jwt_bundles()
        .expect("inside a runtime");
    within(source.ready()).await;
    let own = source.key_set(&trust_domain("example.org"));
    assert_eq!(key_ids(&own), ["own"]);

    // The agent goes away. For an hour the keys it last sent are verified
    // with.
    drop(agent);
    world.recorder.at_least(1, "failed:jwt_bundles").await;
    world.clock.advance_secs(3599);
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    assert_eq!(key_ids(&own), ["own"]);

    // Then nothing has confirmed them for the maximum bundle age: the
    // source refuses the set, and the key set a verifier holds is emptied.
    world.clock.advance_secs(1);
    assert_eq!(
        source.bundles().err(),
        Some(SpireError::Stale(WorkloadCredentialKind::JwtBundles))
    );
    world.recorder.at_least(1, "expired:jwt_bundles").await;
    assert!(key_ids(&own).is_empty());
    // A key set first asked for now is not made from the stale set.
    let partner = source.key_set(&trust_domain("partner.test"));
    assert!(key_ids(&partner).is_empty());

    // The agent returns with the same set: the keys return.
    let agent = world.agent();
    agent.set_jwt_bundles(&borrowed);
    assert_eq!(within(source.updated(2)).await, 3);
    assert_eq!(key_ids(&own), ["own"]);
    assert_eq!(key_ids(&partner), ["theirs"]);
}

/// A bundle set holding `keys` for each of `trust_domains`, read for a
/// workload of the first.
fn bundle_set(trust_domains: &[&str], keys: &[serde_json::Value]) -> Arc<JwtBundleSet> {
    let raw = RawBundles {
        crls: Vec::new(),
        bundles: trust_domains
            .iter()
            .map(|name| ((*name).to_owned(), bundle(keys)))
            .collect(),
    };
    let own = trust_domain(trust_domains[0]);
    Arc::new(JwtBundleSet::from_raw(raw, &own).expect("well-formed bundles"))
}

#[test]
fn cleared_key_sets_have_no_keys_until_the_next_bundle_set() {
    let key_sets = KeySets::default();
    let domains = ["example.org", "partner.test"];
    let own = key_sets.key_set(&trust_domain("example.org"));
    key_sets.replace(&bundle_set(&domains, &[ec_key("held")]));
    assert_eq!(key_ids(&own), ["held"]);

    key_sets.clear();
    assert!(key_ids(&own).is_empty());
    // Made after the clear: not from the set that was forgotten.
    let partner = key_sets.key_set(&trust_domain("partner.test"));
    assert!(key_ids(&partner).is_empty());

    key_sets.replace(&bundle_set(&domains, &[ec_key("next")]));
    assert_eq!(key_ids(&own), ["next"]);
    assert_eq!(key_ids(&partner), ["next"]);
}

/// The watcher stores each new bundle set while key sets are asked for. A
/// key set made at any point is made from the latest set stored, never from
/// one before it, so none is left with keys the agent has withdrawn.
#[test]
fn a_key_set_asked_for_between_two_bundle_sets_has_the_later_keys() {
    let key_sets = KeySets::default();
    let early = key_sets.key_set(&trust_domain("example.org"));
    assert!(key_ids(&early).is_empty(), "nothing stored yet");

    key_sets.replace(&bundle_set(
        &["example.org", "partner.test"],
        &[ec_key("old")],
    ));
    assert_eq!(key_ids(&early), ["old"]);
    key_sets.replace(&bundle_set(
        &["example.org", "partner.test"],
        &[ec_key("new")],
    ));
    // Asked for after the second set was stored, before anything else
    // happened: it has the second set's keys.
    let late = key_sets.key_set(&trust_domain("partner.test"));
    assert_eq!(key_ids(&late), ["new"]);
    assert_eq!(key_ids(&early), ["new"]);
}

/// The same, with the stores and the requests on two threads.
#[test]
fn key_sets_asked_for_while_bundle_sets_change_all_end_on_the_last() {
    const DOMAINS: usize = 32;
    const ROUNDS: usize = 64;
    let names: Vec<String> = (0..DOMAINS).map(|n| format!("td{n}.example")).collect();
    let borrowed: Vec<&str> = names.iter().map(String::as_str).collect();
    let sets: Vec<Arc<JwtBundleSet>> = (0..ROUNDS)
        .map(|round| bundle_set(&borrowed, &[ec_key(&format!("k{round}"))]))
        .collect();
    let key_sets = Arc::new(KeySets::default());

    let storing = {
        let key_sets = key_sets.clone();
        std::thread::spawn(move || {
            for set in &sets {
                key_sets.replace(set);
            }
        })
    };
    let made: Vec<_> = names
        .iter()
        .map(|name| key_sets.key_set(&trust_domain(name)))
        .collect();
    storing.join().expect("the storing thread");

    let last = format!("k{}", ROUNDS - 1);
    for key_set in &made {
        assert_eq!(key_ids(key_set), [last.as_str()]);
    }
}

/// The whole path: a token signed by the trust domain's authority verifies
/// through `JwtVerifier` and `JwtSvidResolver` on keys that came from the
/// agent, and stops verifying when the agent withdraws the key.
#[cfg(all(feature = "jwt-svid", feature = "local-idp"))]
mod verified {
    use std::sync::Arc;

    use axess_clock::SignedDuration;
    use axess_clock::testing::Shift;
    use axess_factors::jwt::svid::JwtSvidResolver;
    use axess_factors::jwt::verifier::JwtVerifier;
    use axess_identity::{IdentityError, Principal, PrincipalResolver, TenantId};

    use super::{trust_domain, within};
    use crate::local_idp::MintClaims;
    use crate::testing::local_idp::LocalIdpFixture;
    use crate::testing::spire_agent::FakeSpireAgent;
    use crate::workload::spire::JwtBundleSource;
    use crate::workload::spire::test_support::World;

    const AUDIENCE: &str = "https://api.example.org";

    /// A trust domain's JWT authority, standing in for a SPIRE server.
    struct Authority {
        idp: LocalIdpFixture,
        tenant: TenantId,
    }

    impl Authority {
        fn new(world: &World, issuer: &str) -> Self {
            Self {
                idp: LocalIdpFixture::new(issuer).with_clock(world.clock.clone()),
                tenant: TenantId::from_bytes([7u8; 16]),
            }
        }

        /// The authority's keys as a SPIFFE bundle marks them.
        fn bundle(&self) -> Vec<u8> {
            let mut document: serde_json::Value =
                serde_json::from_str(&self.idp.jwks_json()).expect("the fixture's JWKS");
            for key in document["keys"].as_array_mut().expect("a keys array") {
                key["use"] = serde_json::json!("jwt-svid");
            }
            document.to_string().into_bytes()
        }

        /// A JWT SVID for `spiffe_id`, valid for five minutes.
        fn svid(&self, world: &World, spiffe_id: &str) -> String {
            let now = axess_clock::Clock::now(&world.clock);
            let claims = MintClaims::new(spiffe_id, now.plus(SignedDuration::minutes(5)))
                .with_audience(AUDIENCE)
                .with_issued_at(now)
                .with_custom_claim("tid", serde_json::json!(self.tenant.to_string()));
            self.idp.mint_at(&claims, now)
        }

        fn verifier(
            &self,
            world: &World,
            source: &JwtBundleSource,
            domain: &str,
        ) -> Arc<JwtVerifier> {
            Arc::new(
                JwtVerifier::new(source.key_set(&trust_domain(domain)))
                    .with_issuer(self.idp.issuer())
                    .with_audience(AUDIENCE)
                    .with_algorithms(self.idp.verifier_algorithms())
                    .with_clock(Arc::new(world.clock.clone())),
            )
        }
    }

    async fn resolve(
        verifier: &Arc<JwtVerifier>,
        domain: &str,
        token: &str,
    ) -> Result<Principal, IdentityError> {
        JwtSvidResolver::new(verifier.clone(), trust_domain(domain), token)
            .without_tenant_cross_check()
            .resolve()
            .await
    }

    fn serve(agent: &FakeSpireAgent, bundles: &[(&str, &Authority)]) {
        let served: Vec<(&str, Vec<u8>)> = bundles
            .iter()
            .map(|(domain, authority)| (*domain, authority.bundle()))
            .collect();
        let borrowed: Vec<(&str, &[u8])> = served
            .iter()
            .map(|(domain, bundle)| (*domain, bundle.as_slice()))
            .collect();
        agent.set_jwt_bundles(&borrowed);
    }

    #[tokio::test(start_paused = true)]
    async fn a_token_verifies_on_the_agents_keys_until_they_are_withdrawn() {
        let world = World::new();
        let agent = world.agent();
        let authority = Authority::new(&world, "https://spire.example.org");
        serve(&agent, &[("example.org", &authority)]);
        let source = world
            .client("example.org")
            .watch_jwt_bundles()
            .expect("inside a runtime");
        within(source.ready()).await;
        let verifier = authority.verifier(&world, &source, "example.org");

        let token = authority.svid(&world, "spiffe://example.org/billing/acme");
        let principal = resolve(&verifier, "example.org", &token)
            .await
            .expect("a token signed by the trust domain's authority");
        let Principal::Workload(workload) = principal else {
            panic!("a JWT SVID resolves to a workload");
        };
        assert_eq!(
            workload.workload_id.as_str(),
            "spiffe://example.org/billing/acme"
        );
        assert_eq!(workload.tenant_id, authority.tenant);

        // The authority's key is replaced: the same verifier, built once,
        // refuses the old token and accepts one signed with the new key.
        let rotated = Authority::new(&world, "https://spire.example.org");
        serve(&agent, &[("example.org", &rotated)]);
        within(source.updated(1)).await;
        assert!(matches!(
            resolve(&verifier, "example.org", &token).await,
            Err(IdentityError::NotAuthenticated)
        ));
        let renewed = rotated.svid(&world, "spiffe://example.org/billing/acme");
        assert!(resolve(&verifier, "example.org", &renewed).await.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn a_token_stops_verifying_once_the_keys_are_stale() {
        let world = World::new();
        let agent = world.agent();
        let authority = Authority::new(&world, "https://spire.example.org");
        serve(&agent, &[("example.org", &authority)]);
        // The default maximum bundle age: one hour.
        let source = world
            .client("example.org")
            .watch_jwt_bundles()
            .expect("inside a runtime");
        within(source.ready()).await;
        let verifier = authority.verifier(&world, &source, "example.org");
        let id = "spiffe://example.org/billing/acme";

        // The agent goes away. A token minted just short of an hour later
        // verifies on the keys the agent last sent.
        drop(agent);
        world.recorder.at_least(1, "failed:jwt_bundles").await;
        world.clock.advance_secs(3599);
        let token = authority.svid(&world, id);
        assert!(resolve(&verifier, "example.org", &token).await.is_ok());

        // At the hour nothing has confirmed those keys, and the same
        // verifier refuses a token signed with them.
        world.clock.advance_secs(1);
        world.recorder.at_least(1, "expired:jwt_bundles").await;
        let token = authority.svid(&world, id);
        assert!(matches!(
            resolve(&verifier, "example.org", &token).await,
            Err(IdentityError::NotAuthenticated)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn a_federated_token_verifies_only_on_its_own_trust_domains_keys() {
        let world = World::new();
        let agent = world.agent();
        let own = Authority::new(&world, "https://spire.example.org");
        let partner = Authority::new(&world, "https://spire.partner.test");
        serve(
            &agent,
            &[("example.org", &own), ("spiffe://partner.test", &partner)],
        );
        let source = world
            .client("example.org")
            .watch_jwt_bundles()
            .expect("inside a runtime");
        within(source.ready()).await;
        let own_verifier = own.verifier(&world, &source, "example.org");
        let partner_verifier = partner.verifier(&world, &source, "partner.test");

        let theirs = partner.svid(&world, "spiffe://partner.test/billing/acme");
        assert!(
            resolve(&partner_verifier, "partner.test", &theirs)
                .await
                .is_ok()
        );
        // The partner's token is not signed by a key of example.org.
        assert!(matches!(
            resolve(&own_verifier, "example.org", &theirs).await,
            Err(IdentityError::NotAuthenticated)
        ));
        // The partner's authority cannot speak for example.org: a token it
        // signs for a name there finds no key in example.org's set.
        let forged = partner.svid(&world, "spiffe://example.org/billing/acme");
        assert!(matches!(
            resolve(&own_verifier, "example.org", &forged).await,
            Err(IdentityError::NotAuthenticated)
        ));
        // And on its own keys the forged token names another trust domain.
        assert!(matches!(
            resolve(&partner_verifier, "partner.test", &forged).await,
            Err(IdentityError::InvalidSpiffeId(_))
        ));
    }
}
