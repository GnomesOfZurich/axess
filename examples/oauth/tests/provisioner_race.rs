//! Two first logins of one identity on a table without the in-process gate:
//! the call that loses the link race signs in as the winner's user, and the
//! user it created for itself is removed.

use axess::authn::{EntityState, IdentityAdmin, IdentityLookup, Tenant, TenantId, User, UserId};
use axess::federation::oauth::OAuthClaims;
use axess::testing::MockIdentityStore;
use axess::{Clock, SystemClock, SystemRng};
use axess_example_oauth::identities::FederatedIdentities;
use axess_example_oauth::provisioning::{Provisioner, Provisioning, TenantPolicy};
use std::sync::Arc;

/// A table whose link already belongs to another login: whoever asks gets
/// `winner` back, as a database `ON CONFLICT DO NOTHING` plus read would.
struct LostRace {
    winner: UserId,
}

impl FederatedIdentities for LostRace {
    async fn find(&self, _issuer: &str, _subject: &str) -> Option<UserId> {
        None
    }

    async fn link_if_absent(&self, _issuer: &str, _subject: &str, _user: UserId) -> UserId {
        self.winner
    }
}

fn claims() -> OAuthClaims {
    OAuthClaims {
        provider: "idp".into(),
        subject: "s-1".to_string(),
        email: None,
        email_verified: None,
        name: Some("Sam".to_string()),
        groups: vec![],
        roles: vec![],
        access_token: None,
        refresh_token: None,
        oidc_sid: None,
        nonce: None,
        id_token_hint: None,
        additional_claims: serde_json::json!({"iss": "https://idp.example"}),
        dpop_key: None,
    }
}

#[tokio::test]
async fn the_race_winner_is_the_user_returned_and_the_loser_is_removed() {
    let tenant = TenantId::new(&SystemRng);
    let identity = MockIdentityStore::new().with_tenant(
        Tenant::new(
            tenant.to_string(),
            "race",
            "Race tenant",
            EntityState::Active,
            UserId::system(),
            SystemClock.now(),
        )
        .expect("tenant"),
    );
    let winner = User::new(
        UserId::new(&SystemRng).to_string(),
        tenant.to_string(),
        "winner-login",
        "Winner",
        EntityState::Active,
        UserId::system(),
        SystemClock.now(),
    )
    .expect("user");
    identity.create_user(winner.clone()).await.expect("winner");

    let provisioner = Provisioner::new(
        identity.clone(),
        Arc::new(LostRace { winner: winner.id }),
        TenantPolicy {
            tenant,
            provisioning: Provisioning::JustInTime,
            require_verified_email: false,
        },
        Arc::new(SystemClock),
        Arc::new(SystemRng),
    );

    let resolution = provisioner.resolve(&claims()).await.expect("resolve");
    assert_eq!(resolution.user().id, winner.id, "signs in as the winner");
    assert!(
        identity
            .find_user("https://idp.example#s-1", &tenant)
            .await
            .expect("lookup")
            .is_none(),
        "the user the loser created is removed"
    );
}
