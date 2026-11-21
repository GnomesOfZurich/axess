//! The kind a tenant's provider is configured with is what every login
//! through it records: beta's provider is configured as
//! `FederatedProvider::Microsoft`, acme's names no kind and records
//! `Custom("sso")`, on the login's rows, the session's assurance, a refused
//! callback, a refresh and a revocation.
//!
//! Run with: `cargo test -p axess-core --features testing,oauth,jwt-aws-lc --test oauth_tenant_world provider_kind`

use super::world::*;
use axess_core::authn::event::{AuthEventType, AuthFailureReason};
use axess_core::authn::factor::{FactorKind, FederatedProvider};
use axess_core::authn::service::OAuthCallbackRoute;
use axess_core::testing::test_session;
use axess_factors::oauth::OAuthLoginOptions;

fn configured() -> FederatedProvider {
    FederatedProvider::Microsoft
}

fn unnamed() -> FederatedProvider {
    FederatedProvider::Custom("sso".into())
}

/// The kinds the rows of `tenant_label` name, in the order written.
fn kinds_of(w: &World, tenant_label: &str) -> Vec<(AuthEventType, FederatedProvider)> {
    w.identity
        .events()
        .into_iter()
        .filter(|row| row.tenant_id == Some(tenant(tenant_label)))
        .filter_map(|row| match row.factor_kind {
            Some(FactorKind::Federated(kind)) => Some((row.event_type, kind)),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn every_row_and_the_assurance_of_a_tenant_login_record_the_configured_kind() {
    let w = world_with_beta_kind(Some(configured())).await;
    let a = tenant_login(&w.authn, &w.acme, "acme", "alice").await;
    let b = tenant_login(&w.authn, &w.beta, "beta", "bob").await;

    for (login, kind) in [(&a, unnamed()), (&b, configured())] {
        let assurance = login.session.assurance().await;
        assert_eq!(assurance.len(), 1, "{assurance:?}");
        assert_eq!(assurance[0].kind, FactorKind::Federated(kind));
    }

    w.authn
        .oauth_for_session(&b.session)
        .await
        .refresh_oauth_token(
            "sso",
            "refresh-from-beta",
            &w.beta.subject(),
            b.nonce(),
            None,
        )
        .await
        .expect("beta refresh");
    w.authn
        .oauth_for_session(&b.session)
        .await
        .revoke_oauth_token("sso", "refresh-from-beta", Some("refresh_token"), None)
        .await
        .expect("beta revocation");

    let beta = kinds_of(&w, "beta");
    let types: Vec<_> = beta.iter().map(|(t, _)| t.clone()).collect();
    assert_eq!(
        types,
        vec![
            AuthEventType::LoginAttempt,
            AuthEventType::Authenticated,
            AuthEventType::LoginAttempt,
            AuthEventType::LogoutAttempt,
            AuthEventType::LogoutAttempt,
        ],
        "the finish, the login, the refresh and the revocation's two rows: {beta:?}"
    );
    assert!(
        beta.iter().all(|(_, kind)| *kind == configured()),
        "{beta:?}"
    );

    let acme = kinds_of(&w, "acme");
    assert_eq!(acme.len(), 2, "{acme:?}");
    assert!(acme.iter().all(|(_, kind)| *kind == unnamed()), "{acme:?}");
}

#[tokio::test]
async fn a_refused_callback_records_the_configured_kind() {
    let w = world_with_beta_kind(Some(configured())).await;
    let session = test_session();
    w.authn
        .begin_oauth_login_with_tenant_provider(
            "sso",
            &OAuthLoginOptions::default(),
            &tenant("beta"),
            &session,
        )
        .await
        .expect("begin");
    w.authn
        .finish_oauth_login(
            OAuthCallbackRoute::of_tenant(&tenant("beta"), "sso"),
            "code-1",
            "not-the-state",
            None,
            &session,
        )
        .await
        .expect_err("the state does not match");

    let refused: Vec<_> = w
        .identity
        .events()
        .into_iter()
        .filter(|row| row.error == Some(AuthFailureReason::CsrfMismatch))
        .collect();
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(
        refused[0].factor_kind,
        Some(FactorKind::Federated(configured()))
    );
}
