//! The by-name OAuth helpers follow the login: a session logged in through a
//! tenant's provider refreshes, reads userinfo, revokes and builds its logout
//! URL against that tenant's IdP, and an IdP-initiated logout token ends the
//! session of the tenant whose issuer sent it.
//!
//! Two wiremock IdPs stand for two tenants' IdPs; both tenants call their
//! provider `sso`. Each IdP records the requests it receives, so every
//! assertion is about which IdP was reached.
//!
//! Run with: `cargo test -p axess-core --features testing,oauth,jwt-aws-lc --test oauth_tenant_world helpers`

use super::world::*;
use axess_core::authn::AuditContext;
use axess_core::authn::event::{AuthEventStatus, AuthEventType};
use axess_core::authn::service::{AuthnService, OAUTH_REVOCATION_REQUESTED_REASON};
use axess_core::federation::backchannel_logout::{BackChannelLogoutHandler, LogoutParams};
use axess_core::session::store::{SessionRegistry, SessionRegistryAdapter};
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use axess_factors::oauth::OAuthError;
use axum::extract::{Form, State};
use serde_json::json;
use std::sync::Arc;

// ── The helpers ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn two_tenants_refresh_each_against_their_own_issuer() {
    let w = world().await;
    let a = tenant_login(&w.authn, &w.acme, "acme", "alice").await;
    let b = tenant_login(&w.authn, &w.beta, "beta", "bob").await;

    let refreshed_a = w
        .authn
        .oauth_for_session(&a.session)
        .await
        .refresh_oauth_token(
            "sso",
            "refresh-from-acme",
            &w.acme.subject(),
            a.nonce(),
            None,
        )
        .await
        .expect("acme refresh");
    let refreshed_b = w
        .authn
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

    assert_eq!(&*refreshed_a.refresh_token, "refresh-from-acme");
    assert_eq!(&*refreshed_b.refresh_token, "refresh-from-beta");
    // Each IdP saw its own refresh grant and no other.
    for (idp, token) in [
        (&w.acme, "refresh-from-acme"),
        (&w.beta, "refresh-from-beta"),
    ] {
        let calls = idp.calls().await;
        assert_eq!(
            calls.iter().filter(|c| path_of(c) == "/token").count(),
            2,
            "one code exchange and one refresh at {}",
            idp.label
        );
        let form = idp.form_of_last("/token").await;
        assert!(form.contains(&("grant_type".into(), "refresh_token".into())));
        assert!(form.contains(&("refresh_token".into(), token.into())));
    }
}

#[tokio::test]
async fn two_tenants_read_userinfo_each_from_their_own_issuer() {
    let w = world().await;
    let a = tenant_login(&w.authn, &w.acme, "acme", "alice").await;
    let b = tenant_login(&w.authn, &w.beta, "beta", "bob").await;

    let info_a = w
        .authn
        .oauth_for_session(&a.session)
        .await
        .fetch_userinfo("sso", "access-from-acme", &w.acme.subject(), None)
        .await
        .expect("acme userinfo");
    let info_b = w
        .authn
        .oauth_for_session(&b.session)
        .await
        .fetch_userinfo("sso", "access-from-beta", &w.beta.subject(), None)
        .await
        .expect("beta userinfo");

    assert_eq!(info_a.sub, w.acme.subject());
    assert_eq!(info_b.sub, w.beta.subject());
    for idp in [&w.acme, &w.beta] {
        let calls = idp.calls().await;
        assert_eq!(
            calls.iter().filter(|c| path_of(c) == "/userinfo").count(),
            1,
            "{}",
            idp.label
        );
    }
}

#[tokio::test]
async fn two_tenants_revoke_each_at_their_own_issuer() {
    let w = world().await;
    let a = tenant_login(&w.authn, &w.acme, "acme", "alice").await;
    let b = tenant_login(&w.authn, &w.beta, "beta", "bob").await;

    w.authn
        .oauth_for_session(&a.session)
        .await
        .revoke_oauth_token("sso", "refresh-from-acme", Some("refresh_token"), None)
        .await
        .expect("acme revoke");
    w.authn
        .oauth_for_session(&b.session)
        .await
        .revoke_oauth_token("sso", "refresh-from-beta", Some("refresh_token"), None)
        .await
        .expect("beta revoke");

    for (idp, token) in [
        (&w.acme, "refresh-from-acme"),
        (&w.beta, "refresh-from-beta"),
    ] {
        let calls = idp.calls().await;
        assert_eq!(calls.iter().filter(|c| path_of(c) == "/revoke").count(), 1);
        let form = idp.form_of_last("/revoke").await;
        assert!(form.contains(&("token".into(), token.into())), "{form:?}");
    }

    // Each revocation is accounted for: a logout row of the tenant, naming
    // the provider and the session's user.
    use axess_core::authn::event::{AuthEventStatus, AuthEventType};
    use axess_core::authn::factor::{FactorKind, FederatedProvider};
    let revocations: Vec<_> = w
        .identity
        .events()
        .into_iter()
        .filter(|e| {
            e.event_type == AuthEventType::LogoutAttempt
                && e.factor_kind
                    == Some(FactorKind::Federated(FederatedProvider::Custom(
                        "sso".into(),
                    )))
        })
        .collect();
    assert_eq!(
        revocations.len(),
        4,
        "a request row and an outcome row per revocation: {revocations:?}"
    );
    for (rows, login, tenant_label) in [
        (&revocations[..2], &a, "acme"),
        (&revocations[2..], &b, "beta"),
    ] {
        assert_eq!(rows[1].event_status, AuthEventStatus::Success);
        for row in rows {
            assert_eq!(row.tenant_id, Some(tenant(tenant_label)));
            assert_eq!(row.user_id, Some(login.user.id));
        }
    }
}

#[tokio::test]
async fn two_tenants_get_the_logout_url_of_their_own_issuer() {
    let w = world().await;
    let a = tenant_login(&w.authn, &w.acme, "acme", "alice").await;
    let b = tenant_login(&w.authn, &w.beta, "beta", "bob").await;

    let url_a = w
        .authn
        .oauth_for_session(&a.session)
        .await
        .build_end_session_url("sso", Some("hint"), None, None)
        .await
        .expect("resolves")
        .expect("acme advertises an end-session endpoint");
    let url_b = w
        .authn
        .oauth_for_session(&b.session)
        .await
        .build_end_session_url("sso", Some("hint"), None, None)
        .await
        .expect("resolves")
        .expect("beta advertises an end-session endpoint");

    assert_eq!(
        url_a.origin(),
        url::Url::parse(&w.acme.issuer).unwrap().origin()
    );
    assert_eq!(
        url_b.origin(),
        url::Url::parse(&w.beta.issuer).unwrap().origin()
    );
    assert_ne!(url_a.origin(), url_b.origin());

    // With no session, the tenant alone says the same.
    let by_tenant = w
        .authn
        .oauth_in_tenant(&tenant("beta"))
        .build_end_session_url("sso", Some("hint"), None, None)
        .await
        .expect("resolves")
        .expect("an end-session endpoint");
    assert_eq!(by_tenant.origin(), url_b.origin());
}

#[tokio::test]
async fn a_tenant_scope_never_reaches_another_tenants_provider_or_the_global_map() {
    let w = world().await;
    tenant_login(&w.authn, &w.acme, "acme", "alice").await;
    // A tenant with no provider of that name.
    let none = w
        .authn
        .oauth_in_tenant(&tenant("gamma"))
        .revoke_oauth_token("sso", "t", None, None)
        .await;
    assert!(
        matches!(none, Err(OAuthError::UnknownProvider(_))),
        "{none:?}"
    );
    // The global scope reads the global registration only.
    let global = w
        .authn
        .oauth_global()
        .revoke_oauth_token("sso", "t", None, None)
        .await;
    assert!(
        matches!(global, Err(OAuthError::UnknownProvider(_))),
        "{global:?}"
    );
    assert!(w.acme.calls().await.iter().all(|c| path_of(c) != "/revoke"));
}

#[tokio::test]
async fn a_session_with_no_tenant_login_reads_the_global_registration() {
    let clock = super::world::frozen_clock();
    let idp = Idp::start("solo", "client-solo").await;
    let provider = axess_factors::oauth::OAuthProviderConfig::discover_screened(
        "sso",
        &idp.issuer,
        &idp.client_id,
        "s3cret",
        REDIRECT,
        axess_factors::egress::EgressPolicy::screened_allowing_loopback_http(),
    )
    .await
    .unwrap()
    .with_clock(Arc::new(clock.clone()))
    .build()
    .unwrap();
    let identity = MockIdentityStore::new().with_clock(clock.clone());
    let authn = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .with_oauth_provider(provider)
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();

    // No login at all: the scope is the global registration, and the answer
    // is the one the global scope gives.
    let scoped = authn.oauth_for_session(&session).await;
    assert!(scoped.tenant().is_none());
    scoped
        .revoke_oauth_token("sso", "t1", None, None)
        .await
        .expect("scoped, global");
    let global = authn.oauth_global();
    assert!(global.tenant().is_none());
    assert!(!global.is_refused());
    global
        .revoke_oauth_token("sso", "t2", None, None)
        .await
        .expect("the global scope");
    assert_eq!(
        idp.calls()
            .await
            .iter()
            .filter(|c| path_of(c) == "/revoke")
            .count(),
        2
    );

    // Each revocation is recorded as a request row and an outcome row. The
    // global scope names no user and no tenant on its own.
    let rows: Vec<_> = identity
        .events()
        .into_iter()
        .filter(|e| e.event_type == AuthEventType::LogoutAttempt)
        .collect();
    assert_eq!(rows.len(), 4, "{rows:?}");
    let (request, outcome) = (&rows[2], &rows[3]);
    assert_eq!(request.event_status, AuthEventStatus::Failure);
    assert_eq!(
        request.error.as_ref().map(|e| e.as_str()),
        Some(OAUTH_REVOCATION_REQUESTED_REASON)
    );
    assert_eq!(outcome.event_status, AuthEventStatus::Success);
    assert_eq!(request.request_id, outcome.request_id);
    for row in [request, outcome] {
        assert!(row.user_id.is_none() && row.tenant_id.is_none(), "{row:?}");
    }
}

// ── Back-channel logout ──────────────────────────────────────────────────────

async fn post_logout(handler: &BackChannelLogoutHandler, token: String) -> u16 {
    use axum::response::IntoResponse;
    BackChannelLogoutHandler::handle_backchannel_logout(
        State(handler.clone()),
        Form(LogoutParams {
            logout_token: token,
        }),
    )
    .await
    .into_response()
    .status()
    .as_u16()
}

#[tokio::test]
async fn a_logout_token_from_tenant_bs_issuer_ends_only_tenant_bs_session() {
    let w = world().await;
    let a = tenant_login(&w.authn, &w.acme, "acme", "alice").await;
    let b = tenant_login(&w.authn, &w.beta, "beta", "bob").await;
    let sid_a = a.session.session_key().await;
    let sid_b = b.session.session_key().await;
    assert!(w.registry.is_valid(&a.user.id, &sid_a).await.unwrap());
    assert!(w.registry.is_valid(&b.user.id, &sid_b).await.unwrap());

    let handler = BackChannelLogoutHandler::for_tenants(
        w.authn.tenant_oauth_providers().expect("configured"),
        Arc::new(SessionRegistryAdapter(w.registry.clone())),
        w.authn.sid_map(),
        Arc::new(w.clock.clone()),
    );

    // The same `sid` at both IdPs; B's token ends B's session alone.
    assert_eq!(
        post_logout(&handler, w.beta.logout_token("jb-1")).await,
        200
    );
    assert!(
        !w.registry.is_valid(&b.user.id, &sid_b).await.unwrap(),
        "tenant B's session ended"
    );
    assert!(
        w.registry.is_valid(&a.user.id, &sid_a).await.unwrap(),
        "tenant A's session stands"
    );

    // A token signed by B's key but naming A's issuer does not verify.
    let forged = w.beta.sign(&json!({
        "iss": w.acme.issuer, "aud": w.acme.client_id,
        "iat": t0().unix_seconds(),
        "exp": t0().unix_seconds() + 120, "jti": "forged", "sid": SID,
        "events": { "http://schemas.openid.net/event/backchannel-logout": {} },
    }));
    assert_eq!(post_logout(&handler, forged).await, 400);
    assert!(w.registry.is_valid(&a.user.id, &sid_a).await.unwrap());

    // A's own token ends A's.
    assert_eq!(
        post_logout(&handler, w.acme.logout_token("ja-1")).await,
        200
    );
    assert!(!w.registry.is_valid(&a.user.id, &sid_a).await.unwrap());
}
