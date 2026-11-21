//! The callback route is compared with the registration a login began with:
//! two tenants each have a provider called `sso`, the global registration
//! has one of that name too, and a callback is finished only on the route of
//! the one the login began with. Every other route is refused before the
//! code is exchanged, so one authorization server's code is never posted to
//! another's token endpoint.
//!
//! The helpers that follow a login (refresh, userinfo, the logout URL, DPoP
//! proofs) are called on a scope, and each scope reaches its own
//! registration of the name and no other.
//!
//! Every IdP is a wiremock server on localhost.
//!
//! Run with: `cargo test -p axess-core --features testing,oauth,jwt-aws-lc --test oauth_tenant_world callback_route`

use super::world::*;
use axess_core::authn::AuditContext;
use axess_core::authn::event::{AuthEventStatus, AuthEventType};
use axess_core::authn::service::{AuthnService, OAuthCallbackRoute, ScopedOAuth};
use axess_core::federation::oauth_tenant::{
    MemoryTenantOAuthProviderStore, StoredTenantOAuthProviders,
};
use axess_core::session::extractor::AuthSession;
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use axess_factors::egress::EgressPolicy;
use axess_factors::oauth::{OAuthError, OAuthLoginOptions, OAuthProviderConfig};
use std::sync::Arc;

/// Three identity providers behind three providers of one name: acme's and
/// beta's own, and the global registration's.
struct Routes {
    acme: Idp,
    beta: Idp,
    global: Idp,
    authn: Authn,
    identity: MockIdentityStore,
}

impl Routes {
    fn idps(&self) -> [&Idp; 3] {
        [&self.acme, &self.beta, &self.global]
    }

    /// How many code exchanges each identity provider has seen: acme's,
    /// beta's, the global one's.
    async fn exchanges(&self) -> [usize; 3] {
        let mut seen = [0; 3];
        for (count, idp) in seen.iter_mut().zip(self.idps()) {
            *count = idp
                .calls()
                .await
                .iter()
                .filter(|(_, path)| path == "/token")
                .count();
        }
        seen
    }

    /// How many requests of `endpoint` each identity provider has seen:
    /// acme's, beta's, the global one's.
    async fn seen(&self, endpoint: &str) -> [usize; 3] {
        let mut seen = [0; 3];
        for (count, idp) in seen.iter_mut().zip(self.idps()) {
            *count = idp
                .calls()
                .await
                .iter()
                .filter(|(_, path)| path == endpoint)
                .count();
        }
        seen
    }

    /// The scope of each registration of `sso`, in the order of `idps`:
    /// acme's own, beta's own, the global one.
    fn scopes(&self) -> [ScopedOAuth<'_, MockIdentityStore, MockFactorStore>; 3] {
        [
            self.authn.oauth_in_tenant(&tenant("acme")),
            self.authn.oauth_in_tenant(&tenant("beta")),
            self.authn.oauth_global(),
        ]
    }

    fn mismatch_rows(&self) -> usize {
        self.identity
            .events()
            .iter()
            .filter(|e| {
                e.event_type == AuthEventType::LoginAttempt
                    && e.event_status == AuthEventStatus::Failure
                    && e.error.as_ref().map(|r| r.as_str()) == Some("provider_mismatch")
            })
            .count()
    }
}

async fn routes() -> Routes {
    let clock = frozen_clock();
    let acme = Idp::start("acme", "client-acme").await;
    let beta = Idp::start("beta", "client-beta").await;
    let global = Idp::start("global", "client-global").await;
    let loopback = EgressPolicy::screened_allowing_loopback_http();
    let directory: Arc<Directory> = Arc::new(
        StoredTenantOAuthProviders::new_unencrypted(
            MemoryTenantOAuthProviderStore::new(),
            axess_core::testing::oauth_tenant::ownership_assumed(),
        )
        .with_egress_policy(loopback)
        .with_clock(Arc::new(clock.clone())),
    );
    for (label, idp) in [("acme", &acme), ("beta", &beta)] {
        directory.upsert(record(tenant(label), idp)).await.unwrap();
    }
    let provider = OAuthProviderConfig::discover_screened(
        "sso",
        &global.issuer,
        &global.client_id,
        "s3cret",
        REDIRECT,
        loopback,
    )
    .await
    .unwrap()
    .with_clock(Arc::new(clock.clone()))
    .build()
    .unwrap();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(tenant_row("acme"))
        .with_tenant(tenant_row("beta"));
    let authn = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .with_tenant_oauth_providers(directory)
        .with_oauth_provider(provider)
        .build()
        .with_audit_context(AuditContext::default());
    Routes {
        acme,
        beta,
        global,
        authn,
        identity,
    }
}

/// The registration a login begins with.
#[derive(Debug, Clone, Copy)]
enum Begun {
    /// `begin_oauth_login`: the global registration.
    Global,
    /// `begin_oauth_login_in_tenant`: the global registration, with the
    /// completion bound to a tenant.
    GlobalBoundTo(&'static str),
    /// `begin_oauth_login_with_tenant_provider`: the tenant's own provider.
    TenantsOwn(&'static str),
}

/// Begin a login and have the identity provider it runs against answer the
/// code exchange, so a finish that is not refused succeeds. Returns the
/// session and the ceremony's `state`.
async fn begin(w: &Routes, begun: Begun) -> (AuthSession, String) {
    let session = test_session();
    let options = OAuthLoginOptions::default();
    let idp = match begun {
        Begun::Global => {
            w.authn
                .begin_oauth_login("sso", &options, &session)
                .await
                .expect("begin");
            &w.global
        }
        Begun::GlobalBoundTo(label) => {
            w.authn
                .begin_oauth_login_in_tenant("sso", &options, &tenant(label), &session)
                .await
                .expect("begin");
            &w.global
        }
        Begun::TenantsOwn(label) => {
            w.authn
                .begin_oauth_login_with_tenant_provider("sso", &options, &tenant(label), &session)
                .await
                .expect("begin");
            if label == "acme" { &w.acme } else { &w.beta }
        }
    };
    let (nonce, csrf) = nonce_and_csrf(&session).await;
    idp.issue(&nonce);
    (session, csrf)
}

/// A callback on any route but the one of the registration the login began
/// with is refused before the code is exchanged: another tenant's route for
/// a provider of the same name, the global route for a tenant's provider, a
/// tenant's route for the global provider (bound to that tenant or not), and
/// another provider name. Each refusal is a CSRF mismatch, is recorded as a
/// provider mismatch, clears the ceremony, and sends no token request to any
/// of the three identity providers. Every one of these finishes would
/// succeed were the route's tenant not compared: the identity provider the
/// ceremony runs against is ready to answer the exchange.
#[tokio::test]
async fn a_callback_on_another_registrations_route_is_refused_before_the_exchange() {
    let w = routes().await;
    let (acme, beta) = (tenant("acme"), tenant("beta"));
    let cases = [
        (
            Begun::TenantsOwn("acme"),
            OAuthCallbackRoute::of_tenant(&beta, "sso"),
        ),
        (Begun::TenantsOwn("acme"), OAuthCallbackRoute::global("sso")),
        (
            Begun::TenantsOwn("beta"),
            OAuthCallbackRoute::of_tenant(&acme, "sso"),
        ),
        (Begun::Global, OAuthCallbackRoute::of_tenant(&acme, "sso")),
        (
            Begun::GlobalBoundTo("acme"),
            OAuthCallbackRoute::of_tenant(&acme, "sso"),
        ),
        (
            Begun::GlobalBoundTo("acme"),
            OAuthCallbackRoute::of_tenant(&beta, "sso"),
        ),
        (
            Begun::TenantsOwn("acme"),
            OAuthCallbackRoute::of_tenant(&acme, "other"),
        ),
    ];

    for (n, (begun, route)) in cases.into_iter().enumerate() {
        let (session, csrf) = begin(&w, begun).await;

        let refused = w
            .authn
            .finish_oauth_login(route, "code-1", &csrf, None, &session)
            .await;

        assert!(
            matches!(refused, Err(OAuthError::CsrfMismatch)),
            "begun with {begun:?}, finished on {route:?}: {refused:?}"
        );
        assert_eq!(
            w.exchanges().await,
            [0, 0, 0],
            "begun with {begun:?}, finished on {route:?}: a code was exchanged"
        );
        assert!(
            session.get_custom("axess.oauth.csrf_state").await.is_none(),
            "begun with {begun:?}, finished on {route:?}: the ceremony stays"
        );
        assert_eq!(w.mismatch_rows(), n + 1, "one provider-mismatch row each");
    }
}

/// The same callbacks on the route of the registration the login began with
/// finish, each against its own identity provider and no other.
#[tokio::test]
async fn a_callback_on_the_route_the_login_began_with_finishes() {
    let w = routes().await;
    let (acme, beta) = (tenant("acme"), tenant("beta"));
    let cases = [
        (
            Begun::TenantsOwn("acme"),
            OAuthCallbackRoute::of_tenant(&acme, "sso"),
            0,
        ),
        (
            Begun::TenantsOwn("beta"),
            OAuthCallbackRoute::of_tenant(&beta, "sso"),
            1,
        ),
        (Begun::Global, OAuthCallbackRoute::global("sso"), 2),
        (
            Begun::GlobalBoundTo("acme"),
            OAuthCallbackRoute::global("sso"),
            2,
        ),
    ];

    for (begun, route, answered_by) in cases {
        let (session, csrf) = begin(&w, begun).await;
        let before = w.exchanges().await;

        let claims = w
            .authn
            .finish_oauth_login(route, "code-1", &csrf, None, &session)
            .await
            .unwrap_or_else(|e| panic!("begun with {begun:?}, finished on {route:?}: {e:?}"));

        let idp = w.idps()[answered_by];
        assert_eq!(
            claims.subject.as_str(),
            idp.subject(),
            "begun with {begun:?}"
        );
        let after = w.exchanges().await;
        for (at, (before, after)) in before.iter().zip(after).enumerate() {
            assert_eq!(
                after > *before,
                at == answered_by,
                "begun with {begun:?}: the exchange went to the wrong identity provider"
            );
        }
    }
    assert_eq!(w.mismatch_rows(), 0);
}

/// A tenant binding that does not read is never taken for no binding: the
/// callback is refused on the global route and on the tenant's alike, with
/// no code exchanged and the ceremony cleared.
#[tokio::test]
async fn a_tenant_binding_that_does_not_read_is_refused_on_every_route() {
    let w = routes().await;
    let acme = tenant("acme");
    for route in [
        OAuthCallbackRoute::global("sso"),
        OAuthCallbackRoute::of_tenant(&acme, "sso"),
    ] {
        let (session, csrf) = begin(&w, Begun::TenantsOwn("acme")).await;
        session
            .set_custom("axess.oauth.expected_tenant", serde_json::json!(7))
            .await;

        let refused = w
            .authn
            .finish_oauth_login(route, "code-1", &csrf, None, &session)
            .await;

        assert!(
            matches!(refused, Err(OAuthError::NoFlow)),
            "{route:?}: {refused:?}"
        );
        assert_eq!(w.exchanges().await, [0, 0, 0], "{route:?}");
        assert!(
            session.get_custom("axess.oauth.csrf_state").await.is_none(),
            "{route:?}: the ceremony stays"
        );
    }
}

// ── The helpers after the login ──────────────────────────────────────────────

/// Between `before` and `after`, the identity provider at `own` saw one
/// request and the other two saw none.
fn assert_only_its_own(own: usize, before: [usize; 3], after: [usize; 3], what: &str) {
    for (idp, (after, before)) in after.into_iter().zip(before).enumerate() {
        assert_eq!(
            after - before,
            usize::from(idp == own),
            "{what} under scope {own}: requests at identity provider {idp}"
        );
    }
}

/// A refresh token is the credential of one registration. Under each scope
/// it goes to that scope's token endpoint and to neither of the other two
/// providers of the same name.
#[tokio::test]
async fn a_refresh_goes_to_the_scopes_own_registration_and_no_other() {
    let w = routes().await;
    for (own, scope) in w.scopes().iter().enumerate() {
        let before = w.seen("/token").await;
        scope
            .refresh_oauth_token(
                "sso",
                "the-refresh-token",
                &w.idps()[own].subject(),
                None,
                None,
            )
            .await
            .expect("the scope's own registration answers");
        assert_only_its_own(own, before, w.seen("/token").await, "refresh");
    }
}

/// An access token goes to the userinfo endpoint of the scope's own
/// registration and to neither of the other two.
#[tokio::test]
async fn userinfo_is_asked_of_the_scopes_own_registration_and_no_other() {
    let w = routes().await;
    for (own, scope) in w.scopes().iter().enumerate() {
        let before = w.seen("/userinfo").await;
        let subject = w.idps()[own].subject();
        let info = scope
            .fetch_userinfo("sso", "the-access-token", &subject, None)
            .await
            .expect("the scope's own registration answers");
        assert_eq!(info.sub, subject);
        assert_only_its_own(own, before, w.seen("/userinfo").await, "userinfo");
    }
}

/// The logout URL is the end-session endpoint of the scope's own
/// registration, so the browser, with the ID token as a hint, is sent to
/// the identity provider that issued it.
#[tokio::test]
async fn the_logout_url_is_the_scopes_own_registrations() {
    let w = routes().await;
    for (own, scope) in w.scopes().iter().enumerate() {
        let url = scope
            .build_end_session_url("sso", Some("hint"), None, None)
            .await
            .expect("the scope resolves the provider")
            .expect("the provider has an end-session endpoint");
        for (idp, provider) in w.idps().into_iter().enumerate() {
            assert_eq!(
                url.as_str()
                    .starts_with(&format!("{}/logout", provider.issuer)),
                idp == own,
                "scope {own}, identity provider {idp}: {url}"
            );
        }
    }
}

/// A DPoP proof is signed for the provider the scope resolves. Each scope
/// that has a provider of the name signs one; a tenant with no provider of
/// the name is an unknown provider, and the global registration of that
/// name does not stand in for it.
#[tokio::test]
async fn a_dpop_proof_is_signed_for_the_scopes_own_registration_or_refused() {
    let w = routes().await;
    let key = w.authn.new_dpop_key();
    for (own, scope) in w.scopes().iter().enumerate() {
        scope
            .generate_dpop_proof("sso", &key, "GET", "https://rs.example/x", None)
            .await
            .unwrap_or_else(|e| panic!("scope {own} has a provider of the name: {e}"));
    }
    let refused = w
        .authn
        .oauth_in_tenant(&tenant("gamma"))
        .generate_dpop_proof("sso", &key, "GET", "https://rs.example/x", None)
        .await;
    assert!(
        matches!(refused, Err(OAuthError::UnknownProvider(_))),
        "a tenant with no provider of the name read another registration: {refused:?}"
    );
}
