//! The audit rows of an OAuth token revocation through a session's or a
//! tenant's scope: what is written before the identity provider is asked,
//! what follows its answer, and what a store that cannot take a row does to
//! the call.
//!
//! Run with: `cargo test -p axess-core --features testing,oauth,jwt-aws-lc --test oauth_tenant_world revocation_audit`

use super::world::*;
use axess_core::authn::AuditContext;
use axess_core::authn::event::{AuthEvent, AuthEventStatus, AuthEventType};
use axess_core::authn::factor::{FactorKind, FederatedProvider};
use axess_core::authn::service::OAUTH_REVOCATION_REQUESTED_REASON;
use axess_core::testing::mock_authn::MockIdentityStore;
use axess_factors::oauth::OAuthError;
use serde_json::json;
use wiremock::{
    Mock, Request, Respond, ResponseTemplate,
    matchers::{method, path},
};

fn revocation_rows(identity: &MockIdentityStore) -> Vec<AuthEvent> {
    identity
        .events()
        .into_iter()
        .filter(|e| {
            e.event_type == AuthEventType::LogoutAttempt
                && e.factor_kind
                    == Some(FactorKind::Federated(FederatedProvider::Custom(
                        "sso".into(),
                    )))
        })
        .collect()
}

fn reason(row: &AuthEvent) -> &str {
    row.error.as_ref().map_or("", |e| e.as_str())
}

/// The request row, then one outcome row of `status` whose reason starts
/// with `outcome` (empty for a success), both under one `request_id`.
fn assert_request_then_outcome(rows: &[AuthEvent], status: AuthEventStatus, outcome: &str) {
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0].event_status, AuthEventStatus::Failure, "{rows:?}");
    assert_eq!(reason(&rows[0]), OAUTH_REVOCATION_REQUESTED_REASON);
    assert_eq!(rows[1].event_status, status, "{rows:?}");
    assert!(reason(&rows[1]).starts_with(outcome), "{rows:?}");
    assert!(rows[0].request_id.is_some(), "{rows:?}");
    assert_eq!(rows[0].request_id, rows[1].request_id, "paired");
}

async fn revoke(w: &World, login: &Login) -> Result<(), OAuthError> {
    w.authn
        .oauth_for_session(&login.session)
        .await
        .revoke_oauth_token("sso", "refresh-from-acme", Some("refresh_token"), None)
        .await
}

/// Answer the next revocation at `idp` with `status`.
async fn revocation_answers(idp: &Idp, response: impl Respond + 'static) {
    idp.server.reset().await;
    Mock::given(method("POST"))
        .and(path("/revoke"))
        .respond_with(response)
        .mount(&idp.server)
        .await;
}

/// The request row is written before the identity provider is asked, so a
/// store that cannot take it fails the revocation with nothing sent.
#[tokio::test]
async fn a_revocation_whose_request_row_cannot_be_written_sends_nothing() {
    let w = world().await;
    let a = tenant_login(&w.authn, &w.acme, "acme", "alice").await;
    w.identity.arm_record_event_failure();

    let err = revoke(&w, &a)
        .await
        .expect_err("a revocation nobody can account for is refused");

    assert!(matches!(err, OAuthError::AuditStore(_)), "{err:?}");
    assert!(
        w.acme.calls().await.iter().all(|c| path_of(c) != "/revoke"),
        "the identity provider was asked to revoke a token the audit trail does not show"
    );
}

/// A revoked token: the request row, a `Failure` until its outcome says
/// otherwise, then a `Success` row under the same request id.
#[tokio::test]
async fn a_revoked_token_leaves_its_request_then_a_success() {
    let w = world().await;
    let a = tenant_login(&w.authn, &w.acme, "acme", "alice").await;

    revoke(&w, &a).await.expect("revoked");

    assert_request_then_outcome(&revocation_rows(&w.identity), AuthEventStatus::Success, "");
}

/// A refusal: the request row, then a failure row with the provider's
/// refusal, and the refusal is the answer.
#[tokio::test]
async fn a_refused_revocation_leaves_its_request_then_its_refusal() {
    let w = world().await;
    let a = tenant_login(&w.authn, &w.acme, "acme", "alice").await;
    revocation_answers(
        &w.acme,
        ResponseTemplate::new(400).set_body_json(json!({ "error": "invalid_request" })),
    )
    .await;

    let err = revoke(&w, &a).await.expect_err("the provider refused");

    assert!(matches!(err, OAuthError::TokenExchange(_)), "{err:?}");
    assert_request_then_outcome(
        &revocation_rows(&w.identity),
        AuthEventStatus::Failure,
        "oauth token revocation refused",
    );
}

/// A provider that does not answer may have revoked the token or not: the
/// outcome row says unconfirmed, not refused.
#[tokio::test]
async fn a_revocation_the_provider_does_not_answer_is_unconfirmed() {
    let w = world().await;
    let a = tenant_login(&w.authn, &w.acme, "acme", "alice").await;
    revocation_answers(&w.acme, ResponseTemplate::new(503)).await;

    let err = revoke(&w, &a).await.expect_err("no answer");

    assert!(
        matches!(err, OAuthError::TokenEndpointTransient { .. }),
        "{err:?}"
    );
    assert_request_then_outcome(
        &revocation_rows(&w.identity),
        AuthEventStatus::Failure,
        "oauth token revocation unconfirmed",
    );
}

/// Revokes the token, and arms the audit store's outage as it does, so the
/// outcome row is the one refused.
struct RevokesThenTheStoreFails(MockIdentityStore);

impl Respond for RevokesThenTheStoreFails {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        self.0.arm_record_event_failure();
        ResponseTemplate::new(200)
    }
}

/// An outcome row the store refuses after the provider revoked the token:
/// the call answers `AuditStore` and says the provider revoked it, and the
/// trail shows the request alone, a `Failure`, never a success.
#[tokio::test]
async fn an_outcome_row_refused_after_a_revocation_says_the_token_was_revoked() {
    let w = world().await;
    let a = tenant_login(&w.authn, &w.acme, "acme", "alice").await;
    revocation_answers(&w.acme, RevokesThenTheStoreFails(w.identity.clone())).await;

    let err = revoke(&w, &a).await.expect_err("the outcome is unrecorded");

    match &err {
        OAuthError::AuditStore(text) => {
            assert!(text.contains("the provider revoked the token"), "{text}")
        }
        other => panic!("expected AuditStore, got {other:?}"),
    }
    let rows = revocation_rows(&w.identity);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].event_status, AuthEventStatus::Failure);
    assert_eq!(reason(&rows[0]), OAUTH_REVOCATION_REQUESTED_REASON);
}

/// Two revocations with no request id in the audit context each draw their
/// own, so their rows pair up even when they interleave.
#[tokio::test]
async fn two_revocations_are_paired_by_their_own_request_ids() {
    let w = world().await;
    let a = tenant_login(&w.authn, &w.acme, "acme", "alice").await;

    let (first, second) = tokio::join!(revoke(&w, &a), revoke(&w, &a));
    first.expect("revoked");
    second.expect("revoked");

    let rows = revocation_rows(&w.identity);
    assert_eq!(rows.len(), 4, "{rows:?}");
    let mut ids: Vec<_> = rows.iter().map(|r| r.request_id.clone()).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 2, "two request ids, two rows each: {rows:?}");
    for id in &ids {
        let pair: Vec<_> = rows.iter().filter(|r| &r.request_id == id).collect();
        assert_eq!(
            pair.iter()
                .map(|r| r.event_status.clone())
                .collect::<Vec<_>>(),
            [AuthEventStatus::Failure, AuthEventStatus::Success],
            "{pair:?}"
        );
    }
}

/// A row the audit pipeline sheds counts as written: the sink chose to drop
/// it to protect its storage, the revocation goes ahead, and the shed is
/// counted where every shed event is.
#[tokio::test]
async fn a_shed_revocation_row_counts_as_written() {
    let w = world().await;
    let a = tenant_login(&w.authn, &w.acme, "acme", "alice").await;
    w.identity.arm_record_event_shedding();

    revoke(&w, &a)
        .await
        .expect("a shed row does not fail the revocation");

    assert_eq!(
        w.acme
            .calls()
            .await
            .iter()
            .filter(|c| path_of(c) == "/revoke")
            .count(),
        1
    );
    assert!(
        revocation_rows(&w.identity).is_empty(),
        "the rows were shed"
    );
}

/// Both rows carry the session id and the request id of the audit context,
/// as a context extracted behind the session layer has them.
#[tokio::test]
async fn the_revocation_rows_carry_the_session_and_request_ids_of_their_audit_context() {
    let w = world().await;
    let a = tenant_login(&w.authn, &w.acme, "acme", "alice").await;
    let session_id = a.session.session_key().await;
    let authn = w.authn.with_audit_context(AuditContext {
        session_id: Some(session_id),
        request_id: Some("req-7f3a".into()),
        ..AuditContext::default()
    });

    authn
        .oauth_for_session(&a.session)
        .await
        .revoke_oauth_token("sso", "refresh-from-acme", Some("refresh_token"), None)
        .await
        .expect("revoked");

    let rows = revocation_rows(&w.identity);
    assert_request_then_outcome(&rows, AuthEventStatus::Success, "");
    for row in &rows {
        assert_eq!(row.session_id, Some(session_id));
        assert_eq!(row.request_id.as_deref(), Some("req-7f3a"));
    }
}
