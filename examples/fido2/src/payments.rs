//! The action that needs more than a login: approving a payment, the Cedar
//! policy that says what it needs, and the step-up a refusal asks for.
//!
//! The flow is three requests. The page asks to approve; the gate answers
//! `403 {"error": "step_up_required", "step_up": "passkey"}`; the page
//! begins that step-up, has the authenticator sign its challenge, finishes
//! it, and asks again. The name travels through the browser and back, and
//! nothing rests on it: the second request is decided by the policy again,
//! on what the step-up actually proved.

use axess::AuthSession;
use axess::authn::{AuditContext, FactorCredential, FactorOutcome, PrepareOutcome, StepUp};
use axess::authz::{AuthzError, RequestEntityProvider, merge_assurance_schema};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use cedar_policy::{Entities, EntityUid};
use serde::Deserialize;
use webauthn_rs::prelude::PublicKeyCredential;

use crate::app::AppState;
use crate::reply;

/// The Cedar namespace of the example's one action.
pub(crate) const NAMESPACE: &str = "Bank";

/// The policy: a payment is approved on a FIDO2 assertion that verified the
/// user within the last five minutes, and `@step_up("passkey")` names the
/// step-up that yields one.
pub(crate) const POLICY: &str = include_str!("../policies/payments.cedar");

/// The schema the policy validates against. `assurance` is a required
/// attribute of the action's context, so a request whose context provider
/// left it out is invalid and denied, never permitted by its absence.
pub(crate) fn schema() -> Result<String, AuthzError> {
    let mut schema = serde_json::json!({
        NAMESPACE: {
            "entityTypes": { "User": {}, "Payment": {} },
            "actions": {
                "ApprovePayment": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["Payment"],
                        "context": {
                            "type": "Record",
                            "attributes": { "assurance": { "type": "AxessAssurance" } }
                        }
                    }
                }
            }
        }
    });
    merge_assurance_schema(&mut schema, NAMESPACE)?;
    Ok(schema.to_string())
}

/// The policy reads the context alone, so no entity is needed to decide it.
/// An application whose policies name roles or owners builds them here.
pub(crate) struct NoEntities;

impl RequestEntityProvider for NoEntities {
    fn entities_for<'a>(
        &'a self,
        session: &'a AuthSession,
        principal: &'a EntityUid,
        resource: &'a EntityUid,
        action: &'a EntityUid,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Entities, AuthzError>> + Send + 'a>,
    > {
        let _ = session;
        tracing::trace!(%principal, %action, %resource, "no entities for the request");
        Box::pin(async { Ok(Entities::empty()) })
    }
}

/// Approve a payment. The route's `require_authz!` gate has already asked
/// the policy, so a request that reaches this handler is permitted.
pub(crate) async fn approve(Path(id): Path<String>) -> Response {
    Json(serde_json::json!({ "approved": id })).into_response()
}

#[derive(Deserialize)]
pub(crate) struct StepUpRequest {
    /// The `step_up` field of the refusal, as the page received it.
    step_up: String,
}

/// Begin the step-up a refusal named and answer with what the page must
/// collect: a FIDO2 challenge for the authenticator, or a password.
///
/// Beginning a step-up moves the session out of `Authenticated` until the
/// factor is verified, so a user who abandons it is signed out of
/// everything but the step itself. Two things here soften that. A step-up
/// already open (the user dismissed the browser's dialog and tried again)
/// is prepared again and not begun twice. And a FIDO2 step-up that none of
/// the user's credentials can answer is refused before the session moves.
///
/// The route acts on a step-up only. A login in progress is also a session
/// waiting for a factor, and its first step takes the password: a request
/// that arrives here with one open ends it and is refused.
pub(crate) async fn step_up_begin(
    State(state): State<AppState>,
    session: AuthSession,
    audit: AuditContext,
    Json(request): Json<StepUpRequest>,
) -> Response {
    let service = state.authn.with_audit_context(audit);
    if !session.step_up_pending().await {
        if let Some(refusal) = refuse_an_open_login(&session).await {
            return refusal;
        }
        let Ok(step_up) = request.step_up.parse::<StepUp>() else {
            return reply::refuse(StatusCode::BAD_REQUEST, "unknown_step_up");
        };
        let Some(user) = state.current_user(&session).await else {
            return reply::not_authenticated();
        };
        if let Some(ceremony) = step_up.fido2_ceremony() {
            let credentials = match state.authn.list_fido2_credentials(&user).await {
                Ok(credentials) => credentials,
                Err(error) => {
                    tracing::error!(%error, "the account's credentials could not be read");
                    return reply::refuse(StatusCode::INTERNAL_SERVER_ERROR, "store_unavailable");
                }
            };
            if !credentials.iter().any(|c| ceremony.accepts(&c.key)) {
                return reply::refuse(StatusCode::CONFLICT, "no_credential_for_step_up");
            }
        }
        if let Err(error) = service.begin_step_up_for(&session, &step_up).await {
            tracing::warn!(%error, step_up = %step_up, "the step-up could not begin");
            return reply::refuse(StatusCode::CONFLICT, "step_up_unavailable");
        }
    }
    match service.prepare_factor(&session).await {
        Ok(PrepareOutcome::Fido2Challenge { challenge }) => {
            Json(serde_json::json!({ "factor": "fido2", "challenge": challenge })).into_response()
        }
        Ok(PrepareOutcome::Ready) => {
            Json(serde_json::json!({ "factor": "password" })).into_response()
        }
        Ok(_) => reply::refuse(StatusCode::CONFLICT, "step_up_unavailable"),
        Err(error) => {
            tracing::warn!(%error, "the step-up could not be prepared");
            reply::refuse(StatusCode::CONFLICT, "step_up_unavailable")
        }
    }
}

/// What the browser sends to finish a step-up: the authenticator's
/// assertion, or the password, whichever the step asked for.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Proof {
    Credential(Box<PublicKeyCredential>),
    Password(String),
}

/// End a login in progress that reached a step-up route, and answer for it.
/// `None` when the session holds no login in progress.
async fn refuse_an_open_login(session: &AuthSession) -> Option<Response> {
    session.authenticating_state().await?;
    session.clear().await;
    Some(reply::not_authenticated())
}

/// Finish the step-up that is open, and only a step-up: with none open
/// there is nothing to finish, and a login in progress is ended and refused
/// like any request that is not signed in. A wrong proof leaves the step-up
/// open, so the user can try again (the page's "Continue it"); the failure
/// is counted and audited like any factor failure, and the route is rate
/// limited.
pub(crate) async fn step_up_finish(
    State(state): State<AppState>,
    session: AuthSession,
    audit: AuditContext,
    Json(proof): Json<Proof>,
) -> Response {
    if !session.step_up_pending().await {
        return refuse_an_open_login(&session)
            .await
            .unwrap_or_else(|| reply::refuse(StatusCode::CONFLICT, "no_step_up_open"));
    }
    let credential = match proof {
        Proof::Password(password) => FactorCredential::Password(password.into()),
        Proof::Credential(assertion) => match FactorCredential::fido2_assertion(&assertion) {
            Ok(credential) => credential,
            Err(_) => return reply::refuse(StatusCode::BAD_REQUEST, "malformed_credential"),
        },
    };
    let service = state.authn.with_audit_context(audit);
    match service.verify_factor(&credential, &session).await {
        Ok(FactorOutcome::Authenticated) => reply::signed_in(),
        Ok(_) => reply::invalid_credentials(),
        Err(error) => {
            tracing::warn!(%error, "the step-up factor was not verified");
            reply::invalid_credentials()
        }
    }
}
