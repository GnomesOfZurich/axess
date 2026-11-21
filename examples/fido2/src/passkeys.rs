//! Managing the account's FIDO2 credentials: registering one through the
//! ceremony its kind names, and deleting one.

use axess::AuthSession;
use axess::authn::{AuditContext, StepUp};
use axess::authz::AuthzRefusal;
use axess::federation::fido2::{Fido2Ceremony, SecurityKeyVerification};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use webauthn_rs::prelude::RegisterPublicKeyCredential;

use crate::app::AppState;
use crate::reply;

/// The longest name a credential may be given.
const MAX_NAME_CHARS: usize = 64;

/// The registration the page asks for, and the typed ceremony it runs.
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Kind {
    /// User verification required, no attestation, and a credential the
    /// authenticator stores (`Fido2Options::discoverable_credential`): the
    /// platform's authenticator, a phone, or a hardware key with room for
    /// one. It can sign in without a username and answer the payment
    /// step-up.
    Passkey,
    /// User verification preferred, a credential the key does not have to
    /// store: a hardware token for the username-first sign-in.
    SecurityKey,
    /// User verification required and direct attestation, verified against
    /// the configured roots; an authenticator that syncs its keys is
    /// refused.
    AttestedPasskey,
}

#[derive(Deserialize)]
pub(crate) struct Begin {
    kind: Kind,
}

/// The refusal for a session too old to change its credentials, if it is.
///
/// A credential change needs a session that authenticated recently
/// (`Fido2Options::max_authn_age`, five minutes by default), so a session
/// left open on a shared machine cannot enrol someone else's passkey hours
/// later. The service enforces it; asking first lets the page be told which
/// step-up refreshes the session, in the shape the payment gate uses.
async fn stale_session_refusal(state: &AppState, session: &AuthSession) -> Option<Response> {
    let max_age = state.max_authn_age?;
    if session
        .authenticated_within(max_age, state.clock.now())
        .await
    {
        return None;
    }
    Some(AuthzRefusal::StepUpRequired(StepUp::Password).into_response())
}

/// Begin a registration of the kind the page chose.
pub(crate) async fn begin(
    State(state): State<AppState>,
    session: AuthSession,
    audit: AuditContext,
    Json(request): Json<Begin>,
) -> Response {
    let Some(user) = state.current_user(&session).await else {
        return reply::not_authenticated();
    };
    if let Some(refusal) = stale_session_refusal(&state, &session).await {
        return refusal;
    }
    let ceremony = match request.kind {
        Kind::Passkey => Fido2Ceremony::Passkey,
        Kind::SecurityKey => Fido2Ceremony::SecurityKey(SecurityKeyVerification::Preferred),
        Kind::AttestedPasskey => match &state.attested {
            Some(ceremony) => ceremony.clone(),
            None => return reply::refuse(StatusCode::NOT_FOUND, "attestation_not_configured"),
        },
    };
    let service = state.authn.with_audit_context(audit);
    match service
        .begin_fido2_registration_with(&user, &session, &ceremony)
        .await
    {
        // Every user here is created with a WebAuthn handle, so none is
        // minted. An application that creates users without one stores the
        // id this returns on the user before the next ceremony.
        Ok((challenge, _)) => Json(challenge).into_response(),
        Err(error) => {
            tracing::warn!(%error, %ceremony, "the registration could not begin");
            reply::refuse(StatusCode::FORBIDDEN, "registration_refused")
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct Finish {
    /// The label the user gave the credential.
    name: String,
    /// What `navigator.credentials.create()` returned.
    credential: Box<RegisterPublicKeyCredential>,
}

/// Finish the registration the session began. The service re-checks the
/// session, verifies the response against the stored challenge, refuses a
/// credential id that this user or another already holds, and stores the
/// credential typed by its ceremony.
pub(crate) async fn finish(
    State(state): State<AppState>,
    session: AuthSession,
    audit: AuditContext,
    Json(request): Json<Finish>,
) -> Response {
    let Some(user) = state.current_user(&session).await else {
        return reply::not_authenticated();
    };
    let name = request.name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME_CHARS {
        return reply::refuse(StatusCode::BAD_REQUEST, "invalid_name");
    }
    let service = state.authn.with_audit_context(audit);
    match service
        .finish_fido2_registration(&user, &request.credential, name, &session)
        .await
    {
        Ok(()) => {
            state.index_passkeys(&user).await;
            StatusCode::CREATED.into_response()
        }
        Err(error) => {
            tracing::warn!(%error, "the registration was refused");
            reply::refuse(StatusCode::FORBIDDEN, "registration_refused")
        }
    }
}

/// Delete the credential whose id (URL-safe base64, as the session listing
/// writes it) is in the path. The account keeps its password, so its last
/// credential may go.
pub(crate) async fn remove(
    State(state): State<AppState>,
    session: AuthSession,
    audit: AuditContext,
    Path(id): Path<String>,
) -> Response {
    let Some(user) = state.current_user(&session).await else {
        return reply::not_authenticated();
    };
    let Ok(credential_id) = URL_SAFE_NO_PAD.decode(id) else {
        return reply::refuse(StatusCode::BAD_REQUEST, "malformed_credential_id");
    };
    if let Some(refusal) = stale_session_refusal(&state, &session).await {
        return refusal;
    }
    let service = state.authn.with_audit_context(audit);
    match service
        .delete_fido2_credential(&user, &session, &credential_id, 0)
        .await
    {
        Ok(true) => {
            state.index_passkeys(&user).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => reply::refuse(StatusCode::NOT_FOUND, "unknown_credential"),
        Err(error) => {
            tracing::warn!(%error, "the credential could not be deleted");
            reply::refuse(StatusCode::FORBIDDEN, "deletion_refused")
        }
    }
}
