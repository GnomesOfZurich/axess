//! Signing in three ways, finishing any open factor step, and signing out.

use axess::AuthSession;
use axess::authn::{
    AuditContext, FactorCredential, FactorKind, FactorOutcome, IdentityLookup, LoginOutcome,
    PrepareOutcome,
};
use axess::federation::fido2::{AuthenticatorAttachment, DiscoverableLogin, DiscoverablePrompt};
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use webauthn_rs::prelude::PublicKeyCredential;

use crate::app::{AppState, TENANT};
use crate::reply;

#[derive(Deserialize)]
pub(crate) struct PasswordLogin {
    username: String,
    password: String,
}

/// Sign in with a username and a password, in one request.
///
/// `login_with_password` answers an unknown user, a locked account and a
/// throttled guess as it answers a wrong password, spends one password
/// check on each, and ends the login it began on every refusal: the session
/// is a fresh guest afterwards for a real account and an unknown one alike,
/// so neither the answer, the cookie nor the session says which usernames
/// exist.
pub(crate) async fn password(
    State(state): State<AppState>,
    session: AuthSession,
    audit: AuditContext,
    Json(form): Json<PasswordLogin>,
) -> Response {
    let service = state.authn.with_audit_context(audit);
    match service
        .login_with_password(&form.username, TENANT, &form.password, &session)
        .await
    {
        Ok(FactorOutcome::Authenticated) => reply::signed_in(),
        // The demo account's method has one step. A method with more
        // continues here with `prepare_factor`.
        Ok(FactorOutcome::FactorRequired(next)) => {
            Json(serde_json::json!({ "authenticated": false, "next": next.as_str() }))
                .into_response()
        }
        Ok(_) => reply::invalid_credentials(),
        Err(error) => {
            tracing::warn!(%error, "password sign-in failed");
            reply::invalid_credentials()
        }
    }
}

/// End a sign-in this module's own routes began (the security-key login, a
/// passwordless ceremony) and that failed: the session goes back to a fresh
/// guest, so no login and no challenge is left to try again, and the answer
/// is the one every failed sign-in gets. `login_with_password` does the same
/// for the password form by itself.
async fn refuse_sign_in(session: &AuthSession) -> Response {
    session.clear().await;
    reply::invalid_credentials()
}

#[derive(Deserialize)]
pub(crate) struct Username {
    username: String,
}

/// Begin a sign-in with a security key: the username first, then the
/// challenge for the keys that user registered.
///
/// The ceremony is `Fido2Options::login_ceremony`, here the security-key
/// ceremony with user verification preferred, and it offers only the
/// credentials it can authenticate: the user's security keys, not their
/// passkeys.
///
/// A username-first WebAuthn login tells its caller whether the username
/// has a security key, because the challenge has to list the key ids. The
/// passwordless sign-in does not have that property.
pub(crate) async fn security_key_begin(
    State(state): State<AppState>,
    session: AuthSession,
    audit: AuditContext,
    Json(form): Json<Username>,
) -> Response {
    let service = state.authn.with_audit_context(audit);
    match service.begin_login(&form.username, TENANT, &session).await {
        Ok(LoginOutcome::FactorRequired(_)) => {}
        Ok(_) => return refuse_sign_in(&session).await,
        Err(error) => {
            tracing::warn!(%error, "security-key sign-in could not begin");
            return refuse_sign_in(&session).await;
        }
    }
    // The method's step is "password or FIDO2"; this route takes the second.
    match service
        .prepare_factor_choice(&session, FactorKind::Fido2)
        .await
    {
        Ok(PrepareOutcome::Fido2Challenge { challenge }) => Json(challenge).into_response(),
        // No security key to offer: the login is not left open.
        Ok(_) | Err(_) => refuse_sign_in(&session).await,
    }
}

/// What the browser sends to finish a security-key sign-in: the
/// authenticator's assertion, and nothing else. The login's step would also
/// take the password; this route does not, and the step-up routes act on a
/// step-up only, so no route but the password form takes a password for a
/// login.
#[derive(Deserialize)]
pub(crate) struct SecurityKeyAssertion {
    credential: Box<PublicKeyCredential>,
}

/// Finish a security-key sign-in. A refused assertion ends the login, so
/// the next attempt begins again from the username.
pub(crate) async fn security_key_finish(
    State(state): State<AppState>,
    session: AuthSession,
    audit: AuditContext,
    Json(body): Json<SecurityKeyAssertion>,
) -> Response {
    let Ok(credential) = FactorCredential::fido2_assertion(&body.credential) else {
        return reply::refuse(StatusCode::BAD_REQUEST, "malformed_credential");
    };
    let service = state.authn.with_audit_context(audit);
    match service.verify_factor(&credential, &session).await {
        Ok(FactorOutcome::Authenticated) => reply::signed_in(),
        Ok(FactorOutcome::FactorRequired(next)) => {
            Json(serde_json::json!({ "authenticated": false, "next": next.as_str() }))
                .into_response()
        }
        Ok(_) => refuse_sign_in(&session).await,
        Err(error) => {
            tracing::warn!(%error, "the security key was not verified");
            refuse_sign_in(&session).await
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct PasskeyLogin {
    /// `autofill`, `modal` or `cross_device`; `autofill` when left out.
    #[serde(default)]
    prompt: DiscoverablePrompt,
}

/// Begin a sign-in with a passkey and no username.
///
/// One ceremony serves three buttons. `autofill` offers the passkeys in the
/// username field; `modal` opens the browser's dialog; `cross_device` opens
/// it on the QR code for a phone (cross-device authentication over the
/// hybrid transport). The QR code and the Bluetooth link run between the
/// browser and the phone, so nothing else here differs: the state stored in
/// the session, its timeout and the finish are the same for all three.
///
/// The ceremony is bound to the tenant of this login page, because a
/// passkey names a user and says nothing of tenants.
pub(crate) async fn passkey_begin(
    State(state): State<AppState>,
    session: AuthSession,
    Json(form): Json<PasskeyLogin>,
) -> Response {
    let login = DiscoverableLogin::default()
        .in_tenant(state.tenant.id)
        .with_prompt(form.prompt);
    match state
        .authn
        .begin_discoverable_login_with(&session, login)
        .await
    {
        Ok(challenge) => Json(challenge).into_response(),
        Err(error) => {
            tracing::error!(%error, "the passkey sign-in could not begin");
            reply::refuse(StatusCode::INTERNAL_SERVER_ERROR, "ceremony_unavailable")
        }
    }
}

/// Finish a passkey sign-in: find the user the credential belongs to, then
/// let the service verify the assertion against that user's stored keys and
/// check that the assertion's user handle names that user.
///
/// A challenge is answered once. The service consumes it on every path that
/// reaches it; the refusals before that (a body that is no assertion, a
/// credential nobody here registered, a store that does not answer) clear
/// the session here, so the same challenge cannot be tried again with
/// another credential.
pub(crate) async fn passkey_finish(
    State(state): State<AppState>,
    session: AuthSession,
    audit: AuditContext,
    Json(body): Json<serde_json::Value>,
) -> Response {
    // Read before the typed parse below, which keeps only what is verified.
    let attachment = body
        .get("authenticatorAttachment")
        .and_then(|value| serde_json::from_value::<AuthenticatorAttachment>(value.clone()).ok());
    let Ok(assertion) = serde_json::from_value::<PublicKeyCredential>(body) else {
        session.clear().await;
        return reply::refuse(StatusCode::BAD_REQUEST, "malformed_credential");
    };

    // The lookup is by credential id within this page's tenant, in the
    // index the page keeps (`AppState::passkey_holder`): an id is not
    // unique across tenants, so an unscoped lookup could name another
    // tenant's user.
    let holder = match state.passkey_holder(assertion.get_credential_id()) {
        Some(user_id) => state.backend.get_user(&user_id).await,
        None => Ok(None),
    };
    let user = match holder {
        Ok(Some(user)) => user,
        // A credential nobody here registered is answered as any failed
        // sign-in is.
        Ok(None) => return refuse_sign_in(&session).await,
        Err(error) => {
            tracing::error!(%error, "the credential's holder could not be read");
            session.clear().await;
            return reply::refuse(StatusCode::INTERNAL_SERVER_ERROR, "store_unavailable");
        }
    };
    let credentials = match state.authn.list_fido2_credentials(&user).await {
        Ok(credentials) => credentials,
        Err(error) => {
            tracing::error!(%error, "the account's credentials could not be read");
            session.clear().await;
            return reply::refuse(StatusCode::INTERNAL_SERVER_ERROR, "store_unavailable");
        }
    };

    let service = state.authn.with_audit_context(audit);
    match service
        .finish_discoverable_login(&assertion, &user, &credentials, &session)
        .await
    {
        Ok(FactorOutcome::Authenticated) => {
            // `authenticatorAttachment` is the browser's own report of where
            // the authenticator is, and no signature covers it. It is good
            // for one thing: after a sign-in from another device, offering
            // to create a passkey on this one. No decision rests on it.
            let cross_device = attachment == Some(AuthenticatorAttachment::CrossPlatform);
            Json(serde_json::json!({
                "authenticated": true,
                "attachment": attachment,
                "offer_local_passkey": cross_device,
            }))
            .into_response()
        }
        Ok(FactorOutcome::FactorRequired(next)) => {
            Json(serde_json::json!({ "authenticated": false, "next": next.as_str() }))
                .into_response()
        }
        Ok(_) => refuse_sign_in(&session).await,
        Err(error) => {
            tracing::warn!(%error, "the passkey sign-in was refused");
            refuse_sign_in(&session).await
        }
    }
}

/// Abandon a sign-in the page began and will not finish: the user dismissed
/// the browser's dialog, or the browser refused the request or let it time
/// out.
///
/// The session becomes a fresh guest, so the login in progress and the
/// challenge that was handed out go with it and nothing is left to finish.
/// A session that is signed in, or in the middle of a step-up, holds no
/// sign-in to abandon and is left as it is.
///
/// A page that never calls this leaves nothing open for long either: the
/// service refuses a challenge five minutes after it was issued
/// (`Fido2Options::ceremony_timeout`) and a login in progress ten minutes
/// after it began (`AuthnServiceBuilder::with_flow_ttl`), and the session's
/// row expires with the idle lifetime the session layer was given.
pub(crate) async fn cancel(session: AuthSession) -> Response {
    if !session.is_authenticated().await && !session.step_up_pending().await {
        session.clear().await;
    }
    StatusCode::NO_CONTENT.into_response()
}

/// Sign out: the session ends in the store and in the registry.
pub(crate) async fn logout(
    State(state): State<AppState>,
    session: AuthSession,
    audit: AuditContext,
) -> Response {
    let service = state.authn.with_audit_context(audit);
    if let Err(error) = service.logout(&session).await {
        tracing::error!(%error, "sign-out failed");
        return reply::refuse(StatusCode::INTERNAL_SERVER_ERROR, "logout_failed");
    }
    StatusCode::NO_CONTENT.into_response()
}
