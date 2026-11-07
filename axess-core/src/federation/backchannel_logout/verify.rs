//! Verifying a back-channel logout token: the signature through the chosen
//! provider's keys, then the claims the specification requires.

use super::{
    BackChannelLogoutHandler, LogoutProviderError, LogoutTokenClaims, ProviderEntry, loggable,
};
use axess_factors::oidc::logout_token::{
    IatCheck, aud_contains, azp_satisfied, check_iat, decode_jwt_payload, events_contains_logout,
};
use axum::http::StatusCode;

impl BackChannelLogoutHandler {
    /// Validate a back-channel logout token JWT.
    ///
    /// Verifies the JWT signature (via the provider's JWKS), then checks
    /// issuer, audience, iat recency, events claim, and presence of sub/sid.
    pub(super) async fn validate_logout_token(
        &self,
        token: &str,
    ) -> Result<LogoutTokenClaims, StatusCode> {
        // 0. Peek at the unverified payload to identify the issuer, so we
        //    know which provider's JWKS to verify against.
        let unverified = decode_jwt_payload(token).map_err(|e| {
            tracing::warn!(error = %e, "back-channel logout: failed to decode JWT");
            StatusCode::BAD_REQUEST
        })?;

        let iss = unverified
            .get("iss")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                tracing::warn!("back-channel logout: missing iss claim");
                StatusCode::BAD_REQUEST
            })?;

        // Read from the unverified payload only to choose whose keys to
        // verify with: the verified payload is checked for `aud` again below.
        let entry = match self.entry_for(iss, &unverified).await {
            Ok(Some(entry)) => entry,
            Ok(None) => {
                // The issuer is the sender's own claim on an endpoint anyone
                // can reach; it is not a reason to write a stranger's string
                // to the warn log.
                tracing::debug!(
                    iss = %loggable(iss),
                    "back-channel logout: no provider of this issuer has a client id the \
                     token's aud names"
                );
                return Err(StatusCode::BAD_REQUEST);
            }
            Err(e @ LogoutProviderError::Ambiguous { .. }) => {
                tracing::warn!(iss = %loggable(iss), error = %e, "back-channel logout refused");
                return Err(StatusCode::BAD_REQUEST);
            }
            Err(e @ (LogoutProviderError::Source(_) | LogoutProviderError::Unavailable { .. })) => {
                // Retryable: the IdP sends the token again.
                tracing::warn!(iss = %loggable(iss), error = %e, "back-channel logout refused");
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
        };

        // 1. Verify JWT signature using the provider's JWKS.
        //    On unknown `kid`, refresh the JWKS and retry once (key rotation).
        //    pattern-match on the typed `OAuthError::UnknownKid`
        //    variant rather than substring-matching the error message.
        let payload = match entry.provider.verify_logout_jwt(token) {
            Ok(p) => p,
            Err(
                e @ (axess_factors::oauth::OAuthError::UnknownKid(_)
                | axess_factors::oauth::OAuthError::JwksExpired),
            ) => {
                tracing::info!(iss = %loggable(iss), reason = %e, "back-channel logout: JWKS unusable; refreshing");
                if let Err(refresh_err) = entry.provider.refresh_jwks().await {
                    tracing::warn!(iss = %loggable(iss), error = %refresh_err, "JWKS refresh failed");
                }
                entry.provider.verify_logout_jwt(token).map_err(|e| {
                    tracing::warn!(iss = %loggable(iss), error = %e, "back-channel logout: JWT verification failed after JWKS refresh");
                    StatusCode::BAD_REQUEST
                })?
            }
            Err(e) => {
                tracing::warn!(iss = %loggable(iss), error = %e, "back-channel logout: JWT verification failed");
                return Err(StatusCode::BAD_REQUEST);
            }
        };

        self.checked_claims(&entry, &payload, iss)
    }

    /// The claims of a logout token whose signature `entry`'s provider has
    /// verified: `aud`, `azp`, `iat`, `events`, `sub`/`sid`, `nonce` and `jti`
    /// are checked here.
    fn checked_claims(
        &self,
        provider: &ProviderEntry,
        payload: &serde_json::Value,
        iss: &str,
    ) -> Result<LogoutTokenClaims, StatusCode> {
        // 2. Check `aud` contains the client ID.
        if !aud_contains(payload, &provider.client_id) {
            tracing::warn!(iss = %loggable(iss), "back-channel logout: aud does not contain client_id");
            return Err(StatusCode::BAD_REQUEST);
        }

        // when aud is multi-valued, OIDC §2 requires
        // `azp == client_id`. Without this, a logout token addressed to
        // [our_client_id, other_client_id] with `azp: other_client_id`
        // would be wrongly accepted.
        if !azp_satisfied(payload, &provider.client_id) {
            tracing::warn!(
                iss = %loggable(iss),
                "back-channel logout: aud is multi-valued and azp does not match client_id"
            );
            return Err(StatusCode::BAD_REQUEST);
        }

        // 3. Check `iat` is recent.
        match check_iat(payload, self.clock.now().timestamp()) {
            IatCheck::Ok => {}
            IatCheck::Missing => {
                tracing::warn!("back-channel logout: missing or invalid iat claim");
                return Err(StatusCode::BAD_REQUEST);
            }
            IatCheck::OutOfRange { iat, now } => {
                tracing::warn!(
                    iat = iat,
                    now = now,
                    "back-channel logout: iat too old or in the future"
                );
                return Err(StatusCode::BAD_REQUEST);
            }
        }

        // 4. Check `events` contains the back-channel logout event.
        if !events_contains_logout(payload) {
            tracing::warn!("back-channel logout: events claim missing back-channel logout URI");
            return Err(StatusCode::BAD_REQUEST);
        }

        // 5. Extract `sub` and/or `sid`.
        let sub = payload
            .get("sub")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let sid = payload
            .get("sid")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        if sub.is_none() && sid.is_none() {
            tracing::warn!("back-channel logout: neither sub nor sid present");
            return Err(StatusCode::BAD_REQUEST);
        }

        // 6. Must NOT contain a `nonce` claim (per spec).
        if payload.get("nonce").is_some() {
            tracing::warn!("back-channel logout: logout token must not contain nonce");
            return Err(StatusCode::BAD_REQUEST);
        }

        // OIDC Back-Channel Logout 1.0 §2.4 makes `jti` REQUIRED. Without it
        // the token cannot be replay-protected, so refuse it.
        let jti = payload
            .get("jti")
            .and_then(|v| v.as_str())
            .filter(|j| !j.is_empty())
            .map(|s| s.to_string());
        if jti.is_none() {
            tracing::warn!("back-channel logout: missing jti claim");
            return Err(StatusCode::BAD_REQUEST);
        }

        Ok(LogoutTokenClaims {
            sub,
            sid,
            iss: iss.to_string(),
            jti,
            tenant: provider.tenant,
        })
    }
}
