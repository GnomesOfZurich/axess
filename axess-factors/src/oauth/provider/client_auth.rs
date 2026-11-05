//! Client authentication for the requests that prove the client's identity:
//! a shared secret in the form, or a `private_key_jwt` assertion
//! (RFC 7523) in its place.

use super::OAuthProviderConfig;
use crate::client_assertion::CLIENT_ASSERTION_TYPE_JWT_BEARER;
use crate::oauth::types::OAuthError;

/// The id and secret of a `client_secret_basic` header, each form-urlencoded
/// first as RFC 6749 section 2.3.1 requires, so a secret carrying `:`, `+` or
/// `%` reaches a strict server intact. The encoding is
/// [`crate::http_basic::form_urlencode`], which the outbound client uses too.
pub(super) fn basic_credentials(id: &str, secret: &str) -> (String, String) {
    use crate::http_basic::form_urlencode;
    (form_urlencode(id), form_urlencode(secret))
}

impl OAuthProviderConfig {
    /// A fresh client assertion for a request to `endpoint`, or `None` when
    /// the provider authenticates some other way.
    ///
    /// The audience is the signer's when it fixed one, the issuer under the
    /// FAPI profile (FAPI 2.0 section 5.3.2.1), and `endpoint` otherwise.
    /// Every call signs a new `jti`, so a request retried after a DPoP nonce
    /// challenge never repeats an assertion.
    pub(super) fn client_assertion_for(
        &self,
        endpoint: &str,
    ) -> Result<Option<String>, OAuthError> {
        let Some(signer) = &self.client_assertion else {
            return Ok(None);
        };
        let default_audience = if self.fapi.is_some() {
            self.metadata.issuer().as_str()
        } else {
            endpoint
        };
        Ok(Some(signer.mint(
            default_audience,
            &*self.clock,
            &*self.rng,
        )?))
    }

    /// The client's authentication on the token, revocation, device and
    /// pushed authorization requests: with a signer, `client_id` and the assertion pair in `form`;
    /// with a secret, the id and secret for a `client_secret_basic` header
    /// (returned, for [`post_form_constrained`](Self::post_form_constrained)),
    /// which RFC 6749 section 2.3.1 has every server accept, and `client_id`
    /// in `form` as well, so the request still names its client; with
    /// neither, `client_id` in `form` (an mTLS client).
    pub(super) fn token_grant_auth(
        &self,
        form: &mut Vec<(String, String)>,
        endpoint: &str,
    ) -> Result<Option<(&str, &str)>, OAuthError> {
        if self.client_assertion.is_none()
            && let Some(secret) = &self.client_secret
        {
            form.push(("client_id".into(), self.client_id.as_str().to_string()));
            return Ok(Some((self.client_id.as_str(), secret.secret().as_str())));
        }
        self.add_client_auth(form, endpoint)?;
        Ok(None)
    }

    /// Append the client's identity to a form for `endpoint`: `client_id`,
    /// then the assertion pair when a signer is held. A secret is never
    /// put in the form; [`token_grant_auth`](Self::token_grant_auth) sends it
    /// as a header.
    fn add_client_auth(
        &self,
        form: &mut Vec<(String, String)>,
        endpoint: &str,
    ) -> Result<(), OAuthError> {
        form.push(("client_id".into(), self.client_id.as_str().to_string()));
        if let Some(assertion) = self.client_assertion_for(endpoint)? {
            form.push((
                "client_assertion_type".into(),
                CLIENT_ASSERTION_TYPE_JWT_BEARER.to_string(),
            ));
            form.push(("client_assertion".into(), assertion));
        }
        Ok(())
    }
}
