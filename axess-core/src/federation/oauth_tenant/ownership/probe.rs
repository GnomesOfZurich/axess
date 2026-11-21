//! [`TokenEndpointProbe`]: a confidential client proves itself to its
//! identity provider's token endpoint.

use super::{
    ClientOwnershipProof, OwnershipClaim, OwnershipFuture, OwnershipProven, OwnershipRefused,
};
use crate::federation::oauth_tenant::TenantClientCredential;
use axess_factors::client_assertion::ClientAssertionSigner;
use axess_factors::oauth::{ClientAuthProbe, ProbeClientAuth, probe_client_authentication};
use axess_factors::oidc::{DiscoveryDocument, OidcError};
use std::time::Duration;

/// How long the probe waits for each of its requests (the discovery
/// document, each token request) before it calls the claim unproven.
pub const DEFAULT_OWNERSHIP_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// How the probe presents a client secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretStyle {
    Basic,
    Post,
}

/// The proof that holds when the identity provider authenticates the
/// record's client with the record's credential.
///
/// The probe reads the token endpoint from the issuer's discovery document
/// and asks it, as the client, to redeem an authorization code it never
/// issued: a `client_secret_basic` request for a secret (the way the tenant's
/// provider authenticates; [`with_client_secret_post`](Self::with_client_secret_post)
/// for a provider that takes the secret in the form), a `private_key_jwt`
/// assertion for a key. Per RFC 6749 section 5.2:
///
/// - `invalid_client`, with HTTP 400 or 401, refuses the record
///   ([`OwnershipRefused::ClientNotAuthenticated`]);
/// - `unauthorized_client`, `unsupported_grant_type`, `invalid_grant` or
///   `invalid_scope`, with HTTP 400, prove ownership: the provider
///   authenticated the client before it refused the grant. It counts only
///   when the same request made with a credential known to be wrong, once
///   before the client's own and once after, is refused as `invalid_client`
///   both times; a provider that refuses a control otherwise never checked
///   the credential (a client it holds as public, a code checked before the
///   client) or could not say (a rate limit, an outage), and the record is
///   refused as unproven, the client's credential unsent when it was the
///   first control;
/// - any other answer (a grant error under another status included), a
///   token, a redirect, a transport failure or a discovery that fails
///   refuses the record as [`OwnershipRefused::Unproven`], with what
///   happened in its reason (traced, never told to the tenant).
///
/// A public client (an empty secret) is refused as
/// [`OwnershipRefused::PublicClient`] without a request. Every request (the
/// discovery document and up to three token requests) goes through a client
/// the directory's egress policy builds, so they follow no redirect and
/// reach no reserved address, and each waits at most
/// [`DEFAULT_OWNERSHIP_PROBE_TIMEOUT`] unless
/// [`with_timeout`](Self::with_timeout) names another bound.
#[derive(Debug, Clone)]
pub struct TokenEndpointProbe {
    secret_style: SecretStyle,
    timeout: Duration,
}

impl Default for TokenEndpointProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenEndpointProbe {
    /// A probe that presents a secret as `client_secret_basic` and waits
    /// [`DEFAULT_OWNERSHIP_PROBE_TIMEOUT`] for each request.
    #[must_use]
    pub fn new() -> Self {
        Self {
            secret_style: SecretStyle::Basic,
            timeout: DEFAULT_OWNERSHIP_PROBE_TIMEOUT,
        }
    }

    /// Present a secret as `client_secret_post`: the client id and secret in
    /// the form, for a provider that does not take HTTP Basic.
    #[must_use]
    pub fn with_client_secret_post(mut self) -> Self {
        self.secret_style = SecretStyle::Post;
        self
    }

    /// Wait at most `timeout` for each request.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    async fn probe(&self, claim: &OwnershipClaim<'_>) -> Result<OwnershipProven, OwnershipRefused> {
        if claim.is_public_client() {
            return Err(OwnershipRefused::PublicClient);
        }
        let record = claim.record;
        let signer = match &record.credential {
            TenantClientCredential::Secret(_) => None,
            TenantClientCredential::PrivateKeyJwt { signer, .. } => Some(
                ClientAssertionSigner::from_spec(
                    record.client_id.clone(),
                    claim.credential,
                    signer,
                )
                .map_err(|e| unproven(format!("the client's private key does not load: {e}")))?,
            ),
        };
        let auth = match (&signer, self.secret_style) {
            (Some(signer), _) => ProbeClientAuth::PrivateKeyJwt(signer),
            (None, SecretStyle::Basic) => ProbeClientAuth::SecretBasic {
                client_id: &record.client_id,
                client_secret: claim.credential,
            },
            (None, SecretStyle::Post) => ProbeClientAuth::SecretPost {
                client_id: &record.client_id,
                client_secret: claim.credential,
            },
        };
        let client = claim
            .egress
            .build_client(|settings| settings.timeout(self.timeout))
            .map_err(|_| unproven("the HTTP client could not be built"))?;
        let discovery = DiscoveryDocument::fetch(&record.issuer, &client)
            .await
            .map_err(|e| unproven(discovery_failure(&e)))?;
        let token_endpoint = discovery
            .token_endpoint
            .ok_or_else(|| unproven("the discovery document names no token_endpoint"))?;
        match probe_client_authentication(
            &client,
            &token_endpoint,
            auth,
            &record.redirect_url,
            &*claim.clock,
            &*claim.rng,
        )
        .await
        {
            ClientAuthProbe::Authenticated { error } => {
                Ok(OwnershipProven::ClientAuthenticated { answer: error })
            }
            ClientAuthProbe::NotAuthenticated => Err(OwnershipRefused::ClientNotAuthenticated),
            ClientAuthProbe::Unproven { reason } => Err(unproven(reason)),
        }
    }
}

impl ClientOwnershipProof for TokenEndpointProbe {
    fn prove<'a>(&'a self, claim: &'a OwnershipClaim<'a>) -> OwnershipFuture<'a> {
        Box::pin(self.probe(claim))
    }
}

fn unproven(reason: impl Into<String>) -> OwnershipRefused {
    OwnershipRefused::Unproven {
        reason: reason.into(),
    }
}

/// Why discovery failed, without the URL a transport error carries.
fn discovery_failure(error: &OidcError) -> String {
    match error {
        OidcError::EgressRefused { setting, range } => {
            format!("discovery refused: {setting} refused: {range}")
        }
        OidcError::NonHttpsIssuer(_) => "discovery refused: HTTPS required".to_string(),
        OidcError::InvalidIssuer(_) => "the discovery document names another issuer".to_string(),
        OidcError::MissingField(field) => {
            format!("the discovery document has no {field}")
        }
        OidcError::DiscoveryParse(_) => "the discovery document does not parse".to_string(),
        _ => "the discovery document could not be fetched".to_string(),
    }
}

#[cfg(test)]
mod tests;
