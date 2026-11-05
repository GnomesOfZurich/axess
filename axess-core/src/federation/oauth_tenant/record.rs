//! The configuration of one tenant's provider, as stored.

use crate::authn::factor::{FactorKind, FederatedProvider};
use crate::authn::factor_secret::{FactorSecretBinding, FactorSecretCipher, FactorSecretError};
use crate::authn::ids::TenantId;
use crate::authn::types::AuthnScope;
use axess_factors::FactorSecret;
use axess_factors::client_assertion::SignerSpec;
use axess_factors::secret::ZeroizedString;
use serde::{Deserialize, Serialize};

/// How the client proves itself to the tenant's IdP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TenantClientCredential {
    /// A shared client secret.
    Secret(FactorSecret),
    /// `private_key_jwt` (RFC 7523): axess signs an assertion with a private
    /// key whose public half, or certificate, the IdP holds.
    PrivateKeyJwt {
        /// The private key, PEM text.
        key_pem: FactorSecret,
        /// How the assertions are shaped (algorithm, `kid`, certificate
        /// thumbprints, audience, lifetime), stored flat beside the key and
        /// turned into the signer by
        /// [`ClientAssertionSigner::from_spec`](axess_factors::client_assertion::ClientAssertionSigner::from_spec).
        #[serde(flatten)]
        signer: SignerSpec,
    },
}

/// Whether a tenant's provider binds its tokens to a DPoP key (RFC 9449):
/// the three behaviours of
/// [`OAuthProviderConfig`](axess_factors::oauth::OAuthProviderConfig).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum TenantDpop {
    /// On when the IdP's discovery document lists `ES256` in
    /// `dpop_signing_alg_values_supported`, off when it does not. The
    /// default, and what a stored record without the field reads as.
    #[default]
    Advertised,
    /// Off whatever the IdP advertises, as
    /// [`without_dpop`](axess_factors::oauth::OAuthProviderBuilder::without_dpop):
    /// for a tenant whose resource servers accept only Bearer tokens.
    Off,
    /// On, and the provider is not built when the IdP does not advertise
    /// DPoP, as [`with_dpop`](axess_factors::oauth::OAuthProviderBuilder::with_dpop):
    /// the login answers `OAuthError::Config` instead of issuing Bearer tokens.
    Required,
}

/// One tenant's provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantOAuthProviderRecord {
    /// The tenant the provider belongs to.
    pub tenant_id: TenantId,
    /// The provider's name within the tenant (`"sso"`, `"entra"`); the same
    /// name may exist under many tenants.
    pub name: String,
    /// Issuer URL, from which discovery runs.
    pub issuer: String,
    /// The client id registered at the IdP.
    pub client_id: String,
    /// The callback URL registered at the IdP.
    pub redirect_url: String,
    /// Scopes to request; empty means `openid email profile`.
    pub scopes: Vec<String>,
    /// How the client authenticates.
    pub credential: TenantClientCredential,
    /// Whether the tokens are bound to a DPoP key. Default
    /// [`TenantDpop::Advertised`]: on wherever the IdP advertises DPoP.
    /// Set [`TenantDpop::Off`] for a tenant whose resource servers accept
    /// only Bearer tokens; [`TenantDpop::Required`] refuses to build the
    /// provider when the IdP does not advertise DPoP. A tenant whose tokens
    /// are bound keeps `OAuthClaims::dpop_key` beside the refresh token.
    #[serde(default)]
    pub dpop: TenantDpop,
    /// Assigned by the store: 1 for a new record, then one more per update.
    /// Whatever the caller sets is overwritten by
    /// [`put`](super::TenantOAuthProviderStore::put).
    pub revision: u64,
}

impl TenantOAuthProviderRecord {
    /// The binding a credential of this record is sealed under: the tenant
    /// and the provider name, with the issuer and client id as context, so a
    /// row copied to another tenant or name, or pointed at another IdP or
    /// client, does not open.
    fn binding_parts(&self) -> (AuthnScope, FactorKind) {
        (
            AuthnScope::Tenant(self.tenant_id),
            FactorKind::Federated(FederatedProvider::Custom(self.name.clone())),
        )
    }

    fn binding_context(&self) -> [&str; 2] {
        [self.issuer.as_str(), self.client_id.as_str()]
    }

    fn secret_mut(&mut self) -> &mut FactorSecret {
        match &mut self.credential {
            TenantClientCredential::Secret(s) => s,
            TenantClientCredential::PrivateKeyJwt { key_pem, .. } => key_pem,
        }
    }

    fn secret(&self) -> &FactorSecret {
        match &self.credential {
            TenantClientCredential::Secret(s) => s,
            TenantClientCredential::PrivateKeyJwt { key_pem, .. } => key_pem,
        }
    }

    /// Seal a plain credential with `cipher`, bound to this tenant and name.
    /// An already sealed credential is left as it is.
    ///
    /// # Errors
    ///
    /// [`FactorSecretError::Seal`] if encryption fails.
    pub fn seal(&mut self, cipher: &FactorSecretCipher) -> Result<(), FactorSecretError> {
        let (scope, kind) = self.binding_parts();
        let Some(plain) = self.secret().plain().map(str::to_string) else {
            return Ok(());
        };
        let context = self.binding_context();
        let sealed = cipher.seal(
            &plain,
            FactorSecretBinding::new(&scope, &kind).with_context(&context),
        )?;
        *self.secret_mut() = FactorSecret::Sealed(sealed);
        Ok(())
    }

    /// The credential's text, opened with `cipher` when it is sealed.
    ///
    /// # Errors
    ///
    /// [`FactorSecretError::NoCipher`] for a sealed credential and no
    /// cipher, [`FactorSecretError::PlainRefused`] for a plain one the
    /// cipher's policy no longer reads, and the cipher's own errors for a
    /// sealed one that does not open for this tenant and name.
    pub fn open_secret(
        &self,
        cipher: Option<&FactorSecretCipher>,
    ) -> Result<ZeroizedString, FactorSecretError> {
        self.open_credential(cipher).map(|(text, _)| text)
    }

    /// Like [`open_secret`](Self::open_secret), also saying whether the
    /// credential is sealed under a previous key or the first release's
    /// binding and is due a [`reseal`](Self::reseal).
    ///
    /// # Errors
    ///
    /// As [`open_secret`](Self::open_secret).
    pub fn open_credential(
        &self,
        cipher: Option<&FactorSecretCipher>,
    ) -> Result<(ZeroizedString, bool), FactorSecretError> {
        let (scope, kind) = self.binding_parts();
        match (self.secret(), cipher) {
            (FactorSecret::Plain(text), None) => Ok((text.clone(), false)),
            (FactorSecret::Plain(text), Some(cipher)) => {
                if cipher.plain_secrets_readable() {
                    Ok((text.clone(), false))
                } else {
                    Err(FactorSecretError::PlainRefused)
                }
            }
            (FactorSecret::Sealed(_), None) => Err(FactorSecretError::NoCipher),
            (FactorSecret::Sealed(sealed), Some(cipher)) => {
                let context = self.binding_context();
                cipher
                    .open(
                        sealed,
                        FactorSecretBinding::new(&scope, &kind).with_context(&context),
                    )
                    .map(|opened| (opened.secret, opened.rotated))
            }
        }
    }

    /// Seal the credential again under `cipher`'s current key and binding,
    /// from the `plain` text [`open_credential`](Self::open_credential)
    /// returned.
    ///
    /// # Errors
    ///
    /// [`FactorSecretError::Seal`] if encryption fails.
    pub fn reseal(
        &mut self,
        cipher: &FactorSecretCipher,
        plain: &str,
    ) -> Result<(), FactorSecretError> {
        let (scope, kind) = self.binding_parts();
        let context = self.binding_context();
        let sealed = cipher.seal(
            plain,
            FactorSecretBinding::new(&scope, &kind).with_context(&context),
        )?;
        *self.secret_mut() = FactorSecret::Sealed(sealed);
        Ok(())
    }
}
