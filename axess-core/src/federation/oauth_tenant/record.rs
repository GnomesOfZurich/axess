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
    /// The kind every login through this provider records:
    /// `Some(FederatedProvider::Microsoft)` for a tenant's Entra ID, say.
    /// `None`, the default and what a stored record without the field reads
    /// as, records `FederatedProvider::Custom(name)`. Written only when set,
    /// so a record without a kind is stored as before. Not part of the
    /// binding a sealed credential is opened under: it decides what a login
    /// records, not where the credential is presented.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<FederatedProvider>,
    /// Assigned by the store: 1 for a new record, then one more per update.
    /// Whatever the caller sets is overwritten by
    /// [`put`](super::TenantOAuthProviderStore::put).
    pub revision: u64,
}

/// The JWA name of `algorithm` (`RS256`, `ES256`, `EdDSA`): the name serde
/// writes, which the stored record's own JSON already depends on, so the
/// binding changes only when the record itself would stop reading. Never a
/// `Debug` rendering, which no dependency promises to keep.
fn algorithm_name(algorithm: jsonwebtoken::Algorithm) -> String {
    match serde_json::to_value(algorithm) {
        Ok(serde_json::Value::String(name)) => name,
        _ => "unnamed".to_string(),
    }
}

/// Every field of the record a sealed credential is bound to, as a context
/// string per field, in a fixed order; tagged so that an absent value and an
/// empty one differ. The first entry names the binding's version.
pub(super) fn binding_fields(record: &TenantOAuthProviderRecord) -> Vec<String> {
    fn tagged(tag: &str, value: Option<&str>) -> String {
        match value {
            Some(value) => format!("{tag}:{value}"),
            None => tag.to_string(),
        }
    }
    let mut scopes: Vec<&str> = record.scopes.iter().map(String::as_str).collect();
    scopes.sort_unstable();
    let mut fields = vec![
        "v2".to_string(),
        format!("issuer:{}", record.issuer),
        format!("client_id:{}", record.client_id),
        format!("redirect_url:{}", record.redirect_url),
        format!("scopes:{}", scopes.join(" ")),
        format!(
            "dpop:{}",
            match record.dpop {
                TenantDpop::Advertised => "advertised",
                TenantDpop::Off => "off",
                TenantDpop::Required => "required",
            }
        ),
    ];
    match &record.credential {
        TenantClientCredential::Secret(_) => fields.push("credential:secret".to_string()),
        TenantClientCredential::PrivateKeyJwt { signer, .. } => {
            fields.push("credential:private_key_jwt".to_string());
            fields.push(format!("algorithm:{}", algorithm_name(signer.algorithm)));
            fields.push(tagged("key_id", signer.key_id.as_deref()));
            fields.push(tagged("x5t_s256", signer.x5t_s256.as_deref()));
            fields.push(tagged("x5t", signer.x5t.as_deref()));
            fields.push(tagged("audience", signer.audience.as_deref()));
            fields.push(tagged(
                "assertion_ttl_secs",
                signer
                    .assertion_ttl
                    .map(|ttl| ttl.as_secs().to_string())
                    .as_deref(),
            ));
        }
    }
    fields
}

impl TenantOAuthProviderRecord {
    /// The kind the logins through this provider record: [`kind`](Self::kind),
    /// or `FederatedProvider::Custom(name)` when it is `None`.
    pub fn federated_kind(&self) -> FederatedProvider {
        self.kind
            .clone()
            .unwrap_or_else(|| FederatedProvider::Custom(self.name.clone()))
    }

    /// The binding a credential of this record is sealed under: the tenant
    /// and the provider name, with every field that decides where the
    /// credential is presented and how as context (the issuer, the client
    /// id, the redirect URL, the scopes, the DPoP mode, the credential's
    /// kind and, for `private_key_jwt`, the signer's algorithm, `kid`,
    /// thumbprints, audience and lifetime), so a row copied to another tenant
    /// or name, or with any of those fields rewritten in the store, does not
    /// open. Releases before this one bound the issuer and client id only; the
    /// directory moves a credential sealed that way to this binding when it
    /// starts, and at use it opens only while the cipher's
    /// [`with_earlier_tenant_binding`](FactorSecretCipher::with_earlier_tenant_binding)
    /// policy reads it (not by default), reported as due a re-seal, which
    /// the directory does on first use.
    fn binding_parts(&self) -> (AuthnScope, FactorKind) {
        (
            AuthnScope::Tenant(self.tenant_id),
            FactorKind::Federated(FederatedProvider::Custom(self.name.clone())),
        )
    }

    /// The context of the binding before every field was bound: the issuer
    /// and client id.
    fn first_binding_context(&self) -> [&str; 2] {
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
        let fields = binding_fields(self);
        let context: Vec<&str> = fields.iter().map(String::as_str).collect();
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
    /// sealed one that does not open for this tenant and name, a credential
    /// under the earlier binding the cipher's
    /// [`with_earlier_tenant_binding`](FactorSecretCipher::with_earlier_tenant_binding)
    /// policy no longer reads included.
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
        let earlier = cipher.is_some_and(FactorSecretCipher::earlier_tenant_binding_readable);
        self.open_with(cipher, earlier)
    }

    /// The text of a sealed credential that is due a re-seal (under a
    /// previous key, the first release's binding or the earlier tenant
    /// binding), or `None` for a plain credential and one already sealed
    /// under the current key and binding. The earlier tenant binding is read
    /// here whatever the cipher's policy for it says: this is the start-up
    /// pass that retires it, not a use of the credential.
    ///
    /// # Errors
    ///
    /// The cipher's own errors for a sealed credential that opens under no
    /// binding.
    pub(crate) fn credential_due_a_reseal(
        &self,
        cipher: &FactorSecretCipher,
    ) -> Result<Option<ZeroizedString>, FactorSecretError> {
        if matches!(self.secret(), FactorSecret::Plain(_)) {
            return Ok(None);
        }
        let (text, due) = self.open_with(Some(cipher), true)?;
        Ok(due.then_some(text))
    }

    /// [`open_credential`](Self::open_credential), reading the earlier
    /// tenant binding when `earlier` says so.
    fn open_with(
        &self,
        cipher: Option<&FactorSecretCipher>,
        earlier: bool,
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
                let fields = binding_fields(self);
                let context: Vec<&str> = fields.iter().map(String::as_str).collect();
                let current = FactorSecretBinding::new(&scope, &kind).with_context(&context);
                match cipher.open(sealed, current) {
                    Ok(opened) => Ok((opened.secret, opened.rotated)),
                    // Sealed by a release that bound the issuer and client id
                    // only: while the cipher's policy reads that binding it
                    // opens, and is due a re-seal under every field.
                    Err(FactorSecretError::Open) if earlier => {
                        let first = self.first_binding_context();
                        cipher
                            .open(
                                sealed,
                                FactorSecretBinding::new(&scope, &kind).with_context(&first),
                            )
                            .map(|opened| (opened.secret, true))
                    }
                    Err(e) => Err(e),
                }
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
        let fields = binding_fields(self);
        let context: Vec<&str> = fields.iter().map(String::as_str).collect();
        let sealed = cipher.seal(
            plain,
            FactorSecretBinding::new(&scope, &kind).with_context(&context),
        )?;
        *self.secret_mut() = FactorSecret::Sealed(sealed);
        Ok(())
    }
}
