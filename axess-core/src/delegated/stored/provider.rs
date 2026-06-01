//! `DelegatedProvider`: per-integration config for a 3rd-party
//! IdP that axess can mint user-authorized credentials against.

use url::Url;

use axess_factors::ZeroizedString;

/// Configuration for a single delegated-access provider: one
/// `DelegatedProvider` per 3rd-party integration that adopters want
/// to support (Gmail, Outlook, Zoho, Salesforce, …).
///
/// All knobs are stable across requests; construct once at startup and
/// share via `Arc`. The `client_secret` is held in a [`ZeroizedString`]
/// so a process heap dump does not surface it in plaintext for the
/// lifetime of the program.
#[derive(Debug)]
pub struct DelegatedProvider {
    /// Stable provider key used as the store lookup key alongside
    /// `(tenant_id, user_id)`. Lowercase, kebab-case is conventional
    /// ("gmail", "outlook", "zoho-mail", "salesforce").
    pub name: String,
    /// OAuth2 authorization endpoint URL. axess redirects the user
    /// here at `begin_grant`.
    pub authorization_endpoint: Url,
    /// OAuth2 token endpoint URL. axess POSTs here at `complete_grant`
    /// (code exchange) and at `StoredDelegationSession::get_access_token`
    /// (refresh).
    pub token_endpoint: Url,
    /// OAuth2 `client_id` registered with the provider.
    pub client_id: String,
    /// OAuth2 `client_secret`, zeroized on drop. axess sends this
    /// over HTTP Basic to the token endpoint.
    pub client_secret: ZeroizedString,
    /// The `redirect_uri` axess registered with the provider. Must
    /// match the URL the user's browser arrives at after the
    /// IdP-side consent screen.
    pub redirect_uri: Url,
    /// Default scopes requested at `begin_grant` time when the caller
    /// doesn't override them.
    pub default_scopes: Vec<String>,
}

impl DelegatedProvider {
    /// Construct a provider config. The `client_secret` is coerced
    /// into a `ZeroizedString` so adopters passing a plaintext
    /// `String` lose access to the original buffer after this call;
    /// the only live copy is inside the provider value.
    pub fn new(
        name: impl Into<String>,
        authorization_endpoint: Url,
        token_endpoint: Url,
        client_id: impl Into<String>,
        client_secret: impl Into<ZeroizedString>,
        redirect_uri: Url,
    ) -> Self {
        Self {
            name: name.into(),
            authorization_endpoint,
            token_endpoint,
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri,
            default_scopes: Vec::new(),
        }
    }

    /// Set the default scopes requested by `begin_grant` when the
    /// caller passes an empty scope list.
    pub fn with_default_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.default_scopes = scopes.into_iter().map(Into::into).collect();
        self
    }
}
