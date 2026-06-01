//! Per-flow OAuth login options + `response_mode` wire enum.

/// OAuth 2.0 response mode: how the authorization server returns parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseMode {
    /// Default: parameters in the query string of the redirect URI.
    Query,
    /// Parameters in the URL fragment of the redirect URI.
    ///
    /// **Server-side handlers cannot read the fragment**: browsers do not
    /// transmit the URL fragment in the HTTP request. Selecting this mode
    /// requires a client-side shim (HTML page served at `redirect_uri` that
    /// reads `window.location.hash` and re-POSTs the parameters back to the
    /// server) before [`finish_oauth_login`](axess_core::authn::service::AuthnService::finish_oauth_login) can complete. For a
    /// pure server-side flow, prefer [`Query`](Self::Query) (default) or
    /// [`FormPost`](Self::FormPost); both deliver the `code` directly.
    Fragment,
    /// Parameters in an auto-submitting HTML form POST to the redirect URI.
    /// Prevents code leakage in browser history, Referer headers, and server
    /// access logs. Required by FAPI 2.0.
    FormPost,
}

impl ResponseMode {
    /// The `response_mode` parameter value for the authorization request.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Fragment => "fragment",
            Self::FormPost => "form_post",
        }
    }
}

/// Options for a single OAuth login flow.
#[derive(Debug, Clone, Default)]
pub struct OAuthLoginOptions {
    /// OIDC `prompt` parameter.
    pub prompt: Option<String>,
    /// OIDC `login_hint` parameter.
    pub login_hint: Option<String>,
    /// Additional scopes beyond the provider's default scopes.
    pub extra_scopes: Vec<String>,
    /// Override the response mode for this flow.
    /// Default (`None`) uses the IdP's default (typically `query`).
    pub response_mode: Option<ResponseMode>,
}

impl OAuthLoginOptions {
    /// Construct an options bundle with all fields unset.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the OIDC `prompt` parameter (e.g. `"login"`, `"consent"`, `"none"`).
    pub fn prompt(mut self, prompt: &str) -> Self {
        self.prompt = Some(prompt.to_string());
        self
    }

    /// Set the OIDC `login_hint` parameter to pre-fill the IdP's username field.
    pub fn login_hint(mut self, hint: &str) -> Self {
        self.login_hint = Some(hint.to_string());
        self
    }

    /// Append a single scope to [`OAuthLoginOptions::extra_scopes`].
    pub fn extra_scope(mut self, scope: &str) -> Self {
        self.extra_scopes.push(scope.to_string());
        self
    }

    /// Set the response mode for this login flow.
    ///
    /// Use [`ResponseMode::FormPost`] to receive the authorization code via
    /// POST body instead of URL query parameters; prevents code leakage in
    /// browser history and Referer headers.
    pub fn response_mode(mut self, mode: ResponseMode) -> Self {
        self.response_mode = Some(mode);
        self
    }
}

#[cfg(test)]
mod response_mode_tests {
    use super::ResponseMode;

    /// Pin the wire string for every `ResponseMode`. The IdP
    /// matches on these literal values per OAuth 2.0 Multiple Response
    /// Type Encoding Practices §2; a typo silently breaks redirects.
    #[test]
    fn response_mode_as_str_pins_known_values() {
        assert_eq!(ResponseMode::Query.as_str(), "query");
        assert_eq!(ResponseMode::Fragment.as_str(), "fragment");
        assert_eq!(ResponseMode::FormPost.as_str(), "form_post");
    }
}

#[cfg(test)]
mod login_options_builder_tests {
    use super::{OAuthLoginOptions, ResponseMode};

    /// Builder methods must return `self` with the new field
    /// set, never reset the bundle to `Default`. Each test threads two
    /// successive calls through one builder so a "return Default::default()"
    /// mutation drops the earlier mutation.
    #[test]
    fn prompt_preserves_prior_login_hint() {
        let opts = OAuthLoginOptions::new()
            .login_hint("alice@example.com")
            .prompt("login");
        assert_eq!(opts.login_hint.as_deref(), Some("alice@example.com"));
        assert_eq!(opts.prompt.as_deref(), Some("login"));
    }

    #[test]
    fn login_hint_preserves_prior_prompt() {
        let opts = OAuthLoginOptions::new()
            .prompt("consent")
            .login_hint("bob@example.com");
        assert_eq!(opts.prompt.as_deref(), Some("consent"));
        assert_eq!(opts.login_hint.as_deref(), Some("bob@example.com"));
    }

    #[test]
    fn extra_scope_appends_and_preserves_prior_fields() {
        let opts = OAuthLoginOptions::new()
            .prompt("login")
            .extra_scope("openid")
            .extra_scope("email");
        assert_eq!(opts.prompt.as_deref(), Some("login"));
        assert_eq!(
            opts.extra_scopes,
            vec!["openid".to_string(), "email".to_string()]
        );
    }

    #[test]
    fn response_mode_preserves_prior_fields() {
        let opts = OAuthLoginOptions::new()
            .prompt("login")
            .response_mode(ResponseMode::FormPost);
        assert_eq!(opts.prompt.as_deref(), Some("login"));
        assert_eq!(opts.response_mode, Some(ResponseMode::FormPost));
    }
}
