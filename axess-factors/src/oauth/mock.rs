//! MockOAuthProvider: deterministic OAuth/OIDC test double.

use super::types::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axess_clock::{Clock, SystemClock};

// ── MockOAuthProvider ────────────────────────────────────────────────────────

/// Mock OAuth/OIDC provider for deterministic simulation testing.
///
/// Simulates OIDC discovery and token exchange without HTTP. Configure with
/// [`with_user`](MockOAuthProvider::with_user) to return specific claims, or
/// [`with_failure`](MockOAuthProvider::with_failure) to simulate provider errors.
///
/// # Examples
///
/// ```rust,ignore
/// use axess::MockOAuthProvider;
///
/// let mock = MockOAuthProvider::new("test-idp")
///     .with_user("user-123", "alice@example.com", vec!["engineers"], vec!["admin"]);
///
/// let authn = AuthnService::builder(identity, factors)
///     .with_oauth_provider(mock)
///     .build();
/// ```
pub struct MockOAuthProvider {
    name: Arc<str>,
    /// Mock issuer URL for back-channel logout validation.
    issuer_url: String,
    /// Mock client ID for back-channel logout validation.
    mock_client_id: String,
    /// Configured user response, if any.
    user: Option<MockOAuthUser>,
    /// Configured failure, if any. Takes precedence over user.
    failure: Option<MockFailure>,
    /// Scopes to advertise.
    scopes: Vec<String>,
    /// Ceremony timeout.
    ceremony_timeout: std::time::Duration,
    /// Source of `iat` for [`mock_logout_token`](MockOAuthProvider::mock_logout_token).
    clock: Arc<dyn Clock>,
    /// Logout tokens minted so far; makes each `jti` distinct.
    logout_tokens_minted: AtomicU64,
    iss_parameter_required: bool,
}

/// Pre-canned error variants the mock can return on token exchange,
/// refresh, or userinfo. Stored as data so the mock stays
/// `OAuthError`-Clone-free; each `as_token_exchange_error` /
/// `as_userinfo_error` reconstructs a fresh variant per call.
#[derive(Clone, Debug)]
enum MockFailure {
    /// Legacy: wraps as `TokenExchange(msg)` on token paths and
    /// `UserInfo(msg)` on userinfo paths. Kept so existing
    /// `with_failure(&str)` callers don't break.
    Legacy(String),
    /// AS responded with `error: "unsupported_token_type"`.
    UnsupportedTokenType,
    /// AS responded with a 5xx; caller can decide retry.
    TokenEndpointTransient { status: Option<u16> },
    /// JWT verification rejected the `kid`.
    UnknownKid(String),
    /// Discovery network/parse failure.
    Discovery(String),
}

impl MockFailure {
    fn as_token_error(&self) -> OAuthError {
        match self {
            Self::Legacy(s) => OAuthError::TokenExchange(s.clone()),
            Self::UnsupportedTokenType => OAuthError::UnsupportedTokenType,
            Self::TokenEndpointTransient { status } => {
                OAuthError::TokenEndpointTransient { status: *status }
            }
            Self::UnknownKid(kid) => OAuthError::UnknownKid(kid.clone()),
            Self::Discovery(s) => OAuthError::Discovery(s.clone()),
        }
    }

    fn as_userinfo_error(&self) -> OAuthError {
        match self {
            Self::Legacy(s) => OAuthError::UserInfo(s.clone()),
            // Typed variants pass through unchanged on the userinfo path.
            other => other.as_token_error(),
        }
    }
}

/// A configured mock user for [`MockOAuthProvider`].
struct MockOAuthUser {
    subject: String,
    email: String,
    groups: Vec<String>,
    roles: Vec<String>,
}

impl MockOAuthProvider {
    /// Create a new mock provider with the given name.
    ///
    /// The mock issuer is set to `https://{name}.example.com` and the mock
    /// client ID is set to `mock-client-id` by default. Override with
    /// [`with_issuer`](MockOAuthProvider::with_issuer) and
    /// [`with_client_id`](MockOAuthProvider::with_client_id).
    pub fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            issuer_url: format!("https://{name}.example.com"),
            mock_client_id: "mock-client-id".to_string(),
            user: None,
            failure: None,
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            ceremony_timeout: std::time::Duration::from_secs(600),
            clock: Arc::new(SystemClock),
            logout_tokens_minted: AtomicU64::new(0),
            iss_parameter_required: false,
        }
    }

    /// Simulate an IdP that advertises
    /// `authorization_response_iss_parameter_supported` (RFC 9207): a
    /// callback finished without the `iss` parameter is then refused.
    #[must_use]
    pub fn with_iss_parameter_required(mut self) -> Self {
        self.iss_parameter_required = true;
        self
    }

    /// Stamp logout tokens with `clock` instead of the system clock.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Override the mock issuer URL.
    pub fn with_issuer(mut self, issuer: &str) -> Self {
        self.issuer_url = issuer.to_string();
        self
    }

    /// Override the mock client ID.
    pub fn with_client_id(mut self, client_id: &str) -> Self {
        self.mock_client_id = client_id.to_string();
        self
    }

    /// Configure the mock to return claims for a specific user.
    ///
    /// When `exchange_code` or `refresh_token` is called, the mock returns
    /// `OAuthClaims` with these values.
    pub fn with_user(
        mut self,
        sub: &str,
        email: &str,
        groups: Vec<&str>,
        roles: Vec<&str>,
    ) -> Self {
        self.user = Some(MockOAuthUser {
            subject: sub.to_string(),
            email: email.to_string(),
            groups: groups.into_iter().map(|s| s.to_string()).collect(),
            roles: roles.into_iter().map(|s| s.to_string()).collect(),
        });
        self
    }

    /// Configure the mock to simulate a provider error.
    ///
    /// When `exchange_code` or `refresh_token` is called, the mock returns
    /// an `OAuthError::TokenExchange` with this error message. On the
    /// userinfo path, the same string surfaces as `OAuthError::UserInfo`.
    /// For typed variants (`UnsupportedTokenType`, `TokenEndpointTransient`,
    /// `UnknownKid`, `Discovery`) use the dedicated `with_*_failure`
    /// setters below.
    pub fn with_failure(mut self, error: &str) -> Self {
        self.failure = Some(MockFailure::Legacy(error.to_string()));
        self
    }

    /// Mock: simulate an AS that responds to the revocation /
    /// refresh endpoint with `error: "unsupported_token_type"`. Lets
    /// DST tests exercise the typed `OAuthError::UnsupportedTokenType`
    /// branch without standing up a wiremock server.
    pub fn with_unsupported_token_type_failure(mut self) -> Self {
        self.failure = Some(MockFailure::UnsupportedTokenType);
        self
    }

    /// Mock: simulate a 5xx response from a token endpoint (`None` for no
    /// answer at all).
    /// Returned as `OAuthError::TokenEndpointTransient { status }`
    /// so callers can route through the [`OAuthError::is_transient`]
    /// retry hint.
    pub fn with_transient_failure(mut self, status: Option<u16>) -> Self {
        self.failure = Some(MockFailure::TokenEndpointTransient { status });
        self
    }

    /// Mock: simulate a JWT validation failure caused by a
    /// `kid` not present in the cached JWKS. Returns the typed
    /// `OAuthError::UnknownKid(kid)` so DST tests for the
    /// back-channel-logout JWKS-rotation retry path don't need a
    /// real signing key.
    pub fn with_unknown_kid_failure(mut self, kid: impl Into<String>) -> Self {
        self.failure = Some(MockFailure::UnknownKid(kid.into()));
        self
    }

    /// Mock: simulate an OIDC discovery network/parse failure.
    /// Surfaces as `OAuthError::Discovery(msg)`.
    pub fn with_discovery_failure(mut self, msg: impl Into<String>) -> Self {
        self.failure = Some(MockFailure::Discovery(msg.into()));
        self
    }

    /// Override the ceremony timeout the mock advertises. The
    /// `is_oauth_expired` rail in `AuthnService` caps the effective
    /// timeout at the RFC 6749 RECOMMENDED 600 s regardless of this
    /// value; the setter exists so tests can verify the cap
    /// kicks in for over-spec configurations.
    pub fn with_ceremony_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.ceremony_timeout = timeout;
        self
    }

    /// Create a mock OIDC Back-Channel Logout Token JWT for testing.
    ///
    /// Produces an unsigned JWT (alg: "none") with the standard back-channel
    /// logout claims. Use this to test
    /// `BackChannelLogoutHandler` (in `axess_core::federation::backchannel_logout`)
    /// without a real IdP.
    ///
    /// # Arguments
    ///
    /// * `sub`: The OIDC subject (user ID). Pass `None` to omit.
    /// * `sid`: The OIDC session ID. Pass `None` to omit.
    ///
    /// At least one of `sub` or `sid` must be provided per the spec.
    ///
    /// `iat` is read from the clock set by [`with_clock`](Self::with_clock).
    /// The `jti` is `mock-jti-{iat}-{n}` where `n` counts the tokens this
    /// provider has minted, so two tokens in the same second differ.
    pub fn mock_logout_token(&self, sub: Option<&str>, sid: Option<&str>) -> String {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        let header = serde_json::json!({
            "alg": "none",
            "typ": "JWT"
        });

        let now = self.clock.now().timestamp();
        let serial = self.logout_tokens_minted.fetch_add(1, Ordering::Relaxed) + 1;
        let mut payload = serde_json::json!({
            "iss": self.issuer_url,
            "aud": self.mock_client_id,
            "iat": now,
            "jti": format!("mock-jti-{now}-{serial}"),
            "events": {
                "http://schemas.openid.net/event/backchannel-logout": {}
            }
        });

        if let Some(sub) = sub {
            payload["sub"] = serde_json::Value::String(sub.to_string());
        }
        if let Some(sid) = sid {
            payload["sid"] = serde_json::Value::String(sid.to_string());
        }

        let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());

        // Unsigned JWT: header.payload. (empty signature)
        format!("{header_b64}.{payload_b64}.")
    }

    /// Build the `OAuthClaims` from the configured mock user.
    fn build_claims(&self, include_refresh: bool) -> Result<OAuthClaims, OAuthError> {
        if let Some(err) = &self.failure {
            return Err(err.as_token_error());
        }
        let user = self.user.as_ref().ok_or_else(|| {
            OAuthError::TokenExchange("MockOAuthProvider: no user configured".to_string())
        })?;

        let mut additional = serde_json::Map::new();
        if !user.groups.is_empty() {
            additional.insert(
                "groups".to_string(),
                serde_json::Value::Array(
                    user.groups
                        .iter()
                        .map(|g| serde_json::Value::String(g.clone()))
                        .collect(),
                ),
            );
        }
        if !user.roles.is_empty() {
            additional.insert(
                "roles".to_string(),
                serde_json::Value::Array(
                    user.roles
                        .iter()
                        .map(|r| serde_json::Value::String(r.clone()))
                        .collect(),
                ),
            );
        }

        Ok(OAuthClaims {
            provider: self.name.clone(),
            subject: user.subject.clone(),
            email: Some(user.email.clone()),
            email_verified: Some(true),
            name: Some(user.email.clone()),
            groups: user.groups.clone(),
            roles: user.roles.clone(),
            access_token: if include_refresh {
                Some(crate::secret::ZeroizedString::new("mock-access-token"))
            } else {
                None
            },
            refresh_token: if include_refresh {
                Some(crate::secret::ZeroizedString::new("mock-refresh-token"))
            } else {
                None
            },
            oidc_sid: None,
            nonce: None,
            id_token_hint: Some(crate::secret::ZeroizedString::new("mock-id-token-jwt")),
            additional_claims: serde_json::Value::Object(additional),
            dpop_key: None,
        })
    }
}

impl MockOAuthProvider {
    /// Build [`UserInfoClaims`] from the configured mock user.
    fn build_userinfo(&self) -> Result<UserInfoClaims, OAuthError> {
        if let Some(err) = &self.failure {
            return Err(err.as_userinfo_error());
        }
        let user = self.user.as_ref().ok_or_else(|| {
            OAuthError::UserInfo("MockOAuthProvider: no user configured".to_string())
        })?;

        Ok(UserInfoClaims {
            sub: user.subject.clone(),
            email: Some(user.email.clone()),
            email_verified: Some(true),
            name: Some(user.email.clone()),
            given_name: None,
            family_name: None,
            picture: None,
            locale: None,
            additional: serde_json::Value::Object(Default::default()),
        })
    }
}

/// The mock signs no DPoP proofs: a key handed to it is refused rather than
/// dropped, as a real provider without DPoP support must.
fn refuse_key(dpop: Option<DpopSigner<'_>>) -> Result<(), OAuthError> {
    match dpop {
        Some(_) => Err(OAuthError::Config(
            "MockOAuthProvider signs no DPoP proofs; pass no key".to_string(),
        )),
        None => Ok(()),
    }
}

impl OAuthProvider for MockOAuthProvider {
    fn name(&self) -> &Arc<str> {
        &self.name
    }

    fn issuer(&self) -> Option<&str> {
        Some(&self.issuer_url)
    }

    fn client_id(&self) -> Option<&str> {
        Some(&self.mock_client_id)
    }

    fn authorization_response_iss_required(&self) -> bool {
        self.iss_parameter_required
    }

    /// The mock signs no DPoP proofs, so its tokens are never bound.
    fn binds_to_dpop(&self) -> bool {
        false
    }

    /// A synthetic authorization URL whose state, nonce and PKCE verifier come
    /// from `rng`, so a ceremony can begin and finish against the mock.
    fn build_auth_url(
        &self,
        _options: &OAuthLoginOptions,
        rng: &dyn axess_rng::SecureRng,
    ) -> Result<AuthUrlResult, OAuthError> {
        use base64::Engine as _;
        let secret = || {
            let mut raw = [0u8; 32];
            rng.fill_bytes(&mut raw);
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
        };
        let (state, nonce, verifier) = (secret(), secret(), secret());
        let mut url = url::Url::parse(&format!("{}/authorize", self.issuer_url))
            .map_err(|e| OAuthError::Config(format!("mock issuer is not a URL: {e}")))?;
        url.query_pairs_mut()
            .append_pair("client_id", &self.mock_client_id)
            .append_pair("state", &state)
            .append_pair("nonce", &nonce);
        Ok(AuthUrlResult {
            url,
            csrf_state: state,
            nonce,
            pkce_verifier: verifier,
        })
    }

    fn scopes(&self) -> &[String] {
        &self.scopes
    }

    fn ceremony_timeout(&self) -> std::time::Duration {
        self.ceremony_timeout
    }

    fn fetch_userinfo_unchecked<'a>(
        &'a self,
        _access_token: &'a str,
        dpop: Option<DpopSigner<'a>>,
    ) -> Pin<Box<dyn Future<Output = Result<UserInfoClaims, OAuthError>> + Send + 'a>> {
        Box::pin(async move {
            refuse_key(dpop)?;
            self.build_userinfo()
        })
    }

    fn refresh_token_unchecked<'a>(
        &'a self,
        refresh_token: &'a str,
        _original_nonce: Option<&'a str>,
        dpop: Option<DpopSigner<'a>>,
    ) -> Pin<Box<dyn Future<Output = Result<RefreshOutcome, OAuthError>> + Send + 'a>> {
        Box::pin(async move {
            refuse_key(dpop)?;
            let claims = self.build_claims(true)?;
            let access_token = claims
                .access_token
                .clone()
                .unwrap_or_else(|| crate::secret::ZeroizedString::new(String::new()));
            let refresh = claims
                .refresh_token
                .clone()
                .unwrap_or_else(|| crate::secret::ZeroizedString::new(refresh_token.to_string()));
            Ok(RefreshOutcome {
                access_token,
                refresh_token: refresh,
                expires_in: None,
                id_token_claims: Some(claims),
            })
        })
    }

    fn exchange_code<'a>(
        &'a self,
        _code: &'a str,
        _pkce_verifier: String,
        nonce: String,
        dpop: Option<DpopSigner<'a>>,
    ) -> Pin<Box<dyn Future<Output = Result<OAuthClaims, OAuthError>> + Send + 'a>> {
        Box::pin(async move {
            refuse_key(dpop)?;
            let mut claims = self.build_claims(true)?;
            // The ID token a real provider verified carries the login's nonce.
            claims.nonce = Some(nonce);
            Ok(claims)
        })
    }

    /// Test-only: decode the logout token payload without signature verification.
    ///
    /// The trait's default returns an error (fail-closed so custom providers
    /// that forget to override don't accept unsigned tokens). The mock
    /// deliberately skips signature checking so tests can construct
    /// unsigned `alg: "none"` tokens and exercise the claim-validation
    /// logic in `BackChannelLogoutHandler` independently of signing keys.
    fn verify_logout_jwt(&self, token: &str) -> Result<serde_json::Value, OAuthError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(OAuthError::IdTokenValidation(format!(
                "expected 3 JWT segments, got {}",
                parts.len()
            )));
        }
        use base64::Engine as _;
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| OAuthError::IdTokenValidation(format!("base64 decode failed: {e}")))?;
        serde_json::from_slice(&payload_bytes)
            .map_err(|e| OAuthError::IdTokenValidation(format!("JSON parse failed: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload_of(token: &str) -> serde_json::Value {
        MockOAuthProvider::new("any")
            .verify_logout_jwt(token)
            .unwrap()
    }

    #[test]
    fn logout_token_iat_comes_from_the_injected_clock() {
        let clock = axess_clock::testing::MockClock::now();
        let start = clock.now().timestamp();
        let provider = MockOAuthProvider::new("idp").with_clock(Arc::new(clock.clone()));

        let first = payload_of(&provider.mock_logout_token(Some("u"), None));
        assert_eq!(first["iat"], start);

        clock.advance_secs(90);
        let later = payload_of(&provider.mock_logout_token(Some("u"), None));
        assert_eq!(later["iat"], start + 90);
    }

    /// The authorization URL comes back as named fields: the state and nonce
    /// are in the URL, and the verifier is not.
    #[test]
    fn the_authorization_url_result_names_its_fields() {
        let provider = MockOAuthProvider::new("idp");
        let rng = axess_rng::testing::MockRng::new(5);
        let auth = provider
            .build_auth_url(&OAuthLoginOptions::default(), &rng)
            .unwrap();
        let query = auth.url.query().unwrap_or_default().to_owned();
        assert!(
            query.contains(&format!("state={}", auth.csrf_state)),
            "{query}"
        );
        assert!(query.contains(&format!("nonce={}", auth.nonce)), "{query}");
        assert!(!query.contains(&auth.pkce_verifier));
        let shown = format!("{auth:?}");
        assert!(!shown.contains(&auth.pkce_verifier), "{shown}");
    }

    /// `fetch_userinfo` and `refresh_token` on the trait check `sub`; the
    /// unchecked forms are the ones that do not.
    #[tokio::test]
    async fn userinfo_and_refresh_check_the_subject_by_default() {
        let provider =
            MockOAuthProvider::new("idp").with_user("alice", "a@example.com", vec![], vec![]);

        assert!(provider.fetch_userinfo("tok", "alice", None).await.is_ok());
        assert!(matches!(
            provider.fetch_userinfo("tok", "mallory", None).await,
            Err(OAuthError::SubjectMismatch)
        ));
        assert_eq!(
            provider
                .fetch_userinfo_unchecked("tok", None)
                .await
                .unwrap()
                .sub,
            "alice"
        );

        assert!(
            provider
                .refresh_token("rt", "alice", None, None)
                .await
                .is_ok()
        );
        let refused = provider.refresh_token("rt", "mallory", None, None).await;
        assert!(
            matches!(refused, Err(OAuthError::IdTokenValidation(_))),
            "{refused:?}"
        );
        assert!(
            provider
                .refresh_token_unchecked("rt", None, None)
                .await
                .is_ok()
        );
    }

    #[test]
    fn two_logout_tokens_in_one_second_have_different_jtis() {
        let clock = axess_clock::testing::MockClock::now();
        let iat = clock.now().timestamp();
        let provider = MockOAuthProvider::new("idp").with_clock(Arc::new(clock));

        let a = payload_of(&provider.mock_logout_token(Some("u"), None));
        let b = payload_of(&provider.mock_logout_token(Some("u"), None));
        assert_eq!(a["jti"], format!("mock-jti-{iat}-1"));
        assert_eq!(b["jti"], format!("mock-jti-{iat}-2"));
    }

    #[test]
    fn build_claims_omits_groups_key_when_user_groups_empty() {
        let provider = MockOAuthProvider::new("google").with_user(
            "user-1",
            "alice@example.com",
            vec![],
            vec![],
        );
        let claims = provider.build_claims(false).unwrap();
        let additional = claims
            .additional_claims
            .as_object()
            .expect("additional_claims must be an object");
        assert!(
            !additional.contains_key("groups"),
            "empty user.groups must not insert the 'groups' key"
        );
    }

    #[test]
    fn build_claims_inserts_groups_key_when_user_groups_present() {
        let provider = MockOAuthProvider::new("google").with_user(
            "user-1",
            "alice@example.com",
            vec!["engineers"],
            vec![],
        );
        let claims = provider.build_claims(false).unwrap();
        let additional = claims
            .additional_claims
            .as_object()
            .expect("additional_claims must be an object");
        let groups = additional
            .get("groups")
            .expect("'groups' key must be present");
        let arr = groups.as_array().expect("'groups' must be an array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0], "engineers");
    }

    #[test]
    fn build_claims_omits_roles_key_when_user_roles_empty() {
        let provider = MockOAuthProvider::new("google").with_user(
            "user-1",
            "alice@example.com",
            vec![],
            vec![],
        );
        let claims = provider.build_claims(false).unwrap();
        let additional = claims
            .additional_claims
            .as_object()
            .expect("additional_claims must be an object");
        assert!(
            !additional.contains_key("roles"),
            "empty user.roles must not insert the 'roles' key"
        );
    }

    #[test]
    fn build_claims_inserts_roles_key_when_user_roles_present() {
        let provider = MockOAuthProvider::new("google").with_user(
            "user-1",
            "alice@example.com",
            vec![],
            vec!["admin"],
        );
        let claims = provider.build_claims(false).unwrap();
        let additional = claims
            .additional_claims
            .as_object()
            .expect("additional_claims must be an object");
        let roles = additional
            .get("roles")
            .expect("'roles' key must be present");
        let arr = roles.as_array().expect("'roles' must be an array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0], "admin");
    }

    #[test]
    fn scopes_returns_default_oidc_scopes() {
        let provider = MockOAuthProvider::new("google");
        let scopes: Vec<&str> = provider.scopes().iter().map(|s| s.as_str()).collect();
        assert_eq!(scopes, vec!["openid", "email", "profile"]);
    }

    #[test]
    fn ceremony_timeout_returns_configured_value() {
        let provider = MockOAuthProvider::new("google")
            .with_ceremony_timeout(std::time::Duration::from_secs(123));
        assert_eq!(
            provider.ceremony_timeout(),
            std::time::Duration::from_secs(123)
        );
    }

    #[test]
    fn ceremony_timeout_default_is_600_seconds() {
        let provider = MockOAuthProvider::new("google");
        assert_eq!(
            provider.ceremony_timeout(),
            std::time::Duration::from_secs(600)
        );
    }
}
