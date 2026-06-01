//! LDAP bind authentication: verify credentials against Active Directory or
//! any LDAP-compatible directory.
//!
//! # Architecture
//!
//! [`LdapProvider`] is the abstraction. Production code uses
//! [`LdapProviderConfig`] (wraps `ldap3`). Tests use [`MockLdapProvider`].
//!
//! The provider is attached to the orchestrator's `AuthnService` via
//! `with_ldap` and triggered when the current factor is the orchestrator's
//! `FactorKind::LdapBind`. The user submits a `FactorCredential::Password`
//! with the same input but a different verification backend.
//!
//! # Active Directory
//!
//! For AD, set `bind_dn_template` to `"{user}@corp.example.com"` (UPN format)
//! or `"CORP\\{user}"` (down-level logon). For OpenLDAP/389ds, use
//! `"uid={user},ou=people,dc=example,dc=com"`.
//!
//! # Group membership
//!
//! After a successful bind, the provider can optionally search for group
//! memberships. Configure [`LdapGroupSearch`] to extract groups from the
//! directory. The groups are returned in [`LdapBindResult`] for the
//! application to map to roles or Cedar entities.
//!
//! # Health checks
//!
//! `LdapProviderConfig` implements axess-core's `HealthCheck` trait via
//! an extension impl in `axess-core` (local trait, foreign type; allowed
//! by the orphan rule). Adopters using axess-core's composite health
//! aggregator see `LdapProviderConfig` participate without any extra
//! wiring; standalone consumers of `axess-factors::ldap` get the
//! verifier types without the axess-core HealthCheck dep.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

// ── Error ────────────────────────────────────────────────────────────────────

/// Errors returned by the LDAP provider during connect, bind, or search operations.
#[derive(Debug, thiserror::Error)]
pub enum LdapError {
    /// Network-level failure while establishing or using the LDAP connection.
    #[error("LDAP connection failed: {0}")]
    Connection(String),

    /// Bind operation rejected by the directory due to invalid credentials.
    #[error("LDAP bind failed (invalid credentials)")]
    InvalidCredentials,

    /// Directory search failed (e.g. invalid filter or insufficient privileges).
    #[error("LDAP search failed: {0}")]
    Search(String),

    /// Operation exceeded the configured deadline before completing.
    #[error("LDAP operation timed out")]
    Timeout,

    /// Provider configuration is invalid or incomplete.
    #[error("LDAP configuration error: {0}")]
    Config(String),
}

// ── Result types ─────────────────────────────────────────────────────────────

/// Result of a successful LDAP bind.
#[derive(Debug, Clone)]
pub struct LdapBindResult {
    /// The distinguished name of the authenticated user.
    pub bind_dn: String,
    /// Group memberships (empty if group search is not configured).
    pub groups: Vec<String>,
}

// ── LdapProvider trait ───────────────────────────────────────────────────────

/// Abstraction over LDAP bind operations.
///
/// Production: [`LdapProviderConfig`].
/// Tests: [`MockLdapProvider`].
pub trait LdapProvider: Send + Sync + 'static {
    /// Attempt a simple bind with the given DN and password.
    ///
    /// `identifier` is the user's login name (before template expansion),
    /// used for group search filters. `bind_dn` is the fully-constructed DN.
    ///
    /// Returns the bind result (including group memberships if configured)
    /// on success, or [`LdapError::InvalidCredentials`] on wrong password.
    fn verify_bind<'a>(
        &'a self,
        identifier: &'a str,
        bind_dn: &'a str,
        password: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<LdapBindResult, LdapError>> + Send + 'a>>;

    /// Construct the bind DN for a given user identifier.
    ///
    /// Uses the provider's `bind_dn_template` to map a login identifier
    /// (e.g. `"alice"`) to a bind DN (e.g. `"alice@corp.example.com"`).
    fn build_bind_dn(&self, identifier: &str) -> String;
}

// ── Group search config ──────────────────────────────────────────────────────

/// Configuration for LDAP group membership searches after a successful bind.
#[derive(Debug, Clone)]
pub struct LdapGroupSearch {
    /// Base DN for the group search (e.g. `"ou=groups,dc=example,dc=com"`).
    pub base_dn: String,
    /// LDAP search filter. `{dn}` is replaced with the user's bind DN,
    /// `{user}` with the user identifier.
    /// Example: `"(member={dn})"` or `"(memberUid={user})"`.
    pub filter_template: String,
    /// Attribute containing the group name (e.g. `"cn"`).
    pub group_attr: String,
}

// ── LdapProviderConfig ───────────────────────────────────────────────────────

/// Production LDAP provider wrapping the `ldap3` crate.
///
/// # TLS requirements
///
/// LDAP simple bind transmits passwords in the protocol data unit. Always use
/// TLS to protect credentials on the wire:
///
/// - **Preferred:** `ldaps://` URLs (TLS from the first byte, port 636).
/// - **Alternative:** `ldap://` with `.with_starttls()` (upgrades to TLS after connect, port 389).
///
/// Certificate validation uses the system CA trust store (via rustls). For
/// private CAs (common in enterprise AD deployments), install the CA
/// certificate in the OS trust store or use the `SSL_CERT_FILE` /
/// `SSL_CERT_DIR` environment variables.
///
/// Plain `ldap://` without STARTTLS sends credentials in cleartext and must
/// not be used outside localhost development.
pub struct LdapProviderConfig {
    /// LDAP server URL (e.g. `"ldap://ad.example.com:389"` or
    /// `"ldaps://ad.example.com:636"`).
    pub url: String,
    /// Template for constructing the bind DN from the user identifier.
    /// `{user}` is replaced with the login identifier.
    ///
    /// Active Directory: `"{user}@corp.example.com"` (UPN) or `"CORP\\{user}"`
    /// OpenLDAP: `"uid={user},ou=people,dc=example,dc=com"`
    pub bind_dn_template: String,
    /// Use STARTTLS on plain LDAP connections. Ignored for `ldaps://` URLs.
    pub starttls: bool,
    /// Connection timeout. Default: 5 seconds.
    pub connection_timeout: Duration,
    /// Optional group membership search after successful bind.
    pub group_search: Option<LdapGroupSearch>,
}

impl LdapProviderConfig {
    /// Create a new LDAP provider configuration.
    ///
    /// # Arguments
    ///
    /// * `url`: LDAP server URL (`ldap://` or `ldaps://`)
    /// * `bind_dn_template`: template with `{user}` placeholder
    pub fn new(url: impl Into<String>, bind_dn_template: impl Into<String>) -> Self {
        let url = url.into();
        let is_ldaps = url.starts_with("ldaps://");
        let is_localhost = url.contains("://localhost")
            || url.contains("://127.0.0.1")
            || url.contains("://[::1]");
        if !is_ldaps && !is_localhost {
            tracing::warn!(
                "LdapProviderConfig: using plain ldap:// without STARTTLS. \
                 Call .with_starttls() to encrypt credentials on the wire. \
                 Plain LDAP is only safe for localhost development."
            );
        }
        Self {
            url,
            bind_dn_template: bind_dn_template.into(),
            starttls: false,
            connection_timeout: Duration::from_secs(5),
            group_search: None,
        }
    }

    /// Enable STARTTLS on plain LDAP connections.
    pub fn with_starttls(mut self) -> Self {
        self.starttls = true;
        self
    }

    /// Set the connection timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.connection_timeout = timeout;
        self
    }

    /// Configure group membership search after successful bind.
    pub fn with_group_search(mut self, search: LdapGroupSearch) -> Self {
        self.group_search = Some(search);
        self
    }

    /// Perform group search using the bound connection.
    async fn search_groups(
        &self,
        ldap: &mut ldap3::Ldap,
        bind_dn: &str,
        identifier: &str,
    ) -> Result<Vec<String>, LdapError> {
        let search = match &self.group_search {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };

        // RFC 4515: escape special characters in user-controlled values
        // before substituting into LDAP search filters.
        let filter = search
            .filter_template
            .replace("{dn}", &ldap_filter_escape(bind_dn))
            .replace("{user}", &ldap_filter_escape(identifier));

        let (results, _) = ldap
            .search(
                &search.base_dn,
                ldap3::Scope::Subtree,
                &filter,
                vec![search.group_attr.as_str()],
            )
            .await
            .map_err(|e| LdapError::Search(e.to_string()))?
            .success()
            .map_err(|e| LdapError::Search(e.to_string()))?;

        let groups = results
            .into_iter()
            .filter_map(|entry| {
                let se = ldap3::SearchEntry::construct(entry);
                se.attrs
                    .get(&search.group_attr)
                    .and_then(|vals| vals.first().cloned())
            })
            .collect();

        Ok(groups)
    }
}

impl LdapProvider for LdapProviderConfig {
    fn verify_bind<'a>(
        &'a self,
        identifier: &'a str,
        bind_dn: &'a str,
        password: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<LdapBindResult, LdapError>> + Send + 'a>> {
        Box::pin(async move {
            let settings = ldap3::LdapConnSettings::new()
                .set_conn_timeout(self.connection_timeout)
                .set_starttls(self.starttls);

            let (conn, mut ldap) = tokio::time::timeout(
                self.connection_timeout,
                ldap3::LdapConnAsync::with_settings(settings, &self.url),
            )
            .await
            .map_err(|_| LdapError::Timeout)?
            .map_err(|e| LdapError::Connection(e.to_string()))?;

            // Drive the connection in the background.
            tokio::spawn(async move { conn.drive().await });

            // Attempt simple bind.
            let result = ldap
                .simple_bind(bind_dn, password)
                .await
                .map_err(|e| LdapError::Connection(e.to_string()))?;

            if result.rc != 0 {
                // RC 49 = invalid credentials (standard LDAP result code).
                let _ = ldap.unbind().await;
                return Err(LdapError::InvalidCredentials);
            }

            // Optionally search for group memberships using the original
            // identifier (not parsed from the DN; avoids fragile extraction).
            let groups = self.search_groups(&mut ldap, bind_dn, identifier).await?;

            let _ = ldap.unbind().await;

            Ok(LdapBindResult {
                bind_dn: bind_dn.to_string(),
                groups,
            })
        })
    }

    fn build_bind_dn(&self, identifier: &str) -> String {
        self.bind_dn_template
            .replace("{user}", &ldap_dn_escape(identifier))
    }
}

// ── MockLdapProvider ─────────────────────────────────────────────────────────

/// Test double for [`LdapProvider`]. Configure accepted credentials via
/// [`with_user`](MockLdapProvider::with_user); unconfigured users and
/// wrong passwords are rejected.
pub struct MockLdapProvider {
    bind_dn_template: String,
    users: std::collections::HashMap<String, MockLdapUser>,
}

struct MockLdapUser {
    password: String,
    groups: Vec<String>,
}

impl MockLdapProvider {
    /// Create a new mock with the given bind DN template.
    pub fn new(bind_dn_template: impl Into<String>) -> Self {
        Self {
            bind_dn_template: bind_dn_template.into(),
            users: std::collections::HashMap::new(),
        }
    }

    /// Register a user that will pass LDAP bind verification.
    ///
    /// `identifier` is the login name (before template expansion).
    /// `password` is the expected password.
    /// `groups` are the group names returned after bind.
    pub fn with_user(mut self, identifier: &str, password: &str, groups: Vec<&str>) -> Self {
        let bind_dn = self
            .bind_dn_template
            .replace("{user}", &ldap_dn_escape(identifier));
        self.users.insert(
            bind_dn,
            MockLdapUser {
                password: password.to_string(),
                groups: groups.into_iter().map(|s| s.to_string()).collect(),
            },
        );
        self
    }
}

impl LdapProvider for MockLdapProvider {
    fn verify_bind<'a>(
        &'a self,
        identifier: &'a str,
        bind_dn: &'a str,
        password: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<LdapBindResult, LdapError>> + Send + 'a>> {
        Box::pin(async move {
            let user = self.users.get(bind_dn).ok_or_else(|| {
                tracing::debug!(
                    target: "axess::testing::mock_ldap",
                    identifier,
                    bind_dn,
                    "MockLdapProvider rejected: bind_dn not registered",
                );
                LdapError::InvalidCredentials
            })?;

            // Constant-time comparison even in test code; good practice and
            // prevents timing side-channels in development/staging environments
            // that may use the mock with real traffic.
            use subtle::ConstantTimeEq;
            let matches: bool = user.password.as_bytes().ct_eq(password.as_bytes()).into();
            if !matches {
                return Err(LdapError::InvalidCredentials);
            }

            Ok(LdapBindResult {
                bind_dn: bind_dn.to_string(),
                groups: user.groups.clone(),
            })
        })
    }

    fn build_bind_dn(&self, identifier: &str) -> String {
        self.bind_dn_template
            .replace("{user}", &ldap_dn_escape(identifier))
    }
}

// ── LDAP filter escaping (RFC 4515) ──────────────────────────────────────────

/// Escape a string for safe substitution into an LDAP Distinguished Name
/// per RFC 4514 section 2.4.
///
/// Escapes: NUL (as `\00`), the DN special characters `" + ,; < > \`, plus
/// `#` at the start of the string and space at the start or end. All other
/// printable characters pass through unchanged. Non-ASCII bytes are
/// hex-escaped as `\XX`.
///
/// Safe for both DN templates (`uid={user},ou=…`) and UPN templates
/// (`{user}@corp.example.com`); a valid UPN local-part contains none of
/// these special characters, so the escape is a no-op in that case.
fn ldap_dn_escape(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    for (i, &byte) in bytes.iter().enumerate() {
        match byte {
            0 => out.push_str("\\00"),
            b'"' | b'+' | b',' | b';' | b'<' | b'>' | b'\\' => {
                out.push('\\');
                out.push(byte as char);
            }
            b'#' if i == 0 => out.push_str("\\#"),
            b' ' if i == 0 || i + 1 == len => out.push_str("\\ "),
            0x21..=0x7E => out.push(byte as char),
            // Non-ASCII or control bytes: hex-escape.
            _ => out.push_str(&format!("\\{byte:02x}")),
        }
    }
    out
}

/// Escape a string for safe inclusion in an LDAP search filter per RFC 4515.
///
/// Escapes all bytes outside the printable ASCII range (0x20..=0x7E) plus the
/// four filter-special characters (`*`, `(`, `)`, `\`). Each escaped byte is
/// written as `\XX` where XX is the two-digit hex value.
fn ldap_filter_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &byte in input.as_bytes() {
        match byte {
            // Printable ASCII excluding filter-special characters.
            0x20..=0x7E if byte != b'*' && byte != b'(' && byte != b')' && byte != b'\\' => {
                out.push(byte as char);
            }
            // Everything else: control chars, high-bit bytes, and filter specials.
            _ => {
                out.push_str(&format!("\\{byte:02x}"));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_accepts_correct_password() {
        let provider = MockLdapProvider::new("uid={user},ou=people,dc=example,dc=com").with_user(
            "alice",
            "Gnomes2+",
            vec!["engineers", "admins"],
        );

        let dn = provider.build_bind_dn("alice");
        assert_eq!(dn, "uid=alice,ou=people,dc=example,dc=com");

        let result = provider
            .verify_bind("alice", &dn, "Gnomes2+")
            .await
            .unwrap();
        assert_eq!(result.bind_dn, dn);
        assert_eq!(result.groups, vec!["engineers", "admins"]);
    }

    #[tokio::test]
    async fn mock_rejects_wrong_password() {
        let provider =
            MockLdapProvider::new("{user}@corp.example.com").with_user("bob", "correct", vec![]);

        let dn = provider.build_bind_dn("bob");
        let err = provider.verify_bind("bob", &dn, "wrong").await.unwrap_err();
        assert!(matches!(err, LdapError::InvalidCredentials));
    }

    #[tokio::test]
    async fn mock_rejects_unknown_user() {
        let provider = MockLdapProvider::new("{user}@corp.example.com");

        let dn = provider.build_bind_dn("nobody");
        let err = provider
            .verify_bind("nobody", &dn, "anything")
            .await
            .unwrap_err();
        assert!(matches!(err, LdapError::InvalidCredentials));
    }

    #[test]
    fn ad_upn_template() {
        let provider = MockLdapProvider::new("{user}@corp.example.com");
        assert_eq!(provider.build_bind_dn("alice"), "alice@corp.example.com");
    }

    #[test]
    fn openldap_dn_template() {
        let provider = MockLdapProvider::new("uid={user},ou=people,dc=example,dc=com");
        assert_eq!(
            provider.build_bind_dn("bob"),
            "uid=bob,ou=people,dc=example,dc=com"
        );
    }

    #[test]
    fn ldap_dn_escape_passes_through_plain_ascii() {
        assert_eq!(ldap_dn_escape("alice"), "alice");
        assert_eq!(ldap_dn_escape("user.name_99"), "user.name_99");
    }

    #[test]
    fn ldap_dn_escape_handles_null_byte() {
        assert_eq!(ldap_dn_escape("a\0b"), "a\\00b");
    }

    #[test]
    fn ldap_dn_escape_handles_dn_special_chars() {
        for (input, expected) in [
            ("a\"b", "a\\\"b"),
            ("a+b", "a\\+b"),
            ("a,b", "a\\,b"),
            ("a;b", "a\\;b"),
            ("a<b", "a\\<b"),
            ("a>b", "a\\>b"),
            ("a\\b", "a\\\\b"),
        ] {
            assert_eq!(ldap_dn_escape(input), expected, "input={input:?}");
        }
    }

    #[test]
    fn ldap_dn_escape_hash_only_at_start_of_dn() {
        assert_eq!(ldap_dn_escape("#alice"), "\\#alice");
        assert_eq!(ldap_dn_escape("a#b"), "a#b");
        assert_eq!(ldap_dn_escape("alice#"), "alice#");
    }

    #[test]
    fn ldap_dn_escape_space_at_dn_boundary() {
        // Leading/trailing spaces use the `\ ` form (line 437 match arm).
        assert_eq!(ldap_dn_escape(" alice"), "\\ alice");
        assert_eq!(ldap_dn_escape("alice "), "alice\\ ");
        assert_eq!(ldap_dn_escape(" "), "\\ ");
        // Interior spaces don't hit the boundary arm; 0x20 is below the
        // 0x21..=0x7E printable range, so they hex-escape via the fallback.
        assert_eq!(ldap_dn_escape("a b"), "a\\20b");
    }

    #[test]
    fn ldap_dn_escape_non_ascii_hex_escapes() {
        assert_eq!(ldap_dn_escape("ü"), "\\c3\\bc");
    }

    #[test]
    fn ldap_provider_config_build_bind_dn_substitutes_user() {
        let cfg = LdapProviderConfig::new(
            "ldap://localhost:389",
            "uid={user},ou=people,dc=example,dc=com",
        );
        assert_eq!(
            cfg.build_bind_dn("alice"),
            "uid=alice,ou=people,dc=example,dc=com"
        );
    }

    #[test]
    fn ldap_provider_config_build_bind_dn_escapes_user() {
        let cfg = LdapProviderConfig::new("ldap://localhost:389", "uid={user},ou=people");
        assert_eq!(cfg.build_bind_dn("a,b"), "uid=a\\,b,ou=people");
    }

    #[test]
    fn ldap_filter_escape_special_chars() {
        assert_eq!(ldap_filter_escape("alice"), "alice");
        assert_eq!(ldap_filter_escape("*)(|(*)"), "\\2a\\29\\28|\\28\\2a\\29");
        assert_eq!(ldap_filter_escape("user\\name"), "user\\5cname");
        assert_eq!(ldap_filter_escape("a\0b"), "a\\00b");
        // Control characters must be escaped.
        assert_eq!(ldap_filter_escape("a\tb"), "a\\09b");
        assert_eq!(ldap_filter_escape("a\nb"), "a\\0ab");
        assert_eq!(ldap_filter_escape("a\rb"), "a\\0db");
        // High-bit bytes (UTF-8 multi-byte) must be escaped.
        assert_eq!(ldap_filter_escape("ü"), "\\c3\\bc");
    }
}
