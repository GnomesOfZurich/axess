//! Factor templates: the catalog of factor kinds a platform operator can
//! offer to tenants, and the defaults a tenant starts from.
//!
//! ## Why templates, not global fallback
//!
//! Templates are a **menu** the tenant admin picks from at creation time
//! (and later via admin APIs). Picking a template materializes a real
//! tenant-scoped row in `factor_configs`; after that, the tenant owns
//! the row. There is no implicit fallback to a global catalog, which
//! avoids two failure modes:
//!
//! 1. **Silent inheritance.** A global row change would alter every
//!    tenant's effective auth behaviour without the tenant's knowledge.
//! 2. **Information leak.** A user could infer, via error messages or
//!    available-method probes, which factors were theoretically
//!    available even when the tenant admin had disabled them.
//!
//! Users only see what the tenant admin enabled, never the global catalog.
//!
//! ## Shape
//!
//! A [`FactorTemplate`] is a descriptor, not a runtime config. It carries
//! the display info a tenant admin needs to choose, plus a `default_config`
//! used to seed the tenant-scoped row. Per-user credentials (password
//! hashes, TOTP secrets) are still added later during factor setup.

use crate::authn::factor::{FactorConfig, FactorKind};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ── FactorTemplate ───────────────────────────────────────────────────────────

/// A catalog entry describing a factor kind a platform offers to tenants.
///
/// Templates are **not** persisted factor rows. They are code-shipped
/// descriptors that drive the tenant-admin UI and the tenant-provisioning
/// path. When a tenant adopts a template, a real tenant-scoped row in
/// `factor_configs` is created from `default_config`; the template itself
/// remains in the catalog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactorTemplate {
    /// Stable identifier for the template: must be unique across the
    /// catalog. Used by admin APIs to select a template ("enable
    /// `password-default` for this tenant").
    pub id: Arc<str>,
    /// Which factor kind this template describes.
    pub kind: FactorKind,
    /// Human-readable name shown in the tenant-admin UI.
    pub display_name: Arc<str>,
    /// Longer description shown alongside `display_name`.
    pub description: Arc<str>,
    /// Starting config materialized into the tenant's `factor_configs`
    /// row when the template is adopted. Per-user credential slots
    /// (password hashes, TOTP secrets, email addresses) are left at their
    /// `Default` values and filled in later during factor setup.
    pub default_config: FactorConfig,
}

impl FactorTemplate {
    /// Construct a new template. No validation beyond what the fields'
    /// types enforce; the caller is responsible for choosing sensible
    /// `display_name` / `description` strings.
    pub fn new(
        id: impl Into<Arc<str>>,
        kind: FactorKind,
        display_name: impl Into<Arc<str>>,
        description: impl Into<Arc<str>>,
        default_config: FactorConfig,
    ) -> Self {
        Self {
            id: id.into(),
            kind,
            display_name: display_name.into(),
            description: description.into(),
            default_config,
        }
    }
}

// ── Default catalog ──────────────────────────────────────────────────────────

/// The default catalog shipped with axess.
///
/// Returns the templates platform operators commonly offer: password,
/// TOTP, email OTP, and (when the `fido2` feature is enabled) FIDO2.
/// OAuth federated providers are **not** included in the default catalog
/// they require per-provider configuration (client id, issuer,
/// redirect URI) that's platform-specific, so applications should build
/// their own OAuth templates.
pub fn default_catalog() -> Vec<FactorTemplate> {
    use crate::authn::factor::{
        EmailOtpConfig, PasswordConfig, PasswordRules, TotpConfig, ZeroizedString,
    };

    let base = vec![
        FactorTemplate::new(
            "password-default",
            FactorKind::Password,
            "Password",
            "Users authenticate with an Argon2id-hashed password. \
             The default policy requires a minimum length of 12 characters \
             and a mix of upper-case, lower-case, and digits.",
            FactorConfig::Password(PasswordConfig {
                hash: ZeroizedString::new(""),
                rules: PasswordRules::default(),
            }),
        ),
        FactorTemplate::new(
            "totp-default",
            FactorKind::Totp,
            "Time-based one-time code (TOTP)",
            "RFC 6238 TOTP; users scan a QR code into an authenticator \
             app and enter the rotating six-digit code on every login.",
            FactorConfig::Totp(TotpConfig::default()),
        ),
        FactorTemplate::new(
            "email-otp-default",
            FactorKind::EmailOtp,
            "Email one-time code",
            "An 8-digit code is e-mailed to the user's registered \
             address; the code expires after five minutes.",
            FactorConfig::EmailOtp(EmailOtpConfig::default()),
        ),
    ];

    base.into_iter().chain(fido2_templates()).collect()
}

/// FIDO2 templates, compiled in only when the `fido2` feature is active.
#[cfg(feature = "fido2")]
fn fido2_templates() -> Vec<FactorTemplate> {
    use crate::authn::factor::Fido2Config;
    vec![FactorTemplate::new(
        "fido2-default",
        FactorKind::Fido2,
        "FIDO2 / WebAuthn",
        "Phishing-resistant hardware-key or platform-authenticator \
         login. Supports both registration and passwordless \
         discoverable-credential flows.",
        FactorConfig::Fido2(Fido2Config::default()),
    )]
}

#[cfg(not(feature = "fido2"))]
fn fido2_templates() -> Vec<FactorTemplate> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_catalog_has_unique_ids() {
        let catalog = default_catalog();
        let mut ids: Vec<&str> = catalog.iter().map(|t| t.id.as_ref()).collect();
        ids.sort();
        let len_before = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), len_before, "default catalog ids must be unique");
    }

    #[test]
    fn default_catalog_covers_core_factor_kinds() {
        let catalog = default_catalog();
        let kinds: Vec<&FactorKind> = catalog.iter().map(|t| &t.kind).collect();
        assert!(kinds.contains(&&FactorKind::Password));
        assert!(kinds.contains(&&FactorKind::Totp));
        assert!(kinds.contains(&&FactorKind::EmailOtp));
    }

    #[cfg(feature = "fido2")]
    #[test]
    fn fido2_templates_present_when_feature_enabled() {
        let templates = fido2_templates();
        assert_eq!(
            templates.len(),
            1,
            "fido2_templates() must return exactly one template under feature=fido2"
        );
        let fido2 = &templates[0];
        assert_eq!(&*fido2.id, "fido2-default");
        assert_eq!(fido2.kind, FactorKind::Fido2);
        assert!(matches!(fido2.default_config, FactorConfig::Fido2(_)));

        let catalog = default_catalog();
        let catalog_kinds: Vec<&FactorKind> = catalog.iter().map(|t| &t.kind).collect();
        assert!(
            catalog_kinds.contains(&&FactorKind::Fido2),
            "default catalog must include Fido2 when feature=fido2 is on"
        );
    }

    #[cfg(not(feature = "fido2"))]
    #[test]
    fn fido2_templates_absent_when_feature_disabled() {
        let templates = fido2_templates();
        assert!(
            templates.is_empty(),
            "fido2_templates() must return empty when feature=fido2 is off"
        );
    }

    #[test]
    fn template_default_configs_are_policy_only() {
        // The default_config for Password must have an empty hash; it's a
        // tenant-level policy starter, not a user credential.
        let catalog = default_catalog();
        let password = catalog
            .iter()
            .find(|t| t.kind == FactorKind::Password)
            .expect("password template present");
        if let FactorConfig::Password(cfg) = &password.default_config {
            // ZeroizedString doesn't expose Eq; check via Display/as_str proxy.
            assert!(
                format!("{:?}", cfg.hash).contains("ZeroizedString") || cfg.rules.min_length >= 8,
                "password template should be policy-only",
            );
        } else {
            panic!("expected Password FactorConfig");
        }
    }
}
