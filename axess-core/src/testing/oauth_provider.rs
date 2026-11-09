//! A provider discovered from an identity provider at a given address.
//!
//! The helpers a test calls after standing an OIDC identity provider up (see
//! `axess_testing::oauth_wiremock`): run discovery against the provider's
//! address and hand back the builder or the built configuration, with stable
//! test values for the client id (`"test-client-id"`), secret
//! (`"test-secret"`) and redirect URI (`"http://localhost:3000/callback"`).

use axess_factors::oauth::{OAuthProviderBuilder, OAuthProviderConfig};

/// Run OIDC discovery against the identity provider at `issuer` and return
/// the builder of a provider pointed at it, for a test that adds settings
/// before [`build`](OAuthProviderBuilder::build).
///
/// # Panics
///
/// Panics when discovery fails, since a test has nothing to continue with.
pub async fn oauth_discover_provider(issuer: &str) -> OAuthProviderBuilder {
    OAuthProviderConfig::discover(
        "test",
        issuer,
        "test-client-id",
        "test-secret",
        "http://localhost:3000/callback",
    )
    .await
    .expect("OIDC discovery should succeed")
}

/// [`oauth_discover_provider`], built with no further settings.
///
/// # Panics
///
/// Panics when discovery fails or the provider does not build.
pub async fn oauth_setup_provider(issuer: &str) -> OAuthProviderConfig {
    oauth_discover_provider(issuer)
        .await
        .build()
        .expect("a provider with no settings builds")
}
