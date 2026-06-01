//! Ready-made [`SocialProvider`] constructors for popular non-OIDC
//! IdPs. Adopters copy the function that matches their provider into
//! their own code, or depend on this module directly.
//!
//! Each constructor is ~30 lines: provider URLs, scope list, and a
//! claim mapper that translates the provider's userinfo response into
//! normalised [`SocialClaims`]. The pattern is uniform across
//! providers; only the URLs, the scope vocabulary, and the claim
//! shapes differ.
//!
//! # Why these and not others
//!
//! GitHub, Discord, Twitter/X, Spotify, and Reddit are the five most
//! commonly requested social-login providers that do not support
//! OIDC. Add your own provider by following the same shape: see
//! [`crate::providers::reddit`] for the simplest case, then adapt.
//!
//! # Security reminder
//!
//! All providers here use plain OAuth 2.0; claims come from a
//! TLS-trusted userinfo endpoint, not from a signed assertion. See
//! [`axess::social`](axess::social) module docs for the security
//! delta vs OIDC.

use axess::social::{SocialClaims, SocialError, SocialProvider, SocialProviderConfig};

/// Function pointer type for static claim-mapper helpers. Using a
/// concrete `fn` (rather than `impl Fn`) keeps the returned
/// `SocialProvider` type nameable, which is useful for adopters that
/// want to hold these in a `HashMap<&str, Provider>` or similar.
pub type MapperFn = fn(&serde_json::Value) -> Result<SocialClaims, SocialError>;
pub type Provider = SocialProvider<MapperFn>;

// ── GitHub ───────────────────────────────────────────────────────────

/// `https://api.github.com/user` returns the user's numeric `id`,
/// `login` (username), `email` (when public or `user:email` scope
/// granted), and `name`.
///
/// Scope `read:user` reads the basic profile; `user:email` returns
/// the email even when the user has hidden it from the public profile.
pub fn github(
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
    redirect_uri: impl Into<String>,
) -> Provider {
    SocialProvider::new(
        SocialProviderConfig {
            name: "github".into(),
            authorization_endpoint: "https://github.com/login/oauth/authorize".into(),
            token_endpoint: "https://github.com/login/oauth/access_token".into(),
            userinfo_endpoint: "https://api.github.com/user".into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            scopes: vec!["read:user".into(), "user:email".into()],
        },
        github_mapper,
    )
}

fn github_mapper(raw: &serde_json::Value) -> Result<SocialClaims, SocialError> {
    let id = raw
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| SocialError::ClaimMapping("GitHub userinfo missing numeric `id`".into()))?;
    Ok(SocialClaims {
        subject: id.to_string(),
        email: raw.get("email").and_then(|v| v.as_str()).map(String::from),
        display_name: raw.get("name").and_then(|v| v.as_str()).map(String::from),
        raw: raw.clone(),
    })
}

// ── Discord ──────────────────────────────────────────────────────────

/// `https://discord.com/api/users/@me` returns the user's snowflake
/// `id` (string), `username`, `discriminator`, `email`, and
/// `verified` (email-verified flag).
///
/// Scope `identify` returns the basic profile; `email` adds the
/// email. Discord requires both scopes for email.
pub fn discord(
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
    redirect_uri: impl Into<String>,
) -> Provider {
    SocialProvider::new(
        SocialProviderConfig {
            name: "discord".into(),
            authorization_endpoint: "https://discord.com/api/oauth2/authorize".into(),
            token_endpoint: "https://discord.com/api/oauth2/token".into(),
            userinfo_endpoint: "https://discord.com/api/users/@me".into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            scopes: vec!["identify".into(), "email".into()],
        },
        discord_mapper,
    )
}

fn discord_mapper(raw: &serde_json::Value) -> Result<SocialClaims, SocialError> {
    let id = raw
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SocialError::ClaimMapping("Discord userinfo missing string `id`".into()))?;
    // Discord only returns `email` if `verified=true`; trust their flag.
    let verified = raw
        .get("verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let email = if verified {
        raw.get("email").and_then(|v| v.as_str()).map(String::from)
    } else {
        None
    };
    Ok(SocialClaims {
        subject: id.to_string(),
        email,
        display_name: raw
            .get("global_name")
            .or_else(|| raw.get("username"))
            .and_then(|v| v.as_str())
            .map(String::from),
        raw: raw.clone(),
    })
}

// ── Twitter / X ──────────────────────────────────────────────────────

/// `https://api.twitter.com/2/users/me` returns the user under a
/// `data` envelope: `data.id` (UUID-like string), `data.username`,
/// `data.name`.
///
/// Twitter **requires** PKCE (covered by `SocialProvider` default).
/// Email is not exposed via the OAuth 2.0 user endpoint at all
/// regardless of scope; Twitter forces a separate
/// `account/verify_credentials` v1.1 call requiring elevated access.
/// This recipe leaves email as `None`.
///
/// Scopes: `tweet.read` is the minimum for `users/me`; `users.read`
/// is implied. Adjust per your read needs.
pub fn twitter_x(
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
    redirect_uri: impl Into<String>,
) -> Provider {
    SocialProvider::new(
        SocialProviderConfig {
            name: "twitter_x".into(),
            authorization_endpoint: "https://twitter.com/i/oauth2/authorize".into(),
            token_endpoint: "https://api.twitter.com/2/oauth2/token".into(),
            userinfo_endpoint: "https://api.twitter.com/2/users/me".into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            scopes: vec!["tweet.read".into(), "users.read".into()],
        },
        twitter_x_mapper,
    )
}

fn twitter_x_mapper(raw: &serde_json::Value) -> Result<SocialClaims, SocialError> {
    let data = raw.get("data").ok_or_else(|| {
        SocialError::ClaimMapping("Twitter userinfo missing `data` envelope".into())
    })?;
    let id = data
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SocialError::ClaimMapping("Twitter `data.id` missing".into()))?;
    Ok(SocialClaims {
        subject: id.to_string(),
        email: None, // Not available through OAuth 2.0 user-context.
        display_name: data.get("name").and_then(|v| v.as_str()).map(String::from),
        raw: raw.clone(),
    })
}

// ── Spotify ──────────────────────────────────────────────────────────

/// `https://api.spotify.com/v1/me` returns the user's `id` (string),
/// `display_name`, `email`, and country / subscription tier metadata.
///
/// Scope `user-read-email` is required for `email`;
/// `user-read-private` covers the profile fields.
pub fn spotify(
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
    redirect_uri: impl Into<String>,
) -> Provider {
    SocialProvider::new(
        SocialProviderConfig {
            name: "spotify".into(),
            authorization_endpoint: "https://accounts.spotify.com/authorize".into(),
            token_endpoint: "https://accounts.spotify.com/api/token".into(),
            userinfo_endpoint: "https://api.spotify.com/v1/me".into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            scopes: vec!["user-read-email".into(), "user-read-private".into()],
        },
        spotify_mapper,
    )
}

fn spotify_mapper(raw: &serde_json::Value) -> Result<SocialClaims, SocialError> {
    let id = raw
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SocialError::ClaimMapping("Spotify userinfo missing string `id`".into()))?;
    Ok(SocialClaims {
        subject: id.to_string(),
        email: raw.get("email").and_then(|v| v.as_str()).map(String::from),
        display_name: raw
            .get("display_name")
            .and_then(|v| v.as_str())
            .map(String::from),
        raw: raw.clone(),
    })
}

// ── Reddit ───────────────────────────────────────────────────────────

/// `https://oauth.reddit.com/api/v1/me` returns the user's `id`
/// (base36 string), `name` (username), and account metadata.
///
/// Reddit does **not** expose the user's email through the OAuth 2.0
/// API; claim mapper leaves it `None`.
///
/// Scope `identity` is required for `api/v1/me`. Reddit also requires
/// a custom `User-Agent` (per their API rules); wire one via
/// [`SocialProvider::with_http_client`].
pub fn reddit(
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
    redirect_uri: impl Into<String>,
) -> Provider {
    SocialProvider::new(
        SocialProviderConfig {
            name: "reddit".into(),
            authorization_endpoint: "https://www.reddit.com/api/v1/authorize".into(),
            token_endpoint: "https://www.reddit.com/api/v1/access_token".into(),
            userinfo_endpoint: "https://oauth.reddit.com/api/v1/me".into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            scopes: vec!["identity".into()],
        },
        reddit_mapper,
    )
}

fn reddit_mapper(raw: &serde_json::Value) -> Result<SocialClaims, SocialError> {
    let id = raw
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SocialError::ClaimMapping("Reddit userinfo missing string `id`".into()))?;
    Ok(SocialClaims {
        subject: id.to_string(),
        email: None, // Reddit does not expose email via OAuth 2.0.
        display_name: raw.get("name").and_then(|v| v.as_str()).map(String::from),
        raw: raw.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Smoke tests: each constructor builds a Provider. Catches
    // accidental URL typos / scope-list breakage at compile time
    // plus a single resolution check that the type system holds.

    #[test]
    fn github_constructor_builds() {
        let _: Provider = github("id", "secret", "https://app.example/cb");
    }

    #[test]
    fn discord_constructor_builds() {
        let _: Provider = discord("id", "secret", "https://app.example/cb");
    }

    #[test]
    fn twitter_x_constructor_builds() {
        let _: Provider = twitter_x("id", "secret", "https://app.example/cb");
    }

    #[test]
    fn spotify_constructor_builds() {
        let _: Provider = spotify("id", "secret", "https://app.example/cb");
    }

    #[test]
    fn reddit_constructor_builds() {
        let _: Provider = reddit("id", "secret", "https://app.example/cb");
    }

    #[test]
    fn github_mapper_extracts_subject() {
        let raw = serde_json::json!({"id": 12345, "login": "octocat", "email": "o@c"});
        let claims = github_mapper(&raw).unwrap();
        assert_eq!(claims.subject, "12345");
        assert_eq!(claims.email.as_deref(), Some("o@c"));
    }

    #[test]
    fn discord_mapper_hides_unverified_email() {
        let raw = serde_json::json!({
            "id": "snowflake",
            "username": "user",
            "email": "u@d",
            "verified": false,
        });
        let claims = discord_mapper(&raw).unwrap();
        assert_eq!(claims.email, None, "unverified email must be dropped");
    }

    #[test]
    fn twitter_x_mapper_unwraps_data_envelope() {
        let raw = serde_json::json!({"data": {"id": "uuid", "name": "Twitter User"}});
        let claims = twitter_x_mapper(&raw).unwrap();
        assert_eq!(claims.subject, "uuid");
        assert_eq!(claims.display_name.as_deref(), Some("Twitter User"));
        assert_eq!(claims.email, None);
    }

    #[test]
    fn spotify_mapper_extracts_display_name() {
        let raw = serde_json::json!({
            "id": "spotify-id",
            "display_name": "Spotify User",
            "email": "s@u",
        });
        let claims = spotify_mapper(&raw).unwrap();
        assert_eq!(claims.subject, "spotify-id");
        assert_eq!(claims.display_name.as_deref(), Some("Spotify User"));
    }

    #[test]
    fn reddit_mapper_drops_email() {
        let raw = serde_json::json!({"id": "abc123", "name": "spez"});
        let claims = reddit_mapper(&raw).unwrap();
        assert_eq!(claims.subject, "abc123");
        assert_eq!(claims.email, None, "Reddit has no email path");
    }
}
