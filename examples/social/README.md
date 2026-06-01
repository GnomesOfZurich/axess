# Axess Example: Social Login (Login with GitHub)

Demonstrates [`axess::social::SocialProvider`]; the **plain-OAuth-2.0**
user-login flow for IdPs that do not support OIDC. This sample wires
GitHub user login end-to-end.

## When to use this vs OIDC

Read [`axess::social` module docs](../../axess/src/lib.rs) for the
security delta. Short version: claims come from a TLS-trusted userinfo
endpoint, not from a signed assertion; your only defense is TLS to the
IdP and your trust in that IdP. **Prefer OIDC whenever the provider
supports it.** Use `SocialProvider` only when you must (GitHub user
login, Twitter/X, Discord, Reddit, Spotify, Strava, …).

## What this example shows

- One generic `SocialProvider` configured with GitHub's
  authorization / token / userinfo URLs.
- PKCE enabled by default (RFC 7636).
- CSRF state minted via `SocialProvider::mint_csrf_state` (32 bytes
  base64url, routed through the same `Arc<dyn SecureRng>` as the PKCE
  verifier; DST-friendly).
- Adopter-supplied claim mapper translates GitHub's userinfo response
  into normalised `SocialClaims`.
- Pre-auth state held in short-lived cookies (a real app would use
  axess's `SessionLayer` pre-auth session).

## Running

1. Create a GitHub OAuth app at <https://github.com/settings/developers>.
2. Set the authorization callback URL to
   `http://localhost:3000/auth/callback/github`.
3. Run:

   ```sh
   GITHUB_CLIENT_ID=your-id \
   GITHUB_CLIENT_SECRET=your-secret \
   cargo run -p axess-example-social
   ```

4. Open <http://localhost:3000/> and click *Login with GitHub*.

## Endpoints

| Route | Purpose |
|---|---|
| `GET /` | Home; explains the security model and links to login |
| `GET /auth/login/github` | Mints CSRF state + PKCE verifier, redirects to GitHub |
| `GET /auth/callback/github` | Verifies state, exchanges code, fetches userinfo, shows claims |

## Adapting to other providers

Swap the URLs and the claim mapper. The skeleton is the same for any
plain-OAuth-2.0 IdP:

| Provider | authorization_endpoint | token_endpoint | userinfo_endpoint | claim shape |
|---|---|---|---|---|
| GitHub | `https://github.com/login/oauth/authorize` | `https://github.com/login/oauth/access_token` | `https://api.github.com/user` | numeric `id`, `login`, `email`, `name` |
| Discord | `https://discord.com/api/oauth2/authorize` | `https://discord.com/api/oauth2/token` | `https://discord.com/api/users/@me` | snowflake `id`, `username`, `email` |
| Twitter/X | `https://twitter.com/i/oauth2/authorize` | `https://api.twitter.com/2/oauth2/token` | `https://api.twitter.com/2/users/me` | `data.id` (UUID), `data.username` |
| Spotify | `https://accounts.spotify.com/authorize` | `https://accounts.spotify.com/api/token` | `https://api.spotify.com/v1/me` | `id`, `display_name`, `email` |
| Reddit | `https://www.reddit.com/api/v1/authorize` | `https://www.reddit.com/api/v1/access_token` | `https://oauth.reddit.com/api/v1/me` | `id`, `name` (username) |

Each provider has its own scope vocabulary and quirks (some require
specific `User-Agent` headers, some return userinfo as a nested
object, …). Adopters maintain their own provider table for the IdPs
they support.

## See also

- [`examples/oauth/`](../oauth/); same kind of demo but for OIDC-compliant
  providers (Google, Auth0, Keycloak, etc.) via `OAuthProviderConfig::discover()`.
  Prefer this whenever the IdP supports it.
- [`examples/fapi/`](../fapi/); FAPI 2.0 security profile (PAR + DPoP + JAR)
  for high-assurance use cases.
- [`axess::social`](https://docs.rs/axess/latest/axess/social/); module docs
  with the full security model and rationale.
