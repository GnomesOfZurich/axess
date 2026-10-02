# Axess Example: Federated Login

Signing in through someone else's identity provider, two ways:

| Binary | Run with | For |
|---|---|---|
| OpenID Connect (default) | `cargo run -p axess-example-oauth` | Providers with OIDC: Google, Auth0, Keycloak, Azure AD, … |
| Social login | `cargo run -p axess-example-oauth --bin social` | Providers without OIDC: GitHub, Discord, Twitter/X, … ([below](#social-login-without-oidc---bin-social)) |

## OpenID Connect

Demonstrates the OAuth 2.0 Authorization Code + PKCE flow using a real OIDC provider. The application redirects the user to an external identity provider (Google, Keycloak, or similar), handles the callback, exchanges the authorization code for tokens, validates the ID token signature, and displays the resulting claims.

This example uses `MockIdentityStore` and `MockFactorStore` because the focus is on the OAuth integration, not local credential storage. In a real application you would combine this with a database-backed store like the SQLite example.

### What it demonstrates

- OIDC discovery (fetching `.well-known/openid-configuration` and JWKS)
- Authorization URL generation with PKCE and state (CSRF) protection
- Token exchange and ID token signature verification
- Claim extraction (subject, email, name, groups, roles)
- Session establishment after federated login

### Endpoints

| Route | Purpose |
|-------|---------|
| `GET /` | Home page with "Login with Google" link |
| `GET /auth/login/:provider` | Initiates the OAuth flow (redirects to IdP) |
| `GET /auth/callback/:provider` | Handles the IdP callback, exchanges code, shows claims |
| `GET /profile` | Displays authenticated user info |

### Running with Google

1. Create OAuth credentials at [Google Cloud Console](https://console.cloud.google.com/apis/credentials).
2. Set the redirect URI to `http://localhost:3000/auth/callback/google`.
3. Run:

```sh
OAUTH_CLIENT_ID=your-id \
OAUTH_CLIENT_SECRET=your-secret \
cargo run -p axess-example-oauth
```

The server starts on [http://127.0.0.1:3000](http://127.0.0.1:3000).

### Running with other providers

Any OIDC-compliant provider works. Set the issuer URL, client ID, and client secret as environment variables. The example calls `OAuthProviderConfig::discover()` which fetches the discovery document and JWKS automatically.

For local testing without an external IdP, see the `wiremock`-based integration tests in `axess-core/tests/oauth_wiremock.rs`. They spin up an in-process OIDC mock server with RSA-signed JWTs.

### Project structure

```
src/
  main.rs    Startup, OAuth provider registration, routes, callback handler
```

Single-file example. The handler logic is inline to keep things readable.

### What this example does not cover

- Mapping OAuth claims to a local user (the callback just displays claims)
- Calling `complete_oauth_login()` to establish a full Axess session
- Refresh token handling: the library supports `refresh_oauth_token()`, just not shown here
- RP-Initiated Logout and token revocation: supported via `build_end_session_url()` and `revoke_oauth_token()`, demonstrated in the [`fapi/`](../fapi/) example
- FAPI 2.0 (PAR, DPoP, form_post): see the [`fapi/`](../fapi/) example

For a production-like integration that ties OAuth to local sessions, combine the patterns from this example with the SQLite example's backend.

### License

MIT OR Apache-2.0

## Social login without OIDC: `--bin social`

Demonstrates [`axess::social::SocialProvider`]; the **plain-OAuth-2.0**
user-login flow for IdPs that do not support OIDC. This sample wires
GitHub user login end-to-end.

### When to use this vs OIDC

Read [`axess::social` module docs](../../axess/src/lib.rs) for the
security delta. Short version: claims come from a TLS-trusted userinfo
endpoint, not from a signed assertion; your only defense is TLS to the
IdP and your trust in that IdP. **Prefer OIDC whenever the provider
supports it.** Use `SocialProvider` only when you must (GitHub user
login, Twitter/X, Discord, Reddit, Spotify, Strava, …).

### What this example shows

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

### Running

1. Create a GitHub OAuth app at <https://github.com/settings/developers>.
2. Set the authorization callback URL to
   `http://localhost:3000/auth/callback/github`.
3. Run:

   ```sh
   GITHUB_CLIENT_ID=your-id \
   GITHUB_CLIENT_SECRET=your-secret \
   cargo run -p axess-example-oauth --bin social
   ```

4. Open <http://localhost:3000/> and click *Login with GitHub*.

### Endpoints

| Route | Purpose |
|---|---|
| `GET /` | Home; explains the security model and links to login |
| `GET /auth/login/github` | Mints CSRF state + PKCE verifier, redirects to GitHub |
| `GET /auth/callback/github` | Verifies state, exchanges code, fetches userinfo, shows claims |

### Adapting to other providers

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

### See also

- The default binary of this crate, described above; the same kind of demo
  for OIDC-compliant providers (Google, Auth0, Keycloak, etc.) via
  `OAuthProviderConfig::discover()`. Prefer it whenever the IdP supports it.
- [`examples/fapi/`](../fapi/); FAPI 2.0 security profile (PAR + DPoP + JAR)
  for high-assurance use cases.
- [`axess::social`](https://docs.rs/axess/latest/axess/social/); module docs
  with the full security model and rationale.
