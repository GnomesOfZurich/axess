# Axess Example: Federated Login

Signing in through someone else's identity provider, two ways:

| Binary | Run with | For |
|---|---|---|
| OpenID Connect (default) | `cargo run -p axess-example-oauth` | Providers with OIDC: Google, Auth0, Keycloak, Azure AD, … |
| Social login | `cargo run -p axess-example-oauth --bin social` | Providers without OIDC: GitHub, Discord, Twitter/X, … ([below](#social-login-without-oidc---bin-social)) |

## OpenID Connect

The OAuth 2.0 Authorization Code + PKCE flow against an OIDC provider (Google, Entra, Keycloak, or similar), carried through to a session: the application redirects the user to the provider, handles the callback, verifies the ID token, finds or creates the local user the identity belongs to, and makes the session `Authenticated`. `/profile` then reads that session.

The example uses `MockIdentityStore` and `MockFactorStore` because the focus is on the federation, not local credential storage. A real application combines this with a database-backed store like the SQLite example; the federated-identity table in `src/identities.rs` is one unique key, and its SQL is in the module docs.

### What it demonstrates

- OIDC discovery (fetching `.well-known/openid-configuration` and JWKS), in one place: `ProviderSettings` in `src/app.rs`
- Authorization URL generation with PKCE and state (CSRF) protection, begun for a tenant (`begin_oauth_login_in_tenant`)
- Token exchange, ID token verification and the RFC 9207 `iss` check (`finish_oauth_login_with_iss`)
- A federated-identity table: `(issuer, subject)` to local user id. The e-mail address is never the link, so the same address from a second issuer is a second user
- Just-in-time provisioning under a tenant policy (`Provisioning::JustInTime` creates the user on first login; `LinkedOnly` refuses an identity nobody linked, and `Provisioner::invite` links one beforehand)
- The claim lock: `complete_oauth_login` refuses claims that did not come out of this session's `finish_oauth_login_with_iss`
- Logout from both ends: `POST /auth/logout` (local, then the provider's end-session endpoint with the ID token as hint) and `POST /auth/backchannel-logout` (the provider ends a session)
- A `/profile` that reads the axess session and the user store, not the claims
- Refresh on demand: `POST /auth/refresh` exchanges the stored refresh token (`refresh_oauth_token` with the stored DPoP key), keeps the rotated one and asks userinfo about the same subject
- DPoP-bound tokens wherever the IdP advertises DPoP: the login's key (`OAuthClaims::dpop_key`) is kept beside the refresh token and signs the refresh and userinfo calls
- `private_key_jwt` instead of a secret: set `OAUTH_PRIVATE_KEY_FILE` to a PEM key (`OAUTH_PRIVATE_KEY_ALG`, default `RS256`; `OAUTH_PRIVATE_KEY_KID` optional)

### Endpoints

| Route | Purpose |
|-------|---------|
| `GET /` | Home page with a sign-in link per provider |
| `GET /auth/login/:provider` | Starts the flow (redirects to the IdP) |
| `GET /auth/callback/:provider` | The IdP's answer: verifies it, finds or creates the user, signs in, redirects to `/profile` |
| `GET /profile` | The signed-in user, read from the axess session |
| `POST /auth/refresh` | Refreshes the IdP's tokens for the signed-in session |
| `POST /auth/logout` | Ends the session and goes to the IdP's logout endpoint |
| `POST /auth/backchannel-logout` | The IdP's signed logout token ends the session it names |

### Running with Google

1. Create OAuth credentials at [Google Cloud Console](https://console.cloud.google.com/apis/credentials).
2. Set the redirect URI to `http://localhost:3000/auth/callback/google`.
3. Run:

```sh
OAUTH_CLIENT_ID=your-id \
OAUTH_CLIENT_SECRET=your-secret \
cargo run -p axess-example-oauth
```

The server starts on [http://127.0.0.1:3000](http://127.0.0.1:3000). Set `OAUTH_PROVISIONING=linked-only` to turn first-login creation off.

### Running with other providers

Any OIDC-compliant provider works. Set `OAUTH_ISSUER`, `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET` and `OAUTH_PROVIDER_NAME` (the name in the routes; the redirect URI to register is `http://localhost:3000/auth/callback/<name>`). The example calls `OAuthProviderConfig::discover()`, which fetches the discovery document and JWKS, and builds the provider with `build()`.

### Testing without an IdP

`cargo test -p axess-example-oauth` drives the application as a browser does, against an in-process OIDC provider (wiremock, RSA-signed tokens): the first login creates the user, the second finds it, the same address from a second issuer creates a second user, a tenant that creates no one refuses an unlinked identity, and both logouts end the session.

### Project structure

```
src/
  main.rs          Reads the environment, serves app::build
  lib.rs           Module map
  app.rs           ProviderSettings, build(), the router and its handlers
  identities.rs    The (issuer, subject) to user table
  provisioning.rs  Claims to a local user: find, or create under the tenant policy
tests/
  federated_login.rs  The browser-driven tests
```

### What this example does not cover

- Token revocation at logout: supported via `revoke_oauth_token()`
- A database: the stores are in memory, so users and links are gone on restart
- FAPI 2.0 (PAR, DPoP under the profile, form_post): see the [`fapi/`](../fapi/) example

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
