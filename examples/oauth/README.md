# Axess Example: OAuth 2.0 / OIDC Login

Demonstrates the OAuth 2.0 Authorization Code + PKCE flow using a real OIDC provider. The application redirects the user to an external identity provider (Google, GitHub, Keycloak, or similar), handles the callback, exchanges the authorization code for tokens, validates the ID token signature, and displays the resulting claims.

This example uses `MockIdentityStore` and `MockFactorStore` because the focus is on the OAuth integration, not local credential storage. In a real application you would combine this with a database-backed store like the SQLite example.

## What it demonstrates

- OIDC discovery (fetching `.well-known/openid-configuration` and JWKS)
- Authorization URL generation with PKCE and state (CSRF) protection
- Token exchange and ID token signature verification
- Claim extraction (subject, email, name, groups, roles)
- Session establishment after federated login

## Endpoints

| Route | Purpose |
|-------|---------|
| `GET /` | Home page with "Login with Google" link |
| `GET /auth/login/:provider` | Initiates the OAuth flow (redirects to IdP) |
| `GET /auth/callback/:provider` | Handles the IdP callback, exchanges code, shows claims |
| `GET /profile` | Displays authenticated user info |

## Running with Google

1. Create OAuth credentials at [Google Cloud Console](https://console.cloud.google.com/apis/credentials).
2. Set the redirect URI to `http://localhost:3000/auth/callback/google`.
3. Run:

```sh
OAUTH_CLIENT_ID=your-id \
OAUTH_CLIENT_SECRET=your-secret \
cargo run -p axess-example-oauth
```

The server starts on [http://127.0.0.1:3000](http://127.0.0.1:3000).

## Running with other providers

Any OIDC-compliant provider works. Set the issuer URL, client ID, and client secret as environment variables. The example calls `OAuthProviderConfig::discover()` which fetches the discovery document and JWKS automatically.

For local testing without an external IdP, see the `wiremock`-based integration tests in `axess-core/tests/oauth_wiremock.rs`. They spin up an in-process OIDC mock server with RSA-signed JWTs.

## Project structure

```
src/
  main.rs    Startup, OAuth provider registration, routes, callback handler
```

Single-file example. The handler logic is inline to keep things readable.

## What this example does not cover

- Mapping OAuth claims to a local user (the callback just displays claims)
- Calling `complete_oauth_login()` to establish a full Axess session
- Refresh token handling: the library supports `refresh_oauth_token()`, just not shown here
- RP-Initiated Logout and token revocation: supported via `build_end_session_url()` and `revoke_oauth_token()`, demonstrated in the [`fapi/`](../fapi/) example
- FAPI 2.0 (PAR, DPoP, form_post): see the [`fapi/`](../fapi/) example

For a production-like integration that ties OAuth to local sessions, combine the patterns from this example with the SQLite example's backend.

## License

MIT OR Apache-2.0
