# FAPI 2.0 Example

Financial-grade API (FAPI) 2.0 Baseline Security Profile example for Axess.

Demonstrates `private_key_jwt` client authentication, PAR (Pushed Authorization Requests), DPoP (sender-constrained tokens), form_post response mode, a DPoP-bound refresh, RP-Initiated Logout, and token revocation.

## What this example actually is

This example is the **Relying Party** (RP) side of OAuth 2.0 / FAPI 2.0. It is the application that delegates identity to an external Identity Provider (the OP), accepts the resulting tokens, and runs a session on top.

It is *not* a competing implementation of Keycloak. The OAuth specs deliberately split the system into two roles:

- **OP (OpenID Provider).** Owns user identity, runs the login UI, issues tokens. Examples: Keycloak, Ory Hydra, Okta, Azure AD, Auth0, your company's central SSO, etc.
- **RP (Relying Party).** Your application. Holds the session, talks to the user, calls the OP for identity, receives tokens. This is what axess provides.

PAR and DPoP are RP-to-OP protocols, so you need an OP to talk to in order to demonstrate them end to end. Axess does not try to be that OP, and that's the architectural decision behind the verifier-vs-orchestrator split in the workspace: axess deliberately does not compete with Keycloak/Hydra/etc. on the IdP side. (The `local-idp` feature mints workload-identity JWTs in-process, but that is on-host issuance for service-to-service flows, not a full user-facing OP. For human-user FAPI flows you want a real OP.)

The `keycloak/` directory in this example is just a quick way to get an OP locally so the demo is clickable. In production you would point `FAPI_ISSUER` at whatever OP your organisation already runs.

## Quick start (Keycloak in podman)

A pre-configured Keycloak realm lives under [`keycloak/`](keycloak/). Spin it up with one command, then run the example.

```sh
# from this directory
podman compose -f keycloak/compose.yml up -d
# wait until Keycloak has imported the realm (about 30 seconds):
until [ "$(podman inspect -f '{{.State.Health.Status}}' axess-fapi-keycloak)" = healthy ]; do sleep 2; done

export FAPI_ISSUER=http://localhost:8080/realms/fapi
export FAPI_CLIENT_ID=axess-fapi-client
export FAPI_PROVIDER_NAME=keycloak
# No FAPI_PRIVATE_KEY_FILE: the client signs with the development key the realm registers.

cargo run -p axess-example-fapi
# open http://localhost:3000
```

Login as the seeded user: `alice` / `alice`. The success page shows the claims and a DPoP proof; refresh the tokens from there or from `/profile`, then log out.

Open `localhost`, not `127.0.0.1`. The session cookie belongs to one host name, and the redirect URI the realm registers is `http://localhost:3000/auth/callback`: a login started on `127.0.0.1` comes back to `localhost` without its cookie and fails. The example listens on `127.0.0.1:3000`, which the browser reaches for `localhost` unless another server holds port 3000 on `::1`.

Tear down when done:

```sh
podman compose -f keycloak/compose.yml down -v
```

(Docker users: the same `compose.yml` works under `docker compose`. Podman is the documented path; Docker is incidental.)

## What the realm pre-configures

The [`keycloak/fapi-realm.json`](keycloak/fapi-realm.json) is imported on Keycloak startup. It sets up:

- Realm `fapi` with brute-force protection enabled, signing with an `ES256` key (Keycloak's default, `RS256`, is outside the FAPI profile's `PS256`, `ES256`, `EdDSA`, and the example refuses an `RS256` ID token)
- Client `axess-fapi-client` with:
  - `private_key_jwt` client authentication (`client-jwt`, `ES256`), the public key of [`keycloak/dev-client-key.pem`](keycloak/dev-client-key.pem) registered as its JWKS under `kid` `axess-fapi-dev`; no client secret
  - PKCE S256 required
  - Pushed Authorization Requests required
  - DPoP-bound access tokens enabled (the compose file starts Keycloak 26.0 with `--features=dpop`; without it Keycloak ignores the proof and issues `Bearer` tokens, which the example refuses)
  - ID tokens signed `ES256`, with `groups` and `roles` mapped into them
  - Standard authorization code flow (no implicit, no direct grants)
  - Redirect URIs locked to `http://localhost:3000/auth/callback` and `127.0.0.1` equivalent
  - Post-logout redirects locked to `http://localhost:3000/` and `127.0.0.1` equivalent
- User `alice` (password `alice`, email `alice@bank.example.com`) in group `finance-team` with realm role `portfolio-viewer` and the realm's default roles, whose `offline_access` lets the login's `offline_access` scope return a refresh token
- Admin console at `http://localhost:8080` with credentials `admin` / `admin` for inspection

## Mock mode (no Keycloak required)

If you want to see the wiring without running any container, drop the env vars:

```sh
cargo run -p axess-example-fapi
```

Mock mode uses an in-process `MockOAuthProvider`. It exercises the API surface but cannot do a real PAR round-trip (no PAR endpoint to push to). Use this for inspecting the example code; use Keycloak for any flow you actually care about end to end.

## Client authentication

FAPI 2.0 lets the client authenticate by `private_key_jwt` or mTLS, never by a client secret, and `build` refuses a FAPI provider that would send one. The example uses `private_key_jwt`: it builds the provider with `OAuthProviderConfig::discover_with_private_key_jwt`, and every PAR, token and revocation request carries a fresh assertion signed for the issuer.

The key:

- `FAPI_PRIVATE_KEY_FILE=/path/to/key.pem` names the PEM private key the client signs with. `FAPI_PRIVATE_KEY_ALG` is its algorithm (`ES256` by default; FAPI 2.0 allows `PS256`, `ES256` and `EdDSA`) and `FAPI_PRIVATE_KEY_KID` the `kid` the IdP registered it under. Register the public half at your IdP for the client.
- Without `FAPI_PRIVATE_KEY_FILE` the example signs with [`keycloak/dev-client-key.pem`](keycloak/dev-client-key.pem) (`ES256`, `kid` `axess-fapi-dev`) and logs a warning. That key is published with the source: the bundled realm accepts it and nothing else must. Never register it at a real IdP.

To use a key of your own with the bundled realm, generate one and put its public JWK in the client's `jwks.string` attribute in `keycloak/fapi-realm.json`, then recreate the container (below):

```sh
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out client-key.pem
```

The example's tests check that the development key and the realm's registered key are one pair.

## Conformance testing

The OpenID Foundation runs a free hosted conformance suite at <https://www.certification.openid.net/>. It acts as a scripted OP that drives an RP through the full FAPI 2.0 test matrix (happy path plus adversarial cases). Point it at this example's `/auth/callback` to certify the implementation; use Keycloak for everyday development.

## What the example demonstrates

| Feature | How it's shown |
|---------|---------------|
| **private_key_jwt** | The provider authenticates with a signed client assertion; no client secret exists |
| **PAR** | `begin_oauth_login` auto-pushes params to PAR endpoint when FAPI enabled |
| **DPoP** | The token request carries a proof; after login the page shows a proof for a hypothetical API call, signed by the key the token is bound to |
| **form_post** | Callback accepts both GET (query) and POST (form_post); code never appears in URL |
| **Refresh** | The refresh button exchanges the stored refresh token with a proof from the login's key, so the new access token stays bound to it |
| **RP-Initiated Logout** | Logout button redirects to IdP's `end_session_endpoint` with the login's `id_token_hint` |
| **Token Revocation** | Logout handler revokes the login's refresh token with `revoke_oauth_token()` before redirecting |
| **Dual-mode** | Same code; env vars switch between mock and Keycloak |

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Home page with login link |
| GET | `/auth/login` | Initiates FAPI login (PAR + redirect) |
| GET | `/auth/callback` | IdP callback (query mode) |
| POST | `/auth/callback` | IdP callback (form_post mode) |
| GET | `/profile` | The signed-in user and the key the tokens are bound to |
| POST | `/auth/refresh` | DPoP-bound refresh of the tokens |
| POST | `/auth/logout` | RP-Initiated Logout + token revocation |

## Customising the realm

Edit `keycloak/fapi-realm.json` and recreate the container:

```sh
podman compose -f keycloak/compose.yml down -v
podman compose -f keycloak/compose.yml up -d
```

The `-v` on `down` wipes the H2 volume so the import re-runs. Without `-v` the existing realm state wins and your JSON changes are ignored.

Alternatively, use the admin console (`http://localhost:8080`, `admin`/`admin`) to tweak the realm interactively, then export from *Realm Settings > Action > Partial export* to update the JSON.
