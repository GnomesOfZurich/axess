# FAPI 2.0 Example

Financial-grade API (FAPI) 2.0 Baseline Security Profile example for Axess.

Demonstrates PAR (Pushed Authorization Requests), DPoP (sender-constrained tokens), form_post response mode, RP-Initiated Logout, and token revocation.

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
# wait ~30 seconds for Keycloak to import the realm and start

export FAPI_ISSUER=http://localhost:8080/realms/fapi
export FAPI_CLIENT_ID=axess-fapi-client
export FAPI_CLIENT_SECRET=axess-fapi-secret
export FAPI_PROVIDER_NAME=keycloak

cargo run -p axess-example-fapi
# open http://127.0.0.1:3000
```

Login as the seeded user: `alice` / `alice`.

Tear down when done:

```sh
podman compose -f keycloak/compose.yml down -v
```

(Docker users: the same `compose.yml` works under `docker compose`. Podman is the documented path; Docker is incidental.)

## What the realm pre-configures

The [`keycloak/fapi-realm.json`](keycloak/fapi-realm.json) is imported on Keycloak startup. It sets up:

- Realm `fapi` with brute-force protection enabled
- Client `axess-fapi-client` with:
  - PKCE S256 required
  - Pushed Authorization Requests required
  - DPoP-bound access tokens enabled
  - Standard authorization code flow (no implicit, no direct grants)
  - Redirect URIs locked to `http://localhost:3000/auth/callback` and `127.0.0.1` equivalent
  - Post-logout redirects locked to `http://localhost:3000/` and `127.0.0.1` equivalent
- User `alice` (password `alice`, email `alice@bank.example.com`) in group `finance-team` with realm role `portfolio-viewer`
- Admin console at `http://localhost:8080` with credentials `admin` / `admin` for inspection

## Mock mode (no Keycloak required)

If you want to see the wiring without running any container, drop the env vars:

```sh
cargo run -p axess-example-fapi
```

Mock mode uses an in-process `MockOAuthProvider`. It exercises the API surface but cannot do a real PAR round-trip (no PAR endpoint to push to). Use this for inspecting the example code; use Keycloak for any flow you actually care about end to end.

## FAPI 2.0 strictness caveat

This setup uses `client_secret_basic` for client authentication. Strict FAPI 2.0 Baseline requires either `private_key_jwt` or mTLS, which is more setup than a five-minute walk-through warrants. Everything else the example demonstrates (PAR, PKCE S256, DPoP-bound tokens, form_post response mode, RP-initiated logout, refresh-token rotation) is FAPI-conformant.

For a production-grade FAPI deployment, switch the client to `private_key_jwt` in Keycloak (Credentials tab) and register the JWK with axess's outbound OAuth config. The example's `OAuthProviderConfig::discover(...)` API supports this swap without changing handler code.

## Conformance testing

The OpenID Foundation runs a free hosted conformance suite at <https://www.certification.openid.net/>. It acts as a scripted OP that drives an RP through the full FAPI 2.0 test matrix (happy path plus adversarial cases). Point it at this example's `/auth/callback` to certify the implementation; use Keycloak for everyday development.

## What the example demonstrates

| Feature | How it's shown |
|---------|---------------|
| **PAR** | `begin_oauth_login` auto-pushes params to PAR endpoint when FAPI enabled |
| **DPoP** | After login, generates a DPoP proof for a hypothetical API call and displays it |
| **form_post** | Callback accepts both GET (query) and POST (form_post); code never appears in URL |
| **RP-Initiated Logout** | Logout button redirects to IdP's `end_session_endpoint` with `id_token_hint` |
| **Token Revocation** | Logout handler calls `revoke_oauth_token()` before redirecting |
| **Dual-mode** | Same code; env vars switch between mock and Keycloak |

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Home page with login link |
| GET | `/auth/login` | Initiates FAPI login (PAR + redirect) |
| GET | `/auth/callback` | IdP callback (query mode) |
| POST | `/auth/callback` | IdP callback (form_post mode) |
| GET | `/profile` | Authenticated user profile |
| POST | `/auth/logout` | RP-Initiated Logout + token revocation |

## Customising the realm

Edit `keycloak/fapi-realm.json` and recreate the container:

```sh
podman compose -f keycloak/compose.yml down -v
podman compose -f keycloak/compose.yml up -d
```

The `-v` on `down` wipes the H2 volume so the import re-runs. Without `-v` the existing realm state wins and your JSON changes are ignored.

Alternatively, use the admin console (`http://localhost:8080`, `admin`/`admin`) to tweak the realm interactively, then export from *Realm Settings > Action > Partial export* to update the JSON.
