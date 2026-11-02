# Conformance: the OpenID Foundation RP tests

This chapter records a run of the [OpenID Foundation conformance
suite](https://gitlab.com/openid/conformance-suite) against the `examples/oauth`
binary. The suite acts as the OpenID Provider and judges the relying party:
axess in its OpenID Connect login and its logout paths. The run is recorded
here, in the repository. It is not published on the OpenID Foundation site and
it is not a certification; the same plans can be run on the hosted suite when
one is wanted.

Every verdict below is what the suite reported. Nothing is listed as passed that
the suite reported otherwise, and the runner decides nothing itself.

## What was run

Five plan runs, all with the relying party registered as a static client, a
plain (non-signed) request object, the `code` response type and the default
response mode:

| Plan | Client authentication | Covers |
|---|---|---|
| `oidcc-client-basic-certification-test-plan` | `client_secret_basic` | OpenID Connect Core: Basic relying party profile (14 modules) |
| `oidcc-client-rp-initiated-logout-rp-basic` | `client_secret_basic` | RP-Initiated Logout 1.0, Basic RP (3 modules) |
| `oidcc-client-back-channel-logout-rp-basic` | `client_secret_basic` | Back-Channel Logout 1.0, Basic RP (8 modules) |
| `oidcc-client-refreshtoken-test-plan` | `client_secret_basic` | Refresh token use and the checks on a refreshed ID token (3 modules) |
| `oidcc-client-test-plan`, the Basic plan's 14 modules | `private_key_jwt` | The Basic profile with the RFC 7523 client assertion in place of the secret |

The Basic certification plan fixes `client_secret_basic` and has no
`client_auth_type` variant, so the `private_key_jwt` run uses the suite's
generic client plan, `oidcc-client-test-plan`, which has one, and runs the same
14 module names the Basic plan holds. That plan instance holds 28 modules for
this variant (the others are discovery, WebFinger, aggregated and distributed
claims and signing-key rotation, which need dynamic registration or discovery
from an identifier; see the refusals below); only the Basic 14 were run, so
the plan instance is not complete and the run is not the Basic certification
plan under another variant.

For each module the runner starts a fresh `axess-example-oauth` process against
the issuer the suite exposes for that module (the suite generates new signing
keys per module), signs in with a cookie-keeping HTTP client that follows the
redirects by hand, asks for a token refresh (the refresh plan) or ends the
session (the logout plans), and waits for the suite to finish the module. No
browser is involved; the RP tests need none.

## Results

The plans were first run on the integration branch with the per-tenant
providers and `private_key_jwt` work merged (commit 0a8be5e) plus the fixes
listed below. The results below are from a full re-run of all five on 0.14.0 in
progress (the example gained the refresh route and the `private_key_jwt`
switch for it), on the date recorded under each plan.

<!-- results:start -->
Suite version 5.3.4, image `registry.gitlab.com/openid/conformance-suite@sha256:ad39ddfcab955805327f3a4c75fc4f2999dfe6b740ca5cc87a96b2690ea98009`.

### `oidcc-client-basic-certification-test-plan`

Run 2026-10-30 21:00 (UTC). Plan instance on the suite: FMiwfJiShcsd6. Variant: `{"client_registration": "static_client", "request_type": "plain_http_request"}`. Modules run: 14 (13 passed, 1 skipped).

| Module | Result | Client saw | Suite findings |
|---|---|---|---|
| `oidcc-client-test` | PASSED | login ended with HTTP 200 (signed in) | none |
| `oidcc-client-test-invalid-iss` | PASSED | login ended with HTTP 400 (not signed in) | none |
| `oidcc-client-test-missing-sub` | PASSED | login ended with HTTP 400 (not signed in) | none |
| `oidcc-client-test-invalid-aud` | PASSED | login ended with HTTP 400 (not signed in) | none |
| `oidcc-client-test-missing-iat` | PASSED | login ended with HTTP 400 (not signed in) | none |
| `oidcc-client-test-kid-absent-single-jwks` | PASSED | login ended with HTTP 200 (signed in) | none |
| `oidcc-client-test-kid-absent-multiple-jwks` | PASSED | login ended with HTTP 400 (not signed in) | none |
| `oidcc-client-test-idtoken-sig-rs256` | PASSED | login ended with HTTP 200 (signed in) | none |
| `oidcc-client-test-idtoken-sig-none` | SKIPPED | login ended with HTTP 400 (not signed in) | none |
| `oidcc-client-test-invalid-sig-rs256` | PASSED | login ended with HTTP 400 (not signed in) | none |
| `oidcc-client-test-userinfo-invalid-sub` | PASSED | login ended with HTTP 400 (not signed in) | none |
| `oidcc-client-test-nonce-invalid` | PASSED | login ended with HTTP 400 (not signed in) | none |
| `oidcc-client-test-scope-userinfo-claims` | PASSED | login ended with HTTP 200 (signed in) | none |
| `oidcc-client-test-client-secret-basic` | PASSED | login ended with HTTP 200 (signed in) | none |

### `oidcc-client-rp-initiated-logout-rp-basic`

Run 2026-10-30 21:00 (UTC). Plan instance on the suite: tdAcaxOGfrfDi. Variant: `{"client_auth_type": "client_secret_basic", "client_registration": "static_client", "request_type": "plain_http_request", "response_mode": "default"}`. Modules run: 3 (3 passed).

| Module | Result | Client saw | Suite findings |
|---|---|---|---|
| `oidcc-client-test-rp-init-logout` | PASSED | login ended with HTTP 200 (signed in); logout ended with HTTP 200 | none |
| `oidcc-client-test-rp-init-logout-other-state` | PASSED | login ended with HTTP 200 (signed in); logout ended with HTTP 200 | none |
| `oidcc-client-test-rp-init-logout-no-state` | PASSED | login ended with HTTP 200 (signed in); logout ended with HTTP 200 | none |

### `oidcc-client-back-channel-logout-rp-basic`

Run 2026-10-30 21:00 (UTC). Plan instance on the suite: nGpvoHrgPXbhf. Variant: `{"client_auth_type": "client_secret_basic", "client_registration": "static_client", "request_type": "plain_http_request", "response_mode": "default"}`. Modules run: 8 (8 passed).

| Module | Result | Client saw | Suite findings |
|---|---|---|---|
| `oidcc-client-test-rp-backchannel-rpinitlogout` | PASSED | login ended with HTTP 200 (signed in); logout ended with HTTP 200 | none |
| `oidcc-client-test-rp-backchannel-rpinitlogout-alg-none` | PASSED | login ended with HTTP 200 (signed in); logout ended with HTTP 200 | none |
| `oidcc-client-test-rp-backchannel-rpinitlogout-no-event` | PASSED | login ended with HTTP 200 (signed in); logout ended with HTTP 200 | none |
| `oidcc-client-test-rp-backchannel-rpinitlogout-with-nonce` | PASSED | login ended with HTTP 200 (signed in); logout ended with HTTP 200 | none |
| `oidcc-client-test-rp-backchannel-rpinitlogout-wrong-alg` | PASSED | login ended with HTTP 200 (signed in); logout ended with HTTP 200 | none |
| `oidcc-client-test-rp-backchannel-rpinitlogout-wrong-aud` | PASSED | login ended with HTTP 200 (signed in); logout ended with HTTP 200 | none |
| `oidcc-client-test-rp-backchannel-rpinitlogout-wrong-event` | PASSED | login ended with HTTP 200 (signed in); logout ended with HTTP 200 | none |
| `oidcc-client-test-rp-backchannel-rpinitlogout-wrong-iss` | PASSED | login ended with HTTP 200 (signed in); logout ended with HTTP 200 | none |

### `oidcc-client-refreshtoken-test-plan`

Run 2026-10-30 21:01 (UTC). Plan instance on the suite: EYHuS18d2vgVc. Variant: `{"client_auth_type": "client_secret_basic", "client_registration": "static_client", "request_type": "plain_http_request", "response_mode": "default", "response_type": "code"}`. Modules run: 3 (3 passed).

| Module | Result | Client saw | Suite findings |
|---|---|---|---|
| `oidcc-client-test-refresh-token` | PASSED | login ended with HTTP 200 (signed in); refresh ended with HTTP 200 | none |
| `oidcc-client-test-refresh-token-invalid-issuer` | PASSED | login ended with HTTP 200 (signed in); refresh ended with HTTP 502 | none |
| `oidcc-client-test-refresh-token-invalid-sub` | PASSED | login ended with HTTP 200 (signed in); refresh ended with HTTP 502 | none |

### `oidcc-client-test-plan` (client_auth_type `private_key_jwt`)

Run 2026-10-30 21:04 (UTC). Plan instance on the suite: bZaePN8cR8J4Y. Variant: `{"client_auth_type": "private_key_jwt", "client_registration": "static_client", "request_type": "plain_http_request", "response_mode": "default", "response_type": "code"}`. Modules run: 14 (1 failed, 12 passed, 1 skipped).

The plan instance holds 28 modules for this variant; the 14 run are the ones listed.

| Module | Result | Client saw | Suite findings |
|---|---|---|---|
| `oidcc-client-test` | PASSED | login ended with HTTP 200 (signed in) | none |
| `oidcc-client-test-nonce-invalid` | PASSED | login ended with HTTP 400 (not signed in) | none |
| `oidcc-client-test-client-secret-basic` | FAILED | login ended with HTTP 400 (not signed in) | FAILURE: This test expected the client to perform client_secret_basic client authorization, but the incoming http request does not contain an authorization header; INTERRUPTED: Test was interrupted before it could complete. The failure 'ExtractClientCredentialsFromBasicAuthorizationHeader: This test expected the client to perform clien |
| `oidcc-client-test-scope-userinfo-claims` | PASSED | login ended with HTTP 200 (signed in) | none |
| `oidcc-client-test-kid-absent-single-jwks` | PASSED | login ended with HTTP 200 (signed in) | none |
| `oidcc-client-test-kid-absent-multiple-jwks` | PASSED | login ended with HTTP 400 (not signed in) | none |
| `oidcc-client-test-missing-iat` | PASSED | login ended with HTTP 400 (not signed in) | none |
| `oidcc-client-test-invalid-aud` | PASSED | login ended with HTTP 400 (not signed in) | none |
| `oidcc-client-test-idtoken-sig-none` | SKIPPED | login ended with HTTP 400 (not signed in) | none |
| `oidcc-client-test-idtoken-sig-rs256` | PASSED | login ended with HTTP 200 (signed in) | none |
| `oidcc-client-test-missing-sub` | PASSED | login ended with HTTP 400 (not signed in) | none |
| `oidcc-client-test-invalid-sig-rs256` | PASSED | login ended with HTTP 400 (not signed in) | none |
| `oidcc-client-test-invalid-iss` | PASSED | login ended with HTTP 400 (not signed in) | none |
| `oidcc-client-test-userinfo-invalid-sub` | PASSED | login ended with HTTP 400 (not signed in) | none |

<!-- results:end -->

## How the example is configured for the run

The example is the one in `examples/oauth`; the run uses its environment
variables and nothing else:

- `OAUTH_ID_TOKEN_ALGS=RS256` pins the algorithms of ID tokens and logout
  tokens to the registration's `id_token_signed_response_alg`, the OpenID
  Connect default. Without a pin the example accepts what the provider's key
  set can verify, and the suite's wrong-algorithm logout test (a token signed
  with ES256 by a key the provider publishes) is accepted.
- `OAUTH_PRIVATE_KEY_FILE`, for the `private_key_jwt` run only: a PEM key the
  runner generates for the run (2048-bit RSA, `RS256`, `kid`
  `axess-conformance-key`), with its public JWK handed to the suite as the
  client's `jwks`. The example then builds its provider with
  `OAuthProviderConfig::discover_with_private_key_jwt` and a
  `ClientAssertionSigner`, and `OAUTH_CLIENT_SECRET` is not set, so a secret
  cannot be sent.
- `POST /auth/refresh`, the example's refresh on demand, which the driver calls
  after login in the refresh plan: it exchanges the stored refresh token
  through `refresh_oauth_token`, keeps the rotated token and asks userinfo
  about the same subject with the new access token.
- `OAUTH_BASE_URL` and `OAUTH_LISTEN` move the example off its default port.
- `AXESS_DEV_INSECURE_COOKIES=1`, because the runner talks plain HTTP.

## Deviations from a hosted run

- **Loopback HTTP.** The suite's origin is `http://localhost:9080`. axess
  accepts `http` for loopback issuers only and trusts the public web PKI for
  `https`, so it cannot be pointed at the suite's self-signed TLS endpoint. A
  small nginx in front of the suite says `X-Forwarded-Proto: https` because the
  suite refuses any request that does not look like HTTPS. The code paths
  under test are the same; the TLS handshake is not exercised.
- **Static client registration.** axess does not implement dynamic client
  registration (it is out of scope), so the dynamic-registration variants and
  the `oidcc-client-config-certification-test-plan` (discovery by WebFinger,
  registration, key rotation) are refused as a profile choice. The issuer is
  configured, not discovered from an identifier.
- **Code flow only.** The Implicit, Hybrid and form_post plans are not run:
  `response_type=id_token` and the hybrid types are refused as a profile
  choice (the authorization code flow with PKCE is the only login flow).

## Skipped modules and refusals

- `oidcc-client-test-idtoken-sig-none`: the suite skips it when the client
  does not accept an unsigned ID token ("As clients are not required to
  support unsigned (alg: none) id_tokens this is okay"). axess never accepts
  `alg: none`; this is a profile refusal, and the suite counts it as a skip
  (in the Basic run and in the `private_key_jwt` run alike).

- `oidcc-client-test-client-secret-basic` under `private_key_jwt`: FAILED, by
  the variant and not by a defect. The module asserts that the token request
  carries an `Authorization: Basic` header (the suite's finding: "expected the
  client to perform client_secret_basic client authorization, but the incoming
  http request does not contain an authorization header"), which a client
  that authenticates by assertion never sends. It is listed because it is in
  the Basic plan's module list; it is not applicable to this variant, and the
  same module passes in the `client_secret_basic` run above.

## Defects the run found, and their fixes

1. **The userinfo response was never asked about its subject.**
   `oidcc-client-test`, `-userinfo-invalid-sub` and `-scope-userinfo-claims`
   wait for a userinfo request. The library already checks the subject
   (`fetch_userinfo`); the example did not call it. The example now calls it
   after the ID token is accepted and refuses a login whose userinfo names
   another subject (OIDC Core 5.3.2).
2. **The back-channel logout endpoint did not say `Cache-Control: no-store`**
   (Back-Channel Logout 1.0 section 2.8), a warning on every logout module.
   `BackChannelLogoutHandler::handle_backchannel_logout` now returns a
   `Response` with the header on every answer, tested for a 200 and a 400.
3. **A logout token was verified with any asymmetric algorithm** the provider's
   key set could check, not the algorithm the client registered
   (`oidcc-client-test-rp-backchannel-rpinitlogout-wrong-alg` failed with a
   200). `OAuthProviderBuilder::with_id_token_signing_algs` pins the list for ID
   tokens and logout tokens; a provider pinned by `with_fapi` now also
   verifies logout tokens with the profile's algorithms. Tested with a
   published RS256 key and a provider pinned to `ES256`.
4. **The example sent no `state` on RP-initiated logout**, so the two state
   modules were skipped. It now sends a random one; its landing page is static
   and does not check it.

## Not run

- `oidcc-client-config-certification-test-plan`, `oidcc-client-dynamic-certification-test-plan`
  (dynamic registration, discovery by WebFinger): refused, see above.
- `oidcc-client-implicit-certification-test-plan`, `oidcc-client-hybrid-certification-test-plan`
  and their `formpost` variants: refused, see above.
- `oidcc-client-front-channel-logout-rp-basic` and the session-management
  plans (`oidcc-client-rp-session-management-rp-basic`): axess has no front-channel
  logout page or session-management iframe.
- The other modules of `oidcc-client-test-plan` for the `private_key_jwt`
  variant (14 of 28 not run): the discovery, WebFinger, signing-key rotation,
  aggregated and distributed claims, `userinfo-signed`, `missing-aud`,
  `invalid-sig-es256` and userinfo bearer modules. The discovery, WebFinger and
  rotation modules need the dynamic or config plans, refused above; the others
  are outside the Basic profile and were not attempted.
- The `client_secret_post`, `client_secret_jwt` and `none` variants of the Basic
  plan, and the refresh plan under `private_key_jwt`.
- Any run on the hosted suite at `certification.openid.net`.

## Re-running

You need podman (or docker with compose), python3 and a Rust toolchain. From
the repository root:

```sh
scripts/conformance/run-rp.sh
```

It pulls the suite's images by digest (see `scripts/conformance/compose.yml`),
starts them as `axess-conformance-*` bound to `127.0.0.1:9080`, builds
`examples/oauth`, runs the five plan runs, rewrites the results section above and
`scripts/conformance/results.json`, and removes the containers. The runner
generates the `private_key_jwt` key itself (it needs `openssl`) and writes it
under `scripts/conformance/out/`, which is not committed. One run, by key
(`basic`, `rpinit`, `bcl`, `refresh`, `basic-private-key-jwt`) or by plan
name, replaces only its own entry in the results and keeps the others:

```sh
scripts/conformance/run-rp.sh --plans refresh
scripts/conformance/run-rp.sh --plans basic-private-key-jwt
```
`KEEP_SUITE=1` leaves the suite up to read its logs at
`http://localhost:9080/log-detail.html?log=<module id>`.

A plan instance id (a short random string) belongs to the local suite
database that run created; it is gone when the containers are. The plan
names are the stable identifiers and exist on the hosted suite too.
