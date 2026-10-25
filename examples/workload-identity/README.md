# Axess Example: Machine Callers

Recipes for machine callers. Two wire JWT-bearer workload-identity flows
into axess's generic `WorkloadResolver` for common issuer schemas:

- **GitHub Actions OIDC**; tokens from `https://token.actions.githubusercontent.com`.
- **Kubernetes service-account projected tokens**; `kubernetes.io.{namespace,serviceaccount.name}` claims.

The third is the last resort, for a caller no identity provider vouches
for (an intake worker, a relay, a cron job):

- **Shared secret** (`src/shared_secret.rs`); the caller signs each request
  with a secret both ends hold, through the `service-secret` feature, and
  the route verifies it and refuses altered, stale and replayed requests.
  This is the weakest machine credential axess offers: prefer the two
  recipes above whenever the caller can use them. The book chapter
  *Shared secrets: the last resort* sets the options side by side.

To try the JWT recipes without a real IdP, the crate also runs one:
`cargo run -p axess-example-workload-identity --bin local-idp` starts an
in-process IdP that mints workload JWTs from a file-backed, rotating key
store ([below](#a-local-idp---bin-local-idp)).

## Why a recipes crate and not a library feature?

axess deliberately ships no per-issuer adapter features (no `wif-github`, no
`wif-k8s`, no `wif-gitlab`, etc.). Each IdP's JWT claim shape is small (~20
lines for the struct, ~30 for the mapping closure) and adopters care about
*their* IdP's exact claim semantics, not a generic average. Hard-coding
per-company features in the library would invite endless additions without
reuse benefit.

Instead: one generic [`WorkloadResolver<C, F, R>`][resolver] in the library
handles JWT verification + trust-domain pinning + `Principal` construction.
This crate provides ready-made `C` (claim struct) + `F` (mapper closure)
implementations for two common IdPs as **copy-paste starting points**.

## Using a recipe

Three options:

1. **Copy the source** into your own codebase, adjust SPIFFE path layout /
   attribute set to fit your conventions. Recommended for production use.
2. **Depend on the crate** and use the public functions directly. Useful
   for prototypes and tests.
3. **Read the source** as documentation for how to write your own recipe
   (GitLab CI OIDC, CircleCI OIDC, Buildkite OIDC, custom internal JWT
   format, …). Each recipe is ~100 lines and follows the same pattern:
   `#[derive(Deserialize)] struct Claims { ... }` plus a mapper function
   that turns verified claims into a `WorkloadMapping`.

## Example: GitHub Actions

```rust,ignore
use axess_example_workload_identity::github_actions::{
    github_actions_mapper, GitHubActionsClaims,
};
use axess_factors::federation::workload::WorkloadResolver;
use axess_factors::jwt::verifier::JwtVerifier;
use axess_identity::{Issuer, TrustDomain};
use std::sync::Arc;

// At process startup; cache and reuse:
let verifier = Arc::new(
    JwtVerifier::new(github_jwks_handle)
        .with_issuer("https://token.actions.githubusercontent.com")
        .with_audience("axess-platform"),
);
let trust_domain = TrustDomain::new("github.actions").unwrap();

// Per request:
let resolver = WorkloadResolver::<GitHubActionsClaims, _, _>::new(
    verifier.clone(),
    trust_domain.clone(),
    tenant_id,
    Issuer::custom("github_actions").unwrap(),
    bearer_token,
    github_actions_mapper(trust_domain),
);
let principal = resolver.resolve().await?;
```

## Writing your own recipe

For a new IdP (e.g. GitLab CI):

1. Decode a sample JWT from your IdP, identify which claims carry the
   workload identity (`project_path`? `namespace_id`? `user_login`?).
2. Define a `#[derive(Deserialize)] struct YourClaims { ... }` with only
   the fields you care about (axess's `JwtVerifier` ignores unknown claims).
3. Write a mapper closure: `Fn(&VerifiedClaims<YourClaims>) ->
   Result<WorkloadMapping, IdentityError>` that produces the
   `(workload_id, service_name, tenant_slug, attributes)` shape.
4. Wire as in the example above, with
   `Issuer::custom("your_idp_label").unwrap()` for audit-log attribution.

The library handles signature verification, `iss`/`aud`/`exp`/`nbf`/`alg`
checks, JWKS rotation, and trust-domain pinning. Your recipe handles only
the claim-shape translation.

## See also

- [`axess_factors::federation::workload`][resolver]; the generic resolver this crate's recipes plug into.
- [`axess_factors::jwt::svid::JwtSvidResolver`][svid]; the one *exception* to the
  "no per-IdP adapter" rule: SPIFFE JWT-SVID is a spec (mandatory `spiffe://` URI
  in `sub`, trust-domain extracted from the URI), not just a claim shape, so it
  earns its own type. Use it when your IdP advertises SPIFFE compliance.

[resolver]: https://docs.rs/axess-factors/latest/axess_factors/federation/workload/struct.WorkloadResolver.html
[svid]: https://docs.rs/axess-factors/latest/axess_factors/jwt/svid/struct.JwtSvidResolver.html

## A local IdP: `--bin local-idp`

Production-pattern example for [`axess::local_idp::LocalIdp`]. Boots
an in-process workload-identity IdP backed by a file system, serves
RFC 8414 discovery + JWKS, and supports atomic key rotation.

### What this shows

- A custom [`axess::local_idp::LocalIdpKeyStore`] implementation
  (`FileLocalIdpKeyStore`) with directory layout, atomic rotation,
  and `LocalIdpKeyError` propagation.
- Mounting [`LocalIdp::router`](https://docs.rs/axess) for the two
  standard discovery endpoints in one line.
- A custom `POST /admin/rotate` endpoint that mints a new key,
  persists it, and atomically swaps it via
  [`LocalIdp::rotate_signing_key`](https://docs.rs/axess).
- A `POST /issue` endpoint demonstrating mint via
  [`LocalIdp::mint`](https://docs.rs/axess).

### Running

```sh
cargo run -p axess-example-workload-identity --bin local-idp
```

On first launch the example generates an RSA-2048 key and writes it
to `./keys/historical/v1.pem`. The server binds to `127.0.0.1:3000`
with issuer `http://localhost:3000`. Override the key directory with
`LOCAL_IDP_KEY_DIR=…`.

`POST /issue` and `POST /admin/rotate` require
`Authorization: Bearer $TOKEN`. Set `LOCAL_IDP_ADMIN_TOKEN` (16 or more
characters) before starting, or copy the token the server logs at startup.

### File layout

```
keys/
  current.kid          text file naming the current kid
  historical/
    v1.pem             every key (current and historical) as PKCS#8 PEM
    v2.pem
```

Rotation flips `current.kid` atomically via temp-file + rename;
historical PEMs are retained so tokens minted under prior keys keep
verifying through the JWKS until ops decides to retire them.

### Curl walkthrough

```sh
# 1. Discover
curl -s http://localhost:3000/.well-known/openid-configuration | jq .
# { "issuer": "http://localhost:3000", "jwks_uri": "http://localhost:3000/jwks.json", ... }

# 2. JWKS (current + historical)
curl -s http://localhost:3000/jwks.json | jq '.keys[].kid'
# "v1"

# 3. Mint a token
curl -s -X POST http://localhost:3000/issue \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"subject":"worker-1","audience":"https://api","ttl_secs":300}'
# { "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6InYxIn0..." }

# 4. Rotate to a new key
curl -s -X POST http://localhost:3000/admin/rotate \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"new_kid":"v2"}'
# { "new_current": "v2", "historical": ["v2", "v1"] }

# 5. JWKS now lists both keys
curl -s http://localhost:3000/jwks.json | jq '.keys[].kid'
# "v2"
# "v1"

# 6. New mints are signed under v2; tokens minted under v1 still
#    verify (the kid -> JWK lookup hits the historical entry).
```

### What's deliberately not in this example

- **Production HTTPS.** Real deployments terminate TLS upstream or
  use `axum-server` with a `RustlsConfig`. Either is purely an axum
  concern.
- **Per-operator authorization on `/admin/rotate`.** One shared bearer
  token guards both admin routes here. A real deployment gates the route
  to named operators (see `require_authz!` in `axess-macros`).
- **`tokio::fs` for non-blocking I/O.** The example uses `std::fs`
  for clarity. The key-store operations are small and infrequent
  enough that the blocking cost is invisible at the example's
  scale, but a real production impl should use `tokio::fs`.
- **Out-of-band key generation.** The `/admin/rotate` handler
  generates a fresh RSA key for demonstration. Real ops generate
  keys with `openssl genrsa` (or out of an HSM / KMS), copy the
  PEM into `historical/`, and then call rotate.

### Adapting to your file layout

`FileLocalIdpKeyStore` is intentionally simple. Common adopter
extensions:

- **Single-file PEM bundle.** Replace `read_dir(historical/)` with
  a multi-PEM parse over one file.
- **kid in metadata header.** Read `kid` from each PEM's leading
  comment rather than from its filename stem.
- **Read-only mode.** Implement `rotate` as `Err(ReadOnly)` and
  rely on operator-driven file swaps + process restart.
- **Filesystem watch.** Wire `notify` to invalidate the store on
  out-of-band file edits.
- **Object-store backend.** Replace `std::fs::*` with `aws-sdk-s3`
  / `google-cloud-storage` / etc.; the trait shape stays the same.

### Adapting to KMS / Vault / HSM

See [`docs/factors/local-idp.md`](../../docs/factors/local-idp.md) §"KMS-backed key
storage" for the envelope-encryption pattern and what stays the same
vs what changes.
