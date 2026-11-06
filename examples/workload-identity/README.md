# Axess Example: Machine Callers

Recipes for machine callers. Three wire JWT-bearer workload-identity flows
into axess's generic `WorkloadResolver` for common issuer schemas:

- **GitHub Actions OIDC**; tokens from `https://token.actions.githubusercontent.com`.
- **GitLab CI ID tokens**; `src/gitlab.rs`, keyed on `project_id` and `namespace_id` with `ref_protected` and `environment` allowlists.
- **Kubernetes service-account projected tokens**; `kubernetes.io.{namespace,serviceaccount.name}` claims. OpenShift and EKS use the same recipe; `src/openshift.rs` and `src/eks.rs` hold each platform's issuer and audience.

The third is the last resort, for a caller no identity provider vouches
for (an intake worker, a relay, a cron job):

- **Shared secret** (`src/shared_secret.rs`); the caller signs each request
  with a secret both ends hold, through the `service-secret` feature, and
  the route verifies it and refuses altered, stale and replayed requests. Replay memory is per process: with several replicas keep the handler idempotent (for example dedupe on the report's contents) or route the webhook to a single instance, or a signed request can be replayed to another replica within its five-minute window.
  This is the weakest machine credential axess offers: prefer the
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
implementations for common IdPs as **copy-paste starting points**.

## Using a recipe

Three options:

1. **Copy the source** into your own codebase, adjust SPIFFE path layout /
   attribute set to fit your conventions. Recommended for production use.
2. **Depend on the crate** and use the public functions directly. Useful
   for prototypes and tests.
3. **Read the source** as documentation for how to write your own recipe
   (CircleCI OIDC, Buildkite OIDC, custom internal JWT
   format, …). Each recipe is ~100 lines and follows the same pattern:
   `#[derive(Deserialize)] struct Claims { ... }` plus a mapper function
   that turns verified claims into a `WorkloadMapping`.

## Example: GitHub Actions

```rust,ignore
use axess_example_workload_identity::github_actions::{
    github_actions_mapper, GitHubActionsClaims, GitHubAllowlist,
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
    |owner_id| tenants.get(owner_id).copied(), // None refuses the token
    Issuer::custom("github_actions").unwrap(),
    bearer_token,
    // Trust owners and repositories by their immutable numeric ids, never by
    // name: a renamed or deleted organisation frees its old name.
    github_actions_mapper(
        GitHubAllowlist::new()
            .owner_id("123456")
            .repository_id("987654321")
            .git_ref("refs/heads/main")
            .event("push"),
    ),
);
let principal = resolver.resolve().await?;
```

The mapper requires the `repository_id` and `repository_owner_id` claims and
refuses a token without them or with an owner id that is not on the allowlist.
The names (`repository`, `repository_owner`) are kept as attributes for audit.

The allowlist also restricts the run and fails closed: the token's `ref` or
`environment` must be one you listed with `git_ref` or `environment`, and its
`event_name` one you listed with `event`. A token without the claim, or an
allowlist with nothing listed, admits nothing.

For Kubernetes, `k8s_sa_mapper_pinned` with `SaUidPins` refuses a service
account whose UID is not the one registered for its namespace and name, which
is what stops a deleted and recreated account from inheriting the old name.

## Writing your own recipe

For a new IdP (e.g. CircleCI):

1. Decode a sample JWT from your IdP, identify which claims carry the
   workload identity (a project id? a tenant id? a user login?).
2. Define a `#[derive(Deserialize)] struct YourClaims { ... }` with only
   the fields you care about (axess's `JwtVerifier` ignores unknown claims).
3. Write a mapper closure: `Fn(&VerifiedClaims<YourClaims>) ->
   Result<WorkloadMapping, IdentityError>` that produces the
   `(service_name, tenant_slug, attributes)` shape; the resolver builds the
   workload id from them under its own trust domain.
4. Wire as in the example above, with
   `Issuer::custom("your_idp_label").unwrap()` for audit-log attribution.

The library handles signature verification, `iss`/`aud`/`exp`/`nbf`/`alg`
checks, JWKS rotation, the workload id and the tenant lookup. Your recipe handles only
the claim-shape translation.

## See also

- The cloud walkthroughs, which chain a recipe to an STS adapter and run
  against mock Azure AD, Key Vault and STS servers:
  [`tests/cloud_azure.rs`](tests/cloud_azure.rs) and
  [`tests/cloud_aws.rs`](tests/cloud_aws.rs), explained in
  [`docs/workload-identity/azure.md`](../../docs/workload-identity/azure.md) and
  [`docs/workload-identity/aws.md`](../../docs/workload-identity/aws.md).
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

Two kinds of bearer token guard the mutating routes, and neither opens the
other's:

- `/admin/rotate` and `/admin/retire` take the admin token. Set
  `LOCAL_IDP_ADMIN_TOKEN` (16 or more characters) before starting, or read the
  one the server generated from `keys/admin-token` (a file only its owner can
  read; the log names the path and never shows the token).
- `/issue` takes an issue token that belongs to one caller and names the
  subjects and audiences that caller may request. Set `LOCAL_IDP_ISSUE_CALLERS`
  to a JSON array, for example
  `[{"name":"ci","token":"<16+ characters>","subjects":["worker-1"],"audiences":["https://api"]}]`.
  Unset, the server generates one `demo` caller (`worker-1` at `https://api`)
  and writes its token to `keys/issue-token`. A request for another subject or
  audience is refused with 403, and every mint is logged with the caller's name,
  the subject and the audience.

### File layout

```
keys/
  current.kid          text file naming the current kid
  historical/
    v1.pem             every key (current and historical) as PKCS#8 PEM
    v2.pem
    v3.pem.new         a key minted for a rotation not yet made; not published
  rotated_at/
    v1                 when v1 stopped being current
  retired/
    v0.pem             keys taken out of the JWKS, kept for audit
```

Rotation flips `current.kid` atomically via temp-file + rename;
historical PEMs are retained so tokens minted under prior keys keep
verifying through the JWKS until they are retired. `POST /admin/retire`
refuses a key until one hour (the longest token lifetime) has passed since
the rotation that replaced it, a kid that was ever used is refused for a new
key, and a rotation that fails removes the key file it wrote. A new key is
staged as `{kid}.pem.new` and renamed to `.pem` inside the rotation, so a
crash between minting and the pointer flip does not publish a key with no
rotation record. A historical key left by a store that kept no `rotated_at`
record is stamped the first time the store loads it, so it can be retired
one hour after that first start, not at once.

### Curl walkthrough

```sh
# 1. Discover
curl -s http://localhost:3000/.well-known/openid-configuration | jq .
# { "issuer": "http://localhost:3000", "jwks_uri": "http://localhost:3000/jwks.json", ... }

# 2. JWKS (current + historical)
curl -s http://localhost:3000/jwks.json | jq '.keys[].kid'
# "v1"

# 3. Mint a token (an issue token: $ISSUE_TOKEN is the contents of keys/issue-token)
curl -s -X POST http://localhost:3000/issue \
  -H "authorization: Bearer $ISSUE_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"subject":"worker-1","audience":"https://api","ttl_secs":300}'
# { "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6InYxIn0..." }

# 4. Rotate to a new key (the admin token: $ADMIN_TOKEN is keys/admin-token)
curl -s -X POST http://localhost:3000/admin/rotate \
  -H "authorization: Bearer $ADMIN_TOKEN" \
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
- **Per-operator authorization on `/admin/*`.** One shared bearer
  token guards both admin routes here, and the issue callers are a static
  list. A real deployment gates the routes to named operators (see
  `require_authz!` in `axess-macros`) and takes callers from its own
  directory.
- **`tokio::fs` for non-blocking I/O.** The example uses `std::fs`
  for clarity. The key-store operations are small and infrequent
  enough that the blocking cost is invisible at the example's
  scale, but a real production impl should use `tokio::fs`.
- **Out-of-band key generation.** The `/admin/rotate` handler
  generates a fresh RSA key for demonstration. Real ops generate
  keys with `openssl genrsa` (or out of an HSM / KMS), copy the
  PEM into `historical/` as `{kid}.pem.new`, and then call rotate.

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
