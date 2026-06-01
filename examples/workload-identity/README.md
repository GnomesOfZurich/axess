# Axess Example: Workload Identity Recipes

Adopter recipes for axess's generic `WorkloadResolver`. Shows how to wire
JWT-bearer workload-identity flows for two common issuer schemas:

- **GitHub Actions OIDC**; tokens from `https://token.actions.githubusercontent.com`.
- **Kubernetes service-account projected tokens**; `kubernetes.io.{namespace,serviceaccount.name}` claims.

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
