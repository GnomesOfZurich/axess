# One JOSE verification core

## Today

The same identity provider's keys are parsed twice and checked by two JOSE
implementations:

- ID tokens: `openidconnect` (`CoreIdTokenVerifier`, `CoreJsonWebKeySet`);
- logout, issuer and workload JWTs: `jsonwebtoken` (`JwkSet`) through
  `jwt::validation::verify_jwt`;
- DPoP proofs: a third path, `jsonwebtoken::crypto` over a hand-split JWS in
  `dpop_verify.rs`.

Each has its own algorithm allow-list, `use` and `alg` filtering, `kid`
matching and refresh. A hardening change made in one does not reach the
others, and choosing `jwt-aws-lc` does not take ID-token verification off the
RustCrypto code inside `openidconnect`.

## Target

`jwt::validation::verify_jwt` is the only JWS verification core. It gets a
`typ` expectation and a self-contained-key mode (the JWK travels in the
token, as DPoP needs). Everything that verifies a signature calls it:

1. ID-token signature and claims, against the one `JwkSet` cache.
2. Logout and issuer JWTs (already there).
3. DPoP proofs, with `kty` and `crv` checked to be EC and P-256 and `x`, `y`
   each 32 bytes before a key is built, and the thumbprint built with
   `serde_json` rather than `format!`.
4. JWT-SVIDs and workload tokens (already there).

`openidconnect` stays for discovery and token-response types, or goes.

## Files

About six files and ten functions:

- `axess-factors/src/oauth/provider/refresh_response.rs`
- `axess-factors/src/oauth/provider/fresh_keys.rs`
- `axess-factors/src/oauth/provider/fapi_profile.rs`
- `axess-factors/src/oauth/provider.rs` (the `OidcClient` type)
- `axess-factors/src/oauth/provider/issuer_jwt.rs` and `axess-factors/src/oidc/jwks_cache.rs`
- `axess-factors/src/oauth/provider/dpop_verify.rs`
- `axess-factors/src/jwt/validation.rs` and `axess-factors/src/jwt/verifier.rs`
  (the `typ` option and the self-contained-key mode)

## Gains and checks

- One JWKS parser, one algorithm policy, one copy each of `p256`,
  `elliptic-curve` and `ed25519-dalek` on the verify path.
- The note in `deny.toml` about `RUSTSEC-2023-0071` and `jwt-aws-lc` is
  corrected to say what is true once the paths merge.
- Tests: every case of the existing ID-token, logout, DPoP and workload
  suites passes unchanged against the one core; a table of `typ` values per
  token kind; a key-confusion test per path.
