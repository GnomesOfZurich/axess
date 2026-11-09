# One RustCrypto major

## Today

The lockfile carries two copies of the curve and big-number stack and a
release-candidate RSA:

| Crate | Lines |
|---|---|
| `p256`, `elliptic-curve`, `crypto-bigint` | 0.13 / 0.13 / 0.5 and 0.14 / 0.14 / 0.7 |
| `rsa` | 0.9 and 0.10.0-rc |
| `ed25519-dalek` | 2 and 3 |
| `hmac`, `sha1`, `sha2`, `argon2` | two each |
| `rand`, `base64` | three each |

The old lines come from `jsonwebtoken` (p256 0.13) and `axess`'s own pin; the
new ones from `openidconnect` and `webauthn-rs` through `crypto-glue`. Two
advisory ignores stay only because of the old lines.

## Plan

1. After the JOSE core merge ([jose-core.md](jose-core.md)) the verify paths
   use one backend. Track a `jsonwebtoken` release on p256 0.14.
2. Until then, move the direct `p256` uses (`oauth/types/dpop_key.rs`,
   `oauth/provider/dpop.rs`, the local IdP's EC keys in
   `local_idp/primitives.rs`) to the backend `jsonwebtoken` uses, or sign DPoP
   proofs through aws-lc when `jwt-aws-lc` is on.
3. Settle on one TLS and crypto provider: switch `ldap3` from
   `tls-rustls-ring` to its aws-lc feature, so ring leaves a build that has
   `ldap` and the rest on aws-lc.
4. Make `fido2` (webauthn-rs) opt-in only, and track the upstream bump that
   removes the `rsa` release candidate.
5. Add `multiple-versions = "deny"` entries for `p256`, `rsa` and
   `crypto-bigint` to `deny.toml`, each with an explicit skip and a reason,
   so a third copy fails CI.

## Files

- `axess-factors/Cargo.toml` and `axess-core/Cargo.toml` (the `p256`, `rsa`,
  `ldap3` lines)
- `axess-factors/src/oauth/types/dpop_key.rs`,
  `axess-factors/src/oauth/provider/dpop.rs`
- `axess-core/src/local_idp/primitives.rs`
- `deny.toml`

## Documented, not changed

Challenge and state entropy in `webauthn-rs` and `openidconnect` come from
their own OS-backed generators, not from `axess-rng`, so deterministic
simulation tests do not cover them. State this in the fido2 and OAuth
chapters.
