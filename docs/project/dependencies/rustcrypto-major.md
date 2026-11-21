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

The old curve line comes from `jsonwebtoken` (p256 and p384 0.13, for its
`rust_crypto` backend). The old `rsa` line comes from `jsonwebtoken`,
`openidconnect`, `axess-core`'s `local-idp-rsa`, `axess-testing` and the
workspace's test code. The new lines come from `openidconnect`, `webauthn-rs`
through `crypto-glue`, and `axess`'s own `p256`, which is on 0.14. Two
advisory ignores stay. The one for `crypto-bigint` stays only because of the
old curve line. The one for `rsa` stays because of both lines: the new one
is `rsa` 0.10.0-rc.19 under `fido2`, a pre-release of the fixed release,
which the advisory counts as affected.

## Plan

1. After the JOSE core merge ([jose-core.md](jose-core.md)) the verify paths
   use one backend. Track a `jsonwebtoken` release on p256 0.14.
2. The direct `p256` uses (`oauth/types/dpop_key.rs`,
   `oauth/provider/dpop.rs`, the local IdP's EC keys in
   `local_idp/primitives.rs`) are on 0.14, so a build on `jwt-aws-lc` carries
   no 0.13 curve stack. Every `rsa` requirement of the workspace moves to
   0.10.0 when `crypto-glue` takes that release and `jsonwebtoken` and
   `openidconnect` accept it (see
   [Held back, and what lifts each](README.md#held-back-and-what-lifts-each)).
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
