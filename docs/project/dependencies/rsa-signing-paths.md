# RSA signing paths, and the plan to make RSA verify-only by default

## The exposure

The `rsa` crate (0.9) carries RUSTSEC-2023-0071, a timing side channel on RSA
private-key operations. The fix is rsa 0.10.0, and axess stays on 0.9 while
jsonwebtoken (11.1.0, `rust_crypto` backend) and openidconnect (4.1.0)
require it; a `fido2` build also carries an rsa 0.10 pre-release through
crypto-glue, which the advisory counts as affected. The weekly
`advisory-fix-watch` workflow opens an issue when each of the three accepts
0.10.0, and the ignore goes when all three have. `deny.toml` ignores the
advisory for the whole workspace, because cargo-deny cannot scope an ignore
to a feature; its entry names every dependent and every place a private RSA
key is used.

An RSA signature is the private-key operation the advisory is about, and
library code makes one in two places:

- the local IdP, when its signing key is an RSA key, which needs the
  `local-idp-rsa` feature;
- `private_key_jwt` client assertions (`ClientAssertionSigner` in
  `axess-factors`, features `oauth` and `outbound-oauth`), when the client's
  key is an RSA key, which needs the `client-assertion-rsa` feature except
  where the `jsonwebtoken` provider in place is the aws-lc one axess
  installed.

Both sign through `jsonwebtoken`'s backend:

- under `jwt-aws-lc`, an RSA signature runs in aws-lc-rs, not in `rsa`;
- under `jwt-rust-crypto` alone, it runs in the `rsa` crate, and this is the
  path the advisory describes.

`axess-core` names `rsa` in one module, `local_idp/primitives/rsa_key.rs`,
compiled with `local-idp-rsa` alone, for RSA key generation and PEM or DER
parsing. `local-idp` without it has ES256 keys (`generate_es256`, the
`from_ec_*` loaders) and compiles no `rsa`: on `jwt-aws-lc` such a build
holds no `rsa` at all, and on `jwt-rust-crypto` it holds the copy
`jsonwebtoken` brings for verifying, which signs nothing.

## Options for the default

1. **ES256 is the local IdP's default key.** `LocalIdp` constructors and the
   `generate_rsa` shorthand move to P-256; RSA stays one explicit call away.
   A verifier that cannot take ES256 is the only reason to choose RSA.
   *Breaks:* every adopter calling `LocalIdpSigningKey::generate_rsa()` and
   relying on the key being RSA. A migration paragraph and a decision.
2. **Refuse RSA signing when `jwt-rust-crypto` is the backend.** Under
   `jwt-aws-lc` nothing changes; under `jwt-rust-crypto` an RS* signing key
   is refused by name (`LocalIdpKeyError`) with the message to use ES256 or
   the aws-lc backend. *Breaks:* a pure-Rust deployment that signs RS256
   locally.
3. **Do nothing to the default, state the exposure.** The ignore stays, the
   path stays, and the page says who is exposed. The cost is the standing
   advisory ignore.

Options 1 and 2 both close the exposure. Option 2 is the smaller break and
closes it exactly where it is; option 1 also stops RSA from being the habitual choice.

## What landed

- The RSA keys of the local IdP are behind `local-idp-rsa`, so the RSA
  constructors are one named feature away and a local IdP without it cannot
  sign through `rsa`. `LocalIdpFixture::new` signs ES256,
  and `LocalIdp` has no default key: the caller hands it one.
- `scripts/check-rsa-sites.sh` fails CI when any production file other than
  the reviewed RSA module names `rsa::`, so the advisory ignore cannot
  quietly cover a new call site, and `scripts/supply-chain.sh` fails when a
  `local-idp` build on `jwt-aws-lc` resolves `rsa`.
- Option 2 is applied as a choice rather than a refusal: on
  `jwt-rust-crypto` alone a `ClientAssertionSigner` for an RSA algorithm is
  refused when it is built (`ClientAssertionError::RsaNotChosen`), before
  its key is read, unless the `client-assertion-rsa` feature chose it. On
  `jwt-aws-lc`, when the `jsonwebtoken` crypto provider in place is the
  aws-lc one axess installed, an RSA client key signs in aws-lc-rs and
  needs no feature. An application or crate that installs a provider before axess
  does gets the same refusal: with both backends compiled that provider
  may be RustCrypto's, which signs in `rsa` 0.9, and `jsonwebtoken` offers
  no read of which one it is.
  `scripts/supply-chain.sh` checks that an `oauth` or `outbound-oauth`
  build resolves `rsa` through no crate of this workspace.

So no RSA signature is made in `rsa` 0.9 unless a feature named for it
(`local-idp-rsa`, `client-assertion-rsa`) chose it, whichever backends are
compiled and whoever installed the provider.
