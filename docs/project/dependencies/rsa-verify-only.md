# RSA verify-only by default

## The exposure

The `rsa` crate (0.9) carries RUSTSEC-2023-0071, a timing side channel on RSA
private-key operations with no fixed release. `deny.toml` ignores it for the
whole workspace, because cargo-deny cannot scope an ignore to a feature.

`axess-core` names `rsa` in one place that matters: the local IdP's
signing-key primitives (`local_idp/primitives.rs`), for RSA key generation
and PEM or DER parsing, behind the `local-idp` feature. Signing goes through
`jsonwebtoken`'s backend:

- under `jwt-aws-lc`, RS256 signing runs in aws-lc-rs, not in `rsa`;
- under `jwt-rust-crypto`, RS256 signing runs in the `rsa` crate, and this is
  the path the advisory describes.

`LocalIdpSigningKey::generate_es256` and the `from_ec_*` loaders already
exist, so an ES256 local IdP needs no `rsa` at all.

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
closes it exactly where it is; option 1 also removes the habit.

## What landed

Neither option is applied; both change behaviour adopters see.

- ES256 as an alternative path was already present.
- `scripts/check-rsa-sites.sh` fails CI when any production file other than
  the reviewed primitives names `rsa::`, so the advisory ignore cannot quietly
  cover a new private-key call site.

Dropping `dep:rsa` from `local-idp` entirely would need the RSA key
generation and parsing moved to aws-lc-rs, which is task four's territory.
