# axess-strings

[![Version](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/version.svg)](https://crates.io/crates/axess-strings)
[![Status](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/status.svg)](https://github.com/GnomesOfZurich/axess)
[![License](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/license.svg)](https://github.com/GnomesOfZurich/axess#licence)

[crates.io](https://crates.io/crates/axess-strings) · [docs.rs](https://docs.rs/axess-strings) · [Book](https://gnomesofzurich.github.io/axess/) · [GitHub](https://github.com/GnomesOfZurich/axess)

Hot-path string primitive for the [Axess](https://github.com/GnomesOfZurich/axess) workspace.

`ShortString` is an **immutable** identifier type, for values that are built
once and then cloned, hashed and compared at high volume: event subject ids,
taxonomy tags, key ids.

It is a 24-byte value in three forms. Strings up to 22 bytes are held inline
with no allocation; `ShortString::from_static` references `&'static str` in
place, in a `const fn`, whatever the length; anything longer goes into an
`Arc<str>`, so a clone is a refcount bump rather than a copy. Contains no
`unsafe` code.

Immutability is what makes the sharing safe, and it is why this is not a
`CompactString` or a `String`: those are growable, so they cannot share, and
cloning one past its inline buffer allocates and copies. If you need to push
to, truncate or build up the value, use `CompactString`. If it is an
identifier, use this.

See [`src/repr.rs`](src/repr.rs) for the representation and its invariants. The
measurements against `CompactString` and `Arc<str>` are in
[`benches/short_string.rs`](https://github.com/GnomesOfZurich/axess/blob/main/axess-strings/benches/short_string.rs),
which lives in the repository rather than the published crate.

## Licence

Dual-licensed under [MIT](https://github.com/GnomesOfZurich/axess/blob/main/LICENSE-MIT) and [Apache-2.0](https://github.com/GnomesOfZurich/axess/blob/main/LICENSE-APACHE).
