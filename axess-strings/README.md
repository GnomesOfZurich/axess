# axess-strings

[![Version](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/version.svg)](https://crates.io/crates/axess-strings)
[![Status](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/status.svg)](https://github.com/GnomesOfZurich/axess)
[![License](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/license.svg)](https://github.com/GnomesOfZurich/axess#licence)

[crates.io](https://crates.io/crates/axess-strings) · [docs.rs](https://docs.rs/axess-strings) · [Book](https://gnomesofzurich.github.io/axess/) · [GitHub](https://github.com/GnomesOfZurich/axess)

Hot-path string primitive for the [Axess](https://github.com/GnomesOfZurich/axess) workspace.

`ShortString` is optimised for the workload of short identifiers that are hashed, compared, and cloned at high volume; event taxonomy tags, factor names, routing discriminators. The internal representation is a 16-byte Umbra-style value with three variants: **Inline** (≤ 12 bytes stored in the value itself, no allocation), **Static** (immutable `&'static [u8]` for compile-time constants via `ShortString::from_static`), and **Heap** (refcounted for longer strings). All three share a 4-byte prefix at a fixed offset so equality can short-circuit without first branching on the variant. See [`src/repr.rs`](src/repr.rs) for the layout, discriminator, and soundness invariants.

## Licence

Dual-licensed under [MIT](https://github.com/GnomesOfZurich/axess/blob/main/LICENSE-MIT) and [Apache-2.0](https://github.com/GnomesOfZurich/axess/blob/main/LICENSE-APACHE).
