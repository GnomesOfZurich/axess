# axess-strings

[![Version](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/version.svg)](https://crates.io/crates/axess-strings)
[![Status](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/status.svg)](https://github.com/GnomesOfZurich/axess)
[![License](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/license.svg)](https://github.com/GnomesOfZurich/axess#licence)

[crates.io](https://crates.io/crates/axess-strings) · [docs.rs](https://docs.rs/axess-strings) · [GitHub](https://github.com/GnomesOfZurich/axess)

Hot-path string primitive for the [Axess](https://github.com/GnomesOfZurich/axess) workspace.

`ShortString` is optimised for the workload of short identifiers that are hashed, compared, and cloned at high volume; event taxonomy tags, factor names, routing discriminators. The current internal representation is a placeholder (`Box<str>` / `&'static str`) suitable for getting the API contract in place; future work may swap to an inline-storage variant without changing the surface.

## Licence

Dual-licensed under [MIT](https://github.com/GnomesOfZurich/axess/blob/main/LICENSE-MIT) and [Apache-2.0](https://github.com/GnomesOfZurich/axess/blob/main/LICENSE-APACHE).
