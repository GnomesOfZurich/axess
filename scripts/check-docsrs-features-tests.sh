#!/usr/bin/env bash
# axess: crafted cases for scripts/check-docsrs-features.sh.
#
# Each case writes a workspace under a temporary root (a root manifest and
# the crates' manifests), runs the check against it with `--root`, and
# asserts the exit status and a fragment of the output. The check's EXCLUDED
# names `sqlite-unbundled` of `axess-core` and of `axess`, so every workspace
# here holds both crates, and a case changes one of them. The cases at the
# end add what a reader is shown: a crate root, a README or an AGENTS.md with
# a feature table, held to the same manifests.
#
# Usage: ./scripts/check-docsrs-features-tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$SCRIPT_DIR/check-docsrs-features.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/axess-docsrs-features.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=lib/case_harness.sh
. "$SCRIPT_DIR/lib/case_harness.sh"

passed=0
failed=0

# case NAME EXPECTED_EXIT FRAGMENT -- FILE CONTENT [FILE CONTENT...]
case_() {
  local name="$1" want="$2" fragment="$3"
  shift 4
  local root="$WORK/$passed-$failed"
  while [ $# -gt 0 ]; do
    mkdir -p "$root/$(dirname "$1")"
    printf '%s\n' "$2" > "$root/$1"
    shift 2
  done
  local out status
  out="$("$CHECK" --root "$root" 2>"$WORK/stderr")"
  status=$?
  rm -rf "$root"
  judge "$name" "$want" "$fragment" "$status" "$out"
}

WORKSPACE='[workspace]
members = ["axess", "axess-core", "axess-leaf", "examples/*"]'

# manifest NAME DOCS_RS_BODY FEATURES_BODY [REST]
manifest() {
  printf '[package]\nname = "%s"\n\n[package.metadata.docs.rs]\n%s\n\n[features]\n%s\n%s\n' "$1" "$2" "$3" "${4:-}"
}

CORE_FEATURES='default = ["authz"]
authz = []
sqlite = []
sqlite-unbundled = []'
CORE="$(manifest axess-core 'features = ["authz", "sqlite"]
rustdoc-args = ["--cfg", "docsrs"]' "$CORE_FEATURES")"
FACADE="$(manifest axess 'features = ["sqlite"]' 'sqlite = []
sqlite-unbundled = []')"
LEAF="$(manifest axess-leaf 'all-features = true' 'serde = []')"

case_ "explicit lists without the excluded feature, and all-features where nothing is excluded, pass" 0 \
  "OK: 3 published crates" -- Cargo.toml "$WORKSPACE" axess-core/Cargo.toml "$CORE" axess/Cargo.toml "$FACADE" axess-leaf/Cargo.toml "$LEAF"
case_ "all-features on a crate with an excluded feature is refused" 1 \
  'axess-core: `all-features = true` makes docs.rs build `sqlite-unbundled`' -- \
  Cargo.toml "$WORKSPACE" axess/Cargo.toml "$FACADE" axess-leaf/Cargo.toml "$LEAF" \
  axess-core/Cargo.toml "$(manifest axess-core 'all-features = true' "$CORE_FEATURES")"
case_ "a feature in neither the list nor the exclusions is refused" 1 \
  'axess-core: the feature `sqlite` is in neither the docs.rs `features` list nor EXCLUDED' -- \
  Cargo.toml "$WORKSPACE" axess/Cargo.toml "$FACADE" axess-leaf/Cargo.toml "$LEAF" \
  axess-core/Cargo.toml "$(manifest axess-core 'features = ["authz"]' "$CORE_FEATURES")"
case_ "an excluded feature in the list is refused" 1 \
  'axess-core: `sqlite-unbundled` is in the docs.rs `features` list and in EXCLUDED' -- \
  Cargo.toml "$WORKSPACE" axess/Cargo.toml "$FACADE" axess-leaf/Cargo.toml "$LEAF" \
  axess-core/Cargo.toml "$(manifest axess-core 'features = ["authz", "sqlite", "sqlite-unbundled"]' "$CORE_FEATURES")"
case_ "a listed name the crate does not define is refused" 1 \
  'axess-core: the docs.rs `features` list names `postgres`, which is not a feature of the crate' -- \
  Cargo.toml "$WORKSPACE" axess/Cargo.toml "$FACADE" axess-leaf/Cargo.toml "$LEAF" \
  axess-core/Cargo.toml "$(manifest axess-core 'features = ["authz", "sqlite", "postgres"]' "$CORE_FEATURES")"
case_ "the feature cargo makes of an optional dependency must be listed" 1 \
  'axess-core: the feature `serde` is in neither the docs.rs `features` list nor EXCLUDED' -- \
  Cargo.toml "$WORKSPACE" axess/Cargo.toml "$FACADE" axess-leaf/Cargo.toml "$LEAF" \
  axess-core/Cargo.toml "$(manifest axess-core 'features = ["authz", "sqlite"]' "$CORE_FEATURES" '
[dependencies]
serde = { version = "1", optional = true }')"
case_ "an optional dependency a feature names with dep: is not a feature" 0 "OK: 3 published crates" -- \
  Cargo.toml "$WORKSPACE" axess/Cargo.toml "$FACADE" axess-leaf/Cargo.toml "$LEAF" \
  axess-core/Cargo.toml "$(manifest axess-core 'features = ["authz", "sqlite", "json"]' "$CORE_FEATURES
json = [\"dep:serde\"]" '
[dependencies]
serde = { version = "1", optional = true }')"
case_ "an exclusion the crate no longer defines is refused" 1 \
  'axess-core: EXCLUDED names `sqlite-unbundled`, which is not a feature of the crate' -- \
  Cargo.toml "$WORKSPACE" axess/Cargo.toml "$FACADE" axess-leaf/Cargo.toml "$LEAF" \
  axess-core/Cargo.toml "$(manifest axess-core 'all-features = true' 'authz = []')"
case_ "an excluded crate missing from the workspace is refused" 1 \
  'EXCLUDED names the crate `axess`, which is not a published member of the workspace' -- \
  Cargo.toml "$WORKSPACE" axess-core/Cargo.toml "$CORE" axess-leaf/Cargo.toml "$LEAF"
case_ "a list that drops the default features is refused" 1 \
  "axess-core: docs.rs is told to drop the default features" -- \
  Cargo.toml "$WORKSPACE" axess/Cargo.toml "$FACADE" axess-leaf/Cargo.toml "$LEAF" \
  axess-core/Cargo.toml "$(manifest axess-core 'features = ["authz", "sqlite"]
no-default-features = true' "$CORE_FEATURES")"
case_ "a crate with neither form is refused" 1 \
  'axess-leaf: [package.metadata.docs.rs] has neither `all-features = true` nor a `features` list' -- \
  Cargo.toml "$WORKSPACE" axess-core/Cargo.toml "$CORE" axess/Cargo.toml "$FACADE" \
  axess-leaf/Cargo.toml "$(manifest axess-leaf 'rustdoc-args = ["--cfg", "docsrs"]' 'serde = []')"
case_ "a published crate with no docs.rs table is refused" 1 "axess-leaf: no [package.metadata.docs.rs]" -- \
  Cargo.toml "$WORKSPACE" axess-core/Cargo.toml "$CORE" axess/Cargo.toml "$FACADE" \
  axess-leaf/Cargo.toml '[package]
name = "axess-leaf"

[features]
serde = []'
case_ "an unpublished member is not read" 0 "OK: 3 published crates" -- \
  Cargo.toml "$WORKSPACE" axess-core/Cargo.toml "$CORE" axess/Cargo.toml "$FACADE" axess-leaf/Cargo.toml "$LEAF" \
  examples/demo/Cargo.toml '[package]
name = "axess-example-demo"
publish = false

[features]
sqlite-unbundled = []'
case_ "a root with no workspace is refused, not passed" 1 "ERROR: no workspace members read" -- \
  Cargo.toml '[package]
name = "alone"'
case_ "a workspace with no published crate is refused, not passed" 1 "ERROR: no published crate found" -- \
  Cargo.toml '[workspace]
members = ["examples/*"]' examples/demo/Cargo.toml '[package]
name = "axess-example-demo"
publish = false'

# ── The feature tables a reader is shown ─────────────────────────────────────

# lib_rs TABLE_ROWS: a crate root whose documentation has a "Feature flags"
# section holding those rows, and a table after the section that is not read.
lib_rs() {
  printf '%s\n' '//! A crate.' '//!' '//! # Feature flags' '//!' \
    '//! | Feature | What it enables |' '//! |---------|-----------------|'
  printf '//! %s\n' "$@"
  printf '%s\n' '//!' '//! # Another section' '//!' '//! | `not-a-feature` | A table outside the section. |' '' 'pub fn f() {}'
}

ALL=(Cargo.toml "$WORKSPACE" axess-core/Cargo.toml "$CORE" axess/Cargo.toml "$FACADE" axess-leaf/Cargo.toml "$LEAF")

case_ "a crate root's table that names exactly the crate's features passes" 0 \
  "1 documented feature table(s) name exactly the features of their crates" -- "${ALL[@]}" \
  axess-core/src/lib.rs "$(lib_rs '| `authz` | Policies. On by default. |' '| `sqlite` / `sqlite-unbundled` | The SQLite stores. |')"
case_ "a table that names a feature the crate does not define is refused" 1 \
  'axess-core: src/lib.rs: the feature table names `full`, which is not a feature of the crate' -- "${ALL[@]}" \
  axess-core/src/lib.rs "$(lib_rs '| `authz` | Policies. |' '| `sqlite` | A store. |' '| `sqlite-unbundled` | The same. |' '| `full` | All of the above. |')"
case_ "a feature written with underscores is not the feature" 1 \
  'axess-core: src/lib.rs: the feature table names `sqlite_unbundled`, which is not a feature of the crate' -- "${ALL[@]}" \
  axess-core/src/lib.rs "$(lib_rs '| `authz` | Policies. |' '| `sqlite` | A store. |' '| `sqlite_unbundled` | The same. |')"
case_ "a feature with no row is refused" 1 \
  'axess-core: src/lib.rs: the feature `sqlite` of the crate has no row in the feature table' -- "${ALL[@]}" \
  axess-core/src/lib.rs "$(lib_rs '| `authz` | Policies. |' '| `sqlite-unbundled` | A store. |')"
case_ "a feature named only in the prose of the section has no row" 1 \
  'axess-core: src/lib.rs: the feature `sqlite-unbundled` of the crate has no row in the feature table' -- "${ALL[@]}" \
  axess-core/src/lib.rs "$(lib_rs '| `authz` | Policies. |' '| `sqlite` | A store. |' '' 'Internal features: `sqlite-unbundled`.')"
case_ "a row that does not start with a feature in backticks is refused" 1 \
  'axess-core: src/lib.rs: a row of the feature table does not start with feature names in backticks' -- "${ALL[@]}" \
  axess-core/src/lib.rs "$(lib_rs '| `authz` | Policies. |' '| sqlite and `sqlite-unbundled` | The stores. |')"
case_ "a feature section with no table is refused, not passed" 1 \
  'axess-core: src/lib.rs: a "Feature flags" section with no table row' -- "${ALL[@]}" \
  axess-core/src/lib.rs '//! # Feature flags
//!
//! See the manifest.
pub fn f() {}'
case_ "a heading inside a fenced block does not end the section" 1 \
  'axess-core: src/lib.rs: the feature table names `full`' -- "${ALL[@]}" \
  axess-core/src/lib.rs '//! # Feature flags
//!
//! ```toml
//! # Cargo.toml
//! axess-core = { features = ["sqlite"] }
//! ```
//!
//! | Feature | What it enables |
//! |---------|-----------------|
//! | `authz` | Policies. |
//! | `sqlite` / `sqlite-unbundled` | The stores. |
//! | `full` | Everything. |
pub fn f() {}'

# A document is put together from parts, each in single quotes: a backtick
# inside a `${name/old/new}` would be run as a command.
NL='
'
README_TABLE='# axess

### Feature flags

#### Storage

| Feature | What it enables | Default |
|---|---|---|
| `sqlite` | A store | no |
| `sqlite-unbundled` | The same, linked to the system library | no |'
README_UMBRELLA='#### Umbrella

| Feature | What it enables | Default |
|---|---|---|
| `full` | Everything | no |'
README_REST='## Security

| `not-a-feature` | A table after the section |'
README_OK="$README_TABLE$NL$NL$README_REST"
case_ "the README's tables, under their sub-headings, are held to the facade" 0 \
  "1 documented feature table(s)" -- "${ALL[@]}" README.md "$README_OK"
case_ "a README row for a feature the facade does not define is refused" 1 \
  'README.md: the feature table names `full`, which is not a feature of axess' -- "${ALL[@]}" \
  README.md "$README_TABLE$NL$NL$README_UMBRELLA$NL$NL$README_REST"
case_ "a facade feature the README leaves out is refused" 1 \
  'README.md: the feature `sqlite-unbundled` of axess has no row in the feature table' -- "${ALL[@]}" \
  README.md '### Feature flags

| Feature | What it enables |
|---|---|
| `sqlite` | A store |'
case_ "a README feature section with no facade to document is refused" 1 \
  'README.md has a "Feature flags" section, which documents `axess`' -- \
  Cargo.toml "$WORKSPACE" axess-core/Cargo.toml "$CORE" axess-leaf/Cargo.toml "$LEAF" README.md "$README_OK"

AGENTS_CORE='## Feature Flags

### axess-core (default = `authz`)

| Feature | What it enables |
|---------|----------------|
| `authz` | Policies (default) |'
AGENTS_SQLITE='| `sqlite` / `sqlite-unbundled` | The SQLite stores |'
AGENTS_REST='### axess-leaf

| Feature | What it enables |
|---------|----------------|
| `serde` | Serialization |

### Common feature combinations

| Use Case | Features |
|----------|----------|
| Minimal | `memory`, `admin` |

## Testing

| `not-a-feature` | A table after the section |'
case_ "AGENTS.md tables are held to the crate their sub-heading names, and no other table is read" 0 \
  "2 documented feature table(s)" -- "${ALL[@]}" AGENTS.md "$AGENTS_CORE$NL$AGENTS_SQLITE$NL$NL$AGENTS_REST"
case_ "an AGENTS.md row for a feature the crate does not define is refused" 1 \
  'AGENTS.md: axess-core: the feature table names `admin`, which is not a feature of axess-core' -- "${ALL[@]}" \
  AGENTS.md "$AGENTS_CORE$NL$AGENTS_SQLITE$NL"'| `admin` | Management APIs |'"$NL$NL$AGENTS_REST"
case_ "an AGENTS.md table that leaves a feature out is refused" 1 \
  'AGENTS.md: axess-core: the feature `sqlite-unbundled` of axess-core has no row in the feature table' -- "${ALL[@]}" \
  AGENTS.md "$AGENTS_CORE$NL"'| `sqlite` | The SQLite store |'"$NL$NL$AGENTS_REST"

# ── A feature named in running text and in a cfg ─────────────────────────────

DEMO='[package]
name = "axess-example-demo"
publish = false'

case_ "a module comment that spells a feature with underscores is refused" 1 \
  'axess-core/src/middleware.rs:5: the comment names the feature `sqlite_unbundled`, which is not a feature of axess-core' -- "${ALL[@]}" \
  axess-core/src/middleware.rs '//! Stores.
//!
//! Generates an id per request. With the `sqlite` feature the store is
//! bundled; without it, every build links the system library. This crate
//! adds that path behind the `sqlite_unbundled`
//! feature.
pub fn f() {}'
case_ "an item comment that spells a feature with underscores is refused" 1 \
  'axess-core/src/middleware.rs:2: the comment names the feature `sqlite_unbundled`, which is not a feature of axess-core' -- "${ALL[@]}" \
  axess-core/src/middleware.rs 'pub struct Store {
    /// Read when the `sqlite_unbundled` feature is enabled.
    pub linked: bool,
}'
case_ "a plain comment in a test file is read as a doc comment is" 1 \
  'axess-core/src/middleware/tests.rs:1: the comment names the feature `sqlite_unbundled`, which is not a feature of axess-core' -- "${ALL[@]}" \
  axess-core/src/middleware/tests.rs '// With feature `sqlite_unbundled` on, the system library is linked.
#[test]
fn links() {}'
case_ "a cfg that names no feature of the crate is refused" 1 \
  'axess-core/src/lib.rs:1: `feature = "sqlite_unbundled"` names no feature of axess-core' -- "${ALL[@]}" \
  axess-core/src/lib.rs '#[cfg(feature = "sqlite_unbundled")]
pub fn f() {}'
case_ "a doc(cfg) that names no feature of the crate is refused" 1 \
  'axess-core/src/lib.rs:2: `feature = "postgres"` names no feature of axess-core' -- "${ALL[@]}" \
  axess-core/src/lib.rs '#[cfg(feature = "sqlite")]
#[cfg_attr(docsrs, doc(cfg(any(feature = "sqlite", feature = "postgres"))))]
pub fn f() {}'
case_ "the right spellings pass, in comments and in cfgs" 0 \
  "4 feature name(s) in comments, cfg attributes and book pages are features" -- "${ALL[@]}" \
  axess-core/src/lib.rs '//! With the `sqlite-unbundled` feature the system library is linked.
/// Behind feature `authz`.
#[cfg(any(feature = "sqlite", feature = "sqlite-unbundled"))]
pub fn f() {}'
case_ "a feature of another crate passes when the line names the crate" 0 "OK: 3 published crates" -- "${ALL[@]}" \
  axess-core/src/lib.rs '/// Forwards to the `serde` feature of axess-leaf.
pub fn f() {}'
case_ "a feature of another crate is refused when no crate is named" 1 \
  'axess-core/src/lib.rs:1: the comment names the feature `serde`, which is not a feature of axess-core' -- "${ALL[@]}" \
  axess-core/src/lib.rs '/// Forwards to the `serde` feature.
pub fn f() {}'
case_ "an example names the features of the crates it uses" 0 "OK: 3 published crates" -- "${ALL[@]}" \
  examples/demo/Cargo.toml "$DEMO" examples/demo/src/main.rs '//! Run with the `sqlite` feature of the facade.
fn main() {}'
case_ "an example that names no feature of the workspace is refused" 1 \
  'examples/demo/src/main.rs:1: the comment names the feature `postgres`, which is not a feature of axess-example-demo' -- "${ALL[@]}" \
  examples/demo/Cargo.toml "$DEMO" examples/demo/src/main.rs '//! Run with the `postgres` feature.
fn main() {}'
case_ "a name written because it is another crate's has its reason on record" 0 "OK: 3 published crates" -- "${ALL[@]}" \
  axess-core/src/lib.rs '/// The `bundled` feature of the SQLite bindings is on.
pub fn f() {}'
case_ "a book page that names no feature of the workspace is refused" 1 \
  'docs/guide/stores.md:3: the page names the feature `postgres`, which is not a feature of any crate of the workspace' -- "${ALL[@]}" \
  docs/guide/stores.md '# Stores

Enable the `postgres` feature, or the `sqlite` feature.'
case_ "a book page reads prose only, and a feature of any crate passes" 0 \
  "2 feature name(s) in comments, cfg attributes and book pages are features" -- "${ALL[@]}" \
  docs/guide/stores.md '# Stores

The `sqlite` feature, and the `serde` feature of the leaf crate.

```toml
# the `postgres` feature is not read here
```'

echo "check-docsrs-features tests: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
