# Regex replaced by hand-written validators

## Today

`regex` is a default dependency of `axess-core` for four validators in
`axess-core/src/validation.rs`: `EMAIL_RE`, `LANG_RE`, `URL_RE` and `NAME_RE`.
They are ASCII character-class and length rules, and `regex` brings its
Unicode tables for them. `URL_RE` accepts URLs the `url` crate parses
differently, so validation and later use can disagree, and `is_valid_name`
runs the pattern before it checks the length.

## Plan

- `is_valid_email`: a byte-level check. A local part from the permitted
  character set, then the domain split on `.`, each label 1 to 63 characters
  of `[a-z0-9-]` with no hyphen at either end. Length checked first.
- `is_valid_language_code`: two lowercase ASCII letters, optionally `-` and two
  uppercase ASCII letters.
- `is_valid_url_format`: `url::Url::parse`, then require the scheme to be
  `http` or `https`, a domain host, and a length of 2048 or less. The `url`
  crate is already a dependency, so validation and use agree.
- `is_valid_name`: check the length first (2 to 128 characters), then a
  `char` loop over `char::is_alphanumeric` and the permitted punctuation.

Then remove `regex` from `axess-core/Cargo.toml`.

## Files

- `axess-core/src/validation.rs` (and its tests)
- `axess-core/Cargo.toml`

## Checks

Every accepted and refused input of the present tests, kept as a table and
run against both implementations before the old one is deleted; a property
test that the hand-written email, language and name checks agree with the
patterns on random ASCII and Unicode strings; a case per URL the `url` crate
parses differently from the old pattern.
