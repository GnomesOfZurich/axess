<!--
Thanks for the contribution! A few asks before you submit:

  * Link the issue this PR addresses (or open one first if it's
    non-trivial; see CONTRIBUTING.md).
  * Run the local check: `cargo fmt --all && cargo clippy --workspace
    --all-features --lib --tests -- -D warnings && cargo test
    --workspace --all-features`.
  * Add a CHANGELOG.md entry under `[unreleased]`. Breaking changes
    belong under `### Changed (breaking)`.
-->

## What

<!-- One-sentence summary of the change. -->

## Why

<!-- The problem this solves. Link the issue (#NNN) if there is one. -->

## How

<!-- Brief notes on the approach; anything reviewers should know that
isn't obvious from the diff (trade-offs, alternatives considered,
follow-up work intentionally deferred). -->

## Checklist

- [ ] `cargo fmt --all` clean
- [ ] `cargo clippy --workspace --all-features --lib --tests -- -D warnings` clean
- [ ] `cargo test --workspace --all-features` clean
- [ ] `CHANGELOG.md` updated
- [ ] Public API change → rustdoc updated, breaking change called out
- [ ] DST: new time / RNG usage goes through `Clock` / `SecureRng` (no `SystemTime::now()` / `rand::rng()` in library code)
