# Contributing to Axess

Thanks for your interest! Axess accepts bug reports, feature requests, documentation improvements, and code contributions.

Before opening a PR for non-trivial work, please file an issue first; this lets us flag overlap with in-flight work in [`ROADMAP.md`](ROADMAP.md) and confirm the change fits the library's direction (see [`docs/intro/architecture.md`](docs/intro/architecture.md)) before you invest time.

## Before you submit

1. **Fork** the repository and create a topic branch from `main`.
2. **Tests**; add or update tests for every behaviour change. The library uses deterministic simulation testing (DST); inject `MockClock` / `MockRng` rather than calling `SystemTime::now()` or `rand::rng()` directly.
3. **Run the full check locally:**
   ```bash
   cargo fmt --all
   cargo clippy --workspace --all-features --lib --tests -- -D warnings
   cargo test --workspace --all-features
   ```
4. **Update `CHANGELOG.md`**; add an entry under the `[unreleased]` section describing the change. Behaviour-changing entries belong under `### Changed (breaking)` if they alter a public API.
5. **Open a PR** with a description that covers the *why*; link the issue, summarise the design choice, and call out any deliberate trade-offs.

## Coding conventions

- Idiomatic Rust, `async`/`await` for IO, `thiserror` for error types, `tracing` for logs.
- Prefer traits + generics on hot paths; vtable dispatch (`Box<dyn …>`) only where it earns its keep.
- Public APIs need rustdoc; including at least one usage example for newly-introduced traits or builders.
- All time + randomness goes through the `Clock` / `SecureRng` traits. This is non-negotiable; it's what makes the test suite deterministic.

See [`.github/copilot-instructions.md`](.github/copilot-instructions.md) for the full house style.

## Workspace layout

| Crate | Role |
|---|---|
| `axess` | Public facade: middleware builder, re-exports, feature gates |
| `axess-core` | Core types, session orchestrator, Cedar authz integration, on-behalf-of credential storage + token exchange |
| `axess-cache` | Generic clock-aware TTL cache |
| `axess-clock` | `Clock` / `MockClock` traits for DST |
| `axess-events` | rkyv-serialisable audit event types |
| `axess-factors` | Authentication factor implementations |
| `axess-identity` | Newtype ID macros + impls |
| `axess-macros` | Procedural macros for route guards |
| `axess-rng` | `SecureRng` / `MockRng` traits |
| `axess-strings` | Short hot-path string primitive |
| `examples/*` | Reference example applications |

## Repository conventions

A few rules that aren't obvious from reading the code but affect every PR. Most exist because the cost of *not* following them showed up somewhere.

### Module layout

axess uses the modern Rust convention: `foo.rs` + a sibling `foo/` directory holding submodules. No `mod.rs` files in new code. Every directory module declares its submodules in the `foo.rs` file next to (not inside) the directory.

### Test-sideways-pull

When `#[cfg(test)]` tests crowd a production file enough to make scrolling expensive, pull them into a sibling `tests.rs`:

```text
axess-core/src/path/file.rs      ; production code +
                                    #[cfg(test)] mod tests;
axess-core/src/path/file/tests.rs; the actual tests, gated by
                                    #![cfg(test)]
```

Applied so far across several files where the tests-to-production ratio exceeded ~40%.

### `pub(crate)` for state-machine internals

`AuthSession` carries identity / session-state accessors as `pub`. State *mutation* methods (`set_authenticated`, `begin_authenticating`, `advance_factor`, `record_attempt_at`) are state-machine transitions that the factor pipeline drives; they are `pub(crate)` so handler code cannot corrupt the state machine. Adopters drive flow through `AuthnService`; the session is read-only-ish from outside axess-core.

Per-app workflow mutations (`set_identifying`, `set_pending_workflow`, `clear`, `regenerate`) remain `pub`; apps build their own two-step identify / workflow-step / logout flows on top.

### No `#[deprecated]` pre-1.0

Breaking changes happen freely across the 0.x line; adopters get one coordinated migration window per minor bump, not a long `#[deprecated]` trail. CHANGELOG documents each break under `### Changed (breaking)`.

### MSRV bumps are breaking changes

The workspace pins `rust-version = "1.87"` in `[workspace.package]`. A bump to a higher MSRV requires a minor-version bump on every published crate (0.x → 0.x+1 for 0.x; 1.x → 1.x+1 once stable). The reasoning: adopters pin Rust toolchains in CI; jumping the floor without warning silently breaks their builds.

Procedure for an MSRV bump:

1. Justify in the PR description (which compiler feature, why it earns the bump).
2. Update `rust-version` in `[workspace.package]` AND the `MSRV` job's
   toolchain pin in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).
3. Add an entry under `### Changed (breaking)` in CHANGELOG.md naming the new floor.
4. Bump the workspace `version` (in `[workspace.package]`) accordingly.

### No `#[non_exhaustive]` on first-party enums

`#[non_exhaustive]` trades one breakage class (adding variants) for another (every downstream `match` needs a wildcard arm forever, even when the caller wants compile-time exhaustiveness on a closed set). Project policy is to bump the version and let downstream `match` failures be loud. CI enforces this; the `ban_non_exhaustive` workflow job rejects any PR that introduces the attribute.

### No ticket-meta date stamps pre-v0.1.0

Source-code comments do not carry `// AX-NNN (YYYY-MM-DD):` markers. The CHANGELOG is the authoritative timeline; in-source stamps add noise without information a future reader can use. ROADMAP + CHANGELOG retain their AX-NNN references unchanged.

### Closed AX-NNN references get stripped

Once an AX-NNN case closes, every reference in source / doc-strings / test names is stripped, preserving the rationale comment but dropping the case number. Open + deferred cases stay referenced.

### Promoting a module out of `axess-core`

axess-core has accumulated significant surface. When proposing a new crate carve-out, check:

1. **No reverse dep from axess-core onto the carved module.** If the module's types appear in `AuthnService` method signatures or in any axess-core trait surface, the carve isn't yet feasible; invert the dependency first.
2. **Module has its own external dep blast.** Carving `delegated/` into `axess-delegated` won because it pulls `aes-gcm` only when adopters opt in. A carve that pulls no extra deps is just churn.
3. **Module is consumable in isolation.** A consumer who wants only the carved module should not transitively recompile axess-core's protocol surface.
4. **Re-export via the facade preserves the import path.** Adopters write `axess::middleware::ratelimit::*`, not `axess_middleware::ratelimit::*`. The facade decides the shape.

## Security

**Do not** open public issues for security vulnerabilities. Report them privately per [`SECURITY.md`](SECURITY.md).

## Licensing

By contributing, you agree your contribution will be dual-licensed under [MIT](LICENSE-MIT) and [Apache-2.0](LICENSE-APACHE), matching the project licence.

## Community

Be respectful and constructive. See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

Maintainer time is volunteer-funded; review turnaround is best-effort.
