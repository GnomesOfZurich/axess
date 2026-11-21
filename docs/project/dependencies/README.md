# Dependency plan

The table lists the dependency tasks of the workspace, the state of each
and the page that records or designs it:

| Task | State | Page |
|---|---|---|
| Keep test-only crates out of production | done: `axess-testing`, `deny-production.toml`, `scripts/check-test-crate-edges.sh` | this page |
| Make RSA verify-only by default | additive parts done; the default change is a decision | [rsa-signing-paths.md](rsa-signing-paths.md) |
| One JOSE verification core | designed | [jose-core.md](jose-core.md) |
| One RustCrypto major | designed | [rustcrypto-major.md](rustcrypto-major.md) |
| Stored session formats | MessagePack written and read; a JSON row is refused and its user signs in again | [stored-format.md](stored-format.md) |
| Regex replaced by hand-written validators | designed | [regex-validators.md](regex-validators.md) |
| Narrow default features (tokio, sqlx, chrono, fred, reqwest) | done | below |
| Leave chrono, which its maintainer declared unmaintained | done for axess's own types; chrono still reaches a build through three upstream crates | below |

## Test-only crates

`axess-testing` holds the tracing capture and the OIDC-over-wiremock identity
provider fixture. Adopters take it as a dev-dependency; no published crate
depends on it except under `[dev-dependencies]`. `wiremock`, and the `rsa` that
`axess-testing` generates test keys with, therefore sit on no production edge, and the
`testing-oauth` feature of `axess-core` is gone.

Two checks keep it so: `cargo deny --config deny-production.toml check bans`
(dev edges excluded; `wiremock` allowed only as a dependency of
`axess-testing`) and `scripts/check-test-crate-edges.sh` (walks the resolved
graph from every other workspace member along normal and build edges and
fails on reaching `axess-testing` or `wiremock`).

## Narrowed features

| Dependency | Before | After |
|---|---|---|
| `tokio` in `axess-core` | `full`, `macros`, `rt-multi-thread` | `macros`, `rt`, `sync`, `time`; `full` for dev only |
| `sqlx` in `axess-core` | default features (`any`, `macros`, `migrate`, `json`) | `default-features = false`, `runtime-tokio`, `derive` |
| `chrono` in the workspace | default features | `std`, `serde`, and no crate enables `clock`; chrono is no longer a dependency of any crate's public API (below) |
| `fred` in `axess-core` | `transactions`, `subscriber-client`, `i-std`, `i-cluster`, `i-scripts`, `blocking-encoding`, `replicas` | `i-std`, `i-scripts`, `subscriber-client`, `blocking-encoding` |
| `reqwest` (dev) in `axess-core` | default features (`native-tls`, `openssl-sys`) | `rustls-tls`, `cookies`, `json` |

## chrono

chrono and chrono-tz are declared unmaintained (RUSTSEC-2026-0543,
RUSTSEC-2026-0555). The workspace's own time types are axess-clock's
(`Timestamp`, `SignedDuration`, `Until`, `UtcDate`), on the standard library
alone, and no public signature of any crate names chrono. chrono is a direct
dependency in two places only:

- `axess-factors`, optional and enabled by `oauth` alone:
  openidconnect's ID-token verifier reads the time through a closure that
  returns a chrono value, so the reading is converted where it crosses,
  in private code;
- `axess-clock`, as a dev-dependency: the oracle of
  `tests/chrono_agreement.rs`, which holds the time types to what chrono
  computed, and the third-party time library in
  `tests/other_time_library.rs`, whose cases show how an adopter's code
  converts at its boundary with these types.

It still reaches a build through three upstream crates: `cedar-policy-core`
(authorization), `oauth2` and `openidconnect` (`oidc`, `oauth`). The facade
`axess` always enables authorization, so its tree holds chrono through
`cedar-policy-core` with no feature chosen; no other published crate's tree
holds it then. `scripts/check-chrono-edges.sh`, in CI's Security Audit job
and the release preflight, holds all of this, and its header says why
`axess` is its one named exception. `deny.toml` and `.cargo/audit.toml`
keep the ignore of RUSTSEC-2026-0543 while chrono is in `Cargo.lock`; it
goes when the three upstream crates drop it.

## Held back, and what lifts each

Three requirements stay on the previous major of their crate. Each is held by
a crate this workspace does not publish, and moving ours alone would put two
copies of a cryptographic or transport crate in one lock without closing an
advisory. Each requirement in the manifests carries a comment with the same
condition.

**rsa 0.9.** The fix for RUSTSEC-2023-0071 is rsa 0.10.0, and `deny.toml` and
`.cargo/audit.toml` keep the ignore while 0.9 is in the lock. openidconnect
requires rsa ^0.9, and crypto-glue (through webauthn-rs) requires an rsa 0.10
release candidate feature that the 0.10.0 release lacks. It lifts when
openidconnect accepts rsa 0.10 and crypto-glue moves to rsa 0.10.0; every rsa
requirement of the workspace then moves in the same change and the ignore goes
with it. `deny.toml` fails once no crate in the lock matches the advisory.

**reqwest 0.12.** oauth2 and openidconnect require reqwest ^0.12. Its types
are in this workspace's public API (`ScreenedClient` is handed to openidconnect
as its own reqwest client), so they are tied to the reqwest openidconnect
uses, and a second reqwest major in the lock would not satisfy that. It lifts
when oauth2 and openidconnect release versions that require reqwest 0.13, and
the workspace moves with them.

**jsonwebtoken 11.** jsonwebtoken 12 requires rsa ^0.10, so it cannot enter
the lock while openidconnect keeps rsa 0.9 there. It lifts with the rsa
change above.
