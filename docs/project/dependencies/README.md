# Dependency plan

The dependency map of the workspace named six tasks. Two are done or in
hand, and the rest are designed here for the work that follows:

| Task | State | Page |
|---|---|---|
| Keep test-only crates out of production | done: `axess-testing`, `deny-production.toml`, `scripts/check-test-crate-edges.sh` | this page |
| Make RSA verify-only by default | additive parts done; the default change is a decision | [rsa-verify-only.md](rsa-verify-only.md) |
| One JOSE verification core | designed | [jose-core.md](jose-core.md) |
| One RustCrypto major | designed | [rustcrypto-major.md](rustcrypto-major.md) |
| One stored-data format | designed | [stored-format.md](stored-format.md) |
| Regex replaced by hand-written validators | designed | [regex-validators.md](regex-validators.md) |
| Narrow default features (tokio, sqlx, chrono, fred, reqwest) | done | below |

## Test-only crates

`axess-testing` holds the tracing capture and the OIDC-over-wiremock identity
provider fixture. Adopters take it as a dev-dependency; no published crate
depends on it except under `[dev-dependencies]`. `wiremock` and the `rsa` it
generates test keys with therefore sit on no production edge, and the
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
| `chrono` in the workspace | default features | `std`, `serde`; `clock` in `axess-clock` only, with `scripts/check-clock-usage.sh` rejecting a new wall-clock read |
| `fred` in `axess-core` | `transactions`, `subscriber-client`, `i-std`, `i-cluster`, `i-scripts`, `blocking-encoding`, `replicas` | `i-std`, `i-scripts`, `subscriber-client`, `blocking-encoding` |
| `reqwest` (dev) in `axess-core` | default features (`native-tls`, `openssl-sys`) | `rustls-tls`, `cookies`, `json` |
