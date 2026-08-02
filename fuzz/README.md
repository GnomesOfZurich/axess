# axess-fuzz

Coverage-guided fuzz harness for axess. Targets the highest-risk
parsing / decoding paths: a crash here is a denial-of-service vector on
the session-load or token-verify hot path.

## Targets

| Target                       | Surface under test                                        |
|------------------------------|-----------------------------------------------------------|
| `session_data_msgpack`       | `rmp_serde::from_slice::<SessionData>(...)`; SQL/Valkey decode path. |
| `session_data_json`          | `serde_json::from_slice::<SessionData>(...)`; legacy-row fallback decode path. |
| `jwt_payload_split`          | Back-channel-logout JWT split + base64url + JSON decode (mirrors `decode_jwt_payload`). |
| `pkce_verifier_predicate`    | RFC 7636 §4.1 `code_verifier` predicate (mirrors `is_valid_pkce_verifier`). |

## Running locally

`cargo-fuzz` requires nightly:

```bash
rustup install nightly
cargo install cargo-fuzz --locked
```

Then, from the repo root:

```bash
cd fuzz
cargo +nightly fuzz run session_data_msgpack -- -max_total_time=60
cargo +nightly fuzz run session_data_json    -- -max_total_time=60
cargo +nightly fuzz run jwt_payload_split    -- -max_total_time=60
cargo +nightly fuzz run pkce_verifier_predicate -- -max_total_time=60
```

`-max_total_time` is libFuzzer's seconds-budget flag; drop it to fuzz
indefinitely. Crashing inputs are written to `fuzz/artifacts/<target>/`.

## Reproducing a crash

```bash
cd fuzz
cargo +nightly fuzz run <target> artifacts/<target>/<crash-id>
```

## Adding a new target

1. Drop a new file in `fuzz/fuzz_targets/<name>.rs`.
2. Append a `[[bin]]` entry to `fuzz/Cargo.toml`.
3. Re-run `cargo +nightly fuzz build` to verify.

Keep targets cheap to evaluate (microseconds, not milliseconds); the
fuzzer needs to execute millions of inputs to be useful.

## CI

The `Fuzz Smoke` job in `.github/workflows/ci.yml` builds every target
and runs each for ~30 seconds on every PR. Catch-on-PR is the goal;
deeper soak runs belong in a scheduled workflow.

## Cargo.lock

`fuzz/Cargo.lock` is intentionally gitignored. The crate opts out of the
main workspace (`[workspace]` is present but empty) and its `axess-core`
dep is a path-only reference with no version pin, so `cargo +nightly
fuzz` regenerates the lockfile on demand — locally and in CI. Committing
it just accumulated stale entries (the last committed value pointed at
`axess-core = 0.0.16` long after the workspace had passed 0.3.0), and
because CI ignored the committed value functionally, the drift was
invisible until someone read the file. The `Fuzz Smoke` CI job always
tests against the current workspace `axess-core` because that is what
the path dep resolves to.
