# axess-fuzz

Coverage-guided fuzz harness for axess. Targets the highest-risk
parsing / decoding paths: a crash here is a denial-of-service vector on
the session-load or token-verify hot path.

## Targets

Each target calls the library's own public functions and holds them to an
independent statement of what they must do; none keeps a copy of a decoder.

| Target                       | Surface under test                                        |
|------------------------------|-----------------------------------------------------------|
| `session_data_msgpack`       | `rmp_serde::from_slice::<SessionData>(...)`; SQL/Valkey decode path (panic-only). |
| `session_data_json`          | `serde_json::from_slice::<SessionData>(...)`; legacy-row fallback decode path (panic-only). |
| `jwt_payload_split`          | The real logout-token, ID-token and bearer-token payload decoders, against the contract (size cap, three segments, base64url JSON). |
| `pkce_verifier_predicate`    | The real `axess_factors::pkce::is_valid_verifier`, against RFC 7636 section 4.1 written out. |
| `client_ip_forwarded`        | `TrustedProxies::client_ip` against a right-to-left reference walk of `X-Forwarded-For`. |
| `egress_reserved_embedded_v4`| `ReservedRange::of` and `EgressPolicy::check_url`: an IPv6 form that embeds a reserved IPv4 address is reserved too. |
| `service_secret_replay_any_scheme` | The signed-request middleware end to end: no replay under any signature scheme, no mutated tag accepted. |
| `throttle_math_props`        | `Throttle::delay_after`, `retry_after` and `subject`: no panic, monotone, never fails open, keyed per /64. |
| `cookie_config_prefix`       | `SessionConfig` builder: any `__Host-` or `__Secure-` spelling meets its prefix rules or is refused. |
| `cedar_uid_injective`        | `build_uids`: distinct tenant and id pairs never render to one resource UID. |

The last five encode defects that are being fixed. Until a fix lands the
target is expected to find its input, and `.github/workflows/hardening.yml`
lets that one run fail without failing the workflow; the file names the date
each allowance comes off.

## Running locally

`cargo-fuzz` requires nightly:

```bash
rustup install nightly
cargo install cargo-fuzz@0.13.2 --locked
```

Then, from the repo root:

```bash
cd fuzz
cargo +nightly fuzz run session_data_msgpack -- -max_total_time=60
cargo +nightly fuzz run session_data_json    -- -max_total_time=60
cargo +nightly fuzz run jwt_payload_split    -- -max_total_time=60
cargo +nightly fuzz run pkce_verifier_predicate -- -max_total_time=60
cargo +nightly fuzz run client_ip_forwarded -- -max_total_time=60
```

The other five targets run the same way, by name.

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
and runs the first four for ~30 seconds on every PR. The `Hardening`
workflow (`.github/workflows/hardening.yml`) runs all ten for 120 seconds
each on every pull request and nightly, and uploads crash inputs.

## Cargo.lock

`fuzz/Cargo.lock` is intentionally gitignored. The crate opts out of the
main workspace (`[workspace]` is present but empty) and its `axess-core`
dep is a path-only reference with no version pin, so `cargo +nightly
fuzz` regenerates the lockfile on demand: locally and in CI. Committing
it just accumulated stale entries (the last committed value pointed at
`axess-core = 0.0.16` long after the workspace had passed 0.3.0), and
because CI ignored the committed value functionally, the drift was
invisible until someone read the file. The `Fuzz Smoke` CI job always
tests against the current workspace `axess-core` because that is what
the path dep resolves to.
