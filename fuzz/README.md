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
| `jwt_payload_split`          | The real logout-token, ID-token and bearer-token payload decoders, against the contract (size cap, three segments, base64url JSON). |
| `pkce_verifier_predicate`    | The real `axess_factors::pkce::is_valid_verifier`, against RFC 7636 section 4.1 written out. |
| `key_proof_parse`            | `axess_factors::key_proof::parse_key_proof` against an independent statement of what parses, and every proof that parses through the three verifications: none stands under a key nobody signed with. |
| `device_proof_cookie`        | The reader of the device-key proof cookie: arbitrary text proves nothing, a genuine value proves its key exactly until it ends, and with one byte changed it proves nothing. |
| `device_key_offer`           | The check of a device-key registration offer: arbitrary text is no offer, a genuine one holds exactly until it expires, and with one byte changed it does not. |
| `device_identifier_header`   | The reader of `Sec-Secure-Session-Id` against an independent statement: a quoted or bare string whose content is a tenant id, a dot and a device id. |
| `client_ip_forwarded`        | `TrustedProxies::client_ip` against a right-to-left reference walk of `X-Forwarded-For`. |
| `egress_reserved_embedded_v4`| `ReservedRange::of` and `EgressPolicy::check_url`: an IPv6 form that embeds a reserved IPv4 address is reserved too. |
| `service_secret_replay_any_scheme` | The signed-request middleware end to end: no replay under any signature scheme, no mutated tag accepted. |
| `throttle_math_props`        | `Throttle::delay_after`, `retry_after` and `subject`: no panic, monotone, never fails open, keyed per /64 outside the ranges that carry an IPv4 client, and one subject per client of a NAT64 gateway. |
| `cookie_config_prefix`       | `SessionConfig` builder: any `__Host-` or `__Secure-` spelling meets its prefix rules or is refused. |
| `cedar_uid_injective`        | `build_uids`: distinct tenant and id pairs never render to one resource UID. |
| `timestamp_rfc3339`          | `axess_clock::Timestamp::parse_rfc3339`: no text panics the reader, and a reading it reads, or one built from the input, is written in both forms and read back as itself. |

Every target is expected to pass: a run that fails has found a defect in
the library or in the target's statement of it, and fails its job.

## Running locally

`cargo-fuzz` requires a nightly compiler. CI uses the dated nightly
`nightly-toolchain.toml` names; from the repo root:

```bash
NIGHTLY="$(sed -n 's/^channel *= *"\(.*\)"$/\1/p' nightly-toolchain.toml)"
rustup toolchain install "$NIGHTLY"
cargo install cargo-fuzz@0.13.2 --locked
```

Then:

```bash
cd fuzz
cargo +"$NIGHTLY" fuzz run session_data_msgpack -- -max_total_time=60
cargo +"$NIGHTLY" fuzz run jwt_payload_split    -- -max_total_time=60
cargo +"$NIGHTLY" fuzz run pkce_verifier_predicate -- -max_total_time=60
cargo +"$NIGHTLY" fuzz run client_ip_forwarded -- -max_total_time=60
```

The other targets run the same way, by name.

`-max_total_time` is libFuzzer's seconds-budget flag; drop it to fuzz
indefinitely. Crashing inputs are written to `fuzz/artifacts/<target>/`.

## Reproducing a crash

```bash
cd fuzz
cargo +"$NIGHTLY" fuzz run <target> artifacts/<target>/<crash-id>
```

## Adding a new target

1. Drop a new file in `fuzz/fuzz_targets/<name>.rs`.
2. Append a `[[bin]]` entry to `fuzz/Cargo.toml`.
3. Add its name to the matrix of the `fuzz` job in
   `.github/workflows/hardening.yml`; the `Fuzz Smoke` job fails until it
   is there.
4. Re-run `cargo +"$NIGHTLY" fuzz build` to verify.

Keep targets cheap to evaluate (microseconds, not milliseconds); the
fuzzer needs to execute millions of inputs to be useful.

## CI

The `Fuzz Smoke` job in `.github/workflows/ci.yml` builds every target
and runs each one the fuzz crate lists (`cargo fuzz list`) for 30 seconds
on every PR. The `Hardening` workflow (`.github/workflows/hardening.yml`)
runs each for 120 seconds on every pull request and nightly, and uploads
crash inputs; its matrix is written by hand, and the smoke job fails when
it does not name exactly the targets the crate lists.

## Cargo.lock

`fuzz/Cargo.lock` is committed. The crate is a workspace of its own
(`[workspace]` is present but empty), so cargo keeps a lock file for it
apart from the workspace's. With it committed, a fuzz build of one commit
is the same build wherever and whenever it is made.

It is held to the workspace's lock file, so the targets run against the
dependency versions the workspace ships with: `scripts/check-fuzz-lock.sh`
fails when a package both files name is at a version the workspace's does
not hold, and the `Lockfile Drift` job also runs `cargo metadata --locked`
on the fuzz manifest. (Left to the resolver, the fuzz build runs on newer
dependencies than the workspace, and a committed lock file held by nothing
drifts from the workspace's.)

After the workspace's `Cargo.lock` changes, or a version bump, from the
repository root with the cargo `rust-toolchain.toml` pins:

```bash
cp Cargo.lock fuzz/Cargo.lock
(cd fuzz && cargo metadata --format-version 1 > /dev/null)
./scripts/check-lock-age.sh
```

The copy carries the workspace's versions over; cargo then drops what the
fuzz crate does not use and resolves what only it uses (`libfuzzer-sys`,
`arbitrary` and their dependencies) under the same publish-age rule as the
workspace's lock: `.cargo/config.toml` sets `registry.global-min-publish-age`,
which cargo 1.100 and later read inside `fuzz/` too. The lock-age check then
reads both lock files and refuses a version younger than that rule.
