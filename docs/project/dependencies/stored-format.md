# One stored-data format

## Today

A stored session is MessagePack, optionally sealed with AES-256-GCM, and every
decode falls back to JSON on any MessagePack failure:
`SessionCodec::decode_payload` tries `rmp_serde::from_slice` and then
`serde_json::from_slice`, and `decode_text` sends a plaintext row that starts
with `{` straight to `serde_json`. Every stored session can therefore be read
in two formats, corruption or a downgrade is accepted silently, and the JSON
path stays a fuzz target (`fuzz/fuzz_targets/session_data_json.rs`) with no
end date. `rkyv` derives sit on the same types (events, ids, factor types)
with no storage call site.

## Plan

1. Turn the JSON fallback off by default behind the existing `LegacyBlobs`
   policy (`session/legacy_blobs.rs`), with an `AcceptUntil` form that names
   the date after which a JSON row is refused, or a cargo feature
   `legacy-json-sessions`. The default is a change adopters see: a migration
   paragraph and a decision.
2. When a JSON row is read under the policy, re-seal it as MessagePack
   (`state.stale = true`), so the population drains.
3. In the next major release delete the fallback and the `decode_text` `{`
   path. `serde_json` then stops being a stored-data parser.
4. Mark `rkyv` unsupported or experimental, or remove it. If it stays,
   callers use the bytecheck access APIs (`rkyv::access`, `from_bytes`) and
   never `access_unchecked`.
5. CI prints `cargo tree -e features` for the storage features, so which
   dependency pulls which feature is visible.

## Files

- `axess-core/src/session/storage/session_codec.rs` and
  `axess-core/src/session/storage/session_codec/`
- `axess-core/src/session/legacy_blobs.rs`
- `fuzz/fuzz_targets/session_data_json.rs`, `fuzz/fuzz_targets/session_data_msgpack.rs`
- `Cargo.toml` (`rkyv`), and the `rkyv` features of `axess-core`,
  `axess-events`, `axess-identity` and `axess-strings`

## Checks

A row written as JSON is read, re-sealed and then read as MessagePack; with
the policy off the same row is refused by name; the MessagePack fuzz target
keeps running and the JSON one is deleted with the fallback.
