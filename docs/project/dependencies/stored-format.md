# Stored session formats

## What is written and what is read

Every session store (SQLite, PostgreSQL, MySQL, Valkey) writes a session as
MessagePack, sealed with AES-256-GCM when the store holds a
`SessionCrypto`: `SessionCodec::encode_bytes` serialises with
`rmp_serde::to_vec_named` on every write, and has since 0.2.0, the first
release that wrote MessagePack. A read accepts MessagePack and nothing
else: `SessionCodec::decode_payload` reads the schema version first and
decodes with `rmp_serde::from_slice`, in the shape this release writes. A
SQL store reads the binary column only. A row whose binary column is NULL
fails with `SqlStoreError::Decode` and loads no session, whatever its text
column holds; so does a row in any other encoding or shape. A row below the
current schema version is not decoded at all: the store hands up its
version, and the session layer refuses it (see *Schema migration*).

`LegacyBlobs` does not apply to a session: a stored session is opened in
the current sealed form only (`axess.session.v2`, bound to the session's
key), whatever the policy says. The policy decides whether a blob without
the current format marker is read for device rows and factor secrets (one
sealed before row binding, a 0.11.0 device format, an OTP secret still in
plain text), and never how the session inside a blob is encoded.

## A session stored as JSON

Before 0.2.0 a session could be stored as JSON. A JSON row, plain or
sealed, whether the 0.1.x line or a hand-written tool wrote it, is
refused: its load fails with `SqlStoreError::Decode` and its user signs in
again. There is no conversion step. An operator who wants the rows gone
deletes the session rows that do not load; a row that is never loaded
expires with its TTL.

## rkyv

The `rkyv` features of `axess-core`, `axess-events`, `axess-identity` and
`axess-strings` derive archive implementations on the ids, the events and
the types of an audit event. No store of the library writes or reads rkyv:
the derives serve an application that encodes these types itself, as the
documentation of `RichAuthnEvent` shows for an analytics stream.

## Where it lives

- `axess-core/src/session/storage/session_codec.rs` and its tests in
  `axess-core/src/session/storage/session_codec/`
- `axess-core/src/session/legacy_blobs.rs`
- `fuzz/fuzz_targets/session_data_msgpack.rs`, which holds the decoder to
  arbitrary input and to a round trip
