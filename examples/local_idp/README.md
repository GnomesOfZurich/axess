# axess-example-local-idp

Production-pattern example for [`axess::local_idp::LocalIdp`]. Boots
an in-process workload-identity IdP backed by a file system, serves
RFC 8414 discovery + JWKS, and supports atomic key rotation.

## What this shows

- A custom [`axess::local_idp::LocalIdpKeyStore`] implementation
  (`FileLocalIdpKeyStore`) with directory layout, atomic rotation,
  and `LocalIdpKeyError` propagation.
- Mounting [`LocalIdp::router`](https://docs.rs/axess) for the two
  standard discovery endpoints in one line.
- A custom `POST /admin/rotate` endpoint that mints a new key,
  persists it, and atomically swaps it via
  [`LocalIdp::rotate_signing_key`](https://docs.rs/axess).
- A `POST /issue` endpoint demonstrating mint via
  [`LocalIdp::mint`](https://docs.rs/axess).

## Running

```sh
cargo run -p axess-example-local-idp
```

On first launch the example generates an RSA-2048 key and writes it
to `./keys/historical/v1.pem`. The server binds to `127.0.0.1:3000`
with issuer `http://localhost:3000`. Override the key directory with
`LOCAL_IDP_KEY_DIR=…`.

## File layout

```
keys/
  current.kid          text file naming the current kid
  historical/
    v1.pem             every key (current and historical) as PKCS#8 PEM
    v2.pem
```

Rotation flips `current.kid` atomically via temp-file + rename;
historical PEMs are retained so tokens minted under prior keys keep
verifying through the JWKS until ops decides to retire them.

## Curl walkthrough

```sh
# 1. Discover
curl -s http://localhost:3000/.well-known/openid-configuration | jq .
# { "issuer": "http://localhost:3000", "jwks_uri": "http://localhost:3000/jwks.json", ... }

# 2. JWKS (current + historical)
curl -s http://localhost:3000/jwks.json | jq '.keys[].kid'
# "v1"

# 3. Mint a token
curl -s -X POST http://localhost:3000/issue \
  -H 'content-type: application/json' \
  -d '{"subject":"worker-1","audience":"https://api","ttl_secs":300}'
# { "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6InYxIn0..." }

# 4. Rotate to a new key
curl -s -X POST http://localhost:3000/admin/rotate \
  -H 'content-type: application/json' \
  -d '{"new_kid":"v2"}'
# { "new_current": "v2", "historical": ["v2", "v1"] }

# 5. JWKS now lists both keys
curl -s http://localhost:3000/jwks.json | jq '.keys[].kid'
# "v2"
# "v1"

# 6. New mints are signed under v2; tokens minted under v1 still
#    verify (the kid -> JWK lookup hits the historical entry).
```

## What's deliberately not in this example

- **Production HTTPS.** Real deployments terminate TLS upstream or
  use `axum-server` with a `RustlsConfig`. Either is purely an axum
  concern.
- **AuthZ on `/admin/rotate`.** Add a `require_authz!` middleware
  layer (see `axess-macros`) gating the route to operators.
- **`tokio::fs` for non-blocking I/O.** The example uses `std::fs`
  for clarity. The key-store operations are small and infrequent
  enough that the blocking cost is invisible at the example's
  scale, but a real production impl should use `tokio::fs`.
- **Out-of-band key generation.** The `/admin/rotate` handler
  generates a fresh RSA key for demonstration. Real ops generate
  keys with `openssl genrsa` (or out of an HSM / KMS), copy the
  PEM into `historical/`, and then call rotate.

## Adapting to your file layout

`FileLocalIdpKeyStore` is intentionally simple. Common adopter
extensions:

- **Single-file PEM bundle.** Replace `read_dir(historical/)` with
  a multi-PEM parse over one file.
- **kid in metadata header.** Read `kid` from each PEM's leading
  comment rather than from its filename stem.
- **Read-only mode.** Implement `rotate` as `Err(ReadOnly)` and
  rely on operator-driven file swaps + process restart.
- **Filesystem watch.** Wire `notify` to invalidate the store on
  out-of-band file edits.
- **Object-store backend.** Replace `std::fs::*` with `aws-sdk-s3`
  / `google-cloud-storage` / etc.; the trait shape stays the same.

## Adapting to KMS / Vault / HSM

See [`docs/factors/local-idp.md`](../../docs/factors/local-idp.md) §"KMS-backed key
storage" for the envelope-encryption pattern and what stays the same
vs what changes.
