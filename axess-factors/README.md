# axess-factors

[![Version](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/version.svg)](https://crates.io/crates/axess-factors)
[![Status](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/status.svg)](https://github.com/GnomesOfZurich/axess)
[![License](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/license.svg)](https://github.com/GnomesOfZurich/axess#licence)

[crates.io](https://crates.io/crates/axess-factors) · [docs.rs](https://docs.rs/axess-factors) · [GitHub](https://github.com/GnomesOfZurich/axess)

Authentication factor primitives for the [Axess](https://github.com/GnomesOfZurich/axess) library. Provides password hashing, TOTP, and HOTP verification.

This crate has no dependency on Axum or the rest of the Axess stack. You can use it standalone for credential verification in any Rust application.

## Capabilities

- **Password** hashing and verification via Argon2id ([password-auth](https://crates.io/crates/password-auth))
- **TOTP** (RFC 6238) generation and verification via [totp-rs](https://crates.io/crates/totp-rs), with constant-time code comparison
- **HOTP** (RFC 4226) verification via [libreauth](https://crates.io/crates/libreauth), with constant-time code comparison
- Secret generation, provisioning URI helpers for authenticator apps
- All decoded secrets wrapped in `Zeroizing` (cleared from memory on drop)

## Feature flags

All enabled by default.

| Feature | What it enables |
|---|---|
| `password` | Argon2id password hashing/verification |
| `totp` | TOTP generation and verification |
| `hotp` | HOTP verification |

## Usage

```rust
use axess_factors::{
    generate_password_hash, verify_password,
    generate_totp_secret, generate_totp_secret_with_rng, verify_totp, build_totp_uri,
    verify_hotp,
};

// Passwords
let hash = generate_password_hash("my-secure-password");
verify_password("my-secure-password", &hash).expect("should match");

// TOTP
let secret = generate_totp_secret();
let uri = build_totp_uri("alice@example.com", "MyApp", &secret, 6, 30);
// verify_totp(secret, code, now, length, period, past_window, future_window) -> Option<step>

// TOTP with injectable RNG (for deterministic tests)
let secret = generate_totp_secret_with_rng(&mut my_rng);

// HOTP
// verify_hotp(secret, code, counter, length, window) -> Option<counter>
```

## Public API

| Function | Purpose |
|---|---|
| `generate_password_hash(password)` | Argon2id hash (PHC string) |
| `verify_password(password, hash)` | Constant-time verification |
| `generate_totp_secret()` | 160-bit random secret, base32-encoded |
| `generate_totp_secret_with_rng(rng)` | Same, with injectable RNG for DST |
| `verify_totp(secret, code, now, ...)` | TOTP verification with configurable window |
| `verify_hotp(secret, code, counter, ...)` | HOTP verification with look-ahead window |
| `build_totp_uri(label, issuer, secret, ...)` | `otpauth://` URI for QR codes |

## License

[MIT](https://github.com/GnomesOfZurich/axess/blob/main/LICENSE-MIT) OR [Apache-2.0](https://github.com/GnomesOfZurich/axess/blob/main/LICENSE-APACHE)

## Security

See [SECURITY.md](https://github.com/GnomesOfZurich/axess/blob/main/SECURITY.md) for vulnerability reporting.
