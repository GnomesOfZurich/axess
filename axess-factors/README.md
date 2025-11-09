# axess-factors

`axess-factors` provides core authentication factor primitives for the [Axess](https://github.com/GnomesOfZurich/axess) authentication library, supporting password hashing, TOTP, and HOTP verification for Axum web applications.

## Capabilities

- Password hashing and verification (via [password-auth](https://crates.io/crates/password-auth))
- TOTP (RFC 6238) code generation and verification (via [totp-rs](https://crates.io/crates/totp-rs))
- HOTP (RFC 4226) code generation and verification (via [libreauth](https://crates.io/crates/libreauth))
- Secret generation and provisioning URI helpers for authenticator apps

## Usage

Add to your workspace or project:

```toml
[dependencies]
axess-factors = "0.0.8"
```

Example:

```rust
use axess_factors::{
    generate_password_hash, verify_password,
    generate_totp_secret, verify_totp, build_totp_uri,
    verify_hotp,
};

// Passwords
let hash = generate_password_hash("mysecret");
assert!(verify_password(&hash, "mysecret").unwrap());

// TOTP
let secret = generate_totp_secret();
let uri = build_totp_uri("alice@example.com", "MyApp", &secret, 6, 30);
let valid = verify_totp(&secret, "123456", std::time::SystemTime::now(), 6, 1, 0);

// HOTP
let hotp_valid = verify_hotp(&secret, "654321", 0, 6, 10);
```

## Public API

- `generate_password_hash(password: &str) -> String`
- `generate_totp_secret() -> String`
- `verify_password(hash: &str, password: &str) -> Result<bool, Error>`
- `verify_totp(secret: &str, code: &str, now: SystemTime, length: usize, past_window: u64, future_window: u64) -> Option<u64>`
- `verify_hotp(secret: &str, code: &str, counter: u64, length: usize, window: u64) -> Option<u64>`
- `build_totp_uri(label: &str, issuer: &str, secret: &str, digits: usize, period: u64) -> String`

## License

MIT

## Links

- [Axess Project](https://github.com/GnomesOfZurich/axess)
- [API Docs](https://docs.rs/axess-factors)