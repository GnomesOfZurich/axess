# axess-testing

Test fixtures for applications built on [axess](https://crates.io/crates/axess):

- `mock_tracing`: capture `tracing` events and assert on them.
- `oauth_wiremock`: an OIDC discovery document, a JWKS endpoint and an RSA key
  pair for a `wiremock` identity provider.

Take it as a **dev-dependency** only:

```toml
[dev-dependencies]
axess-testing = "0.19"
```

It carries `wiremock` and `rsa`, which must not reach a release build; the
workspace's `cargo deny` policy admits `wiremock` only through dev-dependency
edges.

Licensed under either of MIT or Apache-2.0 at your option.
