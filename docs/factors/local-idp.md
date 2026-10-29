# Local IdP

`axess::local_idp` is an in-process workload-identity issuer. It mints
JWTs against a signing key it holds locally, exposes the matching
JWKS, and serves the RFC 8414 discovery document. The crate exposes
this surface in two layers, both built on the same primitives:

- **Production** [`LocalIdp`](https://docs.rs/axess/latest/axess/local_idp/struct.LocalIdp.html).
  Adopter wires a [`LocalIdpKeyStore`] implementation (file system,
  Vault, KMS, ...) and the [`LocalIdp`] reads the current + historical
  keys, mints, and rotates on operator request through the store's rotate.

- **Testing** [`LocalIdpFixture`](https://docs.rs/axess/latest/axess/testing/local_idp/struct.LocalIdpFixture.html).
  In-process value that mints JWTs with a generated keypair and
  exposes a `JwkSet` handle that a [`JwtVerifier`] can read. No HTTP
  endpoints, no key store; just `mint()` + `jwks_handle()`.

Both layers share [`MintClaims`], [`LocalIdpSigningKey`], and the
issuance pipeline that lives in
[`axess::local_idp::primitives`](https://docs.rs/axess/latest/axess/local_idp/primitives/index.html).
A token minted by either layer verifies against the same JWKS shape,
which is the property that lets adopters run the same downstream
verifier in tests and in production.

## What both layers do NOT do

Neither layer is a full OAuth 2.0 Authorization Server. There is:

- no authorization-code flow, no PKCE handshake;
- no end-session endpoint;
- no refresh-token rotation;
- no consent UX;
- no user store.

Use a real Authorization Server (Keycloak, Ory Hydra, Okta, Auth0,
Azure AD, etc.) when you need any of those. `LocalIdp` exists for
**direct workload-identity issuance**: a process mints short-lived
JWTs for service-to-service flows it controls.

The feature flag is `local-idp` (off by default), enabled with
`features = ["local-idp", "jwt-rust-crypto"]` on the `axess` facade. It
pulls in `jwt` transitively and nothing else: minting and the JWKS need no
OAuth machinery, so enabling this does not bring `oauth` or `oidc` with it.
`jwt` needs a crypto backend named beside it: `jwt-rust-crypto` (pure Rust) or `jwt-aws-lc`
(FIPS-capable, needs a C toolchain).

---

## Production: `LocalIdp`

### When to use

- A service needs to mint workload-identity JWTs for its own internal
  flows (e.g. signing tokens that downstream services will verify via
  the published JWKS).

- A development or staging deployment needs a self-contained IdP
  without standing up Keycloak. The same code path runs in
  production; only the [`LocalIdpKeyStore`] backend changes.

- An air-gapped or single-tenant deployment wants on-host token
  issuance with no external dependency.

### When not to use

If you need a user-facing IdP with login UI, OIDC authorization code
flow, refresh tokens, or federation, reach for Keycloak / Ory Hydra
/ similar. `LocalIdp` deliberately stops at issuance.

### The `LocalIdpKeyStore` trait

Adopters implement persistence against their own key material:

```rust,ignore
pub trait LocalIdpKeyStore: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn load_all(&self) -> Result<LoadedKeys, Self::Error>;

    async fn rotate(&self, new_current: LocalIdpSigningKey)
        -> Result<(), Self::Error>;

    async fn retire(&self, key_id: &str) -> Result<bool, Self::Error>;
}

pub struct LoadedKeys {
    pub current: LocalIdpSigningKey,
    pub historical: Vec<LocalIdpSigningKey>,
}
```

`load_all` returns current + historical keys from a single
consistent read. The JWKS published at `/jwks.json`
includes all of them so tokens already in flight under a rotated-out
historical key continue to verify until the operator removes that
key from the store.

`rotate` persists a new current key, demoting the previous current
to historical. The store makes that step atomic (a pointer flip, a
transaction); axess does not add atomicity on top of it. Adopters
typically expose this through their own admin endpoint or out-of-band
tooling.

`retire` removes a historical key so it leaves the JWKS. Call it through
`LocalIdp::retire_historical_key` once no token signed under the key can
still be valid: the time of the rotation plus the longest lifetime the IdP
mints. The current key is refused. Keep the removed key material (the file
store moves it aside) so a later audit can still verify what it signed.

### `MemoryLocalIdpKeyStore` for prototyping

A `MemoryLocalIdpKeyStore` ships with the crate for dev and test
deployments where keys can live in process memory:

```rust,ignore
use axess::local_idp::{LocalIdp, LocalIdpSigningKey, MemoryLocalIdpKeyStore};

let key = LocalIdpSigningKey::generate_es256().with_key_id("v1");
let store = MemoryLocalIdpKeyStore::with_current(key);
let idp = LocalIdp::from_key_store("https://idp.example.com", store)
    .await
    .expect("load keys");
```

Memory storage is not for production: restarts lose the keys, and
every restart produces fresh JWKS that breaks tokens already in
flight. The `local-idp` binary of `examples/workload-identity/` implements a file-backed
[`LocalIdpKeyStore`] with atomic rotation that the production path
should pattern after; the same shape adapts to Vault, AWS KMS, GCP
KMS, or any other key management backend.

### Minting

```rust,ignore
use axess::local_idp::MintClaims;
use chrono::{Duration, Utc};

let token = idp
    .mint(
        &MintClaims::new("worker-1", Utc::now() + Duration::minutes(5))
            .with_audience("https://api.example.com")
            .with_issued_at(Utc::now()),
    )
    .await?;
```

A new `LocalIdp` is strict by default:

- Tokens are capped at one hour (`DEFAULT_MAX_TTL`). Raise it with
  `with_max_ttl(...)`, or remove the cap with `without_max_ttl()` when long
  lived tokens are intended. A mint over the cap returns
  `IssuanceError::LifetimeExceedsCap`.
- A mint without an audience returns `IssuanceError::MissingAudience`. A
  token with no `aud` is accepted by every verifier that does not pin an
  audience, so minting one is a choice: `allow_no_audience()` makes it.

[`MintClaims`] is a builder: `new(subject, exp)` is the minimum;
`with_audience`, `with_audiences` (multi-aud), `with_issued_at`,
`with_not_before`, `with_jwt_id`, and `with_custom_claim` cover the
standard JWT fields. `mint_with_header` accepts a caller-supplied
`jsonwebtoken::Header` for cases that need custom header fields
(`typ`, `cty`, etc.).

The clock is injectable via `.with_clock(...)`. Production wires
`SystemClock`; DST tests wire `MockClock` for reproducible
issuance.

### Rotation

```rust,ignore
let new_key = LocalIdpSigningKey::generate_es256().with_key_id("v2");
idp.rotate_signing_key(new_key).await?;
```

The call:

1. Takes the instance's write lock, so no mint runs against a half-rotated
   state and two rotations on one instance run one after the other.
2. Persists the new current via [`LocalIdpKeyStore::rotate`].
3. Re-reads the key set from the store with `load_all` and rebuilds the JWKS
   from that snapshot, so a rotation another replica made earlier is not
   dropped.

In-flight verifications using the old `kid` continue to succeed
because the historical entry stays in the published JWKS.

#### Several replicas

Each replica holds its own copy of the key set, loaded at startup and
refreshed by its own `rotate_signing_key`, `retire_historical_key` and
`reload`. The store is the single source of truth; the replicas converge
only when they re-read it. To rotate a fleet:

1. Make the store the arbiter: its `rotate` must be atomic and must append to
   the historical set rather than overwrite it (a pointer flip or one
   transaction). Two replicas rotating at once then produce two ordered
   rotations, not a lost one.
2. Rotate on exactly one replica (an admin call routed to one instance).
3. Call `reload()` on every other replica. Until a replica reloads, it keeps
   signing under the previous key, which is still published, so tokens verify
   throughout; it just has not switched yet.
4. Retire a historical key only after the longest token lifetime has passed,
   then `reload()` the others.

`jwks_handle()` returns a snapshot. A handle given to a verifier before a
rotation, retirement or reload does not see it: build a new handle from
`jwks()` after the change, or serve the JWKS to verifiers over HTTP from
`router()`.

### Key algorithms and imported keys

Prefer ES256 (`generate_es256`). RSA signing goes through the `rsa` crate,
whose private-key operations carry a timing side channel (the Marvin
advisory, not fixed upstream); use RSA only for a verifier that cannot take
ES256. Constructors that load a key (`from_rsa_pem`, `from_ec_pem`, the DER
forms) return `LocalIdpKeyError` instead of panicking: an unsupported
algorithm is `UnsupportedAlgorithm`, and an RSA key under 2048 bits is
`WeakKey`. `try_generate_rsa_with_algorithm` is the non-panicking RSA
generator.

### Discovery + JWKS endpoints

`LocalIdp::router()` returns a ready-to-mount Axum router that
serves the two standard endpoints:

```rust,ignore
let app = axum::Router::new()
    .nest("/", idp.router())
    .route("/issue", axum::routing::post(issue));
```

Routes:

- `GET /.well-known/openid-configuration`: RFC 8414 metadata.
- `GET /jwks.json`: current + historical public JWKs.

`with_base_url(...)` overrides the URL the discovery document
advertises for `jwks_uri` when the IdP sits behind a reverse proxy.
`with_metadata_field(name, value)` appends adopter-extension fields
to the discovery document (`scopes_supported`, `claims_supported`,
FAPI fields, etc.).

For full control, the lower-level handlers in
[`axess::local_idp::discovery`](https://docs.rs/axess/latest/axess/local_idp/discovery/index.html)
expose `openid_configuration` and `jwks` as standalone axum
handlers.

### Production-pattern example

The `local-idp` binary in [`examples/workload-identity/`](https://github.com/GnomesOfZurich/axess/tree/main/examples/workload-identity)
(`cargo run -p axess-example-workload-identity --bin local-idp`) is the
reference implementation:

- File-backed `LocalIdpKeyStore` (`FileLocalIdpKeyStore`) with the
  directory layout pattern `historical/{kid}.pem` + atomic
  `current.kid` pointer file.
- `POST /admin/rotate` and `POST /admin/retire` operator endpoints.
- `POST /issue` mint endpoint; it requires an audience and caps the
  lifetime at one hour.
- A curl walkthrough of the full discover-mint-rotate cycle.

---

## Testing: `LocalIdpFixture`

### When to use

Integration tests that exercise:

- The inbound JWT-SVID resolver (`axess::jwt::svid::JwtSvidResolver`).
- The OAuth Resource Server resolver path.
- Any of the [cloud STS adapters](../workload-identity/cloud-sts.md).
- The `JwtVerifier` shape generally.

The fixture mints tokens that verify against its own JWKS, so a
test can produce a token with `mint()` and pass it to the resolver
under test without involving an external IdP.

### What it is NOT

The fixture is **not an HTTP service**. It is a value with `mint()`,
`jwks_handle()`, and a handful of accessors. Tests use it by:

1. Constructing the fixture.
2. Calling `idp.mint(&MintClaims::...)` to obtain a JWT.
3. Wiring a `JwtVerifier` to `idp.jwks_handle()` so verification
   reads the same JWKS the fixture signed against.

There is no authorize endpoint, no token endpoint, no Tower service
wrapping; the fixture just produces signed tokens and exposes the
verification key set.

The feature flag is `testing` plus `local-idp`. The fixture lives
under `axess::testing::local_idp::LocalIdpFixture`.

### Construction

```rust,ignore
use axess::testing::local_idp::LocalIdpFixture;

let idp = LocalIdpFixture::new("https://test.idp.local");
```

`new(issuer)` generates a fresh RSA-2048 keypair per call. Other
constructors:

- `LocalIdpFixture::with_algorithm(issuer, Algorithm::ES256)`:
  generate with a specific signing algorithm. Supported: RS256,
  RS384, RS512, ES256.
- `LocalIdpFixture::with_signing_key(issuer, key)`: explicit key
  (use when the test needs a stable signature across runs).

Builder methods (chained on the constructed fixture):

- `.with_historical_signing_key(key)`: add a key to the JWKS without
  rotating to it. Drives JWKS-cache-refresh tests.
- `.with_extra_public_jwk(jwk)`: add an externally-supplied public
  JWK to the published set.
- `.rotate_signing_key(new_key)`: swap the signing key; the old key
  moves to historical and remains in the JWKS.
- `.with_max_ttl(duration)`: cap minted token lifetime. Over-cap
  mints panic (test-time misuse).
- `.with_issuance_listener(arc)`: install an [`IssuanceListener`]
  for assertion-side recording.
- `.with_key_id(kid)`: override the auto-generated `kid`.

### Minting

```rust,ignore
use axess::testing::local_idp::{LocalIdpFixture, MintClaims};
use chrono::{Duration, Utc};

let idp = LocalIdpFixture::new("https://test.idp.local");

// Standard JWT.
let token = idp.mint(
    &MintClaims::new("alice", Utc::now() + Duration::hours(1))
        .with_audience("https://api.example.com"),
);

// SPIFFE JWT-SVID shape (subject = SPIFFE ID, audience required).
// Subject is spiffe://<trust_domain>/<service>/<tenant>, the same
// segment order `WorkloadId::build` renders. All five are required.
let svid = idp.mint_jwt_svid(
    "test.gnomes",                  // trust domain
    "worker",                       // service
    "acme",                         // tenant
    "sts.amazonaws.com",            // audience
    Duration::minutes(5),
);
```

`mint_with_header` accepts a caller-supplied header for cases that
need custom fields.

### Sharing the JWKS with `JwtVerifier`

```rust,ignore
use axess::jwt::verifier::JwtVerifier;

let verifier = JwtVerifier::new(idp.jwks_handle())
    .with_audience("https://api.example.com")
    .with_algorithms(idp.verifier_algorithms());

let claims = verifier.verify::<MyClaims>(&token).await?;
```

`jwks_handle()` returns an `Arc<RwLock<JwkSet>>` holding a snapshot of the
JWKS at the time of the call. `rotate_signing_key` on the fixture returns a
new fixture and does not touch a handle handed out earlier, so after a
rotation call `jwks_handle()` again and build a new verifier from it.

### Feeding a cloud STS adapter

The fixture's `mint_jwt_svid` produces SPIFFE-shaped tokens suitable
for cloud STS exchange tests:

```rust,ignore
use axess::workload::outbound::cloud_sts::aws::AwsStsClient;

let idp = LocalIdpFixture::new("https://oidc.test.local");
let token = idp.mint_jwt_svid(
    "test.gnomes", "worker", "acme",
    "sts.amazonaws.com",
    Duration::minutes(5),
);

// Hand the token to a mocked AWS STS endpoint to exercise the
// AssumeRoleWithWebIdentity flow without hitting real AWS.
```

---

## Why both shapes coexist

Production `LocalIdp` and the test `LocalIdpFixture` share the same
primitives module (`axess::local_idp::primitives`). The primitives
define `LocalIdpSigningKey`, `MintClaims`, `IssuanceEvent`,
`IssuanceListener`, and the internal JWT-encode pipeline. Both
layers route their `mint()` calls through these primitives.

The consequence: a token minted by the fixture in a test verifies
identically against a `JwtVerifier` configured with production
`LocalIdp`'s published JWKS, given the same signing key. Tests
that pin a specific JWT signature exercise the same code paths that
sign in production.

The split exists for what each layer adds on top:

- Production carries the [`LocalIdpKeyStore`] abstraction so keys
  survive process restarts and can rotate without code changes.
- Testing carries the in-memory key generation, the
  `MockIssuanceListener`, and ergonomic builders that match what
  test code typically wants to assert.

Neither subsumes the other; the production class is not the right
fit for a unit test (no key store means no mint), and the fixture
is not the right fit for production (in-memory keys lose on
restart). The shared primitives are what lets both shapes claim
"this is the same JWT issuer" without code duplication.
