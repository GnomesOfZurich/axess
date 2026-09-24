# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/spec/v2.0.0.html).

---

## [unreleased]

### Fixed

- **`check-doc-identifiers.sh` read stale sources from `target/`.** Its filter
  tested for the substring `/target`, which never matches a top-level
  `target/` because a relative path has no leading slash, so every crate ever
  unpacked by `cargo package` was part of the set a documented name could
  resolve against. `ShortString::prefix`, removed in this release, went on
  resolving locally against `target/package/axess-strings-0.4.0/` while CI,
  which checks out clean, rejected it. Both the Rust and Markdown inputs now
  come from `git ls-files`, so the gate reads what a clean checkout has and
  nothing else. A `REMOVED` list covers the third case the script had no
  answer for: a name this workspace deleted, which a migration section still
  has to write.

## [0.6.0] - 2026-09-24

Breaking: if you use the JWT features you must now pick a crypto backend, and
several security fixes change behaviour. Rationale for the larger decisions
lives in the commit log and in `platform/.claude/decisions/`.

### Changed

- **`jwt` requires a crypto backend.** `axess-factors` enabled `jsonwebtoken`'s
  `aws_lc_rs` for everyone; an adopter who had already picked `rust_crypto` got
  both, and `jsonwebtoken` panics on first verification when it cannot choose.
  Enable exactly one beside `jwt`: `jwt-aws-lc` (FIPS-capable, needs a C
  toolchain and NASM on Windows) or `jwt-rust-crypto` (pure Rust). Neither is a
  build error naming both; both is allowed, and
  `axess_factors::jwt::ensure_crypto_provider` picks one.
  **Migrating:** if you enable `jwt`, `oauth`, `oidc`, `fapi`, `bearer`,
  `jwt-svid`, `local-idp` or `workload-id`, add one of the two. Call
  `ensure_crypto_provider` yourself if you sign tokens.

- **`oidc` now enables `jwt`.** It verified ID tokens with no backend enabled,
  so it built with no crypto and panicked on first use.

- **A lockout records `AuthEventStatus::Locked`.** It was `Failure` with
  `error = "locked"`, leaving the outcome in a free-text field.
  **Breaking for audit-row readers:** match on the status column. Rows written
  before this keep the old encoding. Other non-active states are unchanged.

- **`extract_audit_context` takes the client IP as an argument**, and
  `ip_from_headers` is now `ip_from_headers_untrusted` in both `authn` and
  `authz`. Behaviour of the renamed function is unchanged; the names now carry
  the warning at the call site. The header-reading context form remains as
  `extract_audit_context_untrusted`. **Migrating:** add the argument, resolved
  with `ip_from_headers_trusted` against the peer your server accepted, or
  `None`. The compiler finds every call site.

- **`record_password_hash` and `password_history` moved** from `IdentityAdmin`
  to a new `IdentityPasswordHistory` trait with no default bodies. Both had
  defaults that panicked, and `record_password_hash` is called on **every**
  password change with no guard, so any backend that had not overridden it
  unwound the first time a user changed their password, on a method that
  looked optional because a defaulted trait method does. Same defect and same
  fix as the password-reset pair below.
  **Migrating:** move the two `impl`s into an `impl IdentityPasswordHistory`
  block. A deployment with no password-reuse policy implements nothing, and
  the password-change flow is then unavailable to it at compile time.

- **`store_reset_token` and `verify_reset_token` moved** from `IdentityAdmin`
  to a new `IdentityPasswordReset` trait with no default bodies.
  **Migrating:** move the two `impl`s into an `impl IdentityPasswordReset`
  block. If you do not use password reset, implement nothing.

- **`IdentityAuthnLog::record_event` returns `AuditOutcome`, not `()`.**
  A failed audit write fails the login, and every failed login writes a
  row, so an unauthenticated caller can drive unbounded writes at the
  store. `AuditOutcome::Shed` lets a sink drop one deliberately: the flow
  continues and `AuthnMetrics::audit_event_shed` fires, where `Err` still
  fails the login.
  **Shed on a criterion independent of the identifier**: a global rate, a
  queue depth, a disk watermark. Shedding on anything derived from *which*
  identifier was tried makes the drop observable per-identifier and
  reintroduces the enumeration oracle.
  **Migrating:** return `Ok(AuditOutcome::Recorded)` where you returned
  `Ok(())`. `NoopAuthnLog` now reports `Shed`, which is what it always did.

- **`AuthnService` is a cheap handle, and construction moved to a builder.**
  It was a flat struct of thirteen collaborators, which made it neither
  cheaply shareable nor able to carry anything per request. It is now
  `{inner: Arc<..>, audit: Option<..>}`, so cloning is a refcount bump.
  **Migrating:** `AuthnService::new(a, b).with_clock(c)` becomes
  `AuthnService::builder(a, b).with_clock(c).build()`. `new(a, b)` with no
  customisation is unchanged. `from_backend` gains `builder_from_backend`.
  Customisation moved because the collaborators sit behind an `Arc` once
  built, where every copy of the handle observes them.

- **`AuthnService::with_audit_context`: client metadata now reaches audit
  events.** The pieces all existed and nothing joined them, so every audit
  row axess wrote carried `ip_address: None`.

  ```rust
  let ip = ip_from_headers_trusted(&headers, peer.ip(), &trusted);
  let ctx = extract_audit_context(&headers, Some(ip), Some(&session));
  state.authn.with_audit_context(ctx).begin_login(..).await?;
  ```

  Build with `AuditContextPolicy::Required` to refuse events from a route
  that attached no context. It defaults to `Optional`, the previous
  behaviour, and **`Required` is fail-closed**.

- **`ip_from_headers_trusted`, `TrustedProxies` and `CidrParseError` are
  exported from the `axess` facade.** Only `ip_from_headers_untrusted` was,
  so an adopter on the facade could reach the spoofable helper and not the
  safe one. `AuditContext`, `extract_audit_context` and
  `AuthnServiceBuilder` are exported for the same reason.

- **`AuthEvent::error` is an `AuthFailureReason`, not a `String`.**
  `AuthEventBuilder::with_error` takes the enum. Fifteen tags are variants;
  anything else is `AuthFailureReason::Other`, and parsing never fails, so a
  tag from another version reads back intact. The wire form is unchanged:
  serde and database columns still see the plain tag string.
  **Migrating:** name the variant. One stored value changes:
  `"cross-tenant impersonation refused"` is now `cross_tenant_impersonation`,
  so a dashboard matching the old prose needs updating.

- **`AuthEvent::ip_address` is an `IpAddr`, not a `String`.**
  `AuthEventBuilder::with_ip` takes one too, in place of
  `impl Into<String>`. The field is offered as SOC 2 and PCI-DSS evidence,
  and an evidence field that accepts arbitrary text accepts a forged one;
  `AuditContext::ip_address` was already typed, and the builder threw the
  type away with `ip.to_string()`.
  **Migrating:** parse or pass through an `IpAddr`. Sinks writing to a text
  column call `.to_string()` at the point of the write.

- **`ShortString::prefix` is removed.** Documented as powering an equality fast
  path that never existed; nothing but its own tests called it.

### Added

- **`MtlsResolver::from_chain`**: takes the `PeerCertChain` your TLS
  middleware recorded and returns `MtlsError::EmptyChain` when it holds no leaf.

- **`TrustedProxies::from_cidrs` and `with_cidrs`**: parse `"10.0.0.0/8"` and
  `"2001:db8::/32"` and compose with exact addresses. Exact addresses alone
  were impractical for a load balancer with a changing egress pool, and an
  operator who cannot express the range skips the check entirely. Mixed
  families never match.

- **`ShortString` gains the rest of its shape:** `INLINE_CAPACITY`,
  `is_inline()`, `is_allocated()`, `Borrow<str>`, `new(impl AsRef<str>)`,
  `From<ShortString> for String`, and reverse `PartialEq` so `"case-42" == id`
  compiles. All additive. `is_inline()` and `is_allocated()` differ: a
  `from_static` value is allocation-free without carrying its bytes, so it
  answers `false` to both. Assert on `is_allocated()`.

### Security

- **A panicking default made "forgot password" a user-enumeration oracle.**
  `IdentityAdmin::store_reset_token` defaulted to `unimplemented!()`, and
  `begin_password_reset` returns `Ok(None)` for an unknown identifier while
  reaching the store only for a known one, so an unauthenticated request got
  200 for an unregistered address and a panic for a registered one, in the
  function that equalizes its own timing to avoid exactly that. Fixed by the
  `IdentityPasswordReset` move above: the omission is now a compile error.

- **A failed audit write now fails the login.** `record_event` returning an
  error was logged and discarded. It now surfaces as `AuthnError::Store`, and
  on OAuth paths as `OAuthError::AuditStore`. **This trades availability for
  evidence:** logins fail while the audit store does, so put the sink behind
  something durable rather than a remote service on the request path.
  `AuthnMetrics::audit_store_outage` should page.

- **Rejected logins emit even with no user to attribute them to.** Prerequisite
  for the above: had only known identifiers written audit rows, an attacker
  degrading the audit store would see `Err` for real accounts and an ordinary
  rejection otherwise, reading off which identifiers are registered. Unknown
  tenants and identifiers now write rows tagged `unknown_tenant` and
  `unknown_identifier`. It also ends a blind spot: credential stuffing against
  unregistered addresses previously left no trace.

- **`ip_from_headers_trusted` was spoofable through a correctly configured
  proxy.** It took the leftmost `X-Forwarded-For` entry, but the header is
  append-only: a client sends its own value and the proxy appends the real
  address after it. It now walks from the right, skipping trusted hops, and
  returns the first address that is not one. A malformed entry yields the peer,
  and `X-Real-IP` is read only when `X-Forwarded-For` is absent.
  **This changes the value returned** wherever a client can prepend.

- **The audit trail's client IP was attacker-controlled.**
  `extract_audit_context` filled `AuthEvent::ip_address` from request headers,
  so on any directly reachable service an attacker's failed logins were
  recorded against an address of their choosing: evidence forgery by the
  subject of the evidence, in a catalogue offered as SOC 2 and PCI-DSS
  evidence. Fixed by the signature change above.

- **Lockout now fails closed when its counter store is down.**
  `record_failed_attempt` is a write, and the read-replica split this library
  encourages left logins working and the counter dead during a primary outage:
  brute force was unbounded exactly when monitoring was degraded.
  `LockoutPolicy::on_counter_unavailable` defaults to `CounterUnavailable::Lock`.
  **This changes behaviour**: a user who mistypes during such an outage is
  told they are locked. `CounterUnavailable::Allow` restores the old behaviour.
  `Lock` with `duration: None` needs an administrator per account. Alert on
  `AuthnMetrics::factor_counter_store_outage`.

- **`record_failed_attempt` now states its atomicity requirement.** Its return
  value is compared against `max_attempts`, so a read-modify-write
  implementation loses updates and lets parallel attempts exceed the policy.

- **There is no unsafe code in axess.** All ten crates declare
  `#![forbid(unsafe_code)]`. `axess-strings` was the exception: a 16-byte
  union with a hand-rolled refcount and an `unsafe impl Sync`, 20 blocks in
  all, while the architecture chapter claimed otherwise. Replaced with a safe
  24-byte enum, inline to 22 bytes and `Arc<str>` beyond, at no measurable cost
  on the ids that actually run. The Miri gate went with the code it checked.

- **The RUSTSEC-2023-0071 exception described the wrong dependency graph.**
  `rsa` is also a direct optional runtime dependency under `local-idp`, and
  under `jwt-rust-crypto` it performs RS256 signing. The advisory is a timing
  sidechannel on RSA private-key operations, so the exposed case is a
  deployment minting its own tokens over an attacker-reachable interface;
  those should prefer ES256 or `jwt-aws-lc`. The exception stands, accurately
  justified.

### Fixed

- **Twenty-three chapters described a library that does not exist.** Worth
  re-reading if you built from them. The load-bearing corrections: the
  getting-started example ignored `begin_login`'s result and offered a
  password prompt to a locked account; `FingerprintPolicy`,
  `with_absolute_ttl` and `require_step_up` do not exist; rate-limit buckets
  are in-process with a closed extractor enum, not pluggable; `IdentityStore`
  was documented with the wrong error type and audit verbs; and
  `SessionStore::cycle` takes four arguments, not two.

- **The security-posture chapter states the FIPS position accurately.** There
  is no FIPS-validated build of axess. **If you were counting on that, re-read
  the chapter.**

- **The audit-events and audit-pipeline chapters match the implementation.**
  Axess writes one flat `AuthEvent` with `event_status` carrying the outcome
  and `event_time` in epoch microseconds; it awaits one `record_event` call and
  does not buffer, queue, retry or fan out. The chapters described a different
  model with per-outcome event types and a buffering config.
  **Re-check SIEM queries built from the old chapters**: event names, status
  handling and column names all differ. Two properties worth knowing before
  choosing a sink: the write is on the login hot path, and it now fails the
  login (see Security).

### Dependencies

`lru` 0.18.4 → 0.18.5. Declared minimums raised so consumers pick them up:
`cedar-policy` 4.13.0, `jsonwebtoken` 11.1.0, `quick-xml` 0.42.0, `rand`
0.10.3, `aes-gcm` 0.11.1, `serde_json` 1.0.151.

`axess-strings` and `axess-cache` could not build standalone: the workspace
pins `serde_json` with `default-features = false`, and `axess-cache` depended
on `axess-clock` without `testing`. Both compiled only because another member
enabled those features. This is what blocked Miri from running at all.

`rand` 0.8.6 remains behind the RustCrypto backend, so RUSTSEC-2026-0097 stays
on the `deny.toml` ignore list until `rsa` and its dependants move off it.

### Minimum Supported Rust Version

`1.94.0`, Rust 2024 edition. Unchanged in this release: the floor was
corrected to 1.94.0 in 0.5.0, and nothing here moves it. Restated because
the only other MSRV note in this file sits under 0.2.0 and says `1.87`,
which is what *that* release shipped with, not what this one needs.

## [0.5.1] - 2026-09-16

A dependency patch release. No API change, nothing to migrate.

### Security

- **`rustls` 0.23.44 to 0.23.45**, closing RUSTSEC-2026-0285: TLS 1.3
  handshake messages sent at the wrong encryption level were accepted, where
  RFC 8446 requires the connection to be terminated. Reached directly and through
  the `reqwest`, `openidconnect` and `ldap3` TLS features. The floor in
  `Cargo.toml` moved too, so a consumer keeping its own lockfile cannot stay on
  the vulnerable version.

---

## [0.5.0] - 2026-09-12

Three breaking changes, all single struct fields; see
`docs/production/migrating.md` for the fix at each one.

### Changed (breaking)

- **`SocialProviderConfig::client_secret` is now `ZeroizedString`** (was
  `String`), and so is the matching private field on `SocialProvider`. The
  type derives `Debug` and its docs invite loading it from a config file, so
  an adopter logging their configuration printed the OAuth client secret
  verbatim. `TotpConfig`, `HotpConfig` and `outbound_oauth_client` already
  did this; `social` was the exception.

- **`ClientCredentialsToken::access_token` is now `ZeroizedString`** (was
  `String`). Public, `Debug`-deriving, and the return value of
  `OAuthProvider::client_credentials`, so `debug!(?token)` printed a live
  bearer token. It is the same defect in the other direction: a secret axess
  hands *to* the adopter. `OAuthClaims` already wrapped its tokens.

- **`KeyId`'s inner field is now private**, matching `KindTag`, which always
  kept its own private behind the same `new`/`from_static`/`as_str`. The
  `pub` exposed a `ShortString` that `axess-events` did not re-export, so
  touching the field forced a direct `axess-strings` dependency at the
  workspace's internal pin.

### Security

- **Bearer tokens are zeroized where they land, not only where they are
  stored.** Six private token-endpoint response structs paired
  `#[derive(Debug, Deserialize)]` with a bare-`String` `access_token` and
  then copied it into a `ZeroizedString`, so zeroing the copy left the
  original in the heap for the life of the process. The wire fields are now
  `ZeroizedString` themselves, which deletes the conversion rather than
  duplicating it. All six types are private; no public API change.

- **An unknown tenant no longer discloses itself at login.** `begin_login`
  answered a nonexistent tenant with `Err(AuthnError::NotActive(_))`, a 403
  "account not active", while a wrong password answers
  `Ok(LoginOutcome::InvalidCredentials)`, so tenant existence was readable
  off the status code. It now returns `InvalidCredentials` and runs the same
  dummy store queries against a throwaway tenant id, which closes the timing
  channel that response-shape parity alone would have left open.

- **`h2` 0.4.14 → 0.4.19**, clearing RUSTSEC-2026-0258 ("unbounded empty
  DATA frames"), reached through `axum` → `hyper`. Lockfile-only.
- **`chacha20` 0.10.0 → 0.10.2**, replacing a yanked release pulled in
  through `rand` under `axess-rng`.

### Changed

- **`rust-version` corrected to 1.94.0.** Not an MSRV bump: the declared
  1.93.1 had been false since `sqlx` 0.9.0 landed, so no adopter could have
  built on it with the lockfile as pinned. The CI job meant to catch that
  hardcoded `1.93.1` in both its own name and its toolchain and ran `cargo
  build --workspace --all-features` without `--locked`, so it asserted a
  constant instead of the declared value, and passed. It now reads
  `rust-version` from `Cargo.toml` and runs `scripts/check-msrv.sh`, the same
  script maintainers run locally, so the two cannot drift.

- **That correction now actually takes effect.** The eight example crates and
  the fuzz crate hardcoded `rust-version = "1.93.1"` instead of inheriting
  it, and cargo resolves against the *minimum* across workspace members, so
  correcting the root alone changed nothing. The examples now use
  `rust-version.workspace = true`; the fuzz crate, nightly-only and outside
  the workspace, drops the key. `scripts/check-msrv.sh` rejects any new
  literal.

- **TLS and crypto dependencies moved to their current patch releases**, all
  semver-compatible, with declared floors raised alongside the lockfile:
  `rustls` 0.23.44, `rustls-webpki` 0.103.15, `rustls-pki-types` 1.15.1,
  `tokio-rustls` 0.26.5, `rustls-native-certs` 0.8.4, `webpki-roots` 1.0.9,
  `aws-lc-rs` 1.18.1 (`aws-lc-sys` 0.45.0), `hyper` 1.11.1, `uuid` 1.26.1,
  `moka` 0.12.16, `lru` 0.18.4, and the `rcgen` dev-dependency 0.14.10.

- **The unused `argon2` dev-dependency is gone.** Nothing in the workspace
  ever named it; hashing goes through `password-auth` 1.0.0, which carries
  its own argon2, and every mention of Argon2 in axess's source is a doc
  comment describing that. Verified rather than assumed: `cargo test
  --workspace --all-features --no-run` builds every test target without it.

- **`deny.toml`: `rcgen`'s new `pem` 4 duplicate documented, and a stale skip
  root corrected.** `cedar-policy-core@4.11.2` no longer matched a 4.12.0
  lockfile, so it accepted nothing and the `itertools` and `unicode-width`
  duplicates it existed for had resurfaced as unread warnings. `cargo deny
  check licenses sources bans` now passes with none.

- **`tracing-subscriber` is no longer a mandatory dependency of
  `axess-core`.** A library depends on `tracing`, the facade, and leaves the
  subscriber to the binary: installing one is the application's decision, and
  two libraries that both install one conflict. The only `src/` use was
  `testing::mock_tracing`, so it is now optional and pulled by the `testing`
  feature.

### Fixed

- **Every intra-doc link in the workspace resolves.** 29 diagnostics under
  `cargo doc --workspace --all-features -D warnings`, now none. Three causes:
  relative paths that resolve in the defining module but not where the doc
  comment travels with a re-export, now `crate::`-absolute; links into
  `axess-clock`/`axess-rng`'s `testing` feature, a dev-dependency no
  documentation build can see, now plain code spans; and two links to items
  that do not exist: `IdTokenClaims`, where the type is `OAuthClaims`, and
  `TOTP`, which `totp-rs` 6.0 renamed to `Totp`.

### Added

- **`scripts/check-doc-links.sh`** runs `cargo doc --workspace --all-features`
  under `-D warnings`, then verifies every workspace member rendered a page,
  because `cargo doc` prints nothing and exits 0 when the docs are fresh. The
  member list comes from `cargo metadata`, so a new crate cannot fall outside
  it. Wired in as `test-all.sh` step 6 and in place of
  `release-preflight.sh`'s former docs step, which covered two crates of
  eighteen with warnings allowed.

- **`axess-events` re-exports `ShortString`**, which the
  `From<ShortString> for KindTag` impl needs to name. Additive.

- **`scripts/check-doc-versions.sh`** verifies that every documented
  `axess... = { version = "..." }` snippet in a tracked `.md` or `.rs` is
  compatible with `[workspace.package] version`, by cargo's compatibility
  rule rather than string equality. `release-preflight.sh` step 2. It found
  seven stale snippets on introduction, including a facade `README.md` two
  minor versions behind.

---

## [0.4.0] - 2026-08-16

Breaking security-first release: authorization, factor-scope model,
CSRF, provider registration, session-key rotation.

### Added

- **Session signing-key rotation.** `SessionLayer::with_previous_signing_key(...)`
  mirrors `SessionCrypto::with_previous_key`; cookie AND fingerprint
  verify try current → previous, on fallback re-issue the cookie
  under the current key and update the stored fingerprint. One
  previous slot: see `OPERATIONS.md#signing-key-rotation`.
  Companion `SessionLayer::remove_previous_signing_key()` retires
  the slot at the end of the overlap window.
- **Cedar validator at startup.** `PolicyStore::from_text` runs
  `cedar_policy::Validator` in strict mode; `validate_policies` +
  `validate_sample_entities` exposed for reuse.
- **CSRF form-field + Origin/Referer.** `_csrf` hidden-input
  extraction (`form_field_name`, `form_body_limit` capped at 64 KiB
  by default; multipart not scanned) and opt-in
  `CsrfConfig::require_origin(...)`. `examples/sqlite` wires the
  full flow.
- **Provider hardening.** `OAuthProviderRegistry::add` warns +
  `debug_assert!`s on duplicate name. Predicates
  `has_oauth_providers()` / `has_fido2()` / `has_ldap()` /
  `has_previous_signing_key()`. `with_sid_map_capacity(n)` replaces
  the hardcoded 10 000 OIDC `sid_map` cap.

### Changed (breaking)

- `AuthnScope::Global` → `AuthnScope::System`; storage encodes as
  `(tenant_id = TenantId::SYSTEM, user_id = NULL)`: no NULL-tenant
  for configuration scope anywhere.
- `ScopeColumns.tenant_id`: `Option<TenantId>` → `TenantId`.
- `AuthnScope::lookup_chain` → `resolution_chain`, returns
  `Vec<AuthnScope>`.
- `FactorStore` gains `resolve_factor` (runtime, chain-walking,
  returns `ResolvedFactor`). `load_factor` keeps its name but its
  contract is now "exact scope only": the within-scope fallback
  the docs used to describe moved into `resolve_factor`. Every
  `FactorStore` impl must add `resolve_factor`; every runtime
  auth call site must switch from `load_factor` to `resolve_factor`
  or it silently loses the chain walk.
- `AuthzEntityProvider::validate_against_schema` → `validate_schema`;
  default `Ok(())` removed, adopters type it explicitly.
- `AuthzError::PolicyValidation` new variant (wildcard-less matches
  break).
- `MockStoreError` / `examples/sqlite::BackendError`:
  `InvalidGlobalMethod` → `InvalidSystemMethod`.
- `SessionConfig` fields are `pub(crate)`; adopters read via getters
  (`ttl()`, `cookie_name()`, `secure()`, `same_site()`,
  `http_only()`, `path()`, `max_custom_bytes()`) and construct via
  `SessionConfig::builder()`. Closes a hole where struct-literal
  construction bypassed the `__Host-` / `__Secure-` + non-zero-TTL
  assertions in `SessionConfigBuilder::build`.
- `KeyExtractor::UserId` / `TenantId` no longer read
  `x-user-id` / `x-tenant-id` request headers as a fallback: an
  unauthenticated caller could steer any user's rate-limit bucket
  and lock them out. Only the typed `RateLimitUserId` /
  `RateLimitTenantId` extensions the auth layer injects count.
- `axess-factors` re-exports `Totp` (renamed from `TOTP`) and adds
  `TotpBuilder`; both come from `totp-rs 6.0`. `Totp::generate()`
  now returns a `Token` instead of a `String`. The upstream feature
  `serde_support` was renamed to `serde`.
- `url` is now an unconditional `axess-core` dependency (previously
  optional, pulled by `fido2` / `oauth` / `delegated-*` / `*-sts`).
  CSRF-origin canonicalization needs it on every build; adopters
  compiling with only `authz` / `memory` now pick it up too. No
  functional break: the crate was already present transitively for
  most feature combinations.

### Fixed

- Fingerprint verification under rotation no longer invalidates
  sessions whose stored value was written under a previous master.
- CSRF Origin/Referer comparison delegates to `url::Url::origin`:
  scheme + host are case-folded, `userinfo@` is stripped, default
  port is dropped. Allow-list entries are canonicalized on
  `require_origin(...)`, so adopter-supplied forms and browser-sent
  headers now compare consistently.
- Cedar validator now explicitly requests `ValidationMode::Strict`
  instead of relying on the crate default.
- `examples/sqlite` `resolve_factor` is a single ordered
  `SELECT ... UNION ALL ... LIMIT 1` (was three sequential trips).
- `refresh_session_with_status_check` no longer runs `find_token`
  twice on the happy path: the status check and the rotation share
  the loaded record via a private `refresh_session_from_record`
  helper.
- Cookie verify skips the `base64(HMAC) → decode` round-trip on
  every session-cookie request; `hmac_bytes` returns the raw tag and
  the verifier compares directly against the decoded MAC bytes.
- `RequestIdService::ensure_request_id` sheds its fake `Result`
  return: `UuidGenerator` is documented as ASCII-only, the dead
  fallback branch is deleted.
- Bumped `lru` 0.18.1 → 0.18.2 to resolve **RUSTSEC-2026-0253**
  (potential use-after-free in `LruCache::pop()` under panic).
- HOTP `verify_hotp` no longer overflows the u64 counter when
  `counter + offset` approaches `u64::MAX` (panic in debug, wrap-to-0
  in release: the wrap would then compare against the counter-0 code
  and could pass). Loop now uses `checked_add` and stops iterating on
  overflow.
- HOTP verification success arm advances the stored counter via
  `saturating_add` (was `counter + 1`); a counter at `u64::MAX` now
  sticks instead of wrapping back to zero and re-admitting a
  previously-consumed code. Matches the failure arm's existing
  discipline.
- `CsrfConfig::require_origin` fails fast when every supplied origin
  fails to canonicalize: adopters passing typos (`"not-a-url"`,
  missing scheme, opaque-origin schemes) previously ended up with the
  Origin/Referer gate silently disabled: the empty allow-list is
  what the runtime treats as "no gate configured". Now panics with
  the rejected inputs listed, matching `SessionConfigBuilder::build`'s
  fail-fast discipline for the same misconfig class.
- `RefreshTokenConfig` now implements `Debug` manually and redacts
  `hash_pepper` as `Some(<redacted N bytes>)`. The derived `Debug`
  leaked the pepper via `tracing::debug!(?config)` / `dbg!`; a leaked
  pepper enables offline pre-image scans of the stored token-hash
  table.
- CSRF module docs now warn about the rotation-mid-request footgun:
  a handler that both reads `CsrfToken` from request extensions AND
  rotates the session ships a token bound to the pre-rotation id
  while the response cookie carries the post-rotation token: the
  next state-changing request 403s. Recommendation: redirect (302)
  after rotation rather than render inline with the request-extension
  token.
- Misleading docs corrected in `verification.rs`,
  `docs/sessions/security.md`, `axess-strings/README.md`.

### Migration

- Rename `AuthnScope::Global` → `System`; `lookup_chain` →
  `resolution_chain`.
- `FactorStore` impls: add `resolve_factor`; keep `load_factor`
  but audit every runtime auth call: the old within-scope
  fallback is now `resolve_factor`'s job.
- `AuthzEntityProvider::validate_against_schema` → `validate_schema`
  with an explicit body.
- `ScopeColumns.tenant_id` pattern matches: no more `Option`:
  `TenantId::SYSTEM` for the system tier.
- SQL schema: `factor_configs.tenant_id` and `auth_methods.tenant_id`
  become `NOT NULL` with FK to `tenants(id)`; seed the reserved
  system tenant (`UUID::nil()`). Reference migration in
  `examples/sqlite/migrations/`.
- Reads of `SessionConfig` fields → call the matching getter
  (`config.ttl` → `config.ttl()`, etc.). Struct-literal construction
  is no longer possible: use `SessionConfig::builder()` (which
  panics on the `__Host-` / non-zero-TTL / non-empty-cookie-name
  violations the fields used to admit silently).
- `KeyExtractor::UserId` / `TenantId`: any adopter relying on the
  `x-user-id` / `x-tenant-id` header fallback must instead inject
  `RateLimitUserId` / `RateLimitTenantId` request extensions from
  a trusted upstream layer (typically the auth layer itself). The
  header was spoofable by unauthenticated callers.
- `axess_factors::TOTP` → `Totp`. Constructors move to `TotpBuilder`:
  `TotpBuilder::new().with_algorithm(alg).with_digits(d).with_skew(0)
  .with_step_duration(step).with_secret(secret).build()`. Verify
  returns `Token`; call `.to_string()` to get the zero-padded numeric
  code. If your `Cargo.toml` enables `totp-rs/serde_support`, rename
  it to `totp-rs/serde`.
- `CsrfConfig::require_origin` now panics if every supplied origin is
  malformed. Audit adopter code that assembles origin lists from
  environment / config for typos before deploying 0.4.0; a mistyped
  value that used to silently disable the Origin gate now surfaces
  at startup.

---

## [0.3.3] - 2026-08-08

### Fixed

- `session` + `csrf`: a fresh guest's session id is now stable across
  `finalize_session`, so a CSRF token minted during a request stays valid on
  the client's next state-changing request. Previously a fresh guest (no
  trusted `existing_id`) took the id-cycling branch and minted a *second*,
  different id for the response cookie: even though the request, and the
  `CsrfLayer` token HMAC-bound to it, already ran under the id `load_session`
  minted. The client was left holding a `csrf-token` bound to the old id and an
  `axess.sid` carrying the new one, so its next state-changing request
  (typically the login `POST`) failed validation with `csrf: token validation
  failed` → `403`. The id-cycle branch is now gated on `regenerate` alone; a
  fresh guest is saved under its already-fixation-safe load-minted id. Session
  fixation protection is unchanged: privilege changes and binding-mismatch
  resets still rotate the id via the `regenerate` path.

---

## [0.3.2] - 2026-08-06

### Added

- `axess-rng`: opt-in `numeric` feature adds a reproducible statistical
  RNG surface alongside the always-on cryptographic `SecureRng`:
  - `NumericRng` trait: number-oriented (`next_u64`, `next_uniform`),
    stateful, deterministic given a seed. For Monte Carlo, statistical
    sampling, and DST.
  - `Xoshiro256pp`: xoshiro256++ 256-bit PRNG (Blackman & Vigna 2019).
    Bit-exact reproducible: same seed yields the same sequence
    permanently, independent of any dependency updates.
  - `MockNumericRng` (under `testing`): DST test mock with two
    constructors. `from_seed(u64)` wraps a seeded `Xoshiro256pp` behind
    a `Mutex`; `from_sequence(...)` replays a pre-programmed `u64`
    sequence and panics on exhaustion.
- Default consumers (feature not enabled) see zero API surface change;
  additive minor. Downstream integrators opt in via
  `axess-rng = { version = "0.3.2", features = ["numeric"] }`.

---

## [0.3.1] - 2026-08-02

### Fixed

- `CsrfLayer` self-heals a stale double-submit cookie by re-minting on
  the response when the session id changes mid-request (e.g. after
  `AuthSession::regenerate()` on login completion, MFA add, or tenant
  switch). The fail-closed reject on state-changing requests is
  unchanged; only the recovery path is new.

---

## [0.3.0] - 2026-08-01

Breaking release: the MSRV rises and `jsonwebtoken`'s `Algorithm` type:
re-exposed through this crate's public API: becomes `#[non_exhaustive]`.

### Added

- `EventSubjectRef<'a>` and `EventPayload::subject_ref()`, a borrowed,
  zero-allocation view of the entity an event is *about*
  (`User` / `Tenant` / `Device` / `Session` / `Other { kind, id }`),
  mirroring the owned envelope-level `EventSubject`. Fills the hot-path gap
  the owned type doesn't cover: per-tick routing, per-tenant fan-out,
  per-subject bucketing, and tracing-span tagging without allocating.
  Additive: `subject_ref()` defaults to `None`, so existing `EventPayload`
  implementations are unaffected.

### Changed

- **BREAKING:** `jsonwebtoken` 10 → 11. Its `Algorithm` enum is now
  `#[non_exhaustive]` and is re-exposed via `ALLOWED_ALGORITHMS`,
  `JwtVerifier::with_algorithms`, and the local-IdP helpers, so exhaustive
  `match`es on it downstream must add a wildcard arm. Internally, the
  `alg_family` mirror is replaced by the now-public `Algorithm::family()`.
- **BREAKING:** MSRV raised to **1.93.1**. The library itself builds on 1.88
  (raised from 1.87 by `jsonwebtoken` 11); the declared floor is set to the
  workspace-wide requirement so the full build+test suite runs on a single
  toolchain: `serial_test` 4.0.1 (dev-only) requires 1.93.1.
- Dependency bumps: `base64` 0.22 → **0.23** (SIMD engines; API unchanged for
  our usage), `cedar-policy` → **4.12.0** (unified across the workspace),
  `tokio` → **1.53.1**, `thiserror` → **2.0.19**, `zeroize` → **1.9.0**,
  `serial_test` (dev) → **4.0.1**; versions unified across the workspace.
- Inter-crate and example `axess-*` dependencies are now pinned exactly
  (`=0.3.0`) so the family always resolves as one tested, audited unit.

### Security

- Transitive `event-listener` 5.4.1 → **5.4.2**, closing
  [RUSTSEC-2026-0221] (`!Send` tags could cross thread boundaries via
  `StackSlot`). Lockfile-only; no public-API change.

[RUSTSEC-2026-0221]: https://rustsec.org/advisories/RUSTSEC-2026-0221

## [0.2.2] - 2026-07-19

### Security

Transitive-dependency security patch: no adopter-facing API changes,
same public surface as 0.2.1.

- `crossbeam-epoch` 0.9.18 → 0.9.20 (fixes [RUSTSEC-2026-0204]: invalid pointer dereference in the `fmt::Pointer` impl for `Atomic` / `Shared`).
- `quinn-proto` 0.11.14 → 0.11.16 (fixes [RUSTSEC-2026-0185], severity 7.5 high: remote memory exhaustion via unbounded out-of-order stream reassembly). Pulled by `reqwest` for HTTP/3.
- `anyhow` 1.0.102 → 1.0.104 (fixes [RUSTSEC-2026-0190]: unsoundness in `Error::downcast_mut()`).
- `spin` 0.9.8 → 0.9.9 (0.9.8 was yanked upstream).

Lockfile-only update; no `Cargo.toml` semver constraints changed. All
1469 tests still pass under the new lockfile; `cargo audit --deny warnings`
now clean.

[RUSTSEC-2026-0204]: https://rustsec.org/advisories/RUSTSEC-2026-0204
[RUSTSEC-2026-0185]: https://rustsec.org/advisories/RUSTSEC-2026-0185
[RUSTSEC-2026-0190]: https://rustsec.org/advisories/RUSTSEC-2026-0190

---

## [0.2.1] - 2026-07-19

### Security

- **CSRF token bound to session id.** The double-submit token is now `HMAC(signing_key, nonce || session_id)`, so a token minted under one session cannot be replayed after the session regenerates (e.g. after login). When the `SessionHandle` request extension is absent on a state-changing request, `CsrfLayer` fails closed (403) rather than validating an unbound token, so a mis-ordered middleware stack surfaces as a hard failure. `CsrfLayer` must be layered inside (i.e. run after) the session layer; the module docs and the example in the docstring make the ordering explicit.

### Changed

- Dependency bumps: `aes-gcm` 0.10.3 → 0.11.0, `quick-xml` 0.40.1 → 0.41.0, `chrono` 0.4.44 → 0.4.45, `uuid` 1.23.2 → 1.24.0, `rand` 0.10.1 → 0.10.2.

---

## [0.2.0] - 2026-06-01

First public release.

Axess is a modular, policy-driven authentication and authorization library for the [Axum](https://github.com/tokio-rs/axum) web framework. It is built around a trait-based design that supports deterministic simulation testing (DST) from the ground up: every source of non-determinism (clock, RNG, identity store, factor store, session registry, principal resolver) is an injectable trait with a production implementation and a deterministic test double.

Adopters depend on the `axess` facade crate. The 0.x line is pre-1.0: the public API may evolve based on adopter feedback before stabilising.

### Identity and tenancy

- **Multi-tenant model.** Cross-tenant operations refuse by default. Tenant-level `Suspended` status locks out all users before factor prompts. Atomic `create_tenant(bootstrap)` enforces "every tenant has at least one factor and one enabled method". Reserved `system()` principals for internal callers. See [`docs/identity/tenancy.md`](docs/identity/tenancy.md).
- **Three-tier identity store split.** `IdentityLookup` (10 read verbs) ← `IdentityAuthnLog` (4 per-attempt audit-write verbs) ← `IdentityAdmin` (9 verbs for privileged provisioning, suspension, and GDPR erasure). `IdentityStore: IdentityAdmin` umbrella alias preserves the full-tier shape for production backends. `NoopAuthnLog` adapter wraps an `IdentityLookup` for fixtures and read-replica integrations. See [`docs/identity/store.md`](docs/identity/store.md).
- **Typed identifiers.** `UserId`, `TenantId`, `WorkloadId`, `Principal { Human, Workload }`, all UUID-backed with strict parsing. Shared via the `axess-identity` crate.

### Authentication and session machinery

- **Explicit session state machine** (`AuthState`): `Guest`, `Identifying`, `Authenticating`, `Authenticated`, `PendingWorkflow`. Typed transitions reject invalid moves at compile time.
- **Multi-factor authentication.** Sequential and choice-based verification via `FactorStep::AnyOf`. Factors compose into named methods scoped per tenant or per user.
- **Factor implementations.** Password (Argon2id), TOTP (RFC 6238), HOTP (RFC 4226), email OTP (8-digit, Argon2-hashed, TTL-bound), FIDO2 / WebAuthn (registration, authentication, discoverable / passwordless, clone detection), OAuth 2.0 / OIDC (Authorization Code + PKCE, Client Credentials, Device Code RFC 8628), LDAP bind, mTLS, JWT (incl. JWT-SVID), bearer-token extractors.
- **DST-friendly verification.** TOTP verification, the FAPI `nbf` validator, and the DPoP `jti` replay cache all consume time through `axess_clock::Clock`. Default is `SystemClock`; swap in a `MockClock` for deterministic simulation. `OAuthProviderConfig::with_clock` and `MemoryJtiCache::with_clock` expose the injection point on the OAuth surfaces; `verify_totp` accepts the `DateTime<Utc>` the application's clock returns.
- **Plain-OAuth-2.0 social login.** Generic `SocialProvider` (gated on `social`, **off by default**) for IdPs that don't support OIDC (GitHub user login, Twitter/X, Discord, Reddit, Spotify, …). Identity comes from a TLS-trusted userinfo endpoint rather than a signed assertion; the security model is weaker than OIDC. Parallel types (`SocialClaims` vs `IdTokenClaims`, `SocialProvider` vs `OAuthProviderConfig`) make the difference visible at every call site. PKCE on by default; RNG injectable via `Arc<dyn SecureRng>` for DST.
- **Session lifecycle.** ID cycling for fixation prevention; HMAC-SHA256 fingerprint binding at completion; registry-backed forced logout; concurrent-session limits with oldest-eviction; versioned session data with auto-migration; refresh-token rotation with family revocation on reuse.
- **Session revocation API.** `AuthnService::invalidate_user_sessions`, `invalidate_session`, `active_sessions`, `has_session_registry()`. Returns `NoSessionRegistryError` when no registry is attached.
- **`SessionRevoker` + `SessionRegistryHandle` supertrait pair.** Logout handlers take `Arc<dyn SessionRevoker>` (2 methods); `AuthnService` holds `Arc<dyn SessionRegistryHandle>` (5 methods).

### Workload identity

- **`Principal { Human, Workload }` abstraction** unifying inbound authn across humans and non-human workloads (services, K8s pods, CI/CD runners, batch jobs). `PrincipalResolver` trait + per-feature resolvers; the same `ToCedarEntity` bridge for both shapes so Cedar policies authorise both consistently.
- **SPIFFE adapters.** `JwtSvidResolver` (`jwt-svid`) and `MtlsResolver` (`mtls`) extract SPIFFE identities from JWT-SVID tokens and X.509-SVID leaf certs respectively.
- **Generic federation resolver.** `WorkloadResolver<C, F, R>` (gated on `jwt`) for any non-SPIFFE JWT-bearer workload token (Kubernetes service-account, GitHub Actions OIDC, GitLab CI OIDC, Okta, Azure AD, Auth0, `LocalIdP`, …). Adopter supplies a claim struct + mapping closure per issuer they care about; no per-company feature flags. Ready-made recipes for GitHub Actions + Kubernetes ship in [`examples/workload-identity/`](examples/workload-identity/). The resolver synthesises a SPIFFE-shape `WorkloadId` so policies see uniform entity shape.
- **`axess::workload` hub**; inbound resolvers and outbound primitives behind the `workload-id` umbrella feature.
- **Cloud STS exchange.** `aws-sts`, `gcp-wif`, `azure-fic` adapters for exchanging federated workload identity for cloud temporary credentials. See [`docs/workload-identity/cloud-sts.md`](docs/workload-identity/cloud-sts.md).
- **Outbound identity.** `outbound-oauth` (axess as an OAuth client) and `outbound-mtls` (axess presenting an mTLS identity to downstream services).

### On-behalf-of (OBO) access

- **Two flows under `axess_core::delegated`.** `delegated-stored` implements RFC 6749 §4.1 (Authorization Code + PKCE with persisted refresh token) for long-lived offline access. `delegated-exchange` implements RFC 8693 Token Exchange for short-lived per-request exchange. The `delegated` umbrella feature enables both.
- **`EncryptedDelegatedCredentialStore<S, K>`** decorator wraps any delegated-credential backend with AES-256-GCM at rest. Available via `delegated-stored-encrypted`.

### Authorization

- **Cedar Policy engine** for RBAC + ABAC + ReBAC. `AuthzStore` orchestrates policy evaluation; `ToCedarEntity` bridges principals, resources, and contexts into Cedar entities.
- **Layered policy bundle** (base + overlay); adopters drop additional `.cedar` and `.schema.cedar.json` files into an `overlay/` directory that the loader concatenates onto the base on startup.
- **`require_authn!`, `require_partial_authn!`, `require_authz!`** procedural macros from `axess-macros` guard handler functions at compile time.

### Session storage

- **Five session backends.** `Memory`, `SQLite`, `Postgres`, `MySQL` / MariaDB, `Valkey`. The four persistent backends share `SessionCodec` (MessagePack + optional AES-256-GCM) so byte-level wire-format compatibility is preserved when migrating between databases. The MySQL backend is compatible with MySQL 5.7+, 8.x, and MariaDB 10.x+. See [`docs/sessions/backends.md`](docs/sessions/backends.md).
- **CockroachDB compatibility validated.** Postgres wire protocol works unmodified. A dedicated `cockroach_compat` CI job runs the Postgres integration suite against `cockroachdb/cockroach:latest` to catch dialect divergence.
- **`Store<SessionId, SessionData>` cross-backend surface** shipped on every session backend. Adopters can hold `Arc<dyn Store<…>>` or generic `S: Store<…>` for backend-agnostic dispatch. `SessionStore` remains the primary surface; it carries the `cycle` and `find_sessions_for_user` primitives that `Store` omits.
- **`HealthCheck` trait** on every session and cache backend (bounded 2-second probe). Fail-soft on Valkey: errors degrade to miss + warn-log, so an unhealthy result is operational signal rather than a hard failure.
- **`MemoryStore<K, V>` shared backend** with `axess_clock::Clock` injection. Used by `MemorySessionStore` and the in-memory refresh-token store, with deterministic test mocks driving manual clock advance.

### Caching

- **`axess-cache::ClockTtlCache`**; in-process TTL cache with clock injection for DST. Asymmetric defaults: cache authz decisions, do not cache authn.
- **`CacheInvalidator` trait + scoped invalidation** on `EntityCache` / `MokaEntityCache` / `ValkeyEntityCache` so policy-update, role-change, and tenant-suspension handlers can dispatch through a single trait without naming the concrete cache.
- **`AuthnMetrics::authz_cache_*` methods** (`hit` / `miss` / `eviction` / `invalidation`) with no-op defaults. `EntityCache::flush_metrics` snapshots `axess_cache::CacheStats` counters into per-event trait calls then resets.

### Audit and analytics

- **`AuditArchiver` trait + `AuditRetentionPolicy`** for hot / cold tiering of authn audit rows. Three-stage retention (`archive_after` / `purge_hot_after_archive` / `delete_archive_after`) with conservative finance-aware defaults (90d / 7d / never). `AuditRetentionLoop<S, A>` handles the schedule, retry, and batch-sizing pipeline. `FilesystemAuditArchiver` (behind `audit-archive-fs`) is a reference implementation with day-partitioned JSONL and fsync per batch. See [`docs/production/audit-pipeline.md`](docs/production/audit-pipeline.md).
- **`AuthnAnalyticsSink` + `RichAuthnEvent`**; a denormalised analytics path parallel to the regulatory `AuthEvent`. Optional enrichment fields (device trust, geo, ASN, parsed UA, tags); serde + rkyv derives so adopters can stream to Apache Iggy, ClickHouse, DuckDB, or Snowflake. `AuditLogWithAnalytics<L, S, E>` decorator wraps an `IdentityAuthnLog` + sink + enrichment closure with fire-and-forget dispatch for the analytics path.
- **Device-identity audit events.** Six `AuthEvent` variants (`DeviceFirstSeen` / `DeviceTrustGranted` / `DeviceRevoked` / `DevicePurged` / `DeviceBindingAdded` / `DeviceFingerprintMismatch`) wired into SIEM rules in [`docs/production/audit-events.md`](docs/production/audit-events.md).

### Device identity

- **First-class `Device` aggregate** under `axess-core/src/device/`. Unknown → Seen → Trusted ladder; cascade revocation; pluggable storage. Reference example under `examples/device/`.
- **Five `DeviceStore` backends.** `Memory`, `SQLite`, `Postgres`, `MySQL` / MariaDB, `Valkey`; surface-equivalent across SQL dialects + Valkey hash storage, optional AES-256-GCM envelope on the bindings blob (SQL backends). Adopters needing a custom backend (DynamoDB, MongoDB, …) follow the recipe in [`docs/identity/device.md`](docs/identity/device.md).

### IdP fixtures and workload-token issuance

- **`LocalIdpFixture`**; in-process test IdP minting workload JWTs against an in-memory RSA-2048 keypair, with a matching JWKS endpoint. Multi-key JWKS + rotation, adopter-supplied keypairs, ES256 (P-256) alongside RS256, max-TTL policy, issuance audit hook, RFC 8414 discovery document, file-backed adopter example. See [`docs/factors/local-idp.md`](docs/factors/local-idp.md).

### Middleware

- **Axum / Tower middleware** under `axess-core::middleware`: `csrf` (signed double-submit cookie), `ratelimit` (composable token bucket), `request_id` (X-Request-Id), `trace_id` (W3C Trace Context), `ws` (revocation-aware WebSocket wrapper).

### Deterministic simulation testing

- **Clock, RNG, identity store, factor store, session registry, principal resolver, entity provider, policy evaluator**; all behind traits with `testing::Mock*` doubles under the `testing` feature.
- **`TracingCapture`** test subscriber for asserting on emitted `tracing` events from inside tests.
- **`InMemoryBackend`** assembling a complete in-memory stack for end-to-end test flows.

### Reference examples

| Example | Demonstrates |
|---|---|
| `examples/sqlite/` | Reference app: SQLite sessions + full auth flow |
| `examples/oauth/` | OAuth 2.0 / OIDC login against a public IdP |
| `examples/social/` | Plain-OAuth-2.0 social login (Login with GitHub) |
| `examples/authz/` | Cedar Policy authorization |
| `examples/fapi/` | FAPI 2.0 (PAR, DPoP, JARM, RP-initiated logout) |
| `examples/device/` | Device-identity ladder |
| `examples/local_idp/` | In-process IdP minting workload-identity JWTs |
| `examples/workload-identity/` | Adopter recipes for `WorkloadResolver` (GitHub Actions, Kubernetes service accounts) |

### Conventions

- **Kebab-case feature flags throughout** (`request-id`, `trace-id`, `accept-client-id`, `jwt-svid`, `mtls`, …). No mixed-case or underscored alternatives.
- **`memory`-gated dev backends.** `MemorySessionStore`, `MemorySessionRegistry`, `MemoryStore<K, V>` ship behind the `memory` feature so production builds cannot accidentally pull in a non-persistent store.
- **`testing` feature** (`testing = ["memory"]`) gates all test doubles and fixtures: `MockIdentityStore`, `MockFactorStore`, `MockClock`, `MockRng`, `MockResolver`, `MockEntityProvider`, `MockPolicyEvaluator`, `TracingCapture`, `MemoryRefreshTokenStore`, `LocalIdpFixture`, `InMemoryBackend`.
- **Defaults run zero-infra.** Infra-bound features (`sqlite`, `postgres`, `valkey`, `ldap`, …) are opt-in. Hard rule.
- **Exhaustive enums.** No first-party enum carries `#[non_exhaustive]`; consumer `match` expressions get exhaustive arms and a CI guard rejects any new occurrence.

### Minimum Supported Rust Version

`1.87`, Rust 2024 edition. Latest stable toolchain expected.
