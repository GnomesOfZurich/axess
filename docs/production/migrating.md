# Migration guide

Find your version below; the newest is first. Each break is listed by
**what you will see** rather than by what we changed, because a compile
error, a failed deserialization and a behaviour that quietly differs
send you looking in different places. Each one names the symptom and the
fix.

The behaviour changes are the ones to read closely. Nothing tells you
about those.

## 0.12.0 to 0.13.0

A security release. Compile errors first, then storage, then behaviour.

- **`IdentityAuthnLog` requires `failed_attempts(&UserId) -> (u32,
  Option<DateTime<Utc>>)`** (`not all trait items implemented`). Return the
  failure count and the time of the last failure; `record_failed_attempt` must
  now store that time and `reset_failed_attempts` clear it. The lockout is
  derived from it at every gate, so a log that forgets the time locks nobody.
- **`LocalIdpKeyStore` requires `retire(&self, key_id) -> Result<bool, _>`.**
  Remove the historical key and answer whether one was there.
- **`DeviceStore::record_sighting` returns `Result<DeviceTrustLevel, _>`**
  (`mismatched types` in an implementor). Return the row's level; `Revoked`
  means the row was left as it was.
- **`RefreshToken` has `revoked_reason: Option<RevocationReason>` and
  `revoked_at`; `RefreshTokenConfig` has `max_lifetime` and `reuse_grace`**
  (`missing fields` in a struct literal: add `..Default::default()` or the two
  `None`s). A third-party `RefreshTokenStore` persists both new fields; the
  sqlite example ships the migration. A row without them reads as a rotated
  token, so reuse still revokes the family.
- **`RefreshTokenStore::revoke_device_tokens`** has a default body answering
  `DeviceTokenRevocation::Unsupported`; implement it to let
  `revoke_device` and `CascadingRefreshStore` reach your tokens.
- **`RateLimitConfig` has `rng`; `RateLimitLoginIdentifier` is a struct**
  (`RateLimitLoginIdentifier(x)` no longer compiles: use `new` or
  `new_in_tenant`).
- **`CsrfToken` is no longer a tuple struct**: build one with `CsrfToken::new`
  and read it with `as_str` or `Display`.
- **`refresh_oauth_token(provider, token, expected_subject, original_nonce)`
  returns `RefreshOutcome`**; read `id_token_claims` as an `Option`. An
  `OAuthProvider` implementor changes `refresh_token` and
  `refresh_token_for_subject` the same way.
- **`fetch_userinfo(provider, access_token, expected_subject)`.**
- **`generate_dpop_proof(provider, &DpopKey, ..)`** under `fapi`: make one key
  with `AuthnService::new_dpop_key` (or `DpopKey::from_seed`) and keep it for
  the session; the thumbprint must stay the same across the proofs.
- **`OutboundOAuthClient::new` returns `Result`**; so does `SessionLayer::try_new`
  and `SessionCrypto::try_new` if you move to them (the infallible
  constructors stay and log a constant key).
- **`JtiLog::new(capacity)`**; **`BearerIssuerConfig::new(issuer, audience)`**
  requires the audience (`with_extra_claims` for the rest).
- **`require_authz!` refuses a resource id with two path placeholders** at
  compile time. Use one placeholder, or `{$tenant}` / `{$user}` from the
  session for the qualifying part.
- **Exhaustive matches** add `RefreshError::{ConcurrentRefresh, DeviceRevoked,
  DeviceStore}`, `SqlDeviceStoreError::Contended`, `KdfError::Busy`,
  `IssuanceError::{MissingAudience, RetireCurrentKey, DuplicateKeyId}`,
  `LocalIdpKeyError::{UnsupportedAlgorithm, WeakKey}`,
  `OAuthError::SubjectMismatch`, `OAuthClientError::{InsecureEndpoint,
  ClientBuild}`.

- **`TotpConfig::secret` and `HotpConfig::secret` are a `FactorSecret`**
  (`mismatched types: expected FactorSecret, found ZeroizedString` in a struct
  literal). Add `.into()`: `secret: ZeroizedString::new(text).into()`. Code that
  read the field as a string uses `secret.plain()` (`Option<&str>`). Stored rows
  need no change: a plain secret still serialises as the bare string.

- **`begin_fido2_registration`, `finish_fido2_registration` and
  `delete_fido2_credential` answer `NoFlow` unless the session is
  `Authenticated` as the user passed in** (or pending signup for them). A
  handler that enrolled a passkey from a guest or another user's session now
  fails; pass the signed-in user's own session. `delete_fido2_credential`
  gains a `session: &AuthSession` second parameter
  (`this method takes 3 arguments but 4 were supplied`).
- **`IdentityAuthnLog` requires `reserve_attempt(&UserId, &LockoutPolicy) ->
  Result<Option<u32>, _>` and `release_attempt(&UserId)`** (`not all trait items
  implemented`). `reserve_attempt` must test and increment in one atomic step
  (`UPDATE ... SET n = n + 1 WHERE ... RETURNING n`) and store the time of the
  attempt as `record_failed_attempt` does. The count is fresh (replaced by one)
  when there is no failure, the last is older than `attempt_window`, or a timed
  lockout (`duration`) has run out; otherwise the guess is granted while the
  count is below `effective_max_attempts()` and refused with `None`, changing
  nothing, once it is not. `release_attempt` decrements without going below zero
  and clears the failure time at zero. The sqlite example and the testing mock
  show both. A store that wraps another forwards both.
- **`refresh_session` is deprecated** (a warning, an error under
  `-D warnings`): call `refresh_session_with_status_check`, passing a predicate
  that reads the account's status.

- **`OAuthClaims` has a `dpop_key` field.** A struct literal adds `dpop_key: None`; claims from `finish_oauth_login` on a DPoP provider carry the key to keep with the tokens.
- **`FapiConfig` has `allowed_id_token_algs`.** Construct it with `..FapiConfig::default()`. A FAPI provider now accepts ID tokens signed with `PS256`, `ES256` or `EdDSA` only; an IdP that signs with `RS256` needs the list widened on purpose.



- **`SessionStore` requires `update_if_revision`** (`not all trait items
  implemented`), and **`SessionData` has `revision` and `touched_at`**
  (`missing fields` in a struct literal: add `..Default::default()`). Replace
  the row only while the stored data still carries the expected revision, and
  answer `ConditionalUpdate::Conflict` when it does not and `Gone` when
  there is no live row. Compare and write in one atomic step; an
  `UPDATE ... WHERE` naming the bytes you compared does it in SQL.
- **`SessionRevoker` methods return `Result<(), RevocationError>`.** An
  implementor returns `Ok(())` where it returned nothing; a caller that
  ignored the result handles it (`must_use`).
- **`invalidate_user_sessions` and `invalidate_session` live on
  `RequestAuthnService` and take an `Actor`.** `invalidate_user_sessions_as(id,
  Some(&admin))` becomes `invalidate_user_sessions(id, Actor::Admin(&admin))`,
  and `None` becomes `Actor::System`; the unattributed `AuthnService` methods
  are gone, so derive a request-scoped handle with `with_audit_context`.
  A registry that fails is now an `Err` instead of a logged warning.
- **`suspend_user` and `activate_user` take an `Actor` and the expected
  tenant.** `suspend_user_by_in_tenant(a, u, t, d)` is
  `suspend_user(Actor::Admin(a), u, t, d)`; a platform operator that meant "any
  tenant" calls `suspend_user_across_tenants`. `begin_impersonation_in_tenant`
  is `begin_impersonation`, and the old unscoped `begin_impersonation` is
  `begin_impersonation_across_tenants`.

- **`ServiceSecretLayer::signed` returns a `Result` and needs an audience**
  (`mismatched types` at the call, then `ServiceSecretError::MissingAudience` at
  run time). Name each route as its recipient,
  `SignedRequests::default().audience("billing")`, and have callers sign for
  that name with `ServiceSigner::sign_for("billing", ..)`; `ServiceSigner::sign`
  is gone. Callers that cannot move at once keep working through
  `.accept_unaddressed_until(instant)` on the route, checked against its clock;
  a `v1` signature names no recipient, so inside the window it still replays
  against another service sharing the secret, so give each recipient its own
  secret as well.

Storage.

- **Refresh tokens**: two nullable columns, `revoked_reason` and `revoked_at`
  (the sqlite example's migration shows the shape). No backfill.
- **Devices**: `idx_devices_fingerprint` is replaced by
  `idx_devices_fingerprint_seen`, plus `idx_devices_sweep` and
  `idx_devices_revoked_at`. `init_schema` does it on SQLite and Postgres; on
  MySQL run the `ALTER TABLE` in the `MysqlDeviceStore` docs.
- **Device rows and the envelope key**: a row sealed under the previous key
  is re-sealed by the read that finds it, and a row nobody reads keeps the old
  key, so keep the previous key for the longest device retention you
  configured (see the operations guide), not for one session TTL.
- **Delegated credentials** are written in envelope `v2`; `v1` rows are still
  read. A release that reads only `v1` needs every row re-saved first.
- **Entity caches**: every key changes (the Valkey key gains a segment), so
  cached authz entities are missed once after the upgrade and reloaded.
- **Audit archive sidecars** carry `{batch id} {digest}`; old lines still match.

Behaviour. Read these.

- **The session cookie is `__Host-axess.sid`** when `Secure` is on and the path
  is `/`. Every client with a cookie named `axess.sid` signs in again once.
  Name the cookie yourself to keep the old name. The layer now **panics at
  `Layer::layer`** on a `__Host-` or `__Secure-` name without `Secure`, a
  `__Host-` name off `/`, a zero TTL, an invalid name or `SameSite=None`
  without `Secure`; so does `CsrfLayer::new`.
- **A request without a session cookie stores nothing** and gets no cookie
  until a handler uses the CSRF token or the session. A single-page app that
  reads the CSRF cookie before any handler touches the token needs
  `CsrfConfig::mint_on_every_request(true)`.
- **Lockout is enforced from the stored counter**: an account at
  `max_attempts` answers `Locked` to a correct credential until `duration`
  after the last failure. `max_attempts == 0` means five (was: lock on the
  first failure). A `NoopAuthnLog` locks nobody.
- **A login flow expires**: `verify_factor` and `prepare_factor` answer
  `NoFlow` for a flow older than `flow_ttl` (ten minutes), one begun against a
  password or method that has since changed, or one begun under 0.12.0. A
  session mid-login at the upgrade signs in again.
- **`begin_login` answers `InvalidCredentials`** for a known account that is
  not active and not locked (was `Err(NotActive)`); the audit row keeps the
  reason. **`finish_discoverable_login` returns `FactorOutcome`** and follows
  the user's method, so a passkey alone no longer signs in a user whose method
  needs more.
- **`StepUpPolicy::default()` asks for a factor on every trust level**,
  `Trusted` included; set `trusted` to an empty list to keep the old
  behaviour. A request with no resolved device is judged as `Unknown`.
- **A token revoked by a logout, a user-wide revocation, a cap eviction or an
  earlier family revocation no longer revokes its family on reuse**; only a
  token rotated out does. `reuse_grace` is zero, so parallel refreshes by one
  client are still treated as theft until you set a window.
- **IPv4-mapped IPv6 clients** (`::ffff:10.0.0.1`) are seen as IPv4: they
  match IPv4 proxy entries, and each registers as a new device once.
- **`LocalIdp` mints tokens for at most one hour and refuses a mint without an
  audience**; `without_max_ttl()` and `allow_no_audience()` opt out. Generated
  keys carry a thumbprint `kid`, so two generated keys rotate without renaming.
- **LDAP over plain `ldap://` to a non-loopback host is refused** unless
  `allow_cleartext()` is called.
- **`JwtSvidResolver` refuses a verifier that pins no `iss` or no `aud`**, and
  `verify_jwt` refuses `HS*` even when allowlisted.
- **An empty post-logout redirect allowlist forwards nothing.** Configure
  `with_allowed_post_logout_redirect_uris`.
- **A back-channel logout token with `sid` and `sub` ends only the `sid`
  session**; a full `jti` log answers 503 and the IdP retries.
- **The bearer 401 body is fixed** at `{"error":"invalid_token"}`; the reason
  moved to the debug log.
- **`x-ratelimit-remaining` is sent only for per-user buckets**, and a /24 or
  /48 holds at most 1,024 buckets before clients share one.
- **The KDF executor answers 500 (`KdfError::Busy`)** past `with_max_queue`
  or `with_acquire_timeout`; there is no 503 variant yet.
- **The session layer, given a registry (`with_registry`), treats a session
  the registry no longer holds as revoked**: its row is deleted and the
  request runs as a guest. Any path that authenticates a session without
  registering it is caught by this; register, or leave the registry off.
- **Rotating the refresh-token pepper no longer logs everyone out.** Move the
  old `RefreshTokenConfig::hash_pepper` to `previous_hash_pepper` and set the
  new one as `hash_pepper`. Tokens still stored under the old pepper are found
  by the retry and replaced under the new one on their next refresh (even with
  `rotation: false`). Clear `previous_hash_pepper` after one `ttl`. Moving from
  no pepper to a pepper still invalidates the tokens. The struct has a new
  public field, so a literal without `..Default::default()` needs
  `previous_hash_pepper: None`.
- **`WorkloadResolver` needs a verifier with `with_issuer` and `with_audience`.**
  A verifier that pins either loosely now resolves to `NotAuthenticated`.
  Add the missing pin; `allow_any_audience` does not satisfy the resolver.
- **Sealing OTP secrets at rest is opt in, and turning it on needs a plan for the
  rows you already have.** Build a `FactorSecretCipher` from a 32-byte random
  key, pass it to `AuthnServiceBuilder::with_factor_secret_cipher`, and seal new
  enrolments with `FactorSecretCipher::seal_config` before `save_factor`.
  Without a cipher nothing changes. With one, the default policy refuses a
  secret still stored in plain text (the login fails with an internal error that
  names the cause), so set `with_plain_secrets(LegacyBlobs::AcceptUntil(cutoff))`
  for as long as plain rows remain: each is sealed by its owner's next
  successful login, with no change to your `FactorStore`. A sealed secret read by
  a service with no cipher fails the same way, so deploy the cipher to every
  replica before the first row is sealed. Keep the key outside the database and
  see "Where the OTP secret sits" in the password and TOTP guide for rotation.
- **`axess_core::session::LegacyBlobs` and the core crate's `aes-gcm` dependency no
  longer depend on a storage feature.** Nothing to change unless you named
  `aes-gcm` through a core-crate feature.
- **A password hash made under older Argon2 parameters is replaced at the next
  successful login.** Nothing to do; the row's `hash` changes once. A store that
  keeps a history of hashes or audits factor writes will see the update.
- **Opt in** to the new protections: `with_hidden_signup_conflicts` (signup
  answers `Started` for a taken identifier; read `session.user_id()` after it to
  tell the cases apart, and answer the client the same either way),
  `with_password_reset_cooldown` and `OAuthProviderConfig::with_required_logout_typ`.
- **`with_fapi` returns a working provider** (it returned an error in the first 0.13.0 pass). Against a DPoP provider, refresh with `refresh_oauth_token_with_key(.., Some(&key))` and call userinfo with `fetch_userinfo_with_key`, passing `claims.dpop_key`; the plain forms refuse. For a provider that requires JARM, finish the callback with `finish_oauth_login_jarm(response, &session)`.
- **`JwtVerifier::verify` needs an audience decision.** Add `.with_audience("...")`, or `.allow_any_audience()` where the issuer is yours alone; without either every `verify` fails.
- **Back-channel logout is audited only when you ask.** `BackChannelLogoutHandler::new(..).with_audit(authn.backchannel_logout_audit())`.
- **`AuthSession::user_id` and `tenant_id` are `None` until the login
  completes.** A handler that used them to read the user of a signup or a
  factor step in flight calls `pending_user_id` and `pending_tenant_id`
  instead. A handler that authorizes on them needs no change; it no longer
  sees a half-logged-in user.
- **Devices are recognised by a cookie.** Browsers get a `__Host-axess_device`
  cookie at their first authenticated request after the upgrade, and a new
  `Unknown` device with it; trust earned on a device row of 0.12 or earlier
  has to be earned once more, and the old rows age out in the sweep. The
  cookie needs HTTPS; on plain HTTP in development pass
  `DeviceCookieConfig::insecure_for_local_development()` to
  `LifecycleDeviceResolver::with_cookie`. A `DeviceResolver` of your own is
  unchanged; to issue the cookie, leave its `Set-Cookie` value in the
  `DeviceCookieSlot` the session layer puts in the request extensions.
- **A guest has no device**, so step-up for a login in flight sees `Unknown`
  unless the browser presents a valid device cookie.
- **Sealed rows are re-sealed once.** Every live session and device row is
  rewritten the first time it is read after the upgrade (one extra write
  each). Keep the previous key configured as before.
- **Refresh tokens bind a digest of `device_info`.** Pass the keyed
  fingerprint hex as before; nothing to change. Set `hash_pepper` so the
  digest is keyed.
- **`with_reseal_on_load` is gone from `EncryptedDelegatedCredentialStore`**;
  re-sealing is on, and needs `save_if_unchanged` on the inner store. A
  custom `DelegatedCredentialStore` that wants its rows re-sealed implements
  it with a conditional write; one that does not is left as it is.
- **MySQL**: no schema change. The sweep and the Valkey set are code only.
- **Becoming authenticated clears `custom`.** A cart, a locale or a
  post-login destination stashed before the login is gone after it. List the
  keys that must survive with
  `AuthnServiceBuilder::with_preserved_custom_keys(["post_login_to"])`;
  names match exactly.
- **`AuthSession::clear` rotates the session id.** Code that called `clear`
  and then `regenerate` can drop the second call.
- **`take_custom` can return `None` where it returned a value**, when another
  request took it first or the store cannot be reached. Start the ceremony
  again.
- **A read-only request past half the TTL writes the session once** and
  re-issues the cookie. A deployment that counted session writes sees one per
  half TTL per active session.

## 0.11.0 to 0.12.0

A security release. Compile errors first, then storage, then behaviour.

- **`IdentityLookup` requires `get_tenant(&TenantId) -> Option<Tenant>`**
  (`not all trait items implemented, missing: get_tenant`). Look the tenant
  up by id; a store that wraps another forwards it. Password reset calls it
  before reading the token.
- **`IdentityPasswordReset` requires `check_reset_token`.** It answers
  whether a token is valid for the user without spending it; the in-memory
  backend and the sqlite example show it.
- **`SessionStore` requires `update(id, data, ttl) -> bool`**, which writes
  only a live row and answers `false` for a missing or expired one, and
  **`cycle(old, new, data, ttl, require_old)` returns `CycleOutcome`**: with
  `require_old` set, a missing old row answers `SessionGone` and writes
  nothing. A wrapper forwards both.
- **`RefreshTokenStore::issue_with_eviction` is `issue_capped(new,
  max_per_user)`.** Count the user's active tokens, revoke the oldest past
  the cap and insert, in one transaction or one script.
- **`with_max_sessions_per_user(NonZeroUsize)`**: pass
  `NonZeroUsize::new(n).unwrap()` or a constant. Zero is no longer
  representable.
- **`SweepConfigBuilder::build()` returns a `Result`**; a window that is not
  a whole number of seconds is `SweepConfigError::SubSecondWindow`.
- **`SidMap::insert(key, subject, user, session, at)`,
  `register_subject_session(issuer, subject, user, session)` and
  `take_subject_sessions(issuer, subject) -> Vec<(UserId, SessionId)>`.** Pass
  the IdP `sub`, not the local user id. `take_user_sessions` is gone.
- **`refresh_oauth_token(provider, refresh_token, expected_subject)`**: pass
  the subject the session was signed in as.
- **`ArchiveBatchId::from_ids(ids)`** replaces `from_parts(first, last,
  count)`. Ids now cover every event in the batch, so a batch archived but not
  marked under 0.11.0 is archived once more.
- **Exhaustive matches** add `RefreshError::InvalidConfig` and
  `DelegatedError::UnsupportedTokenType`.

Storage. No `ALTER` is needed in any backend.

- Rows written before row binding (no marker) and device rows written by
  0.11.0 (`AXD\x01`, `AXR\x01`) are refused by default: a session or device
  that was last written by such a release reads as missing, and the user signs
  in again. To keep them readable while they age out, set
  `SessionCrypto::with_legacy_blobs(LegacyBlobs::AcceptUntil(cutoff))` (and the
  same method on `ValkeySessionStore` and `ValkeyDeviceStore`), with a cutoff
  one session lifetime away for sessions and as far as you want to keep old
  devices for devices. Within the window a stale row is re-sealed to its row the
  first time it is read; after the cutoff it is refused. `LegacyBlobs::Accept`
  has no cutoff and is best avoided: an unbound blob opens under any row id.
  Inject the clock the cutoff is checked against with
  `SessionCrypto::with_clock`.
- A Valkey device row read through a legacy blob is also refused when the ids
  inside it differ from the key it was stored under. Session data and SQL
  device bindings carry no ids of their own, so the cutoff is their only
  protection.
- Device blobs use a format (`AXD\x02`, `AXR\x02`) that 0.11.0 cannot open,
  so roll back only with a backup taken before the upgrade.
- Valkey: the device fingerprint index moves from the `dev:fp` string key to
  the `dev:fps` set, one device at a time, on the device's next write. Until
  then the old key is still read. Re-sealing needs `SET ... KEEPTTL` (Redis
  6.0 or Valkey). On a cluster the new keys need the same hash-tag prefix as
  the others.
- MySQL 8: a default account signs in with `caching_sha2_password`, which
  sqlx supports only over TLS or with its `mysql-rsa` feature. Enable one in
  your own `sqlx` dependency (see the backends guide).

Behaviour:

- **A password reset answers `Ok(false)` and keeps the token** when the
  tenant is missing or not active, when the user is unknown (was
  `Err(NoFlow)`), and when the new password is refused.
  `begin_password_reset` refuses a ttl of 0 or over seven days with
  `Err(Internal)`.
- **`require_authz!` with no `RequestContextProvider` evaluates with an empty
  context, as before.** A policy that reads `context` needs a provider in the
  request extensions. A policy guarded with `context has ..` that treats
  absence as allowed stays fail-open; write such guards to deny on absence.
- **A FIDO2 ceremony begun before the upgrade fails** and must be started
  again.
- **Recovery codes with stray symbols no longer match**: normalisation drops
  only whitespace and dashes.
- **Rate limiting**: the window slides, header buckets are capped at 16 per
  user, IPv6 clients share a bucket per /64, and keys over 256 bytes are
  hashed. Limits tuned against the fixed window may admit fewer requests at a
  boundary.
- **Remote response bodies are capped** (token 64 KiB, userinfo 256 KiB, JWKS
  and discovery 1 MiB). A provider answering more fails the call.
- **A non-`Bearer` delegated token is refused**, and a refresh response for
  another subject fails with `OAuthError::IdTokenValidation`.
- **Sweep cutoffs are whole seconds**, so a device can move one second later
  than under 0.11.0.
- **The audit archive takes `.archive.lock` in its root**; two archivers
  sharing a root now wait for each other. The retention loop drains a backlog
  at start instead of waiting a full interval.

## 0.10.0 to 0.11.0

Compile errors first, then schema, then behaviour.

- **`DeviceStore` has four new required methods and every write takes
  `now`.** Implement `set_trust_level_if(tenant, id, expected, new) ->
  TrustTransition` as one conditional write, `replace_bindings(tenant, id,
  expected, new, now) -> BindingsUpdate` as a write of the bindings column
  alone that refuses a `Revoked` row and answers `Conflict` when the stored
  bindings are not `expected`, `claim_owner(tenant, id, user, now) ->
  OwnerClaim` as `UPDATE ... SET user_id = ? WHERE user_id IS NULL`, and
  `find_by_fingerprint_for_user(tenant, user, hash)` over an index on
  `(tenant_id, user_id, fingerprint_hash)`. `save(&Device, now)` gains the
  write time. A store that wraps another forwards all of them and invalidates
  its cache; a caller of `replace_bindings` passes the bindings it read and
  retries on `Conflict`.
- **`Device` has `demoted_at: Option<DateTime<Utc>>`.** Struct literals add
  it (`None` for a device never trusted).
- **`ArchiveSink::archive_batch(&self, batch: &ArchiveBatchId, events)`**, and
  `AuditRetentionSource::EventId` needs `Display`.
- **`AuditLogWithAnalytics::new(inner, sink, enricher)` returns a pair.** Keep
  the first; spawn or run the `AnalyticsWorker`, and call `shutdown` on exit
  so queued events drain. `with_capacity` sizes the queue; `dropped_events`
  counts what a full queue shed.
- **`verify_recovery_code(config, submitted, now, pepper)`.** Pass `None` to
  keep Argon2 rows verifying as before; pass `Some(&pepper)` once you issue
  keyed codes with `generate_recovery_codes_peppered` and configure
  `with_recovery_code_pepper` on the service.
- **`verify_password` returns `PasswordVerifyError`.** Code matching on
  `password_auth::VerifyError` matches `Malformed` or `Mismatch` instead;
  `is_ok` and `is_err` callers compile unchanged. Stored hashes verify as
  before.
- **`AuthnError` and `AuthFailureReason` have new variants** (`Internal`,
  `IpPolicy`); exhaustive matches add arms. `ValkeyDeviceStoreError` adds
  `NotFound`, `Contended` and `UnexpectedScriptReply`; `Contended` means
  eight compare-and-swap attempts lost, so retry.
- **`OAuthProvider` implementors:** `build_auth_url(options, rng)`,
  `build_auth_url_par(options, rng)`, `generate_dpop_proof(.., key_seed, iat,
  jti_bytes)`. Draw the verifier, state and nonce from `rng` as three 32-byte
  base64url values. `begin_grant(provider, scopes, rng)` likewise.
- **`BearerConfig::new(issuers)`** replaces the struct literal; set a clock
  with `with_clock`. `verify_jwt_signature` is gone from the public API; use
  `verify_jwt` with a clock.
- **`SidMap` is a struct.** Code that read the `DashMap` directly uses `get`,
  `insert`, `remove`, `take_user_sessions` and `len`; the service hands it
  out through `AuthnService::sid_map()`.
- **`RateLimitConfig { .. }` literals add `clock`**, or use the builder.
  **`TraceContextLayer`** becomes `TraceContextLayer::new()`.
  **`RefreshTokenConfig::hash_pepper`** is read through `pepper()`.
- **`IdentityPasswordReset::verify_reset_token(&self, user_id, token_hash,
  now)`.** Implementations judge expiry on `now`; the service passes its
  clock. `MockIdentityStore::with_clock` is gone; pass `now` instead.
- **`IdentityAdmin::delete_user`** is required (`not all trait items
  implemented, missing: delete_user`). It must erase every row naming the
  user; the in-memory backend and the sqlite example show the set. The
  panicking default is gone: a backend that cannot erase does not compile.
- **`SocialProvider::exchange_code` returns `ZeroizedString`.** It derefs to
  `str`: pass `&token` where a `&str` is wanted and compare with `&*token`.
- **`AuditRetentionPolicy` has two stages.** Remove `delete_archive_after`,
  `with_delete_archive_after` and `keep_archive_forever` from your code; the
  cold sink owns its own expiry.
- **`MockOAuthProvider` needs the `testing` feature** on axess-factors (or
  core's or the facade's `testing`, which forward it).
- **`JwksCache` key sets expire** (`with_max_age`, 24 h default). Start the
  refresh loop through `AuthnServiceBuilder::with_default_jwks_refresh()` or
  `with_jwks_refresh(interval)`, or expect `OAuthError::JwksExpired` once the
  set ages out; a `JwtVerifier` built on `JwksCache::handle()` bypasses the
  check, so build on `fresh_handle()`.
- **`SessionRegistryHandle::liveness`** is a provided method; override it to
  answer `Gone` (not `Unknown`) for a session the registry knows is ended, or
  subject-registry entries of your sessions are forgotten only on logout.
- **`decide_step_up` is gone.** Call `decide_step_up_for_user(device, user,
  policy)`.
- **`SessionCrypto::encrypt` and `decrypt` are gone.** They sealed with an
  empty AAD, so the ciphertext was not bound to its row. Use
  `encrypt_with_aad(aad, plaintext)` and `decrypt_with_aad(aad, data)` with
  the row's identity as the AAD.

Schema, run once on existing deployments. **Run the `sessions` statement before
the new release serves a request**: the new code selects `data_bin`, and a
table without it makes every load fail and read as an empty session, which
logs everyone out.

- SQLite: `ALTER TABLE sessions ADD COLUMN data_bin BLOB;`. Postgres:
  `ALTER TABLE sessions ADD COLUMN IF NOT EXISTS data_bin BYTEA;`. MySQL:
  `ALTER TABLE sessions ADD COLUMN data_bin LONGBLOB NULL;`. Rows written by
  0.10.0 read as before and move to bytes on their next save; a row the new
  release saved cannot be read by the old one, so a rollback signs that user
  in again.

- SQLite: `ALTER TABLE devices ADD COLUMN demoted_at INTEGER;` then
  `CREATE INDEX IF NOT EXISTS idx_devices_user_fingerprint ON devices
  (tenant_id, user_id, fingerprint_hash, last_seen_at DESC);`.
- Postgres: `ALTER TABLE devices ADD COLUMN IF NOT EXISTS demoted_at BIGINT;`
  and the same `CREATE INDEX IF NOT EXISTS`.
- MySQL: the `ALTER` block in the `device::storage::mysql` module docs
  (`bindings` to `MEDIUMTEXT`, ids and `family_id` to `utf8mb4_bin` with the
  refresh foreign key dropped and re-added around it, `demoted_at`, the
  user-fingerprint index), and `ALTER TABLE sessions MODIFY data MEDIUMTEXT
  NOT NULL;`. The collation changes rebuild primary keys and fail if two
  stored ids differ only in case; resolve those rows first.
- Valkey: nothing to run. Device keys get new TTLs on their next write, rows
  reseal on their next write, `cycle` and the device scripts need scripting
  enabled (the default), and a cluster needs the `{axess}` hash-tag prefix.
- Rows already `Seen` read as never trusted and are revoked by the first
  sweep if idle past `seen_idle` (30 days by default).

Behaviour:

- **Sightings are written at most once per five minutes per device.**
  `last_seen_at` lags use by up to that; `with_sighting_granularity(Duration::zero())`
  restores the old behaviour.
- **Capacity eviction of the sid map no longer ends sessions**, only
  mappings. The TTL prune still ends sessions, at most 128 per login.
- **An IP-denied login writes an audit row** (`AuthFailureReason::IpPolicy`)
  and takes as long as any other refusal.
- **A logout token without `exp` is refused.** A pre-final IdP must send one.
- **The rate limiter answers 429 for a new key at 262,144 live buckets**
  instead of sweeping on every request; raise the window or shard keys if a
  deployment holds more.
- **Signed requests answer 503 when the replay memory is full**
  (`max_remembered`, default 100,000).
- **Argon2 runs on blocking threads.** Under a current-thread test runtime
  install `KdfExecutor::inline()` through `with_kdf_executor`, or the
  verification will hop threads.
- **Password resets apply the tenant's password rules**: `complete_password_reset`
  answers `Ok(false)` for a password that breaks them;
  `axess::validation::meets_password_rules` is the check to run first.
- **Session and device blobs change format**; do not copy a `data` blob
  between rows.
- **CSRF after rotating a session in a handler:** read `CsrfIssuer::token()`;
  `CsrfToken` keeps the pre-rotation value for that request.
- **The analytics wrapper drops events when its queue is full** and counts
  them; before it spawned a task per event without bound.
- **Social login sends no User-Agent on a supplied client without one.**
- **ID tokens over 8 KiB sign in again.**
- **A cookieless request on a route with no CSRF layer and no session use
  gets no Set-Cookie and writes nothing**; a route that mints a CSRF token,
  modifies the session or reads `session_id()` behaves as before.
- **A `sub`-only back-channel logout now ends sid-less logins too**, and a
  mapping dropped at capacity is still ended through `sub`.
- **AWS and GCP STS calls time out after 30 s** (10 s to connect on the
  default client), as Azure's did since this release's first cut;
  `with_timeout` on each client adjusts it.

## 0.9.0 to 0.10.0

The compile errors come first; the behaviour changes after them are the
ones nothing will point you at.

### `not all trait items implemented, missing: insert_factor_if_absent`

`FactorStore` needs one more method. It must be atomic: insert the row if no
row of that kind exists at that scope, and say whether it did.

```rust,ignore
async fn insert_factor_if_absent(
    &self,
    scope: &AuthnScope,
    config: FactorConfig,
) -> Result<bool, Self::Error> {
    let res = sqlx::query(
        "INSERT INTO factor_configs (...) VALUES (...)
         ON CONFLICT(user_id, tenant_id, kind) DO NOTHING",
    )
    // ...binds...
    .execute(&self.pool)
    .await?;
    Ok(res.rows_affected() > 0)
}
```

The library uses the `false` answer as a replay signal for one-time codes:
two parallel first uses of an inherited factor race on this insert, and the
loser is refused. A store that answers `true` twice reopens that replay.

### `missing field authn_time in initializer of RefreshToken`

`RefreshToken` carries `authn_time: Option<DateTime<Utc>>`, the time of the
original sign-in, which rotation copies forward. Add a nullable column, write
it on store and read it back; `None` for rows that predate the column, which
the library reads as `issued_at`. The sqlite example's migration
`20261024000000_refresh_token_authn_time.sql` shows the shape. A store that
does not persist it degrades towards a later `authn_time`, which weakens
"recent login" and step-up checks.

### Logins that are now refused or answered differently

- **`logout` ends only the current session.** Call
  `invalidate_user_sessions` where you meant "everywhere".
- **`begin_login` answers `InvalidCredentials`** for a user with no methods
  and for a suspended or terminated tenant, where it returned `NoFlow` or
  `NotActive`. A suspended user still receives `Locked` or `NotActive`.
- **A timed suspension ends on its own** once its `until` has passed, at
  login, impersonation, password reset, passkey registration and OAuth
  completion. Impersonation and password reset refuse an inactive account;
  the refused reset does not spend its token.
- **Tenant-scoped OAuth login refuses a user resolved into another tenant**
  with `CrossTenant`. It was meant to; it did not.
- **A plain-HTTP `jwks_uri`** outside loopback is refused on fetch and refresh,
  and an error response no longer replaces cached keys.
- **An ID or logout token whose `azp` names another client is refused**, even
  when `aud` lists only yours.
- **Back-channel logout** requires `jti`; a `sub` logs out only users who
  signed in through the sending issuer with a `sid`.

### Devices, passkeys and rate limits

- **A device owned by another user is never reused.** Where your code
  resolves the device before the user is known, call
  `decide_step_up_for_user(&device, &user_id, &policy)`; `decide_step_up`
  remains and ignores ownership. The default device resolver supplies no
  user, so supply one, or the rule cannot apply.
- **`KeyExtractor::Header` keys only within an authenticated identity.**
  Install the rate-limit layer after authentication and set
  `RateLimitUserId`, or key on `UserId`; without an identity the peer
  address is used.
- **`PiiToken::parse`** accepts only `pii:` plus a hyphenated lowercase UUID.
  Re-emit tokens stored in another spelling.

### Identity types

- **`Issuer::custom`** refuses `cli`, `jwt_svid`, `mtls` and `oauth`.
- **`Issuer::Custom` serializes** as `{"kind":"custom","label":"..."}`; it
  failed at runtime before, so no stored data changes.
- **`WorkloadId` and `TrustDomain`** are validated when deserialized, and
  SPIFFE paths reject `.` and `..`. A stored value that was never valid now
  fails to load.

### What is not a break

Sessions, stored factors and refresh tokens from 0.9.0 load unchanged once
the `authn_time` column exists. Nothing needs draining before upgrading.

## 0.8.1 to 0.9.0

Three signatures changed and the MSRV moved to 1.95.0; the rest are
behaviour changes, listed after the compile errors because nothing will
point you at them.

### `mismatched types: expected RotationOutcome, found ()`

`RefreshTokenStore::rotate_token` reports whether it revoked the parent.
Make the revoke conditional on the parent still being live, and store the
child only when it was:

```rust,ignore
let revoked = sqlx::query(
    "UPDATE refresh_tokens SET revoked = 1 WHERE id = ?1 AND revoked = 0",
)
.bind(parent_id.to_string())
.execute(&mut *tx)
.await?
.rows_affected();
if revoked == 0 {
    tx.rollback().await?;
    return Ok(RotationOutcome::ParentAlreadyRevoked);
}
// insert the child, commit
Ok(RotationOutcome::Rotated)
```

`ParentAlreadyRevoked` means a parallel refresh won. The session layer
treats it as a reuse and revokes the family, so an implementation that
always answers `Rotated` reopens the race this release closes.

### `missing field require_exp in initializer of ValidationConfig`

Add `require_exp: true`, or end the literal with
`..ValidationConfig::default()`. Set it to `false` only for an issuer that
genuinely mints tokens without `exp`.

### `unused Result that must be used` on `ValkeyEntityCache::invalidate`

It returns the Valkey error instead of discarding it. Propagate it, or log
it where a failed invalidation is acceptable.

### Tokens and logins that are now refused

- **A JWT with no `exp`**, or with an `exp` or `nbf` that is not an
  integer.
- **A JWT missing `iss` or `aud`** when the verifier pins that claim.
- **An LDAP login with an empty password.**
- **An HOTP or TOTP code configured shorter than six digits.** Re-enroll
  those factors at six or more.
- **An OIDC discovery document** whose `issuer` differs from the URL it was
  fetched from (a trailing slash is ignored), whose `jwks_uri` is plain
  http to a non-loopback host, or that came with an error status.

### Sessions, CSRF and request ids

- **A session bound to a fingerprint and presented without one is
  invalidated.** If a client legitimately loses the inputs your
  fingerprint is built from, it signs in again.
- **CSRF now guards every method except GET, HEAD, OPTIONS and TRACE**,
  so a custom method that skipped the token now needs one.
- **Rate-limit buckets restart once on upgrade**: header-derived keys are
  now prefixed `h:` and peer-address keys `ip:`.
- **An uppercase or otherwise invalid `traceparent` is ignored** and a new
  trace starts, as W3C Trace Context requires.

### Outbound OAuth

`client_secret_basic` now form-encodes the client id and secret before the
Basic encoding, as RFC 6749 §2.3.1 requires. A secret containing `:`, `+`,
`%` or a space is sent differently; a compliant IdP decodes it back.

### What is not a break

Sessions, refresh tokens and stored factors from 0.8 load unchanged.
Nothing needs draining before upgrading.

## 0.7.0 to 0.8.0

A method step that offers a choice, `FactorStep::AnyOf`, used to be
flattened to its first choice at login, so "TOTP or something else" only
ever asked for TOTP. The login state now keeps the steps as they were
declared, and recovery codes arrive as the first factor that needs the
choice. Both breaks below follow from that.

### `mismatched types: expected Vec<FactorStep>, found Vec<FactorKind>`

`AuthState::Authenticating::remaining` and
`AuthSession::authenticating_state` now carry the method's steps rather
than a flat list of kinds. Where you read a kind from them, read
`step.primary()`, which is what the old list held:

```rust,ignore
// 0.7
let next: Option<FactorKind> = remaining.first().cloned();
// 0.8
let next: Option<FactorKind> = remaining.first().map(FactorStep::primary);
```

`FactorRequired` and `prepare_factor` still name that first choice, so a
login page that prompts for TOTP keeps doing so; it may now also offer
the alternatives the step lists. `AuthSessionTestExt::begin_authenticating`
still takes kinds.

Sessions saved mid-login by 0.7 still load: their kinds are read as
required steps. Nothing needs to be drained before upgrading.

### `non-exhaustive patterns: FactorKind::RecoveryCode not covered`

`FactorKind`, `FactorConfig` and `FactorCredential` each gain a variant
(`RecoveryCode`, `RecoveryCodes`, `RecoveryCode`). Add the arm. A factor
store that maps kinds to strings maps the new one to `"recovery_code"`,
which is what `FactorKind::RecoveryCode.as_str()` returns.

### Adopting recovery codes

If you kept recovery codes in your own table, they can move onto the
factor model: store the hashes as `FactorConfig::RecoveryCodes`, offer
them beside the factor they back up with
`FactorStep::AnyOf(vec![FactorKind::Totp, FactorKind::RecoveryCode])`,
and submit `FactorCredential::RecoveryCode` to `verify_factor`. Each code
is spent through the factor store's compare-and-swap, so two logins
racing on the same code cannot both pass. Existing hashes carry over
only if they are PHC strings `verify_password` accepts, taken over the
code as `normalize_recovery_code` renders it (ASCII letters and digits,
upper-cased, separators dropped); otherwise issue a fresh set.

### What is not a break

The `service-secret` feature is new and off by default. Turn it on to
replace a hand-written shared-secret check on an internal route with
`ServiceSecretLayer`, preferably in its signed mode; see
[Shared secrets: the last resort](../workload-identity/shared-secrets.md)
for why it ranks below `jwt` and `mtls`.

## 0.6.0 to 0.7.0

Working out who a request came from was correct only through a path that
cost a policy engine to reach, so the rate limiter did it wrong instead,
the audit context offered a constructor that read a forgeable header, and
the JWT module was filed where it needed an unrelated feature to reach.
Every error below comes from closing that off.

### `no TrustedProxies in authz`

`TrustedProxies`, `CidrParseError`, `ip_from_headers_trusted` and
`ip_from_headers_untrusted` moved from `axess::authz` to
`axess::client_ip`, which is not feature-gated.

```rust,ignore
// Before
use axess::authz::{TrustedProxies, ip_from_headers_trusted};

// After
use axess::client_ip::TrustedProxies;   // the walk is TrustedProxies::client_ip
```

They were behind the `authz` feature, which pulls `cedar-policy`. An
adopter who wanted a correct client address and no policy engine could
not have one.

### `no variant ForwardedIp for KeyExtractor`

Resolve the address once, in a layer, and key on the result:

```rust,ignore
// Before: the limiter read X-Real-IP, then the leftmost X-Forwarded-For.
let config = RateLimitConfig::builder()
    .key(KeyExtractor::ForwardedIp)
    .build();

// After: the layer resolves, the limiter reads the answer.
let app = axess::client_ip::layer(app, trusted);

let config = RateLimitConfig::builder()
    .key(KeyExtractor::ClientIp)
    .build();
```

**Read this one even if it compiles after a rename.** Both headers the
old extractor read are caller-writable, and nothing upstream is obliged
to overwrite them: a proxy that appends to `X-Forwarded-For` leaves the
caller's entry in front of the real one, and no proxy sets `X-Real-IP`
unless configured to. A caller rotating either got a fresh bucket per
request. If your deployment relied on `ForwardedIp` behind a proxy,
assume the limit was not enforced against a caller who cared to avoid
it, and check what your proxy actually does to both headers.

Put the layer outside everything that reads an address, and serve the
router with `into_make_service_with_connect_info::<SocketAddr>()`.
Without the peer there is nothing to check a header against, and every
request resolves to no address and shares one bucket.

`ClientIp` is what every consumer now reads, and none of them takes an
address from the caller any more. Its fields are private; only the layer
and the explicit `ClientIp::resolved` fill one, so a handler cannot build
one out of a header by accident.

### `no method begin_login on AuthnService`

The methods that write an audit event moved to `RequestAuthnService`, which
`with_audit_context` returns. There is no other way to make one.

```rust,ignore
// Before: the stamp was optional, and reaching back to the shared
// service for the second call wrote that row with no address.
state.authn.begin_login(&identifier, tenant, &session, client_ip).await?;

// After
let svc = state.authn.with_audit_context(audit);
svc.begin_login(&identifier, tenant, &session).await?;
svc.verify_factor(&credential, &session).await?;
```

Keep the `AuthnService` in application state and derive a `RequestAuthnService`
per request. It derefs to the service, so `check_session`, the revocation
methods and the capability predicates are reachable through the one
handle; only the authenticating methods require the context.

**`begin_login` lost its `client_ip` argument**, and with it a hole. The
tenant IP policy was enforced only `if let Some(ip) = client_ip`, so a
caller passing `None` skipped it: an allowlist that a caller could switch
off by omitting an argument. 51 of the 52 call sites in this repository
omitted it. The address now comes from the handle, and a tenant policy
that restricts anything refuses a request whose address did not resolve,
because a policy that cannot be evaluated has not been satisfied. If you
have tenants with an `IpPolicy`, install `client_ip::layer` before
upgrading or their logins will fail closed.

### `request_id` goes `None` if you never ran the layer

Nothing fails to compile here. In 0.6.0 `AuditContext::request_id` was
filled straight from the `X-Request-Id` header, ungated, while the
middleware that mints request ids sat behind the `request-id` feature.
The two were unconnected, so a deployment that had never enabled the
feature still recorded whatever a caller put in that header.

If you run `RequestIdLayer` under `request-id`, nothing changes: the
value was the layer's id before and is the layer's id now, read from a
typed extension instead of a header the layer had just written.

If you do not, `request_id` is `None` from here on instead of a
caller-supplied string. That is a column going quiet, not a control
weakening: an unvalidated header value was never evidence of anything.
Turn the feature on and install the layer if you want the column back.

```toml
axess = { version = "0.13", features = ["request-id"] }
```

`accept-client-id` honours an id minted upstream rather than generating
one, validating the inbound value before it reaches the context.
`middleware::request_id::RequestId` is public, so a deployment whose
generator uses a custom `HEADER_NAME` can read the typed value directly.

`trace_id` is new and behaves the same way under `trace-id`, with no
prior value to lose.

### `no variant MissingAuditContext` / `no AuditContextPolicy`

Both are gone, along with `with_audit_context_policy` and the
`audit_context_missing` metric. Delete the builder call; there is nothing
to replace it with, because the thing it checked at runtime is now
checked by the compiler.

`Required` only ever tested whether a route attached a context, never how
much that context held, so it never meant "no authentication without
evidence". A route that forgot the wiring is now a type error. A route
that wired a context while the client-IP layer was missing is the case
the policy could not see either way, and the `ip_source = 'unknown'`
query in *Audit events* is what finds it.

### `no function extract_audit_context`

All four builders are gone: `extract_audit_context`, `..._async`,
`..._untrusted`, `..._async_untrusted`. The context is an extractor.

```rust,ignore
// Before
let ip = ip_from_headers_trusted(&headers, peer, &trusted);
let ctx = extract_audit_context(&headers, Some(ip), Some(&session));
let service = state.authn.with_audit_context(ctx);

// After: the handler asks for it.
async fn login_route(session: AuthSession, audit: AuditContext) {
    let service = state.authn.with_audit_context(audit);
}
```

It reads the address `client_ip::layer` resolved, plus the user-agent,
request id and session id from the request. Install the layer or every
context carries no address, which is honest and is not evidence.

Two of the four read `X-Real-IP` directly and believed it. If your code
called either `_untrusted` form, the addresses in your audit rows were
chosen by the subject of the audit for as long as it did, and they are
not evidence of where anything came from.

### `no function ip_from_headers_trusted`

The walk belongs to the set that decides it:

```rust,ignore
// Before
let ip = ip_from_headers_trusted(&headers, peer, &trusted);

// After
let ip = trusted.client_ip(&headers, Some(peer));
```

`Option<IpAddr>` now, because a unix-domain socket has no peer for an
address set to match. The old `client_ip_layer` is `client_ip::layer`, and
`ip_from_headers_untrusted` is gone with no replacement: walking from the
right is correct wherever reading the leftmost entry was, and correct in
the cases where it was not.

### `could not find jwt in federation`

```rust,ignore
// Before
use axess::federation::jwt::svid::JwtSvidResolver;

// After
use axess::jwt::svid::JwtSvidResolver;
```

The module is gated on `jwt` now rather than `oauth`. If you enabled
`oauth` only to reach it, you can drop that feature.

## 0.5.0 to 0.6.0

`v0.6.0` is the largest break so far. One change is a cargo feature,
five are compile errors in adopter code, and four change behaviour
without any compiler help. The behaviour changes are the ones to read
closely: each was a security defect, and each is fixed by doing
something the old version did not do.

### The build fails before anything else

If you enable `jwt`, `oauth`, `oidc`, `fapi`, `bearer`, `jwt-svid`,
`local-idp` or `workload-id`, the build now stops with:

```text
axess-factors: the `jwt` feature needs a crypto backend. Enable
`jwt-aws-lc` (...) or `jwt-rust-crypto` (...)
```

Add exactly one. `jwt-aws-lc` is FIPS-capable and needs a C toolchain
(and NASM on Windows); `jwt-rust-crypto` is pure Rust and builds
anywhere. Enabling both is allowed, because cargo may switch the second
on when another crate in your build asks for it.

Until 0.5.1 `axess-factors` pinned aws-lc-rs itself, which chose for
adopters who had already chosen the other; with both switched on,
`jsonwebtoken` cannot pick and panics on first verification. If you sign
tokens yourself, call `axess_factors::jwt::ensure_crypto_provider`
before `jsonwebtoken::encode`.

### Compile errors you will see

**`IdentityAuthnLog::record_event` returns `AuditOutcome`.** Replace
`Ok(())` with `Ok(AuditOutcome::Recorded)`:

```rust,ignore
async fn record_event(&self, event: AuthEvent) -> Result<AuditOutcome, Self::Error> {
    // ... unchanged write ...
    Ok(AuditOutcome::Recorded)
}
```

Return `AuditOutcome::Shed` to drop an event deliberately under load. The
flow continues and `AuthnMetrics::audit_event_shed` fires, where an `Err`
fails the login. This is the valve for a hazard the fail-closed audit
creates: every failed login writes a row, including for identifiers that
do not exist, so an unauthenticated caller can drive writes at your
storage without bound.

**Shed on a criterion independent of the identifier**: a global rate, a
queue depth, a disk watermark. Shedding on anything derived from *which*
identifier was tried makes the drop observable per-identifier and
reintroduces the user-enumeration oracle that emitting unattributed events
exists to close.

`MockIdentityStore::arm_record_event_shedding` exercises the path in your
own tests, beside the existing `arm_record_event_failure`.

**`AuthnService` construction moved to a builder.** The service is now a
cheap handle over one `Arc`, so it can carry per-request state; the
collaborators are shared the moment it is built, and customising an
already-shared service is therefore not possible.

```rust,ignore
let service = AuthnService::builder(identity, factors)   // was: ::new(..)
    .with_clock(clock)
    .with_registry(registry)
    .build();                                            // <- new
```

`AuthnService::new(identity, factors)` with no customisation is unchanged.
`from_backend(b)` is unchanged; chain from `builder_from_backend(b)`.

**Client metadata now reaches audit events, if you wire it.** Before this
release nothing in axess attached an `AuditContext` to the events it
emitted, so every row carried a null IP:

```rust,ignore
let ip = ip_from_headers_trusted(&headers, peer.ip(), &trusted);
let ctx = extract_audit_context(&headers, Some(ip), Some(&session));
let service = state.service.with_audit_context(ctx);
service.begin_login(&identifier, tenant, &session, None).await?;
service.verify_factor(&credential, &session).await?;
```

`with_audit_context` returns a copy of the handle; the collaborators are
shared, so this costs a refcount bump per request. Route *every* call in
the request through that copy, not just the first: the stamp is on the
handle, so falling back to `state.service` for `verify_factor` writes the
failed-password row with no address on it. The `sqlite` example derives
one in each of its four audited handlers.

If your audit trail is compliance evidence, build with
`.with_audit_context_policy(AuditContextPolicy::Required)` so a route that
forgets the wiring fails loudly instead of recording blanks.
**That is a fail-closed path**: it turns a missing context into a failed
login, so wire every route before turning it on.

> Removed in 0.7.0. The wiring it checked at runtime is checked by the
> compiler now; see *0.6.0 to 0.7.0* above.

**Two password-history methods are no longer on `IdentityAdmin`.**
`record_password_hash` and `password_history` moved to a new
`IdentityPasswordHistory` trait with no default bodies:

```rust,ignore
impl IdentityPasswordHistory for YourBackend {
    async fn record_password_hash(/* ... */) { /* unchanged body */ }
    async fn password_history(/* ... */) { /* unchanged body */ }
}
```

Both had defaults that panicked, and `record_password_hash` is called on
every password change with no guard, so a backend that had not overridden
it unwound the first time any user changed their password. The method
looked optional, because a defaulted trait method does.

If you have no password-reuse policy, implement nothing. The password
change and reset flows are bounded on this trait, so they become
unavailable at compile time rather than panicking at runtime.

Note that `IdentityAdmin::delete_user` still has a panicking default in
0.10.0 (0.11.0 removes it). It is not called by any axess flow: you reach it
only by calling it yourself, but override it before you rely on it for GDPR
erasure.

**Two password-reset methods are no longer on `IdentityAdmin`.**
`store_reset_token` and `verify_reset_token` moved to a new
`IdentityPasswordReset` trait with no default bodies. Move the two
`impl`s into their own block:

```rust,ignore
impl IdentityPasswordReset for YourBackend {
    async fn store_reset_token(/* ... */) { /* unchanged body */ }
    async fn verify_reset_token(/* ... */) { /* unchanged body */ }
}
```

They defaulted to `unimplemented!()`, so a backend that never
implemented them compiled and then panicked on an open route. If you do
not use password reset, implement nothing: the reset flow is bounded on
the new trait, so it is no longer reachable.

**`extract_audit_context` takes the client IP.** Resolve it against the
peer your server accepted rather than letting the function read
headers:

```rust,ignore
let ip = ip_from_headers_trusted(&headers, peer, &trusted);
let ctx = extract_audit_context(&headers, Some(ip));   // was: (&headers)
```

Passing `None` is honest where you cannot establish the address. The old
behaviour is still available as `extract_audit_context_untrusted`, whose
name now carries the warning.

**`ip_from_headers` is `ip_from_headers_untrusted`**, in both the
`authn` and `authz` modules. The behaviour is unchanged and remains
correct behind a proxy you control. Rename, or switch to
`ip_from_headers_trusted`, which is the one to prefer.

**`OAuthError` has a new variant.** `AuditStore(String)` is returned
when the audit store rejects the event recording an OAuth outcome. The
enum is not `#[non_exhaustive]`, so an exhaustive `match` over it now
fails with `E0004`. It classifies as transient under
`OAuthError::is_transient`.

**`AuthEvent::error` is an `AuthFailureReason`.** It was
`Option<String>`, and `AuthEventBuilder::with_error` took
`impl Into<String>`. This is the field a SOC dashboard groups by, so it is
the same defect `AuthEventBuilder::locked` was introduced to fix for the
outcome: querying meant matching a string, and a string nothing enforced.

```rust,ignore
use axess::authn::AuthFailureReason;

AuthEventBuilder::failure(AuthEventType::LoginAttempt)
    .with_error(AuthFailureReason::UnknownTenant)   // was: .with_error("unknown_tenant")
```

The setter deliberately does *not* take `impl Into<_>`: that would keep
string literals compiling, and a typo would land in `Other` silently,
which is the thing being removed. Where no tag fits, name
`AuthFailureReason::Other` explicitly.

Reading the field, compare against the variant rather than a string:

```rust,ignore
assert_eq!(event.error, Some(AuthFailureReason::CsrfMismatch));
```

**The wire form does not change.** Serde still emits the plain tag string,
and a text column still stores it, so stored rows and JSON are unaffected.
Converting a stored string back is infallible: an unrecognised tag
becomes `Other` rather than an error, so rows from another version are
never dropped:

```rust,ignore
let error = error.map(AuthFailureReason::from);
```

**One stored value does change.** The impersonation refusal was written as
`"cross-tenant impersonation refused"` and is now the tag
`cross_tenant_impersonation`. A dashboard matching the old prose needs
updating; rows written before the upgrade keep the old text and will read
back as `Other`.

**`AuthEvent::ip_address` is an `IpAddr`.** It was `Option<String>`, and
`AuthEventBuilder::with_ip` took `impl Into<String>`, so the field that
this release spent its security budget making trustworthy would still
accept `"not-an-ip"`, or an address the caller invented. `AuditContext`
was already typed; the builder discarded the type with `ip.to_string()`.

```rust,ignore
let ip = ip_from_headers_trusted(&headers, peer, &trusted);
let event = AuthEventBuilder::failure(AuthEventType::LoginAttempt)
    .with_ip(ip)                         // was: .with_ip(ip.to_string())
    .build();
```

Reading the field, the borrow you used to take becomes a plain copy, and a
sink writing to a text column stringifies at the point of the write:

```rust,ignore
let ip_address = event.ip_address.map(|ip| ip.to_string());
```

**Reading rows written before 0.6.0 needs a decision.** That column holds
whatever string the old writer supplied, including values a client forged,
and some will not parse. Prefer warning and storing `None` over dropping
the row: the address is optional metadata rather than identity, and a null
address is honest where an invented one is not. The `sqlite` example does
this, beside the same handling for `factor_kind`.

Note that `cargo-semver-checks` does **not** flag a public struct field
changing type: there is no lint for it, so this break is invisible to
the tool and is documented here and in the changelog instead.

**`ShortString::prefix` is gone.** It was documented as powering an
equality fast path that `PartialEq` never used. Delete the call; there
is nothing to replace it with.

### Behaviour changes with no compile error

**A login now fails if its audit record cannot be written.**
`IdentityAuthnLog::record_event` returning an error used to be logged
and discarded, and the login proceeded unrecorded. It now surfaces as
`AuthnError::Store`, and on OAuth paths as `OAuthError::AuditStore`.

This trades availability for evidence: **logins fail while your audit
store does.** Put the sink behind something durable: write locally and
ship asynchronously, rather than a remote service on the request path.
`AuthnMetrics::audit_store_outage` fires here and should page.

Related, and the reason the above is safe: rejected logins now emit an
audit row even when there is no user to attribute them to, tagged
`unknown_tenant` or `unknown_identifier`. Without that, an attacker who
could degrade your audit store would see `Err` for registered
identifiers and an ordinary rejection for everything else.

**Lockout fails closed when its counter store is unavailable.**
`record_failed_attempt` is a write, so a primary-database outage in a
read-replica deployment used to leave logins working and the lockout
counter dead: brute force unbounded exactly when monitoring was
degraded. `LockoutPolicy::on_counter_unavailable` now defaults to
`CounterUnavailable::Lock`.

During such an outage a user who mistypes is told they are locked and
retries after `duration`. Set `CounterUnavailable::Allow` for the old
behaviour. Note that `Lock` with `duration: None` means a persistently
broken counter store needs an administrator per account. Alert on
`AuthnMetrics::factor_counter_store_outage` either way.

**`ip_from_headers_trusted` returns a different address.** It took the
leftmost `X-Forwarded-For` entry, but that header is append-only: a
client sends its own value and the proxy appends the real address after
it, so the leftmost entry was whatever the attacker chose. It now walks
from the right, skipping hops that are themselves trusted proxies, and
returns the first address that is not. A malformed entry stops the walk
and yields the peer; `X-Real-IP` is read only when `X-Forwarded-For` is
absent. **The value changes on any deployment where a client can
prepend**, which is the point.

If exact proxy addresses were impractical for you, `TrustedProxies`
now accepts CIDR ranges through `from_cidrs` and `with_cidrs`.

### Audit rows you already store

**A lockout is recorded as `AuthEventStatus::Locked`.** It was
`Failure` with `error = "locked"`, so the outcome lived in a free-text
field while the `Locked` variant was unreachable. A dashboard matching
`status = 'failure' AND error = 'locked'` will stop matching: filter on
the status column instead. **Rows written before the upgrade keep the
old encoding**, so a query spanning the boundary needs both. Other
non-active states are unchanged, still `Failure` with
`error = "not_active"`.

If you built SIEM queries or dashboards from the audit chapters before
0.6.0, re-check them regardless: those chapters described a model axess
does not implement, and were rewritten in this release.

## 0.4.0 to 0.5.0

`v0.5.0` has three adopter-facing changes, each to a single struct
field. Two are type changes from `String` to `ZeroizedString`, for the
same reason: the field held a secret in a `Debug`-deriving public type,
so printing the value printed the secret.
`SocialProviderConfig::client_secret` reaches adopters of the `social`
feature; `ClientCredentialsToken::access_token` reaches adopters of
`oauth` who call `OAuthProvider::client_credentials`. The third is a
visibility change: `axess_events::KeyId` stops exposing its inner
`ShortString`.

### Compile errors you will see

Building a `SocialProviderConfig` from a `String` no longer compiles:
`expected 'ZeroizedString', found 'String'` (E0308), at the struct
literal. Wrap the secret:

```rust,ignore
use axess::authn::ZeroizedString;
use axess::social::SocialProviderConfig;

SocialProviderConfig {
    client_secret: ZeroizedString::new(secret),   // was: secret.into()
    // ...
}
```

`ZeroizedString::new` takes `impl Into<String>`, so a `&str`, an owned
`String`, or a generic `impl Into<String>` parameter all wrap directly;
`From<String>` and `From<&str>` mean `.into()` works too, where the
target type is unambiguous. A helper that accepts `impl Into<String>`
and passes it through to this field keeps its own signature, because the
wrap happens at the field; the helper's callers need no change.

The rationale is that `SocialProviderConfig` derives `Debug` and its
documentation invites loading it from a TOML/YAML/JSON config file, so
an adopter logging their own configuration printed the OAuth client
secret verbatim. `ZeroizedString` prints as `ZeroizedString(***)` and
zeroes its bytes on drop, which is what `TotpConfig::secret`,
`HotpConfig::secret` and the outbound OAuth client already did; `social`
was the only place in the crate that did not.

### `ClientCredentialsToken::access_token`

This one is a value axess returns, not one you construct, so most code
needs no change: `&token.access_token` still derefs to `&str` and passes
to anything taking `&str`, including an `Authorization` header value.
Two shapes do need an edit. Code that binds the field as an owned string
(`let bearer: String = token.access_token`) becomes
`token.access_token.to_string()`. Code that builds the struct itself,
which in practice means a test double standing in for a token endpoint,
wraps the value: `access_token: ZeroizedString::new("test-token")`.

Serialization is deliberately unchanged. Unlike `OAuthClaims`, which
marks its token `#[serde(skip_serializing)]`, a client-credentials
response *is* a token, so an adopter caching one must still be able to
serialize it; `ZeroizedString` is transparent to serde in both
directions. What changed is `Debug`: the field now prints as
`ZeroizedString(***)`, which is the disclosure this release closes.

### `KeyId`'s inner field

`axess_events::KeyId` no longer exposes its `ShortString`. A struct
literal or a destructuring pattern stops compiling:

```rust,ignore
let id = KeyId(ShortString::new("kms-2026-01"));   // was
let id = KeyId::new("kms-2026-01");                // now
let id = KeyId::from_static("kms-2026-01");        // const, no allocation

let raw = id.0;            // was
let raw = id.as_str();     // now
```

All three constructors and the accessor existed before this release; only
the field's visibility changed, matching `KindTag`, which had always kept
its own field private. If you do need to name `ShortString` (the
`From<ShortString> for KindTag` impl is the reason you might), `axess-events`
now re-exports it, so `use axess_events::ShortString` replaces a direct
`axess-strings` dependency.

### What is not a break

Config files are unaffected. `ZeroizedString` is a newtype over `String`
deriving `Serialize`/`Deserialize`, which serde treats transparently, so
a bare string in a config file still deserializes into the field.

Most *read* sites keep compiling. `ZeroizedString` derefs to `str`, so
`&config.client_secret`, `config.client_secret.len()` and anything
taking `&str` work unchanged. Only a site that needs an owned `String`
has to say so, with `config.client_secret.to_string()`.

## 0.2.2 to 0.3.0

`v0.3.0` upgrades the `jsonwebtoken` dependency from 10 to 11 and
raises the workspace MSRV. Two adopter-facing changes. (There is no
`0.2.1 to 0.2.2` entry: 0.2.2 was a transitive-dependency security
patch with no public-API change: see *What does not migrate*.)

### Compile errors you will see

An exhaustive `match` on a `jsonwebtoken::Algorithm` obtained from
axess no longer compiles: `non-exhaustive patterns: '_' not
covered`. `jsonwebtoken` 11 marks `Algorithm` `#[non_exhaustive]`,
and axess re-exposes that type through its public surface:
`ALLOWED_ALGORITHMS`, `JwtVerifier::with_algorithms`, and the
local-IdP `algorithm` / `verifier_algorithms` helpers. Add a
wildcard arm to any such match:

```rust,ignore
match alg {
    Algorithm::RS256 => ...,
    Algorithm::ES256 => ...,
    _ => ...,            // required by jsonwebtoken 11
}
```

The rationale is upstream's: `#[non_exhaustive]` lets `jsonwebtoken`
add algorithms in a future minor without that being a breaking
change for them, which moves the "handle the unknown" obligation
onto callers. For a verifier the safe default is to fail closed:
treat the `_` arm as "unsupported algorithm, reject".

### Toolchain

The workspace MSRV is now **1.93.1** (up from 1.87). The library
itself builds on 1.88 (`jsonwebtoken` 11 raised that) but the
declared floor is set to the workspace-wide requirement so the full
build-and-test suite runs on one toolchain. Bump your toolchain to
1.93.1 or later.

### What is not a break

The new `EventSubjectRef` and `EventPayload::subject_ref()` are
purely additive: `subject_ref()` defaults to `None`, so existing
`EventPayload` implementations need no change. The inter-crate
version pins moving to exact `=0.3.0` are internal to the axess
workspace; adopters depend on the `axess` facade with their own
version requirement and are unaffected.

## 0.2.0 to 0.2.1

`v0.2.1` is a patch release. The only behavioural change is a
CSRF hardening: the double-submit token now binds to the session
id (`HMAC(signing_key, nonce || session_id)`) rather than to the
signing key alone, and `CsrfLayer` fails closed with 403 when the
session-id extension is missing on a state-changing request. Two
adopter-facing consequences:

Adopters MUST layer `CsrfLayer` inside (i.e. run after) the
session layer so the `SessionHandle` request extension is present
by the time CSRF validation runs. In `axum`, later `.layer(...)`
calls wrap earlier ones, so `.layer(csrf).layer(session_layer)`
is the correct order. Stacks that had the layers in the opposite
order silently validated an unbound token before 0.2.1; that shape
now returns 403.

Clients that cache the CSRF token across a session change (login,
session regeneration) MUST re-read the token after the change or
their first post-change state-changing request will 403. Tokens
minted under one session id no longer verify against another.

## 0.1.x to 0.2.0

The first crates.io publish is the 0.2.0 release. The accumulated
changes since the previous stable line are catalogued
exhaustively in
[`CHANGELOG.md`](https://github.com/GnomesOfZurich/axess/blob/main/CHANGELOG.md);
this chapter covers the breaking ones an adopter has to act on.

### Compile errors you will see

`use axess::PolicyStore` becomes `use axess::AuthzStore`. The
authorisation entry point was renamed for consistency with the
`Authz*` prefix convention. The new name better describes what
the type is (an immutable store of policies plus schema, not
just a policy collection).

`use axess::AxessSession` becomes `use axess::AuthSession`. The
session extractor was renamed; the new prefix is the shared
`Auth*` prefix from the naming conventions (*Architecture at a
glance*).

`use axess::backends::SqliteStore` becomes
`use axess::backends::sqlite::SessionStore`. The backend module
layout was reorganised so the same trait name (`SessionStore`)
appears under each backend's namespace; the previous flat
`SqliteStore` symbol no longer exists.

`AuthnService::new(backend)` becomes
`AuthnService::new(identity_store, factor_store)`. The service
now takes the two stores separately so adopters can wire
different implementations (for instance, a read-replica
identity store and a write-only factor store). When the two
stores are the same type (the common case), pass it twice.

The signing key is a constructor argument, not a builder call:
`SessionLayer::new(store, signing_key)`, taking `[u8; 32]`. Rotation
is the one related builder, `with_previous_signing_key`, which keeps
the outgoing key valid for verification while the new one signs.

`AuthState::Logged` becomes `AuthState::Authenticated`. The
state was renamed for clarity; nothing else changed about the
variant.

### Configuration changes

The `axess_factors_default_password_hasher` config function is
gone. Argon2id is now the default; deployments that need a
different hasher (PBKDF2, legacy bcrypt) implement a custom
factor and register it. *Factors and methods* covers the
extension pattern.

There is no audit-pipeline config type to migrate. Axess awaits one
call, `IdentityAuthnLog::record_event`, and the implementation behind
it is yours; a deployment that had wired sinks into a config struct
wires them inside that implementation instead. *Audit pipeline* covers
the seam.

The `RateLimitConfig` no longer accepts a `key_fn` field
directly; use `KeyExtractor::Custom(Arc<dyn KeyExtractorFn>)`
to provide a custom extractor, or use one of the built-in
variants (`PeerIp`, `SessionId`, `UserId`, `TenantId`,
`WorkloadId`, `Composite`). The change is to make the common
cases discoverable without losing the escape hatch.

### Behaviour changes

The `Authenticating` state now carries a `Vec<FactorKind>` for
`remaining` rather than the previous `Option<FactorKind>`. The
change is what enables multi-factor methods longer than two
factors. Code that pattern-matched on `Some(kind)` needs to
adapt to `remaining.first()` or to iterate over the list.

`LockoutPolicy` is per-user and has no other scale. It is three
fields (`max_attempts`, `duration`, `attempt_window`) with no
per-tenant or per-IP variant to configure or to turn off. Throttling a
source IP is the rate limiter's job, where the answer is a 429 rather
than a locked account; see *Rate limiting*, and note
`KeyExtractor::LoginIdentifier` for the per-account half of that
defence.

The session cookie's `SameSite` attribute now defaults to `Lax`
rather than `Strict`. The change is to match modern browser
defaults and to admit cross-site link-to-app navigations as
legitimate. Deployments that need `Strict` configure it
explicitly.

Session binding is off unless you ask for it. Nothing is bound until
the layer is built `.with_binding(UserAgentBinding)`, and a mismatch
then resets the session to `Guest`. There is no policy to set and no
quieter setting to start from (*Cookies, fingerprinting, hijack
detection* covers the limits of what the binding catches).

### Schema migrations

The `users` table gained a `tenant_status` field for the
tenant-suspension support. The migration is a single ALTER TABLE
that adds the column with a default value. The
[`examples/sqlite/migrations/`](https://github.com/GnomesOfZurich/axess/tree/main/examples/sqlite/migrations)
shows the SQL.

The `devices` table gained a `fingerprint_hash` field and lost
the previous `fingerprint_raw` field. The migration is destructive:
the `fingerprint_raw` field carried PII that the new design
hashes before storage (*Device identity* covers the rationale).
Adopters who want to preserve the audit trail of past fingerprints
write the migration accordingly; adopters who do not, just
drop the column.

The `authn_attempts` table gained an `event_kind` enum field
that distinguishes between attempt outcomes, rather than relying
on a separate `outcome` string. The migration is non-destructive;
the `outcome` field stays for backward compatibility and is
populated from `event_kind` automatically.

The session-data schema version bumped from 1 to 2. The new
version adds a `device_id` field on `Authenticated` (for the
device-binding work covered in *Device identity*). The
schema-migration code (*Schema migration*) handles existing
sessions transparently; no manual data migration is needed.

### Workspace structure changes

The `axess-delegated` crate folded back into `axess-core`. The
adopter import paths stay the same (`axess::delegated::*`
continues to work through facade re-export); the
`Cargo.toml` no longer needs an explicit `axess-delegated`
dependency, just the `delegated` feature on `axess`. The
workspace dropped from 11 to 10 library crates.

### Recommended migration sequence

For deployments running on the 0.1.x line:

The first step is to read this chapter end-to-end. Make a
checklist of every change that applies to your code.

The second step is a parallel-deploy approach. Stand up a 0.2.0
build alongside the production 0.1.x; route a small fraction of
traffic to it; observe behaviour. The session cookies between
the two versions are not compatible (the schema-migration
mechanism handles cookie reads but not writes across major
versions), so the parallel deploy needs to be on isolated
session storage.

The third step is the cutover. Once the 0.2.0 build has been
green for at least the session TTL on the production-like
sample, route 100% of traffic to it. The 0.1.x build can be
decommissioned after a roll-back window has passed without
incident.

The roll-back path: if 0.2.0 surfaces problems, route traffic
back to 0.1.x; the sessions that started under 0.2.0 will be
invalid against 0.1.x and will land as `Guest`, prompting
re-login. The user-visible impact is one re-login; the
behavioural impact is bounded.

## Future migrations

The pattern from 0.2.0 to 0.2.1 is the pattern future migrations
will follow. Each migration documents itself here, sorted by
release. The pattern:

Symptom: what the compiler or the runtime will tell you.

Rationale: why the change happened. Most changes happen because
the previous shape was wrong in a specific way (a footgun, a
performance bug, a security gap, an inconsistency with the rest
of the library). The rationale gives the explanation; the next
section gives the action.

Action: what to update in adopter code. The action is the
shortest possible change that satisfies the new shape; longer
restructurings are flagged as optional improvements.

A typical migration entry runs five to ten lines for a
small change, a few paragraphs for a larger one. The chapter
grows additively; older migrations are not removed.

## What does not migrate

Some adopter changes do not produce a migration entry. The
patterns:

Behaviour that was bug-fixed. A previous version's incorrect
behaviour might have been load-bearing for an adopter who built
around it; the fix is still the right thing to do, and the
adopter has to adapt. The fix appears in the changelog as a
bug fix; if the bug-fix is large enough to warrant a migration
entry, it lands here, but not all of them do.

Internal refactors that do not change the public API. The
internal split between `axess-core` modules is free to
reorganise without producing a migration entry, as long as the
public re-exports stay stable.

Configuration defaults that change but are configurable. A
default that flipped is a behaviour change, captured above. A
default that is configurable in both directions and the
configuration is the source of truth does not produce a
migration entry; the adopter's existing configuration continues
to apply.

## Further reading

*Schema migration* covers the per-session schema migration
mechanism that handles session-data shape changes. The
[`CHANGELOG.md`](https://github.com/GnomesOfZurich/axess/blob/main/CHANGELOG.md)
covers the exhaustive list of changes per release; this chapter
is the curated migration subset. *Security posture* covers the
security-relevant breaking changes specifically, with the
disclosure protocol for security fixes.
