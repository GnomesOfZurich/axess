# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [0.19.0] - 2026-11-09

### Security

- A refresh token issued from a session carries the session's authentication time, so redeeming it no longer turns an old login into a fresh one for `max_authenticated_age`, `max_lifetime` and every recency gate, and a session past the family's lifetime gets no token (`issue_refresh_token_from_login`).
- `login_with_password` answers the guess that locks an account, and a request racing into a lock, as a wrong password, so the password form no longer shows which accounts exist.
- The per-key guess throttle keeps building while the lockout counter store is down.
- A cancelled refusal in the OAuth login settles on a task of its own, so the sessions it owed an end to are ended and the displaced `sid` mapping is restored or its session ended.
- A cancelled back-channel logout no longer leaves its `jti` in flight: the pair is forgotten when the request is dropped while the replay log is taking its outcome.
- A taken signup identifier rotates the session id as a free one does, so the session cookie no longer shows whether an account exists.
- `with_lockout_revealed_on_begin` shows a lockout only, not an administrative suspension or its end.
- The family-compromise handler `cascade_revoke_by_refresh_family_and_tokens` revokes every refresh token bound to the compromised family's devices; `cascade_revoke_by_refresh_family` says it revokes the devices only.
- The refresh device check reads through `CachedDeviceStore` (`DeviceStore::load_fresh`), so a device revoked on another instance stops the next refresh and not the one after the cache expires.
- An administrator cannot impersonate themselves, a failed impersonation ends the administrator's anchor entry, and `with_impersonation_max_authn_age` makes `begin_impersonation` require a recent administrator authentication.
- Invalidating a resource in the Valkey authz cache takes each index member out as it reads it (`SPOP`), so an entry another pod stores meanwhile is no longer left cached and unindexed until its TTL.
- `require_authz!` resource ids with two or more placeholders refuse a value that holds a character the template uses as a separator, and a template that puts two placeholders next to each other (`{$tenant}{id}`) fails to compile and is refused by `build_uids`, so distinct (tenant, id) pairs can no longer render to one resource id.
- A stale Valkey revocation-subscriber dispatcher or reconnector no longer drops, quits or wakes the watchers of a newer connection: each acts for its own connection generation only, and closing a connection also stops its dispatcher.
- The login throttle keys an IPv6 client address on its /64 prefix (an IPv4-mapped address as its IPv4 address), so rotating addresses inside one /64 no longer starts a fresh throttle key for every guess.
- The login throttle refuses a guess when its delay or retry time is too large to represent (a `max_delay` of `Duration::MAX`) instead of letting it run, and a zero `first_delay` stays no delay however many failures accumulate; the `Retry-After` header saturates instead of wrapping to zero.
- The Valkey session registry orders `active_sessions` by registration time, kept in a second sorted set that use never moves, so `max_sessions_per_user` evicts the oldest session and not the one least recently used.
- A cookie name's `__Host-` and `__Secure-` prefixes are matched without regard to case, as browsers do, in `SessionConfig` and in `CsrfConfig`, so `__HOST-sid` or `__HOST-csrf` with `secure(false)` is refused when the config is built.
- Registering a passkey claims its credential id through the new `FactorStore::claim_fido2_credential` (released by `release_fido2_credential`), so two accounts racing for one id have one winner; a store of your own implements both methods for the guarantee, since the defaults only check the holder.
- A screened egress client no longer follows `HTTP_PROXY`, `HTTPS_PROXY` or `ALL_PROXY` from the environment, because a proxy resolves the target's name itself and the connect-time address screen never saw it.
- The SSRF screen judges an IPv6 address that carries an IPv4 address (NAT64, the locally used NAT64 prefix, 6to4, IPv4-compatible) as the IPv4 address it carries, and refuses the IPv4 special-purpose ranges `192.0.0.0/24`, `198.18.0.0/15`, `240.0.0.0/4` and the three documentation ranges (named `private`), so `https://[64:ff9b::a9fe:a9fe]/` no longer reaches a metadata address.
- `DiscoveryDocument::fetch` and `Discovery::fetch` apply `EgressPolicy::screened()` to the issuer URL and to every URL the document names, `jwks_uri` included, and `Discovery::fetch_screened` takes the policy; the opt-out for an identity provider on the deployment's own network is `EgressPolicy::unscreened()`, passed by name.
- A signed service request accepted once is refused as a replay under every scheme, because the replay cache keys the request (caller, stamp, method, target, body) rather than the tag, so a dual-signed header can no longer be replayed under the older scheme.
- `JwtVerifier::with_typ` and `verify_jwt_with_typ` require the JOSE `typ` header of a token (case-insensitive, a leading `application/` dropped), so a key that signs ID tokens, access tokens, logout tokens and DPoP proofs no longer lets one pass for another; the header type is still not read unless it is asked for.
- `StoredTenantOAuthProviders::upsert` refuses an issuer and client id another tenant or the global registration (`with_global_registration`) already holds, so one tenant can no longer make another's back-channel logout ambiguous and refused.
- `begin_grant` refuses an authorization endpoint that is not HTTPS (HTTP to a loopback host stays allowed) with `DelegatedError::Transport`, so the client id, PKCE challenge and `state` are not sent in clear to a remote IdP.
- `SocialProvider::new` refuses a `redirect_uri` that is plain HTTP to a remote host, and `exchange_code` refuses a token response whose `token_type` is not `Bearer` or is missing, so the authorization code is not returned over cleartext and a token bound to another scheme is not sent as a bearer token.
- An Azure STS error carries the provider's `error`, `error_description` and `correlation_id` (and a non-JSON body) with control characters escaped and the text cut to 512 bytes (128 for the code and the id), so a response cannot forge a log line.
- `refresh_providers_jwks` reports a provider whose JWKS refresh panicked in its failures, under the provider's name, where it used to drop it and let an empty result stand for success.
- `LocalIdp::mint` and `mint_with_header` refuse an expired token and one whose `nbf` is after its `exp` after `without_max_ttl()` too, with `IssuanceError::InvalidLifetime`; removing the cap removes only the upper bound on the lifetime.
- A forwarded entry written as `ip:port`, `[v6]:port` or `[v6]` is read as its address, so a proxy that appends the peer's port no longer ends the `X-Forwarded-For` walk at the proxy's own address, and a trusted proxy whose chain cannot be read is logged as a warning on the `axess::client_ip` target (without the entry).
- `verify_dpop_proof` refuses a proof key that is not an EC P-256 key with 32-byte `x` and `y` before building a key from it, naming the member (`kty`, `crv`, `x`, `y`), and builds the thumbprint with `serde_json` from the decoded coordinates, so one key has one thumbprint however its JWK is spelled.
- `SocialProvider::accept_missing_token_type()` is the named opt-in for a provider whose token response omits `token_type`: the missing value is read as `Bearer`, and a present one that is not `Bearer` is still refused.
- `Issuer::Custom` holds a `CustomLabel`, a newtype with a private field that only `Issuer::custom` builds, so a custom issuer can no longer carry the label of a built-in one (`"oauth"`) or a label the format check refuses; a `compile_fail` doctest pins it.
- The OAuth example refuses a callback whose `{provider}` path is not the provider the login began with, before any code is redeemed, so per-provider redirect URIs give the mix-up protection they are registered for.
- The FAPI example creates a local user only for an identity whose IdP verified the e-mail address, and `is_local_issuer` parses the issuer like an HTTP client, so a backslash can no longer make a remote host look local.
- The minimal example registers the `default` tenant its login names (every login was refused for want of it), and spends one Argon2id check before every early refusal of a login, so an unknown username is no faster to refuse than a known one.
- The OAuth example takes the stored refresh token out of the session before the IdP is called, so two refreshes that arrive together present it once and the IdP does not revoke the token family on reuse.
- Every workflow action is pinned to a commit SHA, every checkout drops its credential, every `cargo install` names a version with `--locked`, and CI images are pinned by digest; `scripts/check-workflow-pins.sh` enforces all four in the release preflight.
- The release packages the crates and the SBOM from one locked tree in a job with no secrets, attests them in a job that builds nothing, audits the lockfile again before upload, and publishes only those byte-identical files with `cargo publish --locked`.
- `scripts/install-mdbook.sh` checks the mdBook and mdbook-mermaid archives against pinned SHA-256 digests with `sha256sum -c` before extracting them.
- `axess-core`, `axess-factors`, `axess-rng` and `axess-clock` refuse to compile in a release build (debug assertions off) with the `testing` feature on, unless the build names `allow-testing-in-release`.
- `scripts/supply-chain.sh` runs `cargo audit`, `cargo deny` with advisories on, unsafe and unused-dependency reports, a duplicate-crypto-crate check and a guard that no published crate or example links `testing`, `memory`, wiremock or tracing-subscriber in a release tree; the release preflight runs it, and `deny.toml` refuses a third version of `p256`, `rsa` or `crypto-bigint`.
- `wiremock` and the `rsa` crate behind the test fixtures can no longer enter a production dependency graph through a feature flag: the fixtures moved out of `axess-core` into `axess-testing`.

### Changed (breaking)

- `axess_core::testing::mock_tracing`, `axess_core::TracingCapture`, `axess_core::testing::oauth_wiremock` and the `testing-oauth` feature are removed; use the `axess-testing` crate as a dev-dependency, and `axess_core::testing::oauth_provider` for `oauth_discover_provider` and `oauth_setup_provider`, which take the provider's address.

### Added

- `axess_core::profile`: `SecurityProfile::Strict` and `Standard` name one readable, overridable value for each setting a high-assurance deployment tightens, from session lifetimes to the Argon2id cost, and apply each to its configuration type; nothing changes until it is applied.
- `MockIdentityStore::arm_account_status_failure` and `MockFactorStore::arm_concurrent_write_on_lost_swap` in `axess_core::testing`.
- `allow-testing-in-release` on `axess`, `axess-core`, `axess-factors`, `axess-rng` and `axess-clock`: the named opt-out for the release-build guard on `testing`.
- A `Hardening` workflow runs the supply-chain script, ten fuzz targets against the real decoders, Miri over the crates that contain `unsafe`, and a compile-fail test that `axess::testing` is absent without its feature.
- `AuthnServiceBuilder::with_argon2_cost` (with `Argon2Cost`, `hash_password_with_salt_and_cost` and `password_needs_rehash_for` in `axess-factors`), `with_password_reset_ttl`, `with_max_password_reset_ttl`, `begin_password_reset_with_default_ttl` and `with_impersonation_max_authn_age`, each defaulting to the behaviour the library already had.
- `DeviceCookieConfig::max_age`, `CachedDeviceStore::ttl` and `JwtVerifier::clock_skew` read back the value their setters write.
- `axess-testing`, a dev-dependency crate that holds the tracing capture, the OIDC wiremock fixture, tables of extreme durations and IPv6 address forms, and a gate for cancellation tests (`stall`).
- `scripts/check-test-crate-edges.sh` and `deny-production.toml` fail when `axess-testing` or `wiremock` is reachable from a normal or build edge.
- `scripts/check-clock-usage.sh` fails on a new wall-clock read outside `axess-clock`.
- `scripts/check-rsa-sites.sh` fails on a new `rsa` call site outside the reviewed local IdP primitives.
- Design pages for the remaining dependency tasks: RSA verify-only, one JOSE verification core, one RustCrypto major, one stored-data format, and regex replaced by hand-written validators.

### Fixed

- A password reset works in a tenant whose timed suspension has run out.
- A discoverable passkey login that fails at a gate clears its ceremony state from the session.
- An email code retry after a lost swap keeps a concurrent change to the row and refuses a row whose address or limits changed, instead of writing a stale copy over it.
- An extreme signup verification TTL, unknown-issuer memory or refresh-token TTL clamps instead of panicking.
- `begin_login` is documented as identifier-first: it tells a caller whether an account exists, and `login_with_password` is the form that does not.
- `spawn_cleanup_task` of the SQLite, Postgres and MySQL session stores refuses a zero interval by name when it is called, instead of ending the task silently on its first tick.
- `InMemoryBackend::with_user_password` no longer overwrites a user of the same tenant whose id a fallback id coincides with.
- The sqlite example gives each sensitive form its own rate-limit bucket instead of one shared by clones of a single limiter, sends a login that needs a further factor to that factor's page instead of the dashboard, and escapes every message it renders into a page.
- The tag workflow created no tag after a merge into `main` (its existence test read an absent tag as present), and the mutation summary's self-test printed its refusal lines as error annotations on a passing step.

### Changed

- The minimal, sqlite, OAuth and FAPI examples set their own session limits to 15 minutes idle and 10 hours in all through named constants; the library defaults are unchanged.
- `axess-core` asks tokio for `macros`, `rt`, `sync` and `time` instead of `full` and `rt-multi-thread`.
- `axess-core` takes `sqlx` without default features (`runtime-tokio` and `derive` only).
- `chrono` is taken without default features across the workspace; `clock` stays on through `axess-clock`, and a lint rejects a new wall-clock read outside it.
- `axess-core` takes `fred` without `transactions`, `replicas` and `i-cluster`.
- The dev-dependency `reqwest` of `axess-core` uses rustls instead of the default TLS stack, so `native-tls` and `openssl-sys` leave the lockfile.
- The publishing runbook enables auto-merge for the release pull request and describes the tag ruleset as immutability only, with the organisation-app route to restricted creation.
- The per-change mutation sweep runs on pull requests into `release/next` and `release/X.Y.x`, where a change arrives on its own, and no longer on the release pull request into `main`, which carries the whole release the weekly sweep covers.

## [0.18.0] - 2026-11-07

### Changed (breaking)

- `PolicyStore::digest()` returns a `String` and `PolicyStore::schema()` a `Schema`, because both follow a policy reload, and `PolicyEvaluator::schema` returns `Option<Schema>` by value for the same reason; `original_digest()` and `original_schema()` borrow the text the object was built from.
- `webauthn-rs` moves from the `=0.6.0-dev` pre-release pin to the 0.6.2 release (`^0.6.2`): `CredentialID`, re-exported from `axess_factors::fido2`, is now `Vec<u8>` instead of `HumanBinaryData`, `webauthn_rs::prelude` no longer exports `Base64UrlSafeData`, and a FIDO2 assertion or registration whose binary fields use the standard base64 alphabet is refused (URL-safe base64, padded or not, is what parses).
- `DelegatedCredentialStore::save_if_unchanged` has no default, so a custom store has to answer the compare-and-swap question: implement it atomically, or return `CredentialSwap::Unsupported` explicitly (a refresh then falls back to the unconditional save and logs a warning naming the store type once).
- `SidMap::insert`, `insert_displacing` and `register_subject_session` take the tenant of the login as an `Option<TenantId>` (`None` for a global provider's login) and the tenant-less forms are gone, so a record can no longer be made that a tenant provider's logout silently never finds; the login path passes the tenant of a tenant provider and `None` for a global one.
- `JwtSvidResolver` refuses every token at `resolve` unless it has a tenant lookup (`with_tenant_lookup`) or the named waiver `without_tenant_cross_check()`, so a token whose `tid` claim and SPIFFE tenant slug cannot be cross-checked no longer resolves to a principal whose slug and id may name two tenants.
- `IdentityPasswordReset::store_reset_token(user_id, token_hash, expires_at, now, max_live)` returns whether it stored the token: a store keeps up to `max_live` live reset tokens per user, `verify_reset_token` and `check_reset_token` match any of them, and a successful `verify_reset_token` deletes all of them.
- `IdentityAdmin::delete_candidates_created_before(before, limit)` is a required method, behind `purge_expired_candidates`.
- `TenantOAuthProviders::built_providers` is a required method (no default), so a registry says which providers the JWKS refresh covers.
- `OidcError::EgressRefused { setting, range }` is a new variant: an egress refusal names the setting and the reason, never the URL or an address.
- `DeviceResolver::resolve` returns `Option<BoundDevice>`; the per-account lockout exempts only a `ProvenDevice` (`AuthSession::proven_device`, `SessionData::device_proven`), which only `resolve_proven` yields.
- `SocialClaims` has an `email_verified: bool` field with no default, so a claim mapper states whether the provider verified `email`; link accounts by email only when it is `true`.
- `Fido2Provider::start_registration` and `start_authentication` take the `Fido2Ceremony` to run, `start_authentication` takes `&[Fido2Key]`, the ceremony state is `Fido2Registration` / `Fido2Authentication`, `finish_registration` returns a `Fido2Key`, and `Fido2Credential::passkey` is `Fido2Credential::key`, so a credential keeps the type of the ceremony that registered it (a passkey row is still stored in the shape 0.17 reads).
- `Fido2Options` gains `registration_ceremony` and `login_ceremony` (both `DEFAULT_FIDO2_CEREMONY`, the passkey ceremony), and a FIDO2 login offers only the credentials its ceremony accepts.
- `AuthState::Authenticating` and `AuthState::Authenticated` gain `assurance` and `StandardRequestContext` gains `assurance`; a session stored before this release carries none and satisfies no policy that reads `context.assurance`.
- `require_authz!` answers `{"error": "step_up_required", "step_up": "<name>"}` instead of `Access denied` when a step-up a policy's `@step_up` annotation names would permit the request, and a policy set whose annotation names no step-up is refused at build and reload.

### Added

- `axess_events::envelope_aad_v2`, `envelope_aad_for` and `EnvelopeFields` bind status, actor, time, envelope version, trace context, algorithm and key id into the AAD of an encrypted event under a new tag, `open_aads_for` lists the AADs to open an event with (the new tag, then the first), and `envelope_aad` is deprecated for sealing and kept for opening events sealed before.
- `SidStore` (`SidMap` in process, `ValkeySidStore` behind `valkey`), `AuthnServiceBuilder::with_sid_store`, `AuthnService::sid_store` and the logout handlers' `with_sid_store` let a back-channel logout end a session that another instance logged in.
- `LogoutReplayLog` (`ValkeyReplayLog` behind `valkey`, `BackChannelLogoutHandler::with_replay_log`) shares the `jti` replay log between instances, and `SessionMetrics::back_channel_logout_unmatched` (`BackChannelLogoutHandler::with_metrics`) counts a verified token that found no session.
- `LogoutTokenClaims::tenant` and `DisplacedSid::tenant` hold the tenant of a login; `SidMap::get_in` and `subject_sessions_in` read the map scoped to a tenant.
- A session records what each factor proved at login and every step-up (`FactorAssurance`: kind, time from the injected clock, user verification, attestation trust anchor, synced or device-bound; `AuthSession::assurance`), and `AssuranceContext`, `AssuranceContextProvider`, `ASSURANCE_SCHEMA_FRAGMENT` and `merge_assurance_schema` expose it to Cedar as `context.assurance`, so "a user-verified, device-bound passkey from the last five minutes" is one policy.
- `AuthzRefusal`, `AuthzSession::require_with_step_up` and `PolicyEvaluator::step_up_for` tell a denial from a shortfall a step-up would cure, naming the step-up (`StepUp`) and nothing of the policy, and `RequestAuthnService::begin_step_up_for` begins it with the FIDO2 ceremony it names.
- `Fido2Ceremony` chooses the typed WebAuthn ceremony per operation (passkey, security key with UV preferred or discouraged, attested passkey against a named `AttestationCaList`), with `begin_fido2_registration_with`, `DefaultFido2Provider::with_trust_anchor` and `with_presence_only_security_keys`, and an attested login records its trust anchor only while the credential's attestation still verifies against it.

### Fixed

- A policy reload now reaches `require_authz!` gates: `reload_policies` points the `PolicyStore` the `AuthzStore` was built with at the new set, so the gate that holds the same `Arc<PolicyStore>` decides on it with no change to the wiring (`PolicyEvaluator` gains the defaulted `adopt`).
- `require_authz!` answers 500 with a named error log when the policies read `context` and no `Arc<dyn RequestContextProvider>` extension is installed, instead of deciding on an empty context.
- A policy reload is bounded in time: a follower's `PolicySource` read, each reload hook or cache invalidation and the announce stop at `ReloadTimeouts` (30, 30 and 10 seconds, `AuthzStore::with_reload_timeouts`), so a stalled step no longer holds the reload lock; a source that cannot be read, times out or panics counts on the refused counter, a panic ends only that read, and `ReloadFollower::is_finished` reports a dead follower.
- A follower no longer goes back to an older bundle: a `PolicySource` that overrides the new defaulted `load_versioned` returns a `VersionedBundle` with a generation, and the follower refuses a generation below the highest it applied and counts the refusal; a local `reload_policies` on a following instance lasts until its next read of the source, as the reload page now says.
- The scheduled upstream watch, which never matched because it parsed `cargo search` output that the runner prints in colour, now reads crates.io's API (`scripts/watch-webauthn-argon2.sh`), fails on a failed or empty answer, and watches `webauthn-rs` leaving `argon2` 0.5 through `crypto-glue`.
- `EncryptedDelegatedCredentialStore` implements `save_if_unchanged` over the sealed rows (atomic exactly when the inner store's is), so a revoke from another process while a refresh is in flight is not overwritten on the store production uses; a store without the compare-and-swap keeps the unconditional save and logs a warning naming its type once.
- The back-channel logout route remembers an issuer the tenant source has no provider for for 30 seconds (`BackChannelLogoutHandler::with_unknown_issuer_memory`, zero turns it off; a provider added through `LiveTenantOAuthProviders` or `StoredTenantOAuthProviders` is found at once, because a remembered miss is trusted only while the new `TenantOAuthProviders::generation` is unchanged), so an anonymous loop of tokens naming made-up issuers costs one source read per interval and not one per request; the handler and rate-limiting docs name `RateLimitLayer` for the route and say what it bounds.
- A back-channel logout token ends only the sessions of the tenant whose provider verified it, so two tenants on one issuer no longer end each other's sessions of the same subject, and a token verified by a global provider stays unscoped.
- A refresh in flight no longer brings back a delegated credential the user just revoked: `StoredDelegationSession::revoke` takes the refresh lock, so it runs after a refresh in flight, and the refreshed credential is written with `save_if_unchanged` against the row the refresh started from, so a deleted or replaced row is not overwritten (a store without compare-and-swap keeps the plain save, ordered by the lock within one process).
- An impersonation ends when the administrator who began it is suspended, deleted or has their sessions ended: `begin_impersonation` registers an entry for the administrator (`Impersonation::registry_anchor`) that the session layer reads on every request, and `end_impersonation` removes it.
- Tenant provider URLs are screened: `StoredTenantOAuthProviders` refuses an issuer, and every endpoint its discovery document names, that is not HTTPS or that is in a loopback, private, link-local, unique-local, shared-address or metadata range, and refuses a connection to a host name that resolves into one; `EgressPolicy::screened()` is the default, `unscreened()` the named opt-out and `screened_allowing_loopback_http()` the test opt-in (`with_egress_policy`, `OAuthProviderConfig::discover_screened`).
- An unverified `Candidate` account holds its identifier for `DEFAULT_CANDIDATE_TTL` (24 hours, `with_candidate_ttl`): the next `begin_signup` for it deletes the row and starts afresh.
- A factor that passes no longer clears the guess throttle; it is cleared when the whole login completes, so wrong guesses at a second factor keep their delay.
- A new password reset request no longer invalidates a live link: an account holds up to `DEFAULT_MAX_LIVE_RESET_TOKENS` (3, `with_max_live_reset_tokens`) live tokens, a request beyond that is refused as throttled and audited `live_tokens_full`, and using any one token consumes them all; a flood of made-up identifiers no longer fills the per-instance cooldown record and refuses a real user's reset, since a full record drops its oldest cooldown, so a refusal falls only on an identifier that is itself cooling down.
- `purge_expired_candidates(limit)` deletes the expired `Candidate` accounts nobody asked for again, one `AccountDeleted` audit row each.
- The JWKS refresh loop and `refresh_all_jwks` include the tenant providers a tenant registry holds built (`TenantOAuthProviders::built_providers`) and refresh up to `JWKS_REFRESH_CONCURRENCY` providers at once.
- A user holds at most `DEFAULT_MAX_UNKNOWN_DEVICES_PER_USER` `Unknown` devices (`with_max_unknown_devices_per_user`); the least recently seen are deleted when a cookieless login would create another.
- `BearerError::UntrustedIssuer` carries the unverified issuer cut to `MAX_ISSUER_ECHO_BYTES` with control characters escaped.
- `DeviceLifecycleService::ensure_device` says that a fingerprint is not proof of a device; the lockout exemption reads only a device `resolve_proven` yielded.
- A handler that changes who a session is (an administrator assuming a user) no longer has the session layer end it as "revoked while its id rotated": the new id was registered for the new user, as a login does.
- The weekly mutation sweep finishes and cannot pass blind: it runs as round-robin shards sized from the measured per-mutant cost, with each mutant's build and tests time-bounded, and fails by name when a shard is missing, cancelled, unfinished or short, where every scheduled run since 2026-06-07 had been cancelled at the 6 h job limit and passed with a warning.
- `cargo mutants -f <file>` mutates only that file: `.cargo/mutants.toml` no longer lists `examine_globs`, which cargo-mutants widened with the command-line `--file` instead of narrowing to it.
- Every GitHub Action the workflows use runs on Node 24, which GitHub now forces in place of the deprecated Node 20: `actions/checkout` v7, `upload-artifact` v7, `download-artifact` v8, `upload-pages-artifact` v5, `deploy-pages` v5, `configure-pages` v6, `attest-build-provenance` v4 and `softprops/action-gh-release` v3, with `Swatinem/rust-cache` v2 already there.
- Comments, docs and CI messages that pointed at ROADMAP entries or tracking keys that do not exist now say where the thing lives: the macro tests in `axess/tests/macro_tests.rs`, the `#[non_exhaustive]` policy in CONTRIBUTING.md and `scripts/mutants.sh`.
- The mutants that survived in `axess-cache` and `client_ip` are caught: `ClockTtlCache::invalidate_entries_by` and `client_ip::layer` are tested, every `Source` name is pinned through `as_str`, `Display` and serde, a single-flight test that hung when the counters read zero fails in 10 s instead, and the no-op `count > 0` guards around the invalidation counters, which made `>` and `>=` indistinguishable, are gone.

### Changed

- A release is published from its `v*` tag, which the tag workflow creates when a release pull request merges into `main` (by hand on a patch line): the release workflow refuses a tag that is not on `main` or a `release/X.Y.x` branch or that disagrees with the workspace version or its dated changelog section, and publishes to crates.io only after the maintainer approves the deployment.
- Pull requests target `release/next`, and `main` changes only by a release pull request, which runs every release preflight step as a required CI check ([publishing runbook](docs/project/publishing.md)).
- After a release from `main`, the release workflow levels `release/next` with `main` (moved to the released commit when nothing newer is on it, `main` merged into it otherwise, a conflict reported by name), so the branch is never deleted or recut by hand.

### Dependencies

- `cedar-policy` 4.14.0 -> 4.14.1 in `axess`, `axess-core`, `axess-macros` and the authz example: entity parse and schema-conformance errors are reported in a fixed order, and `Entities::add_entities` applies only the last of several entries with one uid (validating all of them); no call axess makes changes behaviour.
- `openidconnect` 4.0.1 -> 4.1.0 in `axess-core` and `axess-factors`: it moves to p256 / p384 0.14, ed25519-dalek 3 and base64 0.22, and changes nothing in ID token validation, discovery, redirects or secret comparison.
- `base64` 0.22.1 -> 0.23.1 in the workspace, the fuzz crate and every example, with default features off and `std` on so the `simd-unsafe` engines (0.23's only `unsafe` code) stay out of what axess asks for; the examples' `thiserror` requirement reads 2.0.21 like the workspace's.

## [0.17.0] - 2026-11-06

### Changed (breaking)

- `AuthnMetrics` is replaced by one trait per concern (`AuthFlowMetrics`, `FactorMetrics`, `SessionMetrics`, `RotationMetrics`, `ProviderRegistryMetrics`, `RequestGuardMetrics`, `AuthzCacheMetrics`, `AuditMetrics`), each with no-op defaults, so an adopter implements the concerns it exports and a counter added to one never touches another's implementors; `with_metrics` on `AuthnServiceBuilder`, `SessionLayer`, `RateLimitLayer` and `CsrfLayer` takes a `MetricSinks` (`MetricSinks::all(exporter)` wires one exporter to every concern), and `EntityCache::flush_metrics` takes an `AuthzCacheMetrics`.
- `AuthnService::oauth_providers()` returns an `Arc<OAuthProviderRegistry>` snapshot instead of a reference, and `OAuthProviderRegistry::provider_names()` returns owned names, because the registry is swapped whole when a provider is reloaded.
- A duplicate OAuth provider name panics a debug build at `AuthnServiceBuilder::build` instead of at the repeated `with_oauth_provider` call, after it is reported to `ProviderRegistryMetrics`.

### Added

- Counters for what was only a log line: `RequestGuardMetrics::csrf_rejected` (with a closed `CsrfRefusal` reason, also for the session layer's WebSocket Origin refusal), `ProviderRegistryMetrics::provider_duplicate_registration`, `RotationMetrics::encryption_key_fallback` and `fingerprint_key_fallback`, `SessionMetrics::session_fingerprint_backfilled` and `sid_map_evicted`.
- `SessionCrypto::with_metrics` reports each blob that opened only under the previous encryption key.
- `testing::RecordingMetrics` records every metric call of every concern for assertions.
- The observability page (`docs/production/observability.md`) holds the census of counters and counter-shaped log lines, the metric-versus-event rule, the naming scheme (`axess_<what>_total`) and the label rules; the sqlite example's `/metrics` lists the new names.
- `AuthzStore::reload_policies(policy_text, schema_json)` replaces the Cedar policy set of a running store: the text is parsed and validated in strict mode and the entity provider is checked against the new schema before an atomic swap, a refusal leaves the previous set in force and names the step, and it returns `Reloaded { digest, cache_invalidated, announced }`; `policy_digest()` names the set in force and `with_cache_invalidator` drops the registered caches after every swap.
- `axess::authz::reload` carries the cross-instance side: `ReloadCoordinator` (`InProcessCoordinator`, and `ValkeyReloadCoordinator` behind `valkey` on `{prefix}:authz-policy-reloaded`, or any name through `start_named`), `PolicySource` and `AuthzStore::follow_reloads(source, poll_every)`, which re-reads the source on a notice and on a poll and never applies anything a notice says.
- `PolicyEvaluator::digest()` (defaulted), `PolicyStore::digest()` and `policy_set_digest`; `AuthzCacheMetrics::authz_policy_reloaded` and `authz_policy_reload_refused` (no-op defaults, reported through `AuthzStore::with_metrics(MetricSinks)`, exported as `axess_authz_policy_reloads_total` and `axess_authz_policy_reload_refusals_total`); a reload is an `axess::authz::reload` tracing event with the digest.
- `AuthnService::reload_oauth_provider`, `remove_oauth_provider`, `reload_tenant_oauth_provider`, `remove_tenant_oauth_provider`, `reload_fido2` and `reload_ldap` swap a provider of a running service only after its candidate built and checked (OAuth discovery and issuer check, FIDO2 relying-party parse, LDAP reachability through the new `LdapProvider::check_reachable`) within `with_provider_validation_timeout` (default 30 seconds); a refusal is a named `ProviderReloadError` and the previous provider keeps serving, and a login begun before an OAuth swap finishes only if the issuer is unchanged.
- `LiveTenantOAuthProviders` (with `AuthnServiceBuilder::with_live_tenant_oauth_providers`) is a tenant provider registry keyed by `(tenant, name)`, so one tenant's reload never touches another's.
- `with_provider_coordinator` and `AuthnService::follow_provider_reloads(source, poll_every)` carry a provider change to every instance over a coordinator of its own: the follower asks a `ProviderSource` for `ProviderEntry { key, revision }`, builds only what moved, and applies nothing a notice says.
- The reload coordinator types are in `axess::reload` (still re-exported from `axess::authz::reload`), `ValkeyReloadCoordinator::start_named` takes the channel name, and `ProviderRegistryMetrics` gains `provider_reloaded`, `provider_removed` and `provider_reload_refused` with a closed `ProviderCategory` (`axess_provider_reloads_total`, `axess_provider_removals_total`, `axess_provider_reload_refusals_total`).
- The background JWKS refresh loop (`with_jwks_refresh`, `spawn_jwks_refresh`) reads the live provider registry at every pass, so a reloaded provider's key set is the one refreshed and a removed provider is no longer polled.
- `AuthnService::remove_fido2` and `remove_ldap` take the FIDO2 or LDAP provider out of a running service (counted, announced, `NotFound` when none is attached), and the provider follower removes a FIDO2 or LDAP provider it installed when its source stops listing it.
- `Fido2Provider::relying_party_id()` (required) lets a FIDO2 reload see the relying-party id, which a passkey is bound to: `reload_fido2` refuses a changed id as `ProviderReloadError::RpIdChanged`, `reload_fido2_with(candidate, ReloadFido2::allow_rp_id_change())` and `BuiltProvider::Fido2AllowingRpIdChange` acknowledge it, and an acknowledged change is counted by `ProviderRegistryMetrics::fido2_rp_id_changed` and logged with both ids; `DefaultFido2Provider::new` reads the id from the `Webauthn` it wraps and `MockFido2Provider::with_relying_party_id` sets it.
- `ProviderFollower::reads(ReadCause)` counts how often the follower read its source for each cause (`Start`, `Notice`, `Lagged`, `Poll`).
- New direct dependency `arc-swap` (already in the tree through `fred`) holds the policy swap slot, so the request path reads it without a lock; nothing changes for an adopter that never calls `reload_policies`.

## [0.16.0] - 2026-11-06

### Changed (breaking)

- `SessionLayer::new(store, key, registry)` takes the session registry, so a revocation ends the session on every route; `without_registry_insecure(store, key)` is the opt-out and logs an error once; `with_registry` is gone; `MemorySessionRegistry::handle()` gives the handle the layer takes.
- `SessionConfig::default()` ends a session 7 days after it authenticated and an impersonation after 1 hour; `with_max_session_age(None)` and `with_max_impersonation_age(None)` lift the caps, and the setters take `Option<Duration>`.
- `RefreshTokenConfig::default()` ends a family 90 days after login (`with_max_lifetime(None)` lifts it); `device_info` with no `hash_pepper` is `InvalidConfig` unless `allow_unkeyed_hashes()`; `previous_hash_pepper` is a `PreviousPepper`, whose `Unkeyed` moves a deployment to a pepper without invalidating a token.
- `SessionCrypto::new`, `SessionLayer::new`, `without_registry_insecure` and `FactorSecretCipher::new` panic on a constant key, and `with_previous_key` on a constant or the current key; `try_new` returns the error; `new_unchecked` and `testing::test_key(seed)` serve tests under `testing`.
- A service with no `FactorSecretCipher` refuses to store a TOTP or HOTP secret (`FactorSecretError::PlaintextNotAllowed`) unless `allow_plaintext_factor_secrets()`; `StoredTenantOAuthProviders::new` takes the cipher, `new_unencrypted` is for tests.
- `JwtVerifier::verify` and `verify_jwt` refuse a token with no issuer and no audience pinned; `allow_any_issuer()` and `allow_any_audience()` state the intent.
- `AuthzStore::try_new` validates the entity provider against the schema at startup (`new` is `new_unvalidated`); `AuthzEntityProvider::entities_for_tenant` is required; `axess::authz::require` takes a `Context`, and `require_authz!` warns once when the policies read a context no provider supplies.
- `require_authz!` always takes `validator = ..`; the three-argument form is removed.
- A new `AuthnServiceBuilder` holds a 60 second password-reset cooldown and refuses the last five passwords; `without_password_reset_cooldown()` and `history_count: 0` opt out.
- `LockoutPolicy::throttle` slows consecutive wrong guesses down per account and client address (1 s doubling to 64 s, answered as `FactorOutcome::Throttled { retry_after }` / `AuthnError::Throttled`, 429 with `Retry-After`) before the per-account lock; `IdentityAuthnLog` requires `throttle_state`, `record_throttle_failure` and `clear_throttle`; `without_throttle()` is the opt-out.
- `AuthSession::set_authenticated` is crate-private (tests use `testing::AuthSessionTestExt`); `refresh_session`, `refresh_session_in_tenant`, `refresh_session_with_device_check`, `refresh_session_with_status_check` and `refresh_session_with_status_check_in_tenant` are removed in favour of `Refresh::new(token, tenant, status_check)`.
- `Refresh::new` takes the tenant (`Refresh::any_tenant` opts out; `in_tenant` is gone); `WorkloadResolver` and `MtlsResolver` take a slug-to-tenant lookup, derive the tenant from the verified identity and build the `WorkloadId` from their own trust domain.
- `active_sessions` returns an error when the registry cannot list sessions, and the concurrent-session cap refuses a login on that outage.
- `SessionStore::find_sessions_for_user` is required; the SQL and Valkey stores answer `Unsupported`.
- `SessionRegistryHandle::liveness` is required; `SessionRegistryAdapter` is unchanged.
- `RefreshTokenStore::revoke_device_tokens` has no default body; a store implements it or answers `Unsupported`.
- `FactorSecretCipher::with_first_binding` defaults to `Reject`; secrets sealed in the 0.14.0 binding open only under `Accept` or `AcceptUntil`.
- `factors_completed` carries a time per factor (`Vec<(FactorKind, DateTime<Utc>)>` in `AuthState`, epoch microseconds in `AuthEvent`), so a step-up no longer re-times the original login; rows written as a plain list still load.
- `AuthState::user_id` is `pending_user_id`; `authenticated_user_id` answers only for `Authenticated`.
- Rate limiters answer 500 when the identity extension or peer address they key on is missing; `allow_shared_bucket()` restores the shared bucket.
- `begin_signup` answers `Started(Some(SignupVerification))` with a single-use secret (24 hours, `with_signup_verification_ttl`) that `complete_signup(&session, secret)` requires; a taken identifier answers `Started(None)`.
- Social login: `build_auth_url()` returns `AuthUrl { url, state, pkce_verifier }`, `exchange_code` checks the state and refuses a PKCE verifier under 43 characters, `with_http_client_builder` replaces `with_http_client`; the OIDC `AuthUrlResult` has named fields.
- OAuth: trait `fetch_userinfo` and `refresh_token` take the expected `sub` (implementors provide the `_unchecked` forms); a token exchange without `issued_token_type` is malformed; `FrontChannelLogoutHandler::new` is session-bound, `new_unbound` is the opt-out.
- `SessionLayer` refuses a cross-site WebSocket upgrade (403) by the CSRF layer's rule; `with_websocket_origins` sets the allow-list.
- Signed requests are `v3`: `Content-Type` and `Content-Encoding` are signed, `sign_for` takes the headers, `v2` is read only until `accept_v2_until`, and `max_body_bytes` defaults to 256 KiB.
- `TraceContextLayer` ignores an inbound `traceparent` by default; `trust_inbound(true)` opts in.
- The unsealed session-store and device-store constructors are `plaintext_insecure` on the SQLite, Postgres, MySQL and Valkey stores, and the device stores' no-op `with_clock` is removed; the READMEs' quickstart builds `SqliteSessionStore::new(pool, SessionCrypto::new(key))`.
- New enum variants for exhaustive matches: `IssuanceError::InvalidLifetime(LifetimeFault)`, `CycleOutcome::Conflict`, `SqlStoreError::PayloadTooLarge` and `::Unsupported`, `ValkeyStoreError::Unsupported`.
- `StatusDetail` carries `cause: StatusCause` (`Administrative`, `Verification`, `Lockout`, `Closure`, `Other(key)`), built by `StatusDetail::administrative(reason, since)` and kin, and `EntityState::is_administratively_disabled()` and `can_self_recover()` answer an eligibility check without reading `reason`; a row stored without a cause reads as `Other("unspecified")`; `EntityState::is_locked` is `is_suspended`.

### Added

- A locked account's own `Seen` or `Trusted` devices still log in (`with_device_store`) while the lockout keeps every other origin out.
- `AuthSession::completed_factor_within(kind, max_age, now)` and `AuthState::factor_completed_at(kind)`.
- `SessionStore::cycle_if_revision`: a rotation conditional on the revision it merged, implemented by the five in-tree stores.
- `ratelimit::inject_login_identifier`: the layer step that sets `RateLimitLoginIdentifier` before a `LoginIdentifier` limiter reads it.
- `with_max_payload` on the SQL session stores (64 KiB by default, as Valkey).
- `hash_new_password(password, &PasswordRules)` refuses an over-long or rule-failing password before hashing (`NewPasswordError`); `PasswordRules::accepts` is the one check, and `MAX_PASSWORD_BYTES` lives in `axess-factors`.
- A breached-password check at password choice: `AuthnServiceBuilder::with_breached_password_check` takes a `BreachedPasswordCheck`, after which a password reset, and an application's own signup or change through `AuthnService::check_chosen_password` and `hash_chosen_password`, refuse a password the check knows (`NewPasswordError::Breached`, audit reason `password_breached`) and by default one it could not screen (`BreachCheckUnavailable`, opt-out `allow_unchecked_when_breach_check_unavailable()`); `PasswordRules::breached_check` exempts a tenant; `range_prefix` and `count_in_range` are the k-anonymity range protocol's pure halves, `hash_new_password_checked` the free-function form, and `BreachedPasswordList` (under `testing`) a fixed list for tests and examples.

### Changed (breaking)

- `PolicyStore::digest()` returns a `String` and `PolicyStore::schema()` a `Schema`, because both follow a policy reload; `original_digest()` and `original_schema()` borrow the text the object was built from.

### Fixed

- A session rotation no longer loses a write that lands while it runs; a conflict is merged and retried, then fails closed.
- A login or logout that scrubbed the session keeps it scrubbed through the cycle and through `consume_custom`.
- A rotation ends when the old id is gone, and a re-read that answers `Unknown` follows `UnknownLiveness`.
- `verify_factor` checks the factor the person chose and prepared.
- The audit archive sets a refused row aside and archives the rows behind it.
- `EntityCache::invalidate_resource` drops the entries built under a parent.
- The password reset cooldown is never pushed out by other identifiers; a full record sounds an error.
- Impersonation checks the administrator's stored tenant.
- A device with no owner is `Unknown` to step-up.
- `AuthzStore::for_session` on an unauthenticated session returns `NoPrincipal` (401).
- Login identifiers past the table cap share overflow buckets keyed on the identifier; a missing identity extension is limited per peer; an authenticated user without the keyed header holds one slot; `RateLimitLayer::new` refuses a zero limit or window.
- `CsrfLayer` without a session hands handlers an empty `CsrfToken`.
- `RevocationAwareSocket::recv` closes on a revocation before a queued message.
- The Valkey registry scores and prunes on the server's `TIME`, reports a failed revocation `PUBLISH`, reads without renewing the session, rechecks after the client reconnects by itself, and caps an enormous TTL, as the session store does.
- `MemorySessionRegistry` forgets users who never return.
- A token answer cut off after a 200 is transient; `AuthFailureReason` round-trips as itself; a non-rotating refresh token keeps its expiry across a pepper rotation; `InMemoryBackend` never gives a user an id another tenant holds.
- The local IdP builds its `EncodingKey` once, refuses an unusable lifetime, and its fixture clears `jku`, `jwk`, `x5u` and `x5c`.

### Security

- A cookie `Path` that could inject attributes is refused, and a path other than `/` warns that it drops the `__Host-` prefix.
- A response that sets the session cookie is never cacheable by a shared cache.
- A session that logged in with no `User-Agent` is bound to the absence, and an authenticated session with no stored fingerprint is bound on its next request.
- `SessionCrypto::encrypt_with_aad` refuses an empty AAD, and the blob layout of 0.12.0 and earlier reads only under a legacy-reading `LegacyBlobs` policy.
- `SessionLayer::derive_subkey` refuses labels in the reserved namespace.
- Debug logs in the Valkey store and registry name a session by its first eight characters.

### Documentation

- `SIGNATURE_HEADER` says no header is signed; `max_body_bytes` says the body is buffered before any secret is checked; ceremony secrets are as private as the session store; `RefreshTokenConfig::default()` has no `max_lifetime`; entity cache invalidation is local to the pod; the workload trust-domain check catches mapper bugs.
- The step-up wiring calls `begin_step_up`; the `revoke_family` SQL records the reason; the Valkey docs describe the sealed format and the `LegacyBlobs` policy; the social and authz quick starts compile; duplicate cookie names and `__Host-` are explained; `SignupOutcome::Started` says a taken identifier answers it too.

### Example apps

- The sqlite example enrols TOTP in one transaction with a server-held secret behind the current password and the limiter, completes signup through an emailed link, answers taken and free usernames alike, sends no-store, frame and CSP headers, and seeds only in a debug build or with `EXAMPLE_SEED=1`.
- The FAPI example runs its mock IdP only with `FAPI_MOCK=1`, signs with the published key only for a localhost issuer, takes `form_post` only, checks the origin of refresh and logout, and creates a first login only for a domain in `FAPI_ALLOWED_EMAIL_DOMAINS`.
- The OAuth example provisions `linked-only` by default and revokes new tokens at the IdP on a subject mismatch.
- `local-idp` writes its admin token to an owner-only file and takes separate, scoped tokens for `/issue`.
- The Kubernetes wire-up uses the UID-pinned mapper.

## [0.15.0] - 2026-11-05

### Changed (breaking)

- **`HumanPrincipal` and `AuthState::Authenticating` have `impersonator`**:
  the administrator acting in the user's name, emitted to Cedar as
  `axess::Human.impersonator`; a step-up keeps it. Add `impersonator: None`
  to literals; stored sessions load.
- **Hex-encoded OTP secrets are no longer read**: `verify_totp` and
  `verify_hotp` decode base32 only. axess never wrote a hex secret; re-encode
  any you stored.
- **`build_totp_uri` and `build_totp_uri_with_algorithm` return
  `Option<String>`**: `None` for `digits` outside 6 to 8 or a `period` under
  5 seconds (they used to clamp).
- **TOTP is computed in-tree and `totp-rs` is gone**: the HOTP value at
  counter `time / period`, pinned by the RFC 6238 vectors. `TotpAlgorithm` is
  an in-tree enum with the same variants; the `TotpBuilder` and `Totp`
  re-exports are removed.
- **The `moka-cache` feature and `MokaEntityCache` are removed** with the
  `moka` dependency; use `EntityCache` or `ValkeyEntityCache`.
- **New error variants**: `IssuanceError::EmptyKeyId` (the local IdP refuses
  an empty or repeated `kid` on every load and in `rotate_signing_key`),
  `ProvisioningError::InvalidTenant(String)` (an identifier the creation
  rule refuses), `AuthnError::UnknownTenant` (impersonation and signup
  completion when the tenant does not load; was `CrossTenant`).
- **`OAuthError::TokenEndpointTransient` is `{ status: Option<u16> }`**:
  `None` when no answer arrived; the empty `body` field is gone.
  `MockOAuthProvider::with_transient_failure` takes `Option<u16>`.

### Security

- A passkey credential id held by another user of the tenant is refused at
  `finish_fido2_registration` (`NoFlow`, failed `FactorSetup` audit row).
  `FactorStore::fido2_credential_holder` answers the lookup; the default
  answers nobody, so a store that does not implement it admits.
- `finish_discoverable_login` verifies the assertion only against the
  caller's stored credentials with the same public key, so a stored
  credential id cannot be borrowed to log in as someone else.
- A `v2` delegated credential row reads as expired (its expiry is not
  covered by the envelope) and is refreshed, never re-sealed as `v3`; a row
  labelled for another provider is refused.
- Factor secrets are bound to the factor variant and tenant OAuth
  credentials to issuer and client id (`FactorSecretBinding::with_context`).
  Secrets sealed by 0.14.0 open and re-seal (`OpenedSecret::rotated`);
  `FactorSecretCipher::with_first_binding(LegacyBlobs)` decides whether the
  old binding is accepted: `Accept` by default in this release, `Reject` in
  the next; `AcceptUntil(cutoff)` is recommended now. A tenant OAuth record
  opened under the old binding is written back under the current one through
  the new `TenantOAuthProviderStore::put_if_revision` (memory and SQLite
  stores; the default writes nothing).
- A custom key provider cannot save an envelope it cannot read back (a key
  id with a `.` or empty, a repeated-byte key).
- `Debug` redacts `CsrfToken` and `DevicePiiMapping::value`; the delegated
  refresh skew is clamped to 0 through one day; `envelope_aad` panics on a
  field over 4 GiB instead of saturating.
- Audit archive: one refused row no longer stops archiving or purging; a
  down sink costs three calls a tick; `drain` goes past a refused row and
  returns the first refusal at the end; a torn day file is cut back to its
  last newline before the next batch; a bare-id sidecar line no longer marks
  a batch as written (a batch retried across the upgrade is archived once
  more).
- MySQL device store: the create lock is released after the commit, on the
  connection that runs the create; a cancelled create closes its connection
  instead of returning it to the pool with the lock held.
- Audit reasons that name a known tag are recorded as that tag, not
  `Other("...")`; every FIDO2 registration and LDAP row names its session; a
  password reset for an unknown identifier no longer overwrites the system
  user's reset token.

### Added

- `ScopedOAuth::is_refused` tells a refused scope from the global
  registration.
- `cascade_revoke_devices_and_tokens` revokes devices and the refresh tokens
  issued to them; call it from `on_token_compromise`.
- `MemorySessionRegistry::with_ttl` and `with_clock`: entries unused for the
  TTL (24 hours by default) are forgotten.
- `require_authz!(ns, action, resource, validator = ...)` also requires the
  session to be live in the registry.
- `prepare_factor_choice` prepares the factor picked at an `AnyOf` step;
  `build_totp_uri_with_algorithm` writes `algorithm=` into the URI.

### Changed

- `StoredTenantOAuthProviders` reports a store error when a re-read finds a
  later revision than the resolution read, and none when the record was
  deleted meanwhile; the record is wiped after hashing.
- No device store claims a revoked device that has no owner: `claim_owner`
  answers `OwnedByOther` in the memory, Valkey, SQLite, Postgres and MySQL
  stores.
- `RevocationAwareSocket::is_closed` replaces `is_revoked` (removed); the
  socket closes with a reason: `4001 session_revoked`, `4002
  lifetime_reached`, `4003 session_unverified` (`LIFETIME_REACHED_CLOSE_CODE`,
  `SESSION_UNVERIFIED_CLOSE_CODE`). A client that signs out on `4001`
  reconnects on the other two.
- New accounts and tenants refuse look-alike identifiers (surrounding or
  non-ASCII whitespace, a form NFKC would change; a tenant identifier also
  the invisible-character and NFC rules): `is_acceptable_new_identifier`,
  `Tenant::validate_new`. Rows read back are unchanged; migrating.md has a
  query for existing rows the rule would refuse.
- JWT replay protection keys the store on issuer and `jti` together; a token
  recorded just before the upgrade can be accepted once more within its
  remaining lifetime.
- The outbound OAuth client and `TokenExchangeClient` refuse a token response
  without `token_type`; one path sends the device authorization request, and
  a `client_secret_basic` request also names `client_id` in its form.
- Documented and pinned: after a backward clock step larger than the
  tolerance, server-stamped service callers are refused as stale until the
  clock passes the newest stamp forgotten before the step.
- Dependencies: `totp-rs`, `moka`, `dashmap`, `lru`, `hex`, `rand`,
  `tower-cookies` and `form_urlencoded` leave the library crates; `base64` is
  0.22 with the rest of the tree; `parking_lot` gives way to `std` locks
  (poisoned locks are recovered); `axess-cache` has its own LRU with the
  same eviction; `axess_rng::hex` is the one hex codec (a device fingerprint
  that is not 64 hex characters is refused with one message); `SystemRng`
  reads the OS generator through `getrandom`; the unused `once_cell` and
  `hyper` lines go; `session::config::SameSite` is
  now `cookie::SameSite` at the same path. The library crates resolve 187
  crates with default features (was 271) and 359 with all (was 591).
- The sqlite example's key file is never rewritten: a valid key only narrows
  the mode, a new file is linked into place whole, a file with no key stops
  the start.

### Changed (breaking)

- `PolicyStore::digest()` returns a `String` and `PolicyStore::schema()` a `Schema`, because both follow a policy reload; `original_digest()` and `original_schema()` borrow the text the object was built from.

### Fixed

- Sessions: `set_pending_workflow` (and `begin_signup`), `set_identifying`
  and `begin_authenticating` rotate the session id; a one-shot value taken
  after a rotation writes only the removal to the old row; a rotated session
  merges a concurrent write instead of bringing a taken value back; a
  pending-workflow session is bound to the client's fingerprint; a handler
  error still stores the session; `derive_subkey` no longer returns the
  cookie or fingerprint key for the layer's reserved labels (an application
  that asked for those two labels gets a different key).
- Session registry and sweeps: a used Valkey session keeps its member and
  eviction past `max_sessions_per_user` is by last activity; the SQL sweep
  removes a row at the second it expires; a session revoked during id
  rotation stays revoked; a Valkey watcher polls when its registry check gets
  no answer; a socket whose watcher died is closed by `send` with `4003`;
  `MemorySessionRegistry` drops the entry of a user whose last session was
  invalidated.
- Devices and tokens: the default `find_by_fingerprint_for_user` pages past
  `OWN_DEVICE_SCAN_LIMIT`; a Postgres retention sweep cannot undo a
  revocation; the Valkey device store refuses to save over a row it cannot
  decode unless the save is a revocation (delete the device to clear it); a
  refresh-token compromise revokes the linked devices' other tokens;
  `RefreshTokenConfig::validate` refuses a `ttl` of zero or less;
  `ValkeyEntityCache` writes sub-second TTLs in milliseconds; an
  earlier-format device binding under a row id holding a zero byte is not
  re-sealed under that row.
- Impersonation and authz: a step-up keeps the impersonation; a nested
  attempt is refused with `Impersonated` and `nested_impersonation`; a
  refused impersonation still ends the administrator's old session id; a
  caller attribute named like a built-in (`session_id`, `impersonator`) does
  not reach the Cedar principal; `require_authz!` answers an anonymous caller
  401, not 400, on a malformed path parameter.
- Rate limits and addresses: IPv6 rules wider than /96 cover IPv4 clients
  (`::/0` denies or admits them); `normalise_identifier` strips invisible
  characters before NFKC, so one login name is one key; `X-Real-IP` is
  canonicalised; the login overflow bucket is per IPv4 address (per IPv6
  /48); a window under one millisecond no longer divides by zero; a new
  address folds into its prefix's overflow bucket once the table is three
  quarters full; `Retry-After` rounds a partial second up.
- OAuth client: the device authorization request authenticates the client;
  a DPoP nonce retry signs a new client assertion; a device-code poll meeting
  a `5xx` is an error, not a denial; DPoP `htu` drops query and fragment; a
  `use_dpop_nonce` challenge is found anywhere in `WWW-Authenticate`; a
  device response without `interval` polls every 5 seconds;
  `with_private_key_jwt` with a signer for another client is refused by
  `build()`; client secrets travel only in a Basic header on the revocation,
  `client_credentials`, device-poll and pushed authorization requests; a
  `token_type` other than `Bearer` is refused; the DPoP seed is decoded into
  zeroizing buffers.
- OIDC: issuer comparison is exact (a trailing slash differs); Bearer
  middleware tries every config for the issuer, reads the scheme
  case-insensitively, trims the token, and answers 401 to a non-text header
  or a `Bearer` with no token (it passed as anonymous); social login appends
  with `&` to an authorization endpoint that has a query; back-channel logout
  picks the provider by `azp` among `aud` and answers 503 to a resend while
  the first delivery runs; tenant providers are rebuilt when a record is
  deleted and written anew, and a lower revision is discovered once; a refused non-Bearer refresh still saves the
  rotated refresh token; an exchange response without `scope` grants the
  requested scopes; the claim lock hashes its fields with lengths (ceremonies
  in flight during the upgrade restart); a start time in the future is
  expired; a JARM response with no code ends the ceremony; an issued-at far
  from now is out of range, not an overflow; a token verified in its last
  accepted second is remembered for that second; `SidMap` sweeps name a
  session once; the GCP impersonation endpoint base keeps its last segment.
- Signed service requests: a replay is refused across a clock step in either
  order; a signature stamped ahead of the clock is set aside outside the
  `max_remembered` count and counts again when the clock catches up; a stamp
  at or below the newest one forgotten for age is stale.
- Factors: a passkey login no longer shortens a method with an empty `AnyOf`
  step (`AuthMethod::is_complete`); `axess-factors` builds with `--features
  totp` alone; `build_totp_uri` writes `algorithm=SHA1`; a replayed TOTP or
  HOTP code that loses the write race is audited and counted against the
  lockout; a failure record never overwrites a factor enrolled meanwhile;
  `begin_fido2_registration` returns `NoFlow` when the ceremony state does
  not fit in the session; LDAP puts a user name with an interior space or a
  non-ASCII letter into the bind DN as itself and leaves a literal `{user}`
  in the group filter alone.
- Identifiers and testing: `PiiToken` deserialises through `parse` (an
  uppercase or braced stored token no longer loads; rows the library wrote
  are unaffected); `WorkloadId::parse` refuses a bad path segment with
  `InvalidSpiffeId`; `InMemoryBackend::with_clock` reaches the identity
  store and `with_user_password` keeps one user per tenant; `TracingCapture`
  keeps a second dispatcher registered for the life of the process, so a
  callsite first hit by a thread with no subscriber is still captured.
- Caches and keys: `invalidate_resource` also drops entries whose entity set
  holds the resource, on `EntityCache` and `ValkeyEntityCache` (the Valkey
  cache keeps a per-UID index beside each entry); the local IdP clears `jku`, `jwk`, `x5u` and `x5c`
  from a header given to `mint_with_header`.
- Documented: the password reset cooldown bounds repeat requests, not a
  caller who mints identifiers; `MemoryDeviceStore` scans the whole table on
  every write.

Example applications (not published; copy with these changes):

- **sqlite**: `available_methods` lists only the asked tenant's methods; the
  TOTP master key file is kept at mode 0600; `activate_user` clears a timed
  suspension and the failure counters; the plain-secret cutoff is a fixed
  date; concurrent TOTP enrolments store one factor and answer the other 409;
  an unknown `users.status` or unreadable `steps_json` is an error, not a
  guest or an empty method.
- **oauth**: a refresh whose userinfo names another subject ends the session;
  an unknown or non-text `OAUTH_PROVISIONING` stops the server; the social
  example passes on neither Spotify's nor GitHub's unverified email, falls
  back to the Discord username when `global_name` is null, and gives its
  pre-login cookies a ten minute `Max-Age`.
- **workload-identity**: `GitHubAllowlist` also lists the `ref` or
  `environment` and the event, and admits nothing when none is listed; the
  local IdP retires a key only after its tokens have expired, never reuses a
  kid, stages a new key as `.pem.new` until the rotation, removes the key
  file of a failed rotation, and stamps a historical key on first load; a run
  admitted through its `environment` records the attribute.

## [0.14.0] - 2026-11-02

`docs/production/migrating.md` lists every break by what an adopter sees.

### Changed (breaking)

Types and traits:

- **`AuthState` carries the impersonation marker and the LDAP groups**:
  `impersonator` holds an `Impersonation { admin, since }` (capped by
  `max_impersonation_age`, kept by custom-data changes, carried by
  `AuthSnapshot`) and `ldap_groups` replaces the custom key
  `axess.ldap.groups`. **Migrating:** add `impersonator: None`,
  `ldap_groups: None` and `impersonation: None` to literals; sessions load.
- **`AuditContext` has `impersonator`**, and an event built with it names the
  administrator as `actor_id`. **Migrating:** add `..Default::default()`.
- **New fields**: `OAuthClaims::nonce` (pass it as `original_nonce` on
  refresh); `PasswordConfig::password_id`, the identity a rehash keeps;
  `HotpConfig::throttle`, whose lock (a minute, doubling to an hour) never
  moves the counter, so a password holder cannot desynchronise the token.
  **Migrating:** add the field, `password_id: None` and
  `throttle: Default::default()` to literals; stored rows read as unlocked.
- **New variants**: `AuthEventType::{AccountDeleted, SignupResumed}`,
  `RevocationReason::Device`, `AuthnError::{Busy, Impersonated}`, typed
  `AuthFailureReason` refusals, `LdapError::Directory`,
  `KeyProviderError::WeakKey`, `SqlDeviceStoreError::CreateLockTimeout`,
  `OAuthError::{DpopKeyRequired, Store, ClientAssertion}`,
  `OAuthClientError::RequestBuild`, `DelegatedError::ClientCredentials`, the
  `ClientBuild` errors, `MemoryLocalIdpKeyStoreError::DuplicateKeyId` and
  `MockStoreError::Unavailable`. **Migrating:** add the arms.
- **`BearerIssuerConfig.audience` is the `Audience` enum**; only
  `Audience::AnyDangerous` skips the check. **Migrating:** write
  `Audience::Exact(aud)` for `Some(aud)`.
- **Fallible constructors return their cause**: `TokenExchangeClient::new`,
  the STS constructors, `StoredDelegationSession::new` and
  `SocialProvider::new` return `Result` (`ClientBuild` keeps the
  `reqwest::Error` as its source) instead of a client that follows redirects
  or a panic; the STS `Default` impls are gone. **Migrating:** add `?`.
- **`basic_credentials` returns `ZeroizedString`.** **Migrating:** build the
  header with the new `basic_authorization`, which marks it sensitive.
- **`handle_backchannel_logout` returns an axum `Response`**, always with
  `Cache-Control: no-store`. **Migrating:** a mounted route is unchanged; a
  direct caller reads the status.
- **`with_hidden_signup_conflicts` is removed** (hiding a taken identifier is
  the default) and **`LocalIdpFixture::new` signs ES256**. **Migrating:**
  `with_signup_conflicts_revealed` restores `AlreadyExists`; `new_rsa`.
- **A single-repeated-byte key is refused** by `MemoryKeyProvider::new` and
  `CsrfConfig::try_new` (`WeakKeyError`), and logged by `CsrfConfig::new` and
  `EncryptionKey::from_bytes`. **Migrating:** generate the key.
- **Required trait methods**: `DeviceStore::create_or_find`,
  `SessionRegistryHandle::held_sessions` (`active_sessions` is provided),
  `OAuthProvider::binds_to_dpop`, and the tenant policies and
  `record_last_login`, whose permissive defaults let a decorator switch a
  policy off; `IdentityLookup::lockout_policy` is gone. **Migrating:**
  implement them; a store with one policy returns it for every tenant.
- **Trait contracts**: every revoking `RefreshTokenStore` method records a
  reason and time; `LocalIdpKeyStore::rotate` refuses a duplicate `kid`;
  `LdapProvider` answers `Directory` for a result that does not judge the
  password; `SessionStore` keeps nothing under a zero TTL. **Migrating:**
  bring a custom store to the documented contract.
- **One refresh entry point, `Refresh`**: `new(plaintext, status_check)`, then
  `in_tenant`, `device_info` and `device_store` as needed, then `run`, over one
  pipeline (an expired token is `Expired` before the device check; a device
  another user owns is `DeviceMismatch`). The `refresh_session*` forms are
  deprecated wrappers. **Migrating:** build a `Refresh`.

OAuth and federation:

- **`discover` and `discover_with_private_key_jwt` return an
  `OAuthProviderBuilder`** whose `build()` checks every setting together (FAPI
  client authentication and PAR, DPoP, ID-token algorithms, each endpoint's
  transport), whatever the call order. **Migrating:** drop the `?` after
  `with_fapi`; end the chain with `.build()?`.
- **A FAPI provider that would send a client secret is refused**
  (`OAuthError::Config`): FAPI 2.0 permits only `private_key_jwt` and mTLS.
  **Migrating:** use `discover_with_private_key_jwt` or `with_private_key_jwt`,
  or `SenderConstraint::Mtls`; a secret client keeps DPoP without the profile.
- **One method per DPoP-capable operation**: the `_with` and `_with_key`
  forms are gone; the bare names take the key (`dpop: Option<DpopSigner>`,
  `dpop_key: Option<&DpopKey>`), and a binding provider given `None` answers
  `DpopKeyRequired` before sending. **Migrating:** pass the key or `None`.
- **`private_key_jwt` has one representation, `ClientAssertionSigner`**:
  `ClientAuthMethod::PrivateKeyJwt` takes a boxed signer (with Entra's `x5t`
  headers), which refuses a key unfit for its algorithm at startup;
  `mint_client_assertion` is gone. **Migrating:**
  `ClientAuthMethod::PrivateKeyJwt(Box::new(signer))`.
- **`keys::EXPECTED_TENANT` is `keys::CEREMONY_TENANT`**, the same session
  key now holding `{"tenant", "provider_from_tenant"}`; a 0.13 value reads.
  **Migrating:** name the new constant.
- **`with_session_match_required` returns a `BoundFrontChannelLogoutHandler`**,
  whose only route takes the caller's `AuthSession`;
  `handle_frontchannel_logout_bound` is gone. **Migrating:** route its
  `handle_frontchannel_logout` behind the session layer.
- **`SidMap::take_subject_sessions` and `SidMap::remove` are removed**; the
  first dropped mappings before the registry confirmed. **Migrating:**
  `subject_sessions`, then `remove_session` for each session ended.

Storage:

- **The Valkey device fingerprint index is a sorted set** (`dev:fpz`); the
  layouts of earlier releases are read only under
  `with_legacy_fingerprint_keys`. **Migrating:** set it until every device has
  been sighted since the upgrade.
- **MySQL device indexes are `last_seen_at DESC, id ASC`.** **Migrating:** run
  the `ALTER TABLE` from the `DeviceStore` module docs once.
- **Delegated credentials are sealed in envelope `v3`**, binding `expires_at`;
  a `v2` row is re-sealed by the read that finds it.
- **`LegacyBlobs::AcceptUntil` is a deadline for the row's next write**: a read
  no longer re-seals a blob with no row binding. **Migrating:** set the cutoff
  after every wanted row is next written.
- **Half-finished logins are dropped once at the upgrade**; the user starts
  again. **Device timestamps are whole seconds**; a tie goes to the smaller id.

Behaviour:

- **`begin_login` answers a locked account `InvalidCredentials`**, as an
  unknown one, and a lockout at the limit outlives the attempt window.
  **Migrating:** `with_lockout_revealed_on_begin` restores `Locked { until }`.
- **`User::validate` refuses an identifier signup would refuse**, against all
  of Unicode 16.0 Cf less the joiners. **Migrating:** find such rows with
  `normalise_identifier` and have the users rename.
- **The KDF queue is bounded** (16 per permit); a saturated executor answers
  `503` with `Retry-After` (`AuthnError::Busy`). **Migrating:**
  `with_max_queue(usize::MAX)` restores the unbounded queue.
- **The CSRF cookie is `__Host-axess.csrf`** under `Secure`, and `CsrfLayer`
  panics for `SameSite::None` without `Secure`. **Migrating:** read the new
  name in front-end code (a first request after the upgrade fails once).
- **A WebSocket upgrade must come from the request's own `Host`** without a
  CSRF allow-list, and `RevocationAwareSocket` fails closed and lives a day.
  **Migrating:** list the origin; set `fail_closed`, `max_lifetime` knowingly.
- **A non-rotating client keeps its token across a pepper rotation**; it is
  re-stored under the current pepper instead of rotated.
- **`finish_oauth_login` is refused** by a provider that advertises the
  RFC 9207 `iss` parameter. **Migrating:** call `finish_oauth_login_with_iss`.
- **A provider binds its tokens to a DPoP key when the IdP advertises DPoP**:
  the login makes its key at `begin_oauth_login`, and a ceremony or refresh
  without it is refused (`dpop_key_invalid`, `token_refresh_dpop_key_missing`).
  **Migrating:** keep `OAuthClaims::dpop_key` beside the refresh token, or
  `without_dpop()` (`TenantDpop::Off`) where resource servers want Bearer.
- **An impersonated session cannot change passkeys or get a refresh token**
  (`AuthnError::Impersonated`, 403), and `Fido2Options::max_authn_age` refuses
  an old authentication. **Migrating:**
  `with_impersonated_credential_changes_allowed` opts in.
- **Audit reasons are typed**: the refresh path's `impersonated_session` is
  `impersonated`, and a signup resubmit is a `SignupResumed` row, not a success
  row with the reason `resumed`. **Migrating:** query the new names.
- **`invalidate_session` refuses a session the registry does not hold for that
  user**; `begin_impersonation` answers an unknown target `CrossTenant`; a
  rotated session the registry fails to register follows `UnknownLiveness`.
- **A back-channel logout the registry could not complete answers 503** so the
  IdP retries; the `jti` log is bounded per issuer, dropped with its last entry.
- **`begin_password_reset` answers `Ok(None)` for an account that may not log
  in**, and **`begin_step_up` asks only for enrolled factors** (none is
  `NoFlow`). **Migrating:** show the factor it returns.

### Added

- **Per-tenant identity providers**: `TenantOAuthProviders` (by issuer, the
  built providers and the broken records), `StoredTenantOAuthProviders` (one
  build per record revision, credentials sealed, issuer indexed in SQLite)
  and `begin_oauth_login_with_tenant_provider`.
- **`oauth_for_session` and `oauth_in_tenant`** return a `ScopedOAuth` whose
  refresh, userinfo, revocation and logout helpers use the login's provider;
  `as_user` names the user for a background refresh.
- **`BackChannelLogoutHandler::for_tenants`** verifies tenants' logout tokens:
  an issuer and client id two providers share is `Ambiguous`, and a token only
  a broken record could verify answers 503 while the others verify.
- **`private_key_jwt` on the user login** (`ClientAssertionSigner`, RFC 7523;
  `SignerSpec` for a stored record) and **`with_id_token_signing_algs`**, which
  pins ID and logout token algorithms and narrows FAPI's list, never widens it.
- **DPoP without FAPI**: `with_dpop`, `without_dpop`,
  `TenantOAuthProviderRecord::dpop`; DPoP and `verify_dpop_proof` need only
  `oauth`, of which `fapi` is now an alias.
- **`RequestAuthnService::delete_user`** ends sessions and refresh tokens, then
  deletes the user; **`issue_refresh_token`** and
  `revoke_refresh_token_in_tenant`, exported by `axess::session`.
- **`with_previous_recovery_code_pepper`** keeps recovery codes valid across a
  pepper rotation and flags the set for regeneration.
- **`force_refresh_of(token)`**, `normalise_identifier`, `SidMap::remove_if`
  and `subject_sessions`; the facade exports both logout handlers and DPoP.
- **The oauth example ends with a session** (identities keyed by
  `(issuer, subject)`, provisioning, logout from both ends, `private_key_jwt`);
  **the fapi example completes a real Keycloak login** (`ES256`, DPoP).
- **Workload identity**: a `gitlab` recipe on numeric ids, `openshift` and
  `eks` issuer modules; Kubernetes refusals name the claim.
- **Testing**: `AuthSessionTestExt::set_impersonator`, `CallLog::on`,
  `arm_record_event_hang`, `arm_get_user_failure`.

### Changed (breaking)

- `PolicyStore::digest()` returns a `String` and `PolicyStore::schema()` a `Schema`, because both follow a policy reload; `original_digest()` and `original_schema()` borrow the text the object was built from.

### Fixed

- **A one-shot session value cannot be handed out twice or written back**:
  every stored-session write is a compare-and-swap whose merge base moves
  forward with each write, so a value consumed meanwhile is not restored.
- **Nested impersonation is refused, as is a suspended administrator's**, and
  refused rows no longer carry ids the caller chose.
- **Password reset**: the cooldown keys on the normalised identifier, the
  commit re-checks the tenant, a dropped request cannot leave sessions valid,
  and a refused reset writes no password history.
- **The discoverable passkey login takes the tenant from the store** before its
  gates; `delete_fido2_credential` re-checks account status.
- **An LDAP outage no longer counts towards lockout**, `ldapi://` is not
  refused as a remote cleartext bind, and a password rehash keeps the
  password's identity, so it drops no login in progress on any instance.
- **`AuditLogWithAnalytics` and `InMemoryBackend` forward every trait
  method**, keeping a store's IP allowlists, password rules and lockout policy.
- **A revocation during rotation is not lost**, no cookie is set for a session
  the store did not keep, and a re-seal no longer fails a conditional write.
- **A failing device resolver no longer unbinds the session**, and the
  resolver sees a tenant held in the session (`SessionTenant`).
- **Devices**: a device revoked mid-request is not served; two first sightings
  make one device on every store; a SQLite save racing another write no longer
  fails with `database is locked`; the Valkey store no longer reads a user's
  every device on a miss.
- **A device-bound refresh token survives a pepper rotation**, a lost device's
  token is refused as `Revoked`, and a store blip during a concurrent refresh
  no longer revokes the family.
- **A callback whose provider no longer resolves is audited**
  (`provider_unavailable`) and clears the ceremony; a JARM response that is not
  the ceremony's leaves it in place.
- **A FAPI ID token without `nbf` is accepted** (Keycloak logins were refused);
  discovery is fetched once; federated audit rows carry the tenant, never a
  user read from the IdP; a displaced `sid` stays reachable by a `sub` logout.
- **`SocialProvider` checks all three endpoints for HTTPS at construction**,
  and the `social` feature compiles on its own.
- **The outbound OAuth client never serves a token a `401` condemned**, shares
  one fetch outcome with its waiters and keeps a valid token through a failed
  refresh; its timeout error names the timeout as set.
- **Client secrets stay in zeroized buffers**, transport errors no longer print
  the URL, and the assertion signer pins the crypto provider.
- **`LocalIdp` refuses an empty `aud`**, and a retired key leaves memory even
  when the re-read fails; a delegated credential loads when the key provider
  cannot name its current key.
- **The Cedar schema is authoritative for action entities**; `require_authz!`
  audits a UID it cannot build; an IPv4-mapped trusted-proxy CIDR trusts the
  proxies it names; the overflow bucket withholds `x-ratelimit-remaining`.
- **Clock steps and stalls**: the service-secret warn throttle re-arms, the
  Valkey revocation subscriber reconnects, the JWKS refresh and session
  cleanup tickers run once, and the audit archiver archives no batch twice.
- **`logout` clears the session before awaiting the audit write**; the sqlite
  example costs the same for an unknown identifier and its decoders return an
  error for a malformed row; `TracingCapture` sees a sibling test's events.

### Documentation

- OpenID Foundation runs in `docs/factors/conformance.md`, Azure and AWS
  workload identity walkthroughs, and guides that match the code.

---

## [0.13.0] - 2026-10-29

The 0.12.0 retest and deep dive: 254 items, 246 fixed with a test that fails
without the fix, 8 rejected with evidence. `docs/production/migrating.md`
lists every compile error and storage step by what an adopter sees; this
entry says what changed.

### Changed (breaking)

Logins and factors:

- Lockout is derived from the store at every gate: `IdentityAuthnLog`
  requires `failed_attempts`, `reserve_attempt` and `release_attempt`, and a
  guess is counted before its credential is checked, so parallel guesses
  cannot pass `LockoutPolicy::max_attempts` (0 means five). The sqlite
  example gains a `last_failed_at` column.
- A half-finished login expires (`with_flow_ttl`, ten minutes) and dies with
  a credential change. `begin_login` answers `InvalidCredentials` for a known
  inactive account; `begin_signup` answers `AlreadyExists` instead of
  resuming another session's candidate; signup refuses non-NFC identifiers,
  invisible format characters and passwords over `MAX_PASSWORD_BYTES`.
- `finish_discoverable_login` returns `FactorOutcome` and follows the user's
  method: a passkey alone no longer authenticates a user whose method needs
  more. Passkey enrolment and deletion need the user's own authenticated or
  pending-signup session; `delete_fido2_credential` takes the session.
- `TotpConfig::secret` and `HotpConfig::secret` are a `FactorSecret`, `Plain`
  or `Sealed`: a struct literal needs `.into()`, reading the text is
  `secret.plain()`. Stored rows load unchanged.
- `StepUpPolicy::default()` asks for a factor at every trust level, since a
  fingerprint is client-controlled. `PrepareOutcome::AlreadySent` carries a
  masked address; the HOTP attempt limit restarts the count.
- `begin_impersonation` is the tenant-scoped form and requires an
  authenticated admin session. `suspend_user`, `activate_user`,
  `invalidate_user_sessions` and `invalidate_session` take an `Actor` and the
  expected tenant, with `suspend_user_across_tenants` and
  `activate_user_across_tenants` for the platform operator; the `_by`,
  `_in_tenant` and `_as` variants are removed. A registry that fails is
  `AuthnError::ExternalService`, and no audit row claims the sessions ended.
- `refresh_session` is deprecated for `refresh_session_with_status_check`; a
  caller with no status to consult passes `|_| async { true }`.

Sessions and cookies:

- `SessionStore` requires `update_if_revision`; `SessionData` gains
  `revision` and `touched_at`. `AuthSession::take_custom` is single-use across
  nodes, `clear` cycles the id, and `user_id` and `tenant_id` answer only for
  an `Authenticated` session (`pending_user_id` names the login in flight).
  Becoming authenticated clears the session's `custom` data except the keys
  named by `with_preserved_custom_keys`.
- The default cookie is `__Host-axess.sid`. `SessionLayer` and
  `CsrfLayer::new` panic on a prefixed name without `Secure`, a `__Host-`
  name off `/`, a zero TTL or `SameSite=None` without `Secure`; a cookie name
  present twice counts as absent.
- `CsrfToken` is built with `CsrfToken::new` and read with `as_str`. A request
  that uses neither the session nor the token stores nothing and sets no
  cookie; `CsrfConfig::mint_on_every_request(true)` restores the old behaviour.
- `AuthnService::logout` always clears and rotates, even when the audit write
  fails; `SessionRevoker` methods return `Result<(), RevocationError>`.
- `LegacyBlobs` defaults to `Reject`: a session blob with no row binding and
  the 0.11.0 device formats are refused unless `SessionCrypto` is given
  `with_legacy_blobs(LegacyBlobs::AcceptUntil(cutoff))`, on the clock set by
  `with_clock`. `SessionCrypto::encrypt` and `decrypt` are removed; use
  `encrypt_with_aad` and `decrypt_with_aad`. Bound blobs are sealed under a
  per-record subkey, so AES-GCM's random-nonce limit no longer applies, and
  earlier blobs are re-sealed on read. `session::crypto` and `aes-gcm` no
  longer depend on a storage feature.

Devices and refresh tokens:

- A device is matched by a token in a `__Host-axess_device` cookie, never by
  its fingerprint; a guest creates no device and a cookieless request writes
  nothing; devices of earlier releases are not matched again.
  `DeviceStore::record_sighting` returns the trust level (`Revoked` means the
  row was not touched); `SqlDeviceStoreError::Contended` replaces a
  self-contradicting `Refused`; the SQL stores replace
  `idx_devices_fingerprint` with `idx_devices_fingerprint_seen` and add
  `idx_devices_sweep` and `idx_devices_revoked_at` (MySQL runs the
  `ALTER TABLE` in the `MysqlDeviceStore` docs).
- `RefreshToken` gains `revoked_reason` and `revoked_at`; `RefreshTokenConfig`
  gains `max_lifetime`, `reuse_grace` and `previous_hash_pepper`;
  `RefreshError` gains `ConcurrentRefresh`, `DeviceRevoked` and
  `DeviceStore(String)`. Only the reuse of a token rotated out revokes its
  family, and a token stores a keyed digest of its device string, not the
  string.
- `RateLimitConfig` gains `rng`; `RateLimitLoginIdentifier` is a struct that
  normalises with NFKC; `x-ratelimit-remaining` is no longer sent for
  login-identifier, tenant or shared buckets. `KdfError::Busy`: the KDF
  executor refuses past `with_max_queue` or `with_acquire_timeout`.

Federation, workload identity and network:

- `refresh_oauth_token` takes `original_nonce` and returns `RefreshOutcome`
  (the ID token is optional and the rotated refresh token is never lost with
  the error); `fetch_userinfo` takes `expected_subject`.
  `OAuthProviderConfig::with_fapi` works and no longer needs the `fapi`
  feature; `FapiConfig` gains `allowed_id_token_algs`; `OAuthClaims` gains
  `dpop_key`; DPoP proofs take a `DpopKey`. An empty `post_logout_redirect_uri`
  allowlist forwards nothing. A back-channel logout token with both `sid` and
  `sub` ends only the `sid` session; `iss` is pinned, `typ` checked, and a
  full `jti` log answers 503.
- `JwtVerifier::verify` fails without an audience pin unless
  `allow_any_audience()` was called; `JwtSvidResolver` and `WorkloadResolver`
  refuse a verifier that pins no `iss` or `aud`; `verify_jwt` refuses
  `HS256/384/512` and a JWK whose `use` is not `sig`; `JwtError::TooLarge`
  refuses a token over `MAX_JWT_BYTES` before decoding. `MtlsResolver` refuses
  a leaf with more than one SPIFFE SAN, a CA leaf, or one that may sign.
- Every credential-bearing outbound client refuses a non-HTTPS, non-loopback
  endpoint before sending, follows no redirects and has timeouts
  (`OutboundOAuthClient::new` now returns `Result`; `TokenExchangeClient`,
  `AwsStsClient`, `GcpStsClient`, `GcpServiceAccountImpersonator`,
  `AzureFicClient`); a client passed to `with_http_client` drops those
  protections. `LdapProviderConfig` refuses a cleartext bind to a remote host
  (`allow_cleartext()` opts in).
- `LocalIdp` caps tokens at one hour and requires an audience
  (`without_max_ttl()` and `allow_no_audience()` opt out);
  `LocalIdpKeyStore::retire` is required; `rotate_signing_key` refuses a
  duplicate `kid` (`IssuanceError::DuplicateKeyId`), and generated keys carry
  an RFC 7638 thumbprint `kid`.
- Signed service requests are addressed: `SignedRequests` needs an
  `audience`, `ServiceSecretLayer::signed` returns `Result`, a signature made
  for another recipient no longer verifies, `ServiceSigner::sign` is removed
  for `sign_for`, and `accept_unaddressed_until(instant)` keeps `v1` callers
  through a window.
- `EncryptedDelegatedCredentialStore` writes envelope `v2` and re-seals a row
  on load through the new `DelegatedCredentialStore::save_if_unchanged`
  (`without_reseal_on_load` opts out; `v1` rows follow
  `with_legacy_envelopes`); `complete_grant` takes a `&dyn Clock`.
- `ClientIp`, `TrustedProxies` and `DefaultFingerprintExtractor` canonicalise
  IPv4-mapped IPv6 addresses; the bearer layer's 401 body is
  `{"error":"invalid_token"}`; the filesystem audit archiver records
  `{batch id} {content digest}` in its sidecars.

Authorization:

- `PolicyStore` adds the schema's action entities to every evaluation, and
  principal attributes cannot shadow the built-in Cedar attributes. Entity
  cache keys carry the provider's `cache_discriminator` and an invalidation
  generation, so existing entries are not found after the upgrade.
  `require_authz!` refuses a resource id with more than one path placeholder
  at compile time.

Dependencies and test doubles: `axess-core` depends on `unicode-normalization`
and, unconditionally, on `aes-gcm`; `webauthn-rs` is pinned `=0.6.0-dev`;
`MockLdapProvider` and `MockFido2Provider` exist only under `cfg(test)` or the
`testing` feature.

### Added

- A guess is reserved before its credential is checked, so parallel guesses
  cannot pass the lockout; one Argon2id verification runs on every password
  path, and a hash made under older parameters is replaced at the next login.
- OTP secrets sealed at rest: `FactorSecretCipher` seals a TOTP or HOTP secret
  into a `SealedFactorSecret` bound to its row, and the login that verifies a
  plain secret seals it, inside a dated window.
- Pepper rotation for refresh tokens (`previous_hash_pepper`) and recovery
  codes (`verify_recovery_code_rotating`).
- Signup can hide a taken identifier and password resets can cool down per
  identifier; the documented step-up flow is `begin_step_up`.
- The session layer consults the registry for every authenticated session and
  caps authenticated age; a read-only request keeps a session alive; the layer
  finalizes in a task of its own, so a dropped request cannot leave a
  logged-out session `Authenticated`; `require_authn!(validator = v)` ends a
  revoked session.
- Device revocation reaches refresh tokens, a password reset or suspension
  revokes the user's refresh tokens, and the Valkey device store reads one
  user's devices rather than every one that shares a fingerprint.
- A per-prefix rate-limit budget, a bounded KDF queue, and revocation-aware
  WebSockets with a periodic poll and a maximum lifetime.
- FAPI 2.0: DPoP on the token request with the nonce retry and key-bound
  refresh and userinfo calls, mTLS client authentication through the endpoint
  aliases, JARM, the RFC 9207 `iss` check, and back-channel logout audit.
- Workload identity: a bearer issuer requires an audience, the JWT-SVID
  resolver can cross-check the tenant claim, service signatures bind to a
  named recipient, and the local IdP can retire and reload keys.
- Authorization: entity providers declare a cache discriminator, invalidation
  by resource, the `{$tenant}` and `{$user}` placeholders in `require_authz!`,
  and decision events for denials made before Cedar is asked.
- The example crates gain a pinned Kubernetes mapper, the local IdP's key
  retirement route, a logout route and a sealing key for TOTP enrolments.

### Changed (breaking)

- `PolicyStore::digest()` returns a `String` and `PolicyStore::schema()` a `Schema`, because both follow a policy reload; `original_digest()` and `original_schema()` borrow the text the object was built from.

### Fixed

- Logins: parallel logins at a session cap no longer revoke each other; the
  failure counter moves before the audit await; a known barred user makes the
  same store calls as an unknown one; an email OTP burn keeps its cooldown; a
  password reset installs, invalidates, clears, revokes and audits in that
  order and re-checks the status before spending the token; FIDO2 clears its
  ceremony stamp on every failure path and audits a failed registration; an
  LDAP outage is audited and names the user.
- Sessions: a fingerprint matched under the previous key no longer ends the
  session on the next request; the custom-data cap applies to every write; a
  cookieless `AuditContext` extraction stores nothing; Valkey `cycle` with a
  zero TTL reports `SessionGone`.
- Devices and refresh: `ensure_device` never reuses a `Revoked` device,
  prefers the caller's own device and settles two racing first sightings on
  one; `save` leaves a `Revoked` row untouched; a family-less token's child is
  revoked with its parent; the retention sweep runs in batches of 1,000 rows;
  a legacy blob is refused when the tenant and id inside it differ from its
  key, and a nonce that happens to begin with a format marker still opens.
- OAuth and federation: a refused login restores the `(iss, sid)` mapping it
  displaced; discovery reads `end_session_endpoint`, `revocation_endpoint` and
  the PAR endpoint from the raw document (`build_end_session_url` had always
  answered `None`); DPoP proofs at zero skew could replay within their second;
  a cancelled delegated refresh no longer loses the rotated token; the outbound
  client caches a token for half its life and shares one fetch across callers;
  `TokenExchangeRequest`, `AuthUrl` and `DeviceAuthResponse` no longer print
  tokens through `Debug`; the AWS STS client zeroes the response body;
  `UnknownKid` carries at most 128 bytes of the `kid`.
- Infrastructure: the audit archiver marks a batch only after every file and
  directory is durable; the rate limiter survives a backwards clock step and
  HMACs its log fingerprints; the service-secret replay cache keeps sweeping
  after a clock step; Valkey watchers recheck after a lost connection, with
  2 s setup timeouts and a 5 s poll without a subscriber; `spawn_jwks_refresh`
  no longer bursts missed ticks; the request-id layer no longer panics on a
  non-ASCII custom id; an authz invalidation racing a cache load no longer
  loses; `DEFAULT_FLOW_TTL` is exported without the `oauth` feature.
- Reference examples: cookies are `Secure` unless
  `AXESS_DEV_INSECURE_COOKIES=1`; the sqlite example wires a session registry,
  derives its CSRF key from the session key, rate-limits on `ClientIp`, makes
  tenant- and system-scope factor rows unique (migration `20261028000100`,
  re-embedded by a `build.rs`), no longer replaces an enrolled TOTP factor and
  logs no reset token; the FAPI example runs under the profile, reuses the
  login's DPoP key and logs out through `logout`; the local IdP prints its
  admin token once, requires an audience and survives a huge `ttl_secs`.

### Documentation

- `docs/production/migrating.md` gains the 0.12.0 to 0.13.0 section.
  `SECURITY.md` and the password and TOTP guide state where an OTP secret
  sits at rest and how to seal it; the mTLS docs state that the root store
  holds only the pinned trust domain's bundle; the AES-GCM nonce bound, the
  `jwks_handle` snapshot, the multi-replica rotation procedure and
  `AuditRetentionLoop`'s one-process rule are documented; `require_authz!`'s
  principal needs no tenant-qualified form; the cargo-audit rationale matches
  `deny.toml`, and the preflight fails if the two advisory lists differ.

---

## [0.12.0] - 2026-10-28

### Changed (breaking)

- **`IdentityLookup::get_tenant`** is required. A password reset refuses, and
  keeps the token, when the tenant is missing or not active.
- **`IdentityPasswordReset::check_reset_token`** is required.
  `begin_password_reset` answers `Err(Internal)` for a ttl of 0 or over seven
  days; `complete_password_reset*` answers `Ok(false)` for an unknown user.
- **`SessionStore::update`** is required, and **`SessionStore::cycle`** takes
  `require_old: bool` and returns `CycleOutcome`. A rotation or a save no
  longer revives a session ended mid-request.
- **`RefreshTokenStore::issue_with_eviction(evict_ids, new)` is
  `issue_capped(new, max_per_user)`**: the store counts, evicts and inserts in
  one step. `RefreshError::InvalidConfig` refuses an empty pepper and a cap of
  zero.
- **`AuthnServiceBuilder::with_max_sessions_per_user` takes `NonZeroUsize`.**
- **`SweepConfigBuilder::build` returns `Result<SweepConfig,
  SweepConfigError>`**; sweep windows are whole seconds in every store.
- **`SidMap::insert`, `register_subject_session` and `take_subject_sessions`
  take the IdP subject**, and `take_subject_sessions` returns `(UserId,
  SessionId)` pairs. `take_user_sessions` is removed.
- **`refresh_oauth_token` takes `expected_subject`**; a refresh response for
  another subject is refused and audited as `TokenRefreshProviderRejected`.
- **`DelegatedError::UnsupportedTokenType`**: a non-`Bearer` credential is
  refused.
- **`ArchiveBatchId::from_parts(first, last, count)` is `from_ids(ids)`.**
- **The FIDO2 session keys are `axess.fido2.{auth,reg,disc}_started`**; a
  ceremony begun before the upgrade fails closed.
- **`normalize_recovery_code` drops only whitespace and dashes.**
- **Device blobs are sealed as `AXD\x02` and `AXR\x02`**, with tenant and
  device id length-prefixed. 0.11.0 blobs and unbound blobs still read and are
  re-sealed on read; 0.11.0 cannot read the new format.
- **The Valkey device fingerprint index is a set under `dev:fps`.** The old
  single-id `dev:fp` key is still read, and the next write of the device it
  names moves it into the set. On a cluster, the new keys share the store's
  hash-slot prefix.

### Added

- `RequestContextProvider`: `require_authz!` reads it from the request
  extensions and evaluates with the context it returns; a provider error
  answers 403.
- `LegacyBlobs::{Accept, Reject}`, `SessionCrypto::with_legacy_blobs` and the
  Valkey stores' `with_legacy_blobs`. Sessions and devices re-seal a stale blob
  when they read it, in every store, so legacy rows can be drained and then
  refused.
- `CycleOutcome`, `RefreshTokenConfig::validate`,
  `ValkeySessionRegistry::with_rng`, `SweepConfig::purge_due`,
  `AuditRetentionLoop::drain`, `MemoryJtiCache::with_capacity`,
  `OAuthProvider::refresh_token_for_subject` (provided).
- `axess_factors::http_body`: bounded reads for remote response bodies.
- Live Postgres and MySQL suites for the session and device stores, run by
  CI's ignored-test step.

### Changed (breaking)

- `PolicyStore::digest()` returns a `String` and `PolicyStore::schema()` a `Schema`, because both follow a policy reload; `original_digest()` and `original_schema()` borrow the text the object was built from.

### Fixed

- A passkey deleted between ceremony start and finish no longer logs in, and
  the authentication, registration and discoverable ceremonies are single-use
  and separate. Registration re-checks account status.
- `require_authz!` evaluated every policy with an empty context, so a rule
  reading `context` could never permit; it now uses the provided context.
- A `sub`-only back-channel logout ends the sessions of the IdP subject (it
  had parsed `sub` as a local user id and found nothing for linked users), and
  a logout token's `jti` is remembered for the whole span its `iat` is
  accepted.
- Parallel email-OTP requests cannot bypass the cooldown.
- A refused new password keeps the reset link, and an unknown identifier costs
  the same as a known one.
- One user can no longer fill the rate limiter: at most 16 header buckets per
  user, IPv6 keyed by /64, keys over 256 bytes hashed. The window slides, so
  twice the limit no longer passes across a boundary. The log carries a key
  fingerprint, not the key.
- The KDF permit is held until Argon2 finishes, also when the request is
  dropped.
- Parallel logins converge on the session cap and the refresh-token cap.
- Device stores no longer undo one another's decisions: the memory sweep never
  reapplies a stale decision over a revoke, a save never un-revokes a stored
  row, `record_sighting` never moves time back and skips revoked devices, and
  Valkey rows and their indexes change in one script, with stale index members
  neither listed, revoked nor returned by fingerprint.
- Device finders order by `last_seen_at` descending, then id, in every store; a
  revoked device saved without `revoked_at` is stamped and purged; one
  undecodable row no longer stops a sweep; and a fingerprint stays findable
  while any device in the tenant carries it.
- A guarded trust change whose write missed is retried instead of reported
  applied; a losing bindings swap no longer waits on its own connection.
- The Valkey revocation listener wakes only the watchers of the revoked
  session, rechecks after a lag with jitter, and replaces a dead subscriber.
  `is_valid` no longer prunes a session registered again meanwhile.
- DPoP: a `jwk` with private members is refused, `htm` is compared exactly,
  the iat skew is bounded and checked without overflow, and the `jti` cache
  is bounded.
- Every remote response body is read with a cap: token and PAR 64 KiB,
  userinfo 256 KiB, JWKS and discovery 1 MiB, error bodies cut to 1 KiB.
- Delegated tokens: `expires_in: 0` is already expired, an omitted `scope`
  keeps the requested or stored scopes, and an empty grant state is refused.
- An OAuth login ends displaced sessions only after the login succeeds, and
  runs its registry calls concurrently, at most 16 at a time.
- The audit archive cannot lose a batch on a half-failed rollback; two
  archivers sharing a root cannot write one batch twice (`.archive.lock`); new
  day directories are synced; retention drains a backlog and starts at boot.
- `testing::LocalIdp` installs a JWT crypto provider before signing.

---

## [0.11.0] - 2026-10-25

### Changed (breaking)

- **`DeviceStore` requires `set_trust_level_if`, `replace_bindings`,
  `claim_owner` and `find_by_fingerprint_for_user`; `save`, `replace_bindings`
  and `claim_owner` take the time of the write.** All are conditional writes
  in every backend.
- **`Device` carries `demoted_at`.** SQL stores need an `ALTER TABLE` and a
  `CREATE INDEX` (module docs); Valkey rows carry it in the blob.
- **Device sightings are written at most once per `sighting_granularity`**
  (default five minutes).
- **`record_sighting` and `set_trust_level` answer `NotFound`** for a missing
  device. `ValkeyDeviceStoreError` gains `NotFound`, `Contended`,
  `UnexpectedScriptReply`.
- **Valkey device rows expire by the full ladder** and are sealed to their key.
- **MySQL device and session tables**: ids and `family_id` are `utf8mb4_bin`,
  `devices.bindings` and `sessions.data` are `MEDIUMTEXT` (module docs carry
  the `ALTER`s).
- **`decide_step_up` is removed**; use `decide_step_up_for_user`.
- **Session and device blobs are sealed to their row**; old blobs read and
  reseal on save. `SessionCrypto::encrypt` and `decrypt` are deprecated for
  `encrypt_with_aad` and `decrypt_with_aad`.
- **`SessionStore::cycle` on Valkey is one server-side step.**
- **`ArchiveSink::archive_batch` takes an `ArchiveBatchId`**;
  `AuditRetentionSource::EventId` must implement `Display`.
- **`AuditLogWithAnalytics::new` returns `(Self, AnalyticsWorker)`**; events
  queue on a bounded channel the caller drains (`with_capacity`, `flush`,
  `shutdown`, `dropped_events`).
- **`verify_recovery_code` takes `Option<&RecoveryCodePepper>`**; a keyed row
  without a pepper fails closed.
- **`verify_password` returns `PasswordVerifyError`** (`Malformed`,
  `Mismatch`). `password-auth` is removed; `argon2` 0.6 hashes and verifies
  with the same parameters and output.
- **`AuthnError::Internal` and `AuthFailureReason::IpPolicy` are new
  variants.** An IP-denied login writes an audit row.
- **`OAuthProvider::build_auth_url` and `build_auth_url_par` take `&dyn
  SecureRng`; `generate_dpop_proof` takes `iat` and `jti_bytes`;
  `begin_grant` takes the RNG.** `complete_grant_at(.., now)` is added.
- **`BearerConfig::new(issuers)` with `with_clock`; `BearerTokenLayer::with_clock`.**
  `verify_jwt_signature` is test-only.
- **`SidMap` is a struct** with an insertion-ordered queue and an
  `(issuer, user)` index; `AuthnService::sid_map()` returns it. Capacity
  eviction drops the mapping without ending the session; TTL pruning ends at
  most 128 sessions per login.
- **`verify_logout_jwt` requires `exp`.**
- **`RateLimitConfig` has a public `clock` field.** Windows are clock
  milliseconds; one sweep per `max(window / 8, 1 s)`; at 262,144 buckets a new
  key answers 429 with `Retry-After`. The 64K soft cap is gone.
- **`TraceContextLayer` is a struct** (`TraceContextLayer::new()`).
- **`RefreshTokenConfig::hash_pepper` is `Option<Zeroizing<Vec<u8>>>`**, read
  through `pepper()`.
- **Social login sets the User-Agent on the default client only.**
- **Features:** `oauth` enables `axess-rng`, `subtle`, `chrono`; `fapi`
  enables `sha2`.
- **`CsrfIssuer::token` is the token after rotating a session in a handler**;
  `CsrfToken` keeps the pre-rotation value for that request.

- **`IdentityPasswordReset::verify_reset_token(user_id, token_hash, now)`**
  judges expiry on the instant passed. `MockIdentityStore::with_clock` is gone.
- **SQL session stores keep the session as bytes** in a new nullable
  `data_bin` column (BLOB, BYTEA, LONGBLOB); loads read it first and fall back
  to the legacy text, rewriting on the next save. The `ALTER` is required
  before the new release serves a request (module docs).
- **A cookieless request stores a session and sets a cookie only when
  something needs it**: a modification, a CSRF token shipped, or
  `AuthSession::session_id()` read.
- **`AuditRetentionPolicy::delete_archive_after`, `with_delete_archive_after`
  and `keep_archive_forever` are removed**; the policy is two-stage and the
  cold sink owns its own expiry.
- **`MockOAuthProvider` is behind axess-factors' `testing` feature**, forwarded
  by core's and the facade's `testing`.
- **Cached JWKS keys expire.** `JwksCache::with_max_age` (default 24 h);
  `fresh_handle` refuses an older key set with `OidcError::JwksExpired` and
  `OAuthError::JwksExpired` until a refresh succeeds; ID-token, refresh-token
  and logout-token verification all read the refreshable key set and retry
  once after a refresh on an unknown kid or an expired set.
  `AuthnServiceBuilder::with_jwks_refresh(interval)` and
  `with_default_jwks_refresh()` (1 h) start the loop with the service and stop
  it with the last clone; without the loop, keys expire by `max_age` and
  verification fails closed.
- **`SidMap` carries a subject registry** keyed by issuer and subject that
  every OAuth login enters, with or without a `sid`; a `sub`-only back-channel
  logout ends sid-less and capacity-evicted logins through it. Capacity
  eviction never forgets a live session.
- **`SessionRegistryHandle::liveness` (`SessionLiveness::{Valid, Gone,
  Unknown}`)** is a provided method; the adapter maps a registry error to
  `Unknown`, and only `Gone` lets a subject entry be forgotten.
- **`IdentityAdmin::delete_user` has no default body.** A backend that cannot
  erase does not compile.
- **`SocialProvider::exchange_code` returns a `ZeroizedString`**, zeroed on
  drop; it derefs to `str`.

### Added

- `axess::blocking::KdfExecutor` and `AuthnServiceBuilder::with_kdf_executor`:
  Argon2 runs on blocking threads behind a CPU-count semaphore, inline under
  tests.
- Keyed recovery codes: `RecoveryCodePepper`, `generate_recovery_codes_peppered`,
  `with_recovery_code_pepper`; verified in constant time with no Argon2.
- Injected RNG: `SessionLayer::with_rng`, `CsrfConfig::rng`,
  `LifecycleDeviceResolver::with_rng`, `EncryptedDelegatedCredentialStore::with_rng`,
  `TraceContextLayer::with_rng`, `RngUuidGenerator`, `PiiToken::mint(&dyn
  SecureRng)`, `MemoryDevicePiiStore::with_rng`.
- Injected clock: `JwksCache::with_clock`, `OAuthProviderConfig::with_clock`
  (reaching openidconnect's ID-token checks), `MockOAuthProvider::with_clock`,
  `MemoryRefreshTokenStore::with_clock`,
  `InMemoryBackend::with_clock`; `impl Clock for Arc<C>`.
- `AuthnService::refresh_all_jwks()` and
  `axess_factors::oauth::refresh_providers_jwks`.
- `SignedRequests::max_remembered(n)` (default 100,000); 503 when full.
- `IdentityLookup::get_user_tenant`; `require_valid_session` reads only it.
- `RequestEntityProvider::shared_entities_for -> Arc<Entities>`; both caches
  return the cached `Arc`, `require_authz!` calls it.
- `AuthnMetrics::authz_cache_{hits,misses,evictions,invalidations}(count)`.
- Delegated sessions share one HTTP client; refresh is single-flight per
  tenant, user and provider.
- `AzureFicClient::with_timeout` (30 s default); `AzureFicRequest` zeroes its
  token on drop.
- `AwsStsClient::with_timeout`, `GcpStsClient::with_timeout` and
  `GcpServiceAccountImpersonator::with_timeout` (30 s default, 10 s connect
  timeout on the default client); the bound applies whichever HTTP client is
  supplied.
- `MAX_ID_TOKEN_BYTES` (1 MiB).
- Public: `TrustTransition`, `BindingsUpdate`, `OwnerClaim`, `ArchiveBatchId`,
  `SessionUser`, `JtiLog`, `OWN_DEVICE_SCAN_LIMIT`, `axess::validation`.
- Test support: `testing::CallLog` with `with_call_log` on both mock stores,
  `MockIdentityStore::delete_user`, `user_record_at`, `tenant_record_at`,
  `test_session_with_rng`, `LocalIdpFixture::mint_at`, `mint_jwt_svid_at`.
- `scripts/check-file-sizes.sh`: files at most 800 lines, functions at most
  150, baselined.

- `IdentityAdmin::delete_user` implemented by `InMemoryBackend` (every row
  naming the user; `with_session_registry` ends the sessions too) and by the
  sqlite example.
- `SessionCodec::decode_row` and `encode_bytes`; `SharedSubscriber` behind
  the Valkey registry: revocation watchers share one subscriber connection,
  the last watcher out quits it.
- `DEFAULT_JWKS_MAX_AGE`, `DEFAULT_JWKS_REFRESH_INTERVAL`, `JwksCache::ensure_fresh`.
- `SidMap::register_subject_session`, `take_subject_sessions`,
  `forget_subject_session`, `sweep_subject_candidates`, `subject_len`.

### Changed (breaking)

- `PolicyStore::digest()` returns a `String` and `PolicyStore::schema()` a `Schema`, because both follow a policy reload; `original_digest()` and `original_schema()` borrow the text the object was built from.

### Fixed

- ID-token verification keys refresh: a token signed with a key the IdP
  rotated in after discovery verifies after one refresh, and an unpublished
  key is refused after exactly one.
- A registry outage no longer drops live subject entries from the sid map.
- Argon2 no longer runs on the async executor.
- Every pre-user refusal of `begin_login` makes the same store calls in the
  same order and leaves one audit row.
- Session ids, CSRF nonces, trace and request ids, envelope nonces, device
  ids, PKCE verifiers, states, nonces and DPoP `iat`/`jti` come from the
  injected RNG and clock.
- Bearer, ID-token, logout-token and delegated-refresh lifetimes are judged on
  the injected clock.
- Valkey device writes are compare-and-swap; concurrent bindings edits,
  promotions and passkey writes no longer undo a revocation.
- A Trusted device idle past 90 days is demoted, a demoted device is revoked 30
  days later, a never-trusted device after 30 idle days, in every store.
- A device created during a guest request is owned by its first user.
- A password reset enforces the tenant's password rules.
- A retried audit batch is written once; the retention loop rests a full
  interval between ticks; the filesystem archive writes a batch all or none.
- A retention of `Duration::MAX` keeps everything; analytics receive an event
  only after its regulatory write succeeded.
- The rate limiter, the signed-request replay cache and the DPoP `jti` cache
  no longer scan their tables on every request.
- `require_valid_session` no longer loads the whole user.
- Valkey device reads use one `MGET` per 512 members and prune expired
  members.
- The sid map is pruned in bounded batches by insertion order; back-channel
  logout by subject uses an index.
- DPoP proof generation installs the JWT crypto provider before signing.
- The DPoP proof is parsed once; `at_hash` and `ath` compare in constant time;
  HOTP compares codes numerically; LDAP bind and search are bounded by
  `connection_timeout`; TOTP secret bytes, the CSRF key and the refresh pepper
  are wiped.
- `set_custom` on a non-object session bag no longer panics.
- Session rotation on SQLite and Postgres upserts before deleting; Valkey
  TTLs under one second store as one second; the session registry prunes
  expired members.
- `require_authz!` keeps a `::`-namespaced entity type whole, refuses a
  placeholder in the type position and authorizes a route with no path
  parameters.
- Deleting a device no longer drops another device's fingerprint lookup; a
  device carrying the same refresh family twice saves;
  `find_active_for_user` filters revoked devices before its limit.
- An audit failure on OAuth login ends the session and drops its `sid`
  mapping; a `sub`-only back-channel logout ends only the sending issuer's
  sessions.
- The JWKS cache keeps its keys on an empty refresh and backs off five seconds
  after a failed one.
- `url_with_redirect_query` matches the parameter name; cache entries expire
  at exactly `insert + ttl`; `Issuer::custom` refuses every built-in name;
  `begin_signup` stores the user in the tenant it validated; passkey writes
  commit through `compare_and_save_factor`.
- The public health message names no component.
- Docs match the code: provisioning, step-up defaults, the FIDO2 and
  `into_response` clock exceptions, the detach semantics of the JWKS refresh
  and archive handles, the local IdP TTL cap, the device composition recipe.

---

## [0.10.0] - 2026-10-25

### Changed (breaking)

- **`FactorStore` requires `insert_factor_if_absent`.** Insert the row if no
  row of that kind exists at that scope and answer whether you did.
- **`RefreshToken` has `authn_time: Option<DateTime<Utc>>`**, the original
  sign-in time, copied on rotation. Add a nullable column; `None` reads as
  `issued_at`.
- **`logout` ends only the current session.** Use `invalidate_user_sessions`
  to sign out everywhere.
- **`KeyExtractor::Header` keys within an authenticated identity**, else on
  the peer address. Set `RateLimitUserId` after authentication.
- **`begin_login` answers `InvalidCredentials`** for a user with no methods
  and for a suspended or terminated tenant.
- **`PiiToken::parse` accepts only the hyphenated lowercase UUID form.**
- **`Issuer::custom` refuses `cli`, `jwt_svid`, `mtls` and `oauth`.**
- **`WorkloadId` and `TrustDomain` are validated on deserialize.**
- **Back-channel logout requires `jti`**, and a `sub` logs out only users who
  signed in through the sending issuer with a `sid`.
- **A plain-HTTP `jwks_uri` is refused**, loopback excepted.

### Added

- `decide_step_up_for_user(device, user, policy)`; `decide_step_up` stays and
  ignores ownership.
- `basic_credentials` and `expiry_after` (axess-factors, `outbound-oauth`).
- `EntityState::effective_at(now)`.
- `Issuer::Custom` serializes as `{"kind":"custom","label":"..."}`.

### Changed (breaking)

- `PolicyStore::digest()` returns a `String` and `PolicyStore::schema()` a `Schema`, because both follow a policy reload; `original_digest()` and `original_schema()` borrow the text the object was built from.

### Fixed

- **One-time codes replayed in parallel.** Two concurrent requests with the
  same TOTP, HOTP or email code both passed, including inherited factors;
  parallel first failures counted as one. Exactly one passes and every
  failure counts.
- **Another user's trusted device reused.** A fingerprint match owned by
  someone else returned their trusted device and skipped step-up. A device
  is reused only for its owner.
- **Tenant-scoped OAuth login ignored the tenant.** The expected tenant was
  cleared before the check; a user in another tenant is refused with
  `CrossTenant`.
- **A refreshed session reported `authn_time = now`**, so an old refresh
  chain passed recent-login and step-up checks.
- **`require_authz!` spliced ids into Cedar text.** Quotes, backslashes or
  `\u{..}` in an id could name another principal or resource.
- **A revoked device stayed trusted in the cache** for the TTL; sweeps left
  stale rows cached.
- **Registering a passkey erased existing passkeys** when the store read
  failed; every passkey got the last-used stamp on any login.
- **JWKS error responses replaced the cached keys**; `azp` was unchecked
  with a single-value `aud`; `nbf`, `groups`, `roles` and `sid` were dropped
  from ID tokens, so FAPI login failed and `sid` logout found no session.
- **A failed audit write left the session authenticated** after login,
  signup or impersonation.
- **Timed suspensions never ended**; impersonation and password reset
  accepted inactive accounts; a refused reset spent its token.
- **Local IdP `extra` fields overrode derived discovery fields.**
- **`IpPolicy` let IPv4-mapped IPv6 past an IPv4 denylist**, and skipped an
  unreadable deny entry.
- **OBO exchange and stored grants sent the client secret unencoded**;
  `expires_in` above `i64` panicked, `u64::MAX` wrapped to expired.
- **STS request `Debug` printed the token**; Azure tenant and GCP account
  names were not confined to one URL segment; SPIFFE paths accepted `..`.
- **`find_active_for_user` applied its limit before dropping revoked
  devices.** `max_attempts = 0` disabled the OTP limit. An email code with no
  expiry never expired. Code generation overflowed at 20 digits. Each
  password was recorded twice. `min_length` counted bytes.
- **A zero JWKS refresh interval ended the refresh task.**
  `MemoryStore::prune_expired` underflowed. The first form after a session id
  change failed on submit.

---

## [0.9.0] - 2026-10-24

### Changed (breaking)

- **`RefreshTokenStore::rotate_token` returns `RotationOutcome`.** Revoke
  the parent only while it is live; answer `ParentAlreadyRevoked` otherwise
  and store nothing.
- **`ValidationConfig` has `require_exp`** (default `true`).
- **`ValkeyEntityCache::invalidate` returns `Result`.**
- **MSRV is 1.95.0**, required by `parking_lot` 0.13.
- **Dependencies**: cedar-policy 4.14.0, lru 0.19.0, parking_lot 0.13.0,
  sha2 0.11.1, proptest 1.12.0, rkyv 0.8.18, zeroize 1.9.1, uuid 1.29.0,
  tokio 1.54.1, serde_json 1.0.154.

### Changed (breaking)

- `PolicyStore::digest()` returns a `String` and `PolicyStore::schema()` a `Schema`, because both follow a policy reload; `original_digest()` and `original_schema()` borrow the text the object was built from.

### Fixed

- **A JWT without an integer `exp` was accepted forever.** `exp` is required
  and `exp`/`nbf` must be integers; `require_exp(false)` opts out.
- **A pinned `iss` or `aud` was enforced only when present.** It is required.
- **The replay store forgot a `jti` at `exp`** while the token was still
  accepted within the leeway.
- **An LDAP bind with an empty password passed** as an anonymous success.
- **Discovery accepted `http://localhost.attacker.com`** by prefix. The
  issuer URL is parsed; the document's `issuer` must equal the URL fetched;
  `jwks_uri` follows the same rule; an error status is a failed fetch.
- **Moka authz-cache invalidation did nothing**; a revoked role authorized
  until the TTL.
- **Registered JWT claims could be set as custom claims**; the local IdP
  accepted `issuer` and `jwks_uri` as custom metadata.
- **A failed session cycle left the old session live.**
- **HOTP and TOTP accepted codes under six digits** and a zero TOTP step.
- **Two refreshes racing on one token each minted a live child.** The loser
  is a reuse and revokes the family.
- **A fingerprint-bound session presented without a fingerprint passed.**
- **CSRF checked only POST, PUT, PATCH and DELETE.** Every method outside
  GET, HEAD, OPTIONS and TRACE is checked.
- **Cedar entity ids were unescaped on the authz store path.**
- **Valkey invalidation patterns were not glob-escaped**, and a failed `DEL`
  was discarded.
- **A rate-limit header value could alias a peer address.**
- **`traceparent` accepted uppercase hex, version `ff` and all-zero ids.**
- **The WebSocket revocation watcher outlived its socket.**
- **The bearer 401 body was formatted from the error** rather than encoded.
- **`client_secret_basic` sent the id and secret unencoded.**
- **`mutate_custom` missed an equal-length change.**
- **The entity-cache setters reset each other's settings.**
- **`rustls` requires 0.23.46** (RUSTSEC-2026-0346 to 0349). `Cargo.lock`
  takes rustls-webpki 0.103.16, webpki-roots 1.0.11 and ctutils 0.4.5.
  RUSTSEC-2026-0387 (crypto-bigint 0.5.5) is accepted; see `deny.toml`.

---

## [0.8.1] - 2026-10-15

### Security

- **A policy that errors during evaluation now denies the request**, even
  where another `permit` would allow. Cedar skips an erroring policy, so a
  failing `forbid` let the request through. Logged at error level.
- **`Cargo.lock` takes `quinn-proto` 0.11.19 and `rustls` 0.23.46**
  (RUSTSEC-2026-0338 to 0342, 0346 to 0349). Adopters resolve their own
  versions: run `cargo update -p quinn-proto -p rustls`.

---

## [0.8.0] - 2026-10-02

A step that offers a choice now is one. `AnyOf` was part of the method
model, and the login flow flattened every `AnyOf` to its first choice, so
"TOTP or something else" only ever asked for TOTP. Recovery codes, the
fallback for a lost authenticator, are the first factor that needs the
choice, and arrive with it. Internal service callers get a shared-secret
check to replace hand-written ones. See
[the migration guide](docs/production/migrating/0.7.0-to-0.8.0.md).

### Added

- **Recovery codes, `FactorKind::RecoveryCode`.** `axess-factors` gains
  the `recovery_code` feature (on by default; zero-infra, built on
  `password`; the functions and types are re-exported from `axess`):
  `generate_recovery_codes` mints a set through the injectable
  `SecureRng` (10 codes of 10 characters from a 32-symbol alphabet without
  `0`/`O`/`1`/`I`, 50 bits each, shown as `ABCDE-FGHJK`) and returns the
  plaintext for one-time display beside a `RecoveryCodesConfig` of Argon2id
  hashes; `verify_recovery_code` accepts any spacing, dash or case, checks
  every unspent hash whether or not one matched, and returns the set with
  the matched code spent. In `axess-core` that is
  `FactorConfig::RecoveryCodes` and `FactorCredential::RecoveryCode`, and
  verification returns the spent set as a pass-with-update, so the factor
  store's compare-and-swap makes each code single-use even when two logins
  race on it. Offer it beside the factor it backs up:
  `FactorStep::AnyOf(vec![FactorKind::Totp, FactorKind::RecoveryCode])`.
- **`FactorStep::primary` and `FactorStep::kind_for`**, and
  **`FactorCredential::fits`**: what a step prompts for first, and which
  of its choices a presented credential is for.
- **Shared-secret service callers, `service-secret` feature**, for
  machine callers that cannot hold a key; it is the weakest machine
  credential axess offers, below `jwt` and `mtls`.
  `ServiceSecretLayer::signed` (preferred) verifies an HMAC-SHA256
  signature over timestamp, method, path and body sent by
  `ServiceSigner`, so the secret never travels, and refuses stale and
  replayed requests; `ServiceSecretLayer::bearer` and `::header` accept
  the secret itself. Secrets are named for rotation, at least 32 bytes,
  kept only as derived values and compared in constant time; the handler
  extracts `ServiceCaller`. An unconfigured route answers `404`. See
  [Shared secrets: the last resort](docs/workload-identity/shared-secrets.md).

### Changed

- **Nine example crates become six.** `device` is now
  `cargo run -p axess-example-sqlite --bin device`, `social` is
  `cargo run -p axess-example-oauth --bin social`, and `local_idp` is
  `cargo run -p axess-example-workload-identity --bin local-idp`.
  [`examples/README.md`](examples/README.md) says which to read first.

### Changed (breaking)

- **`AuthState::Authenticating::remaining` is `Vec<FactorStep>`**, the
  method's steps with their choices, not `Vec<FactorKind>`.
  `AuthSession::authenticating_state` returns the steps likewise.
  `verify_factor` verifies a credential as the choice its shape fits (a
  `RecoveryCode` credential fits only `RecoveryCode`; an OTP code fits
  TOTP, HOTP and email OTP, first listed wins); `FactorRequired` and
  `prepare_factor` report the step's first choice, so a UI that prompts
  for TOTP keeps doing so and may offer the alternative. A session saved
  mid-login by 0.7 still loads: its kinds are read as required steps.
  **Migrating:** read `remaining` as steps (`step.primary()` for the
  former value); `AuthSessionTestExt::begin_authenticating` still takes
  kinds.
- **`FactorKind`, `FactorConfig` and `FactorCredential` each gain a
  variant** (`RecoveryCode`, `RecoveryCodes`, `RecoveryCode`).
  **Migrating:** add the arm to exhaustive matches; a store mapping kinds
  to strings maps `"recovery_code"`.

---

## [0.7.0] - 2026-09-25

Working out where a request came from is now one answer, resolved once by
a layer, carrying its own provenance. Reaching it used to cost a policy
engine, so five consumers each did it their own way and two of them
believed a header the caller writes.

### Changed (breaking)

- **Client-address resolution moved to `axess::client_ip`, ungated.**
  It was in `axess::authz`, behind the feature that pulls `cedar-policy`.
  **Migrating:** import `TrustedProxies` and `CidrParseError` from
  `axess::client_ip`; the walk is `TrustedProxies::client_ip`; wrap the
  router in `client_ip::layer` and serve with
  `into_make_service_with_connect_info::<SocketAddr>()`.
  `ip_from_headers_trusted` and `ip_from_headers_untrusted` are gone;
  walking from the right is correct wherever reading the leftmost entry
  was, and correct where it was not.

- **The authenticating methods are on `RequestAuthnService`.**
  `AuthnService::with_audit_context` returns it; `begin_login`,
  `verify_factor`, `logout`, the signup, reset, impersonation,
  admin-status, FIDO2 and OAuth-completion calls live there. It derefs to
  `AuthnService`, so the rest of the surface is reachable through it.
  **Migrating:** keep the `AuthnService` in application state and derive
  one per request.

- **`begin_login` no longer takes `client_ip`.** The address comes from
  the handle. **Migrating:** drop the argument.

- **`AuditContext` is an extractor.** `extract_audit_context` and its
  `_async`, `_untrusted` and `_async_untrusted` variants are gone; two of
  them read `X-Real-IP` and believed it. **Migrating:** take
  `audit: AuditContext` in the handler.

- **`AuditContextPolicy`, `AuthnError::MissingAuditContext` and
  `AuthnMetrics::audit_context_missing` are removed.** The wiring they
  checked at runtime is a compile error now. **Migrating:** delete the
  `with_audit_context_policy` call; there is no replacement.

- **`KeyExtractor::ForwardedIp` is `KeyExtractor::ClientIp`**, reading
  what the layer resolved rather than two caller-writable headers.
  **Migrating:** install the layer, or every request shares one bucket.

- **`TrustedProxies::client_ip` returns `ClientIp`, not `Option<IpAddr>`**,
  and `trusts` is now `trusts_peer` and `trusts_hop`: peer trust and chain
  trust are different questions. **Migrating:** call `.get()` for the
  address; `private_transport()` is the policy for a transport with no
  checkable peer, such as a unix socket.

- **`X-Real-IP` is no longer read unless you say your proxy overwrites
  it.** A trusted peer that sets neither forwarded header left this one in
  the caller's hands, which is the forgery the module exists to prevent;
  Caddy never sets it at all. **Migrating:** if your proxy does overwrite
  it (nginx's `proxy_set_header X-Real-IP $remote_addr`), call
  `TrustedProxies::proxy_overwrites_real_ip()`. Otherwise the peer is the
  answer, as it should have been.

- **`request_id` comes from the request-id layer, not the `X-Request-Id`
  header.** 0.6.0 read the header directly and ungated, so a deployment
  that had never enabled `request-id` still recorded whatever a caller put
  there. **Migrating:** nothing, if you run `RequestIdLayer` under the
  `request-id` feature; the id is the same one. Without that feature
  `request_id` is now `None` rather than a caller-supplied string.
  `middleware::request_id::RequestId` is public so a custom `HEADER_NAME`
  deployment can read the typed value, and `accept-client-id` validates an
  upstream id before it reaches the context.

- **`axess::federation::jwt` is `axess::jwt`**, gated on `jwt` rather than
  `oauth`. `features = ["jwt-svid"]` previously left no path to the
  resolver it compiled.

### Added

- **`ClientIp::source()` returns `Source::{Unknown, Peer, Forwarded,
  Supplied}`**, and `AuditContext` and `AuthEvent` carry it as `ip_source`.
  `unknown` means the layer is not installed; `peer` where a proxy runs
  means the trusted set does not name it. Add the column and query it.

- **`ClientIp::resolved`** for a front end axess cannot check: Cloudflare's
  `CF-Connecting-IP`, Fly's `Fly-Client-IP`, a service mesh. Insert it in
  your own middleware; it stamps `Source::Supplied`.

- **`AuditContext` and `AuthEvent` carry `trace_id`**, from `TraceContext`
  under the `trace-id` feature.

- **`IpPolicy::restricts`** and **`MockIdentityStore::with_ip_policy`**.

### Changed (breaking)

- `PolicyStore::digest()` returns a `String` and `PolicyStore::schema()` a `Schema`, because both follow a policy reload; `original_digest()` and `original_schema()` borrow the text the object was built from.

### Fixed

- **A tenant IP allowlist could be switched off by the caller.**
  `begin_login` enforced the tenant's `IpPolicy` only when passed an
  address, and 51 of the 52 call sites here passed `None`. A restricting
  policy now refuses a request whose address did not resolve; an empty
  policy is unaffected. **Migrating: if any tenant has an `IpPolicy`,
  install `client_ip::layer` before upgrading, or their logins fail
  closed.**

- **The device gate's `client_ip_fn` returned `None` unconditionally.** It
  reads the resolved address now.

- **The `sqlite` example wrote audit rows with no client IP on four of its
  six audited calls**, including the failed-password row.

- **The mTLS chapter documented a factor that was never built**, down to a
  `FactorCredential::Mtls` variant. Rewritten to the terminator-and-gate
  shape axess supports, and moved to Part VIII.

### Dependencies

- `thiserror` 2.0.20 -> 2.0.21, `tokio-test` (dev) 0.4.5 -> 0.4.6.

---

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

  ```rust,ignore
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

### Changed (breaking)

- `PolicyStore::digest()` returns a `String` and `PolicyStore::schema()` a `Schema`, because both follow a policy reload; `original_digest()` and `original_schema()` borrow the text the object was built from.

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

---

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

### Changed (breaking)

- `PolicyStore::digest()` returns a `String` and `PolicyStore::schema()` a `Schema`, because both follow a policy reload; `original_digest()` and `original_schema()` borrow the text the object was built from.

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

### Changed (breaking)

- `PolicyStore::digest()` returns a `String` and `PolicyStore::schema()` a `Schema`, because both follow a policy reload; `original_digest()` and `original_schema()` borrow the text the object was built from.

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

### Changed (breaking)

- `PolicyStore::digest()` returns a `String` and `PolicyStore::schema()` a `Schema`, because both follow a policy reload; `original_digest()` and `original_schema()` borrow the text the object was built from.

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

### Changed (breaking)

- `PolicyStore::digest()` returns a `String` and `PolicyStore::schema()` a `Schema`, because both follow a policy reload; `original_digest()` and `original_schema()` borrow the text the object was built from.

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

---

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
