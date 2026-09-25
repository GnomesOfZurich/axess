# Migration guide

Find your version below; the newest is first. Each break is listed by
**what you will see** rather than by what we changed, because a compile
error, a failed deserialization and a behaviour that quietly differs
send you looking in different places. Each one names the symptom and the
fix.

The behaviour changes are the ones to read closely. Nothing tells you
about those.

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
axess = { version = "0.7", features = ["request-id"] }
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

Note that `IdentityAdmin::delete_user` still has a panicking default. It is
not called by any axess flow: you reach it only by calling it yourself
but override it before you rely on it for GDPR erasure.

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
