# Welcome

Axess authenticates users and non-human callers in
[Axum](https://github.com/tokio-rs/axum) applications: a session layer,
factor verification, cookies, policy evaluation. Three decisions make it
different from the alternatives.

**A session is never half logged in.** Authentication state is a typed
enum, and a partially-completed login is its own variant
(`Authenticating`), not an `Authenticated` session with a flag unset. A
handler cannot mistake one-factor for finished, because the type does not
allow it.

**No clock or RNG is read directly.** Session ids, OTP windows and lockout
expiry all go through a `Clock` or `SecureRng` trait: the system in
production, a controlled sequence in tests. A whole login flow, side
effects included, runs in a unit test with no infrastructure and no
flakes. That is what makes a token-issuance race a failing test rather
than a postmortem.

**Authorisation is Cedar policy, not scattered role checks.** Declarative,
schema-validated, deny-by-default, in policy files rather than handlers.
Your code asks and gets an `AuthzDecision`, so reviewing the rules is one
artifact review instead of a hunt across handlers.

Ten small crates, so an adapter you do not use is an adapter you do not
compile. The split also draws the line that matters most: per-credential
algorithms in `axess-factors`, the state machine and federation machinery
in `axess-core`. The next chapter covers it.

## What axess is not

- **Not a SaaS.** No hosted control plane, and your application keeps
  owning its user data.
- **Not an Identity Provider**, in its primary use. In OAuth and OIDC
  terms axess is the Relying Party: it delegates identity to an external
  IdP and runs a session on the resulting tokens. Point it at Keycloak,
  Ory Hydra, Okta, Entra ID or whatever you already run. Later chapters
  use RP and OP for those two roles. The `local-idp` feature does mint
  workload JWTs in-process, but that is service-to-service issuance, not
  a user-facing OP.
- **Not an HTTP server.** Axum is; axess is a Tower layer plus
  extractors, and your code owns the lifecycle.
- **Not a general-purpose session library.** The session machinery serves
  the authentication state machine. If you want HTTP sessions without
  authentication or authorisation, smaller libraries do it better.

## The workspace, in one table

The crate split is structural, and the table below is a fair
approximation of which one you reach for in any given situation. The
chapter *Architecture at a glance* expands on the dependency direction
and the rules that keep leaf crates from depending on the orchestrator.

| Crate | Role |
|---|---|
| `axess` | Facade. Re-exports the public API. Application code depends on this. |
| `axess-core` | Session state machine, `AuthnService`, `AuthzStore`, federation adapters (OAuth, OIDC, LDAP, mTLS, FIDO2, JWT, K8s SA, GitHub OIDC), device identity, OBO/delegated access, middleware, storage backends. The orchestrator. |
| `axess-factors` | Per-credential verifier primitives: Argon2id, TOTP, HOTP. Composable on their own. |
| `axess-identity` | Typed IDs (`UserId`, `TenantId`, `WorkloadId`) and the `Principal { Human, Workload }` enum. |
| `axess-events` | Audit event payloads and async sinks. |
| `axess-cache` | TTL+LRU cache with single-flight. Used by the Cedar entity cache and the OIDC JWKS cache. |
| `axess-clock` | `Clock` trait, `SystemClock`, `MockClock`. The DST time foundation. |
| `axess-rng` | `SecureRng` trait, `SystemRng`, `MockRng`. The DST entropy foundation. |
| `axess-strings` | `ShortString`, an immutable identifier: inline to 22 bytes, `&'static str` in place, or shared behind an `Arc`. |
| `axess-macros` | `require_authn!`, `require_partial_authn!`, `require_authz!` procedural macros. |

## When to reach for axess

Axess fits when at least two of these hold:

- **Multi-factor authentication that varies** per user or per tenant.
  The most common driver: composing factors and threading the result
  through a typed state machine is the value over a session library.
- **Policy-driven authorisation** in one language across roles,
  relationships and contextual conditions.
- **Multi-tenancy.** Factors, methods and policies scope at three tiers
  (`System`, `Tenant`, `User`) by default.
- **Device identity, workload identity or delegated access.**
- **A regulated industry.** The audit trail is shaped as evidence, and
  there is FAPI 2.0 conformance work behind it.

It does not fit a single-factor session, a hosted IdP, or a non-HTTP
protocol: the state machine is shaped against Axum extractors and
middleware. Each has better answers elsewhere.

## Where to read next

- **Evaluating?** Read *Architecture at a glance* next: the
  verifier-versus-orchestrator line, the dependency direction, the three
  state slices in a request, and the DST mechanics underneath. Twenty
  minutes there saves an hour in every chapter after.
- **Integrating?** *Getting started* walks a minimal Axum application
  end to end, and `examples/sqlite/` is the production-shaped version
  with a real database, encrypted sessions, two-factor login, rate
  limiting, health checks and metrics.
- **Inherited an integration?** The navigation is grouped by concern.
  Parts II and V carry the day-to-day surface; the rest is reference.
- **Deploying?** Read *Security posture* and *Operations runbook* first.
  The defaults are conservative for development, and production has
  knobs that must be set explicitly. Both chapters name them.

## Status

Axess is [published on crates.io](https://crates.io/crates/axess); that
page carries the current version. The 0.x line is pre-1.0: minor versions
may break source compatibility, and each break is catalogued in
[*Migration guide*](../production/migrating.md). The goal post-1.0 is to
maintain the SemVer discipline Rust libraries are held to elsewhere.

Vulnerability reports go through the private channel described in
[`SECURITY.md`](https://github.com/GnomesOfZurich/axess/blob/main/SECURITY.md).
Please do not file security issues on the public GitHub tracker.
