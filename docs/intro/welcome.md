# Welcome

Axess is a library for authenticating users (and non-human callers) in
[Axum](https://github.com/tokio-rs/axum) applications. Most of what it
offers is not unusual: a session layer, factor verification, cookies,
policy evaluation. What makes it interesting is what those pieces refuse
to do, and what the refusals add up to.

The first refusal is the most consequential. A session in axess is never
"half logged in". The authentication state is a typed enum with five
variants, and a partially-completed login is one of those variants
(`Authenticating`) rather than an `Authenticated` session with a missing
flag. Handlers that receive a session cannot mistake a one-factor login
for a finished one because the types do not permit it. Code reviewers
reading a handler do not need to model which fields are populated when;
the variant they match on tells them what is in scope and what is not.

The second refusal concerns time and entropy. Production authentication
code is full of both: session identifiers come from the operating
system's random source, one-time-password windows are measured against
the wall clock, account lockout clears on a schedule. None of that goes
through the operating system directly in axess. Every wall-clock read,
every random byte, is sourced from a `Clock` or `SecureRng` trait whose
production implementation delegates to the system and whose test
implementation reproduces a controlled sequence. The same login flow,
including all its side effects on the session registry and the audit
log, runs in a unit test without infrastructure and without flakes. The
discipline is called deterministic simulation testing, and it is the
reason a race condition between token issuance and use can become a
failing test rather than a postmortem.

The third refusal is to ship scattered `if user.role == "admin"` checks
as the authorisation story. Cedar Policy, the policy language axess uses
for authorisation, is declarative, schema-validated, deny-by-default,
and one language for what most codebases split between role checks,
ownership checks, and contextual rules. Policies live in policy files,
not in handlers. The Rust code asks the question and receives an
`AuthzDecision`. Reviewing the policy set is then a single artifact
review, not a hunt across handlers.

Most of the rest of axess follows from these three decisions, in
combination with one structural choice: the library is split across
ten small crates so adopters who do not need (say) a given
federation adapter do not compile its dependencies. The split is
also the verifier-versus-orchestrator boundary in code. Per-credential
algorithms live on one side (`axess-factors`), the state machine,
composition, and federation machinery live on the other (`axess-core`).
The split is the most important line in the workspace, and it is
described in detail in the next chapter.

## What axess is not

It helps to know the boundaries. Axess is not a SaaS, has no hosted
control plane, and does not own your user database. It is a library
your application depends on, and your application keeps owning its data.
It is not an Identity Provider in its primary use. In OAuth/OIDC
terms axess is the Relying Party (the application that delegates
identity to an external IdP and runs a session on the resulting
tokens), not the OpenID Provider (the IdP itself, with login UI,
consent screens, and user database). For the OP role, point axess at
Keycloak, Ory Hydra, Okta, Azure AD, or whatever SSO your
organisation already runs. The `local-idp` feature does mint workload
JWTs in-process, but that is on-host service-to-service issuance, not
a user-facing OP; *Local IdP* covers the surface. It is not an HTTP
server. Axum is the HTTP server; axess plugs into it as a Tower layer
plus a set of extractors, and your code is what owns the lifecycle. It
is not a general-purpose session library. The session machinery is in
service of the authentication state machine, not the other way around;
if all you need is HTTP sessions without authentication or
authorisation, smaller libraries do that better.

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
| `axess-strings` | Shared string newtypes (`Arc<str>` interning). |
| `axess-macros` | `require_authn!`, `require_partial_authn!`, `require_authz!` procedural macros. |

## When to reach for axess

Axess fits when at least two of the following are true. Multi-factor
authentication that varies per user or per tenant is the most common
driver, because composing factors and threading their result through a
typed state machine is the value over a single-factor session library.
Policy-driven authorisation in one language, across roles, relationships,
and contextual conditions, is the second. Multi-tenancy is the third,
since axess scopes factors, methods, and policies at three tiers
(Global, Tenant, User) by default. Device identity, workload identity,
or delegated access are the fourth, fifth, and sixth, in the order most
adopters need them. Regulated industries land here for the audit
pipeline and FAPI 2.0 conformance work, because the trail axess emits is
already shaped as evidence.

It does not fit when a single-factor session is all you need. It does
not fit when you want a hosted IdP. It does not fit when your protocol
is not HTTP, because the state machine is shaped against Axum extractors
and middleware. Each of these has better answers elsewhere.

## Where to read next

If you are evaluating axess, the next chapter is the one to read.
*Architecture at a glance* covers the verifier-versus-orchestrator line,
the dependency direction, the three independent state slices that make
up a request, and the DST mechanics that ride underneath. Twenty
minutes there will save an hour in every chapter after.

If you are starting an integration, jump to *Getting started*. It walks
through a minimal Axum application end-to-end and points at
`examples/sqlite/` for the production-shaped version with a real
database, encrypted sessions at rest, two-factor login, rate limiting,
health checks, and metrics.

If you have inherited an existing axess integration, the left-hand
navigation is grouped by concern. Parts II and V (Authentication and
Sessions) carry most of the day-to-day surface; the rest reads as
reference and can wait until you need it.

If you are responsible for the production deployment, read *Security
posture* and *Operations runbook* before launch. The defaults in code
are conservative for development; production has specific knobs that
must be set explicitly, and both chapters name them.

## Status

Axess is published on crates.io at `v0.2.1`. The 0.x line is pre-1.0:
minor versions may break source compatibility, and each break is
catalogued in [*Migration guide*](../production/migrating.md). The goal
post-1.0 is to maintain the SemVer discipline that Rust libraries are
held to elsewhere.

Vulnerability reports go through the private channel described in
[`SECURITY.md`](https://github.com/GnomesOfZurich/axess/blob/main/SECURITY.md).
Please do not file security issues on the public GitHub tracker.
