# Factors and methods

A factor is a single credential check: a password, a TOTP code, a
WebAuthn assertion, an LDAP bind, an OAuth token exchange. A method is
a sequence of factors that together count as a successful login.
Composing factors into methods, and scoping methods to apply per-user
or per-tenant rather than globally, is the day-to-day surface adopters
work with. This chapter explains the vocabulary, the types that carry
it, and the pattern for adding a factor that axess does not ship.

## Vocabulary

The four words that recur are factor, step, method, and scope. They
sound interchangeable in casual writing, and they are not in the code.

A *factor* is one credential verifier, identified by a `FactorKind`
variant: `Password`, `Totp`, `Hotp`, `EmailOtp`, `Fido2`, `LdapBind`,
or `Federated(FederatedProvider)`. Each factor has a config struct
(`PasswordConfig`, `TotpConfig`, and so on) that the relevant adopter
seeds at provisioning time and the service reads at verification time.

A *step* is one node in a method. A step is either a `Required(kind)`
demand for a specific factor, or an `AnyOf(vec![kind1, kind2, ...])`
disjunction that lets the user choose among several factors at that
position. The step is the unit of authoring; a method is a sequence
of steps.

A *method* is an ordered sequence of steps with a stable name. Examples
in the wild: "password-only" (one step, `Required(Password)`),
"password-then-TOTP" (two steps, `Required(Password)` then
`Required(Totp)`), "password-then-second-factor"
(two steps, `Required(Password)` then `AnyOf(vec![Totp, Fido2,
EmailOtp])`). The name matters because the session records which
method is in progress, and the audit trail names the method when
recording success or failure.

A *scope* is the tier at which a method is configured. There are three
tiers (Global, Tenant, and User), covered in detail in *Scope
hierarchy*. The short version: a global default applies everywhere; a
tenant can override it; a user can override the tenant. Resolution is
the simple inversion of authority: user override beats tenant override
beats global default.

## The factor list

The current `FactorKind` enum and its companion config sum-type live in
[`axess-core/src/authn/factor.rs`](https://github.com/GnomesOfZurich/axess/blob/main/axess-core/src/authn/factor.rs).

```rust,ignore
pub enum FactorKind {
    Password,
    Totp,
    Hotp,
    EmailOtp,
    Fido2,
    LdapBind,
    Federated(FederatedProvider),
}

pub enum FederatedProvider {
    Github,
    Google,
    Microsoft,
    Custom(String),
}

pub enum FactorConfig {
    Password(PasswordConfig),
    Totp(TotpConfig),
    Hotp(HotpConfig),
    EmailOtp(EmailOtpConfig),
    Fido2(Fido2Config),
    LdapBind(LdapBindFactorConfig),
    // Federated configs live with their provider's verifier crate.
}
```

`FactorKind` is the discriminator the state machine carries.
`FactorConfig` is the data the verifier needs. They mirror each other
because the verifier-versus-orchestrator split (see *Architecture at
a glance*) puts the algorithm and its config in `axess-factors` and
puts the discriminator and the composition machinery in `axess-core`.
A new factor lands as a new `FactorKind` variant, a new `FactorConfig`
variant, and a new verifier crate (or module) under `axess-factors`.

The federated case is intentionally a parameterised variant rather
than a flat list. Each federated provider has its own configuration
shape (Google's audience claim differs from GitHub's; Microsoft adds
tenant directory parameters), and the wire formats are different
enough that flattening them into one enum would require a discriminator
inside the config. Parameterising the kind itself makes the config
sum-type smaller and the type system honest about the variation.

`Custom(String)` is the extension point for IdPs the upstream library
does not name explicitly. Adopters who federate against Okta, Auth0,
Azure AD as a generic OIDC provider, or an in-house IdP plug in with
the OAuth-RS resolver and a custom string identifier; the workload
identity chapter (*Workload identity overview*) describes the same
pattern from the inbound-resolver side.

## How factors compose

The composition primitives are `FactorStep` and `Method`. A `FactorStep`
is one node in a method. A `Method` is a vector of steps plus a name.

```rust,ignore
pub enum FactorStep {
    Required(FactorKind),
    AnyOf(Vec<FactorKind>),
}

pub struct Method {
    pub name: Arc<str>,
    pub steps: Vec<FactorStep>,
}
```

The two-step `Required(Password)` then `AnyOf(vec![Totp, Fido2])`
method handles a common shape: the user must enter their password,
then must complete one of two second factors, and the choice of second
factor is theirs (perhaps because they have not registered a passkey
yet, or perhaps because their phone is at home and they only have
their hardware key with them). The state machine's
`Authenticating::remaining` field carries the residue of steps yet to
complete: after the password step, `remaining` looks like
`[AnyOf(vec![Totp, Fido2])]` and the application's login page renders
the choice between them.

`Required(kind)` is shorthand for a one-element `AnyOf(vec![kind])`,
but the distinction matters for audit clarity. A successful login that
went `password + totp` reads cleanly when the audit log records
"completed `Required(Totp)`"; the same login through an `AnyOf` step
records "completed `AnyOf::Totp`" and a reviewer asks why the choice
was offered at all. Use `Required` when there is no choice.

The orchestrator does not support arbitrary expression trees of
factors (you cannot say "two of these three" with a single step). The
omission is on purpose. Real authentication methods are short sequences
with at most one decision point per step, and admitting arbitrary
expressions would invite policies that pass formal review but defeat
operational understanding.

## The verify_factor path

Application code drives factor verification through
`AuthnService::verify_factor`. The signature is

```rust,ignore
pub async fn verify_factor(
    &self,
    credential: &FactorCredential,
    session: &AuthSession,
) -> Result<FactorOutcome, AuthnError<I::Error>>;
```

with `FactorCredential` the runtime credential value:

```rust,ignore
pub enum FactorCredential {
    Password(ZeroizedString),
    OtpCode(Arc<str>),
    Fido2Assertion(serde_json::Value),
}
```

and `FactorOutcome` the result of the call:

```rust,ignore
pub enum FactorOutcome {
    Authenticated,
    FactorRequired(FactorKind),
    InvalidCredential,
    Locked { until: Option<DateTime<Utc>> },
}
```

The handler in your application takes the credential off the request
(form body, JSON, header, whatever), wraps it in the right
`FactorCredential` variant, and calls `verify_factor`. Three things
then happen inside the service.

First, the service acquires the session's write lock and reads its
current state. If the state is not `Authenticating`, the call returns
an `AuthnError`. If the state is `Authenticating`, the service inspects
`remaining` to determine which factor is expected next. A mismatch
between the credential the client supplied and the factor the method
expects returns `FactorOutcome::InvalidCredential` without engaging
the verifier, which keeps the cryptographic cost of failed attempts
predictable.

Second, the service dispatches to the appropriate verifier in
`axess-factors`. The password case calls Argon2id. The TOTP case calls
the RFC 6238 verifier with the user's stored secret and the current
window. The FIDO2 case calls the WebAuthn ceremony, which is itself
stateful and threads through the session's challenge field. Federated
cases dispatch to their respective OAuth or OIDC handlers.

Third, the service translates the verifier's result into a
`FactorOutcome` and an `AdvanceOutcome` from the state machine. A
successful verification calls `AuthState::advance_factor`, which
returns `Completed` if no factors remain (the orchestrator promotes
the session to `Authenticated`) or `StillAuthenticating` if more
factors are required (the orchestrator leaves the state in
`Authenticating` and returns `FactorOutcome::FactorRequired(kind)`
with the next expected kind). A failed verification increments
`attempt_count`, updates `last_attempt`, and returns
`FactorOutcome::InvalidCredential` or `Locked` depending on the
attempt policy.

The `Locked` outcome is the lockout decision in band. The
`until: Option<DateTime<Utc>>` field carries the unlock time when one
is scheduled (a five-minute exponential backoff after three attempts,
for instance) or `None` when the lockout requires administrative
intervention. The application surfaces this to the user with the right
copy; the audit log records the lockout regardless.

## Begin and complete

`verify_factor` is the verb that drives a method forward, but a login
also has a start and an end. The start is `AuthnService::begin_login`,
which transitions a `Guest` session into `Authenticating`. The end is
the orchestrator's promotion of `Authenticating` to `Authenticated`
when the last factor completes (or to `PendingWorkflow` when a workflow
is in progress).

`begin_login` does three things that are worth naming explicitly.
First, it looks up the user in the configured identity store, in the
tenant that the caller named, and returns `UserNotFound` if no user
matches. Second, it loads the method that applies to that user under
the scope hierarchy (covered in *Scope hierarchy*); the result is the
specific sequence of steps the user will walk. Third, it transitions
the session into `Authenticating` with the loaded method's
`remaining` set to the method's full step list.

`complete_signup` is the corresponding verb for the `PendingWorkflow`
case. After a signup ceremony completes (email verified, KYC checks
passed, terms accepted), the orchestrator transitions the session
from `PendingWorkflow { kind: Signup, ... }` to `Authenticated`. The
factor list on the resulting `Authenticated` variant is the list that
was used during the signup, which is what the audit trail wants and
what subsequent policy evaluation reads.

## Adding a custom factor

The pattern for adding a factor that axess does not ship is the same
pattern that produced the factors that axess does ship. There are
four moving parts.

The first part is the verifier itself. It lives in `axess-factors`
(or in a separate crate that depends on `axess-factors`) and exposes
a function or trait that takes the stored config plus the runtime
credential and returns a verifier-side result. For a hash-based
factor this is straightforward (compute the hash, constant-time
compare); for a ceremony-based factor (FIDO2, OAuth) the verifier
threads through the session-side challenge and the response.

The second part is the `FactorKind` variant. Adding a variant is a
breaking change to the public surface, which is what you want: any
match on `FactorKind` in adopter code now flags a missing arm, and the
adopter chooses to handle the new factor or to reject it with an
explicit pattern. There is no "add a variant silently" mechanism in
axess, and that omission is intentional.

The third part is the `FactorConfig` variant and the storage adapter
that loads it. The factor config goes into the configured factor
store; the load path resolves the scope (Global, Tenant, User) and
returns the right config for the user being authenticated. Adopters
implement the factor store, so the storage decision is theirs.

The fourth part is the credential type. A new factor that requires a
new shape of input adds a variant to `FactorCredential`. A factor
that maps to one of the existing variants (a password-like factor
reuses `Password`, a code-based factor reuses `OtpCode`) avoids the
addition.

The work is small. The factors that axess ships today each take fewer
than a thousand lines of Rust including tests. The reason the work
stays small is that the orchestration and the state machine do not
change; the verifier is doing one job, behind a fixed contract.

## Step-up authentication

Step-up is the pattern where an already-`Authenticated` session is
asked to re-prove identity (or to prove with a stronger factor) before
performing a sensitive action. Axess models this by transitioning the
state from `Authenticated` back to `Authenticating` with a non-empty
`remaining` list. The orchestrator method that drives this is
`AuthnService::require_step_up`, which takes the session and the
factor or factors the caller demands.

The state-machine view is uniform. The session is `Authenticating`
again; the factor list contains the stepped-up factors; the session
remembers (in `completed`) which factors it already cleared.
`verify_factor` works the same way it did during the original login,
and on the final `Completed` outcome the session transitions back to
`Authenticated` with a fresh `authn_time` and an updated
`factors_completed`.

The application controls when step-up is required. The Cedar policy
engine can express "this action requires `Fido2` in
`factors_completed`" (see *Cedar policy fundamentals*), or the
handler can demand it directly. The state machine does not impose a
policy; it provides the shape that lets the policy be enforced.

## What this enables

A method composed of a `Required(Password)` followed by an
`AnyOf(vec![Totp, Fido2, EmailOtp])` covers an enormous share of real
deployments without any further structure. A per-tenant override for
a specific tenant that requires `Required(Fido2)` instead of the
disjunction covers the rare case where one tenant must be stricter.
A per-user override that adds `Required(EmailOtp)` for a flagged user
covers the regulatory case where one user is on a watch list.

None of these require new code beyond an entry in the method store.
The state machine, the verifier dispatch, and the audit pipeline all
read the method out of the configured scope and execute it. The next
chapter, *Scope hierarchy*, covers the configuration tier in detail.

## Further reading

*Scope hierarchy* covers Global, Tenant, and User configuration tiers
and how `begin_login` resolves them at runtime. *Cedar policy
fundamentals* covers how the policy engine reads
`factors_completed` and authorises against it. Part III, *Factor
cookbooks*, has a chapter per real-world factor (*Password and TOTP*,
*FIDO2 and WebAuthn passkeys*, *OAuth 2.0 and OIDC*, and so on) that
walks through the integration details one factor at a time.
