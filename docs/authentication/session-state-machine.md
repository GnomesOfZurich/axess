# The session state machine

`AuthState` is the most important type in axess. Everything that matters
about an authenticated session, both for the type system and for a
reviewer reading a handler, is captured by which of its five variants
you are looking at. The library is built on the
claim that authentication is not a boolean, not a
flag column, and not a row in a sessions table that the handler reads
and then trusts. It is an enum, transitions on the enum are methods on
the enum, and a partial login is a distinct variant rather than a
"finished" session with one field missing.

The split between the pure state machine and its orchestration keeps
the machine independently testable.

## The five variants

The enum lives at
[`axess-core/src/session/data.rs`](https://github.com/GnomesOfZurich/axess/blob/main/axess-core/src/session/data.rs)
in the workspace. Each variant carries exactly the data its phase needs.
There is no field on `Authenticated` for "current factor being verified"
because at that point no factor is in progress, and there is no field
on `Guest` for "tenant" because no user has been identified yet. The
absence is the point.

```rust,ignore
pub enum AuthState {
    Guest,

    Identifying {
        user_id: UserId,
        tenant_id: TenantId,
    },

    Authenticating {
        user_id: UserId,
        tenant_id: TenantId,
        method_name: Arc<str>,
        remaining: Vec<FactorStep>,
        completed: Vec<(FactorKind, Timestamp)>,
        attempt_count: u32,
        last_attempt: Option<Timestamp>,
        flow: AuthFlow,
    },

    Authenticated {
        user_id: UserId,
        tenant_id: TenantId,
        authn_time: Timestamp,
        signed_in_at: Timestamp,
        factors_completed: Vec<(FactorKind, Timestamp)>,
    },

    PendingWorkflow {
        user_id: UserId,
        tenant_id: TenantId,
        workflow: WorkflowState,
    },
}
```

`Guest` is the default. A request with no cookie, or a cookie whose
session has been logged out or expired, arrives at the handler with an
`AuthSession` whose state is `Guest`. There is no user identity in
scope.

`Identifying` is the brief intermediate state for flows that prompt for
a username before asking for any credential. Most applications skip it
and go straight from `Guest` to `Authenticating`. It exists for the
two-page login pattern where step one collects the identifier and step
two collects the password, possibly with the identifier carried over a
hidden form field or a short-lived intermediate token. The variant
records who is being identified but says nothing about credentials.

`Authenticating` is the state in which factors are verified. The session
knows seven things: who it is trying to authenticate, which method is in
progress, what factors are still required, what factors have already
been verified this attempt, how many credential attempts have been
made, when the last attempt landed, and what the pending step is for.

The method is recorded because a tenant might have several, and the
choice is locked in before any factor runs. `attempt_count` and
`last_attempt` exist because lockout decisions depend on them. A method
that allows three attempts before locking the user out for fifteen
minutes needs exactly this information, and putting it in the variant
rather than in a side table keeps the decision local and reviewable.

The last field is `flow`, an `AuthFlow`: `Login` for a login in progress,
`StepUp` for a session that was signed in and is asked for another
factor. Both wait in this state and both finish through `verify_factor`,
so the state records which it is. `AuthSession::step_up_pending` reads
it, so a route that finishes a step-up can refuse a login in progress,
whatever the login's method is called.

A step-up carries the `signed_in_at` of the signed-in state it began from
(`AuthFlow::StepUp { signed_in_at }`). Until its factor is verified the
session is still that signed-in session, and the session layer checks it
as one on every load: against the registry, the absolute age cap from its
login, and the impersonation cap. A login in progress is in no registry
yet and is not checked.

`Authenticated` is the terminal success state. It carries the user id,
the tenant id, two times (`signed_in_at` and `authn_time`, described
below), and the list of factors that were used, each with the time it
was verified. Audit events record that list. The factor list is
load-bearing. A tenant policy that requires `Fido2` for certain routes
can check `factor_completed_at(&FactorKind::Fido2)` (or `has_completed_factor`) directly,
without consulting an external store.

`Authenticated` holds two times for two purposes. `signed_in_at` is when
the login that created the session completed: the absolute age cap counts
from it, and a step-up or an id rotation leaves it as it is, so stepping
up now and then never makes a session live for ever. `authn_time` is when
the person last proved presence, at the login or the latest step-up:
recency checks (`AuthSession::authenticated_within`, a FIDO2
`max_authn_age`, the recency an impersonation asks of the administrator)
read it.

`PendingWorkflow` models
the state where a user has authenticated enough to identify themselves
but is in the middle of a multi-step ceremony (signup, password reset,
email verification, or a custom workflow) and should not be treated as
fully logged in until the ceremony completes. The variant wraps a
`WorkflowState` that records which workflow is in progress, which step
the user is on, and when the workflow started.

```rust,ignore
pub struct WorkflowState {
    pub kind: WorkflowKind,
    pub current_step: u32,
    pub total_steps: u32,
    pub initiated_at: Timestamp,
}

pub enum WorkflowKind {
    Signup,
    PasswordReset,
    EmailVerification,
    Custom(Arc<str>),
}
```

`Custom(Arc<str>)` is the extension point. If your application has a
KYC flow, a hardware-key registration flow, or a multi-step recovery
ceremony, you name it as a custom workflow and the session machinery
treats it like the built-in kinds. The name is an `Arc<str>`, so a
clone of the state shares the string instead of copying it.

## The transition method

Every transition of the state machine is `pub(crate)`. Factor
verification goes through `AuthState::advance_factor`, which takes the
factor's proof, a `FactorAssurance` that holds its `FactorKind` and the
`Timestamp` it was verified at, and returns an `AdvanceOutcome` that
tells the caller what just happened.

```rust,ignore
impl AuthState {
    pub(crate) fn advance_factor(&mut self, proof: FactorAssurance) -> AdvanceOutcome { ... }
}

pub(crate) enum AdvanceOutcome {
    NotApplicable,
    StillAuthenticating,
    Completed,
}
```

The method is `pub(crate)`, which keeps the orchestration honest: the
pure state mutation is reachable only from within `axess-core`.
Application code calls `RequestAuthnService::verify_factor` instead,
which is the orchestrator method that locks the session, performs the
factor's cryptographic verification through `axess-factors`, calls
`advance_factor` on the typed state, and dispatches on the returned
outcome.

The three outcomes are exhaustive. `NotApplicable` means the call was
made against a state that does not accept factor verification (you
cannot verify a factor against a `Guest` session, for instance).
`StillAuthenticating` means the factor verified and more factors are
required to complete the method. `Completed` means the final required
factor for this method just passed, and `advance_factor` has replaced
the state with an `Authenticated` variant carrying the right
`authn_time`, `signed_in_at` and `factors_completed`. On `Completed` the
orchestration layer binds the fingerprint, rotates the session id to
defeat fixation, and marks the session for writing back to the store.

## The orchestration split

The split between `AuthState` (the pure data and pure transition
methods) and `AuthSession` (the Axum extractor with its `RwLock`,
dirty flag, and side-effect dispatch) has two payoffs.

The first payoff is testability. Unit tests on the state machine need
no `tokio`, no `RwLock`, no fake session store and no extractor harness. They construct an `AuthState`
directly, call `advance_factor` (or one of the other `pub(crate)`
transition methods), and assert on the resulting variant. A regression
in the transition logic surfaces as a one-line test against the enum,
not as an integration test against a contrived HTTP request.

The second payoff is auditability. Every orchestration side effect (id
rotation, fingerprint binding, dirty-flag handling, store write-back)
lives in one file (the `SessionService::call()` method, walked through
in *Session lifecycle and crypto envelope*) rather than scattered
across transition methods. Each half can be reviewed without reconstructing the other.

Pure state machines compose cleanly with async orchestrators that hold
the locks and dispatch side effects, and the two halves get reviewed
and tested independently.

## Where `Authenticated` stops being the right shape

Do not treat `Authenticated` as "done" and `Guest` as "not done" and
ignore the intermediate variants. The intermediate variants represent
flows that do not fit a binary; using them lets your application behave
correctly without keeping parallel state of its own.

A signup flow that captures a username and password, mints a session,
and then asks the user to verify their email before granting any
access should sit in `PendingWorkflow { kind: EmailVerification, ... }`,
not in `Authenticated`. A handler that protects the dashboard checks
`is_authenticated()`, which returns true only for the `Authenticated`
variant, and the user sees the email-verification page until the
ceremony completes. When the ceremony completes, the session
transitions to `Authenticated`, the same handler now lets the user in,
and the application does not need to model a "needs to verify email"
column on the users table.

A password-reset flow follows the same pattern with
`WorkflowKind::PasswordReset`. The user proves identity (with an
email-OTP, say), the session enters `PendingWorkflow`, the
password-reset page becomes accessible, the user submits a new
password, and the session transitions back to `Guest` (forcing them to
log in fresh with the new password). The reset page is unreachable
from `Guest` and unreachable from `Authenticated`, which is correct in
both directions: a not-logged-in user should not see it, and a fully
logged-in user does not need it.

The pattern generalises to any post-identification ceremony. The
question is: should the user count as fully logged in during this step? If the answer is no, `PendingWorkflow` is the
right variant. If the answer is yes, and you simply want the user to
do something next, then `Authenticated` plus a flag on the user record
fits better.

## Logging out and identifier rotation

`RequestAuthnService::logout` (and `AuthSession::clear`, which calls into it)
transitions any state to `Guest`. The transition is more than a state
change. The session identifier is rotated, the cookie is cleared on
the response, the session row is deleted from the session store, and
an audit event is emitted. The combination defeats session fixation.
Even if an attacker knew the session id before logout, the id changes
on the next login.

The orchestration layer also rotates the session id at the transition
to `Authenticated`, for the same reason. A user who logs in receives a
new session id, distinct from any id observed while they were a guest.
The cookie is reissued; the old id is unreachable on subsequent
requests. The rotation is invisible to application code and lives in
the orchestration; the state machine just sees the variant change.

## Custom session data

Real applications need to attach data to a session that axess does not
model: a preference, a feature-flag selection, a partial form draft.
`SessionData` has a `custom` field for this, with a size cap of 64 KiB
by default (`SessionConfigBuilder::max_custom_bytes` sets it, and zero
turns it off). The cap bounds the serialised size of the custom data. A session is
a server-side record (the cookie carries its id and a signature), and a session
that grows without bound in the store becomes a DoS surface. 64 KiB is
enough for almost any sensible use; anything larger probably belongs in the database keyed by user id rather than in the
session.

Adding a custom field is purely additive. The `SessionData` struct
exposes `custom: serde_json::Value`, a JSON object keyed by name (the
implementation may evolve, but the field-with-cap shape is stable),
and you write through accessor methods on the session handle. The
state-machine variants do not change. *Schema migration* covers upgrades that keep existing sessions
working.

## The foundation the rest of the book stands on

The state machine is the foundation that lets the rest of the book be
shorter. Factor composition (*Factors and methods*) works because
`Authenticating::remaining` is a list, not a single field. Step-up
authentication works because the orchestrator can transition from
`Authenticated` to `Authenticating` with a non-empty `remaining` list
when a sensitive route demands a stronger factor. Cedar authorisation
works because `Authenticated` carries `factors_completed`, which the
entity provider can serialise into a Cedar attribute the policy can
match on. Audit events work because every transition produces a
distinct `AuthEvent` variant with the right fields populated.

None of these features required a different enum; they all read out of
the state machine that was already there. The enum carries the
authentication question, and the rest of the library asks it.

## Further reading

Four chapters build directly on this one. *Factors and methods*
covers which factors fit into the variants and how methods compose.
*Scope hierarchy* covers how `begin_login` picks the right method
given System, Tenant and User overrides. *Refresh tokens and session
continuity* covers long-lived sessions,
key rotation and token theft. *Session lifecycle and crypto envelope*
in Part V covers the cookie, the encryption envelope, and the
orchestration's dirty-flag handling.
