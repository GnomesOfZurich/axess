# The session state machine

`AuthState` is the most important type in axess. Everything that matters
about an authenticated session, both for the type system and for a
reviewer reading a handler, is captured by which of its five variants
you are looking at. The whole library is built around the
representational claim that authentication is not a boolean, not a
flag column, and not a row in a sessions table that the handler reads
and then trusts. It is an enum, transitions on the enum are methods on
the enum, and a partial login is a distinct variant rather than a
"finished" session with one field missing.

This chapter walks through the variants, the transition method, the
outcome enum that dispatches transitions, the `PendingWorkflow` escape
hatch for signup and password reset, and the orchestration-versus-pure
split that keeps the state machine independently testable.

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
        remaining: Vec<FactorKind>,
        completed: Vec<FactorKind>,
        attempt_count: u32,
        last_attempt: Option<DateTime<Utc>>,
    },

    Authenticated {
        user_id: UserId,
        tenant_id: TenantId,
        authn_time: DateTime<Utc>,
        factors_completed: Vec<FactorKind>,
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

`Authenticating` is where most of the action happens. The session knows
who it is trying to authenticate, which method is in progress (because
a tenant might have multiple methods, and the choice is locked in
before any factor runs), what factors are still required, what factors
have already been verified this attempt, how many credential attempts
have been made, and when the last attempt landed. The last two fields
exist because lockout decisions depend on them. A method that allows
three attempts before locking the user out for fifteen minutes needs
exactly this information, and putting it in the variant rather than in
a side table keeps the decision local and reviewable.

`Authenticated` is the terminal success state. It carries the user id,
the tenant id, the moment of successful authentication (for the audit
trail), and the list of factors that were used. The factor list is
load-bearing. A tenant policy that requires `Fido2` for certain routes
can check `factors_completed.contains(&FactorKind::Fido2)` directly,
without consulting an external store.

`PendingWorkflow` is the variant most adopters do not initially expect
and end up reaching for once they ship a real signup flow. It models
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
    pub initiated_at: DateTime<Utc>,
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
treats it like the built-in kinds. The string is interned through
`Arc<str>` because workflow names recur and the cost of repeated
allocation adds up across a busy login surface.

## The transition method

Factor verification is the only mutation that the state machine
exposes. The transition is `AuthState::advance_factor`, which takes a
`FactorKind` and a timestamp, and returns an `AdvanceOutcome` that
tells the caller what just happened.

```rust,ignore
impl AuthState {
    pub(crate) fn advance_factor(
        &mut self,
        kind: &FactorKind,
        authn_time: DateTime<Utc>,
    ) -> AdvanceOutcome { ... }
}

pub enum AdvanceOutcome {
    NotApplicable,
    StillAuthenticating,
    Completed,
}
```

The visibility on the method is `pub(crate)`, which is the choice that
keeps the orchestration honest. The pure state mutation is reachable
only from within `axess-core`. Application code never calls it
directly. Instead, application code calls `AuthnService::verify_factor`,
which is the orchestrator method that locks the session, performs the
factor's cryptographic verification through `axess-factors`, calls
`advance_factor` on the typed state, and dispatches on the returned
outcome.

The three outcomes are exhaustive. `NotApplicable` means the call was
made against a state that does not accept factor verification (you
cannot verify a factor against a `Guest` session, for instance).
`StillAuthenticating` means the factor verified and more factors are
required to complete the method. `Completed` means the final required
factor for this method just passed, and the session should transition
to `Authenticated`. The orchestration layer translates `Completed`
into a typed `Authenticated` variant with the right `authn_time` and
`factors_completed`, applies session id rotation to defeat fixation,
and writes the session back to the store.

## The orchestration split

The split between `AuthState` (the pure data and pure transition
methods) and `AuthSession` (the Axum extractor with its `RwLock`,
dirty flag, and side-effect dispatch) is a deliberate choice with two
payoffs.

The first payoff is testability. Unit tests on the state machine do not
need `tokio`, do not need `RwLock`, do not need a fake session store,
and do not need an extractor harness. They construct an `AuthState`
directly, call `advance_factor` (or one of the other `pub(crate)`
transition methods), and assert on the resulting variant. A regression
in the transition logic surfaces as a one-line test against the enum,
not as an integration test against a contrived HTTP request.

The second payoff is auditability. Every orchestration side effect (id
rotation, fingerprint binding, dirty-flag handling, store write-back)
lives in one file (the `SessionService::call()` method, walked through
in *Session lifecycle and crypto envelope*) rather than scattered
across transition methods. A code review of the orchestration is
self-contained; a code review of the state machine is self-contained;
neither has to mentally reconstruct the other.

The pattern is worth naming because it shows up again in the runtime.
Pure state machines compose cleanly with async orchestrators that hold
the locks and dispatch side effects, and the two halves get reviewed
and tested independently.

## When `Authenticated` is and is not the right shape

The natural temptation when integrating axess for the first time is to
treat `Authenticated` as the "done" state and `Guest` as the "not done"
state, and to ignore the intermediate variants. Resist it. The
intermediate variants are how axess represents real-world flows that
do not fit a binary, and reaching into them lets your application
behave correctly without inventing parallel state on the side.

A signup flow that captures a username and password, mints a session,
and then asks the user to verify their email before granting any
access should sit in `PendingWorkflow { kind: EmailVerification, ... }`,
not in `Authenticated`. A handler that protects the dashboard checks
`is_authenticated()`, which returns true only for the `Authenticated`
variant, and the user sees the email-verification page until the
ceremony completes. The variant change at completion time then
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
typical question to ask is "should the user be considered fully logged
in during this step?" If the answer is no, `PendingWorkflow` is the
right variant. If the answer is yes, and you simply want the user to
do something next, then `Authenticated` plus a flag on the user record
fits better.

## Logging out and identifier rotation

`AuthnService::logout` (and `AuthSession::clear`, which calls into it)
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
`SessionData` has a `custom` field for this, and the size cap is
sixty-four kilobytes. The cap exists because the session is
round-tripped through a cookie (or its server-side analogue), and a
session that grows without bound becomes a DoS surface. Sixty-four
kilobytes is enough for almost any sensible use; anything larger
probably belongs in the database keyed by user id rather than in the
session.

Adding a custom field is purely additive. The `SessionData` struct
exposes `custom: HashMap<String, serde_json::Value>` (the
implementation may evolve, but the field-with-cap shape is stable),
and you write through accessor methods on the session handle. The
state-machine variants do not change. The schema-migration story
covered in *Schema migration* handles upgrade paths without breaking
existing sessions.

## What this enables

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

The chapters that build directly on this one are *Factors and methods*
(which factors fit into the variants, and how methods compose), *Scope
hierarchy* (how `begin_login` picks the right method given Global,
Tenant, and User overrides), and *Refresh tokens and session continuity*
(how the session continues across long-lived sessions, key rotation,
and detection of token theft). *Session lifecycle and crypto envelope*
in Part V covers the cookie, the encryption envelope, and the
orchestration's dirty-flag handling.
