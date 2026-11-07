# Authentication assurance and ceremonies

Before this, a Cedar policy could ask one thing about how a user proved who
they are: `context.mfa_verified`, a flag the application computed for the
whole session. It could not ask whether the user was verified by the
authenticator, whether the passkey was synced or bound to one device, whether
the authenticator was attested, or how long ago any of it happened. And the
WebAuthn ceremony that ran was always the passkey one, whatever the operation
needed. This page is the design: what a session records, what Cedar sees,
how a gate asks for a step-up, how the ceremony is chosen per operation, the
invariants, how it fails, and what an adopter changes.

## What you get

- At login and at every step-up, the session records one
  `FactorAssurance` per factor: what it proved and when, from the injected
  `Clock`.
- `AssuranceContext` turns a session's record into one Cedar context
  attribute, `assurance`, whose names and types are fixed and shipped as a
  schema fragment (`ASSURANCE_SCHEMA_FRAGMENT`).
- "This action needs a user-verified, device-bound passkey from the last
  five minutes" is one Cedar rule (below).
- A gate that denies only because the session's assurance is short answers
  with a distinct refusal, `step_up_required`, naming the step-up that would
  satisfy it, never the policy text.
- The FIDO2 ceremony is chosen per operation: registration and login in
  `Fido2Options`, a step-up for a named action from the `@step_up`
  annotation on the very Cedar rule that requires it.

## What a factor proved

`FactorAssurance` has five fields:

| Field | Type | Meaning |
|---|---|---|
| `kind` | `FactorKind` | the factor that was verified |
| `at` | `DateTime<Utc>` | when, from the service's `Clock` (never `Utc::now`) |
| `user_verified` | `bool` | the factor proved the person, not only a device or a channel |
| `trust_anchor` | `Option<Arc<str>>` | the trust anchor an attested ceremony verified the authenticator against; `None` unless one ran |
| `credential` | `CredentialBinding` | `DeviceBound`, `Synced` or `NotApplicable` |

`user_verified` and `credential` per factor:

| Factor | `user_verified` | `credential` | Why |
|---|---|---|---|
| FIDO2 | the assertion's UV flag (`AuthenticationResult::user_verified`) | `DeviceBound` when the authenticator reports neither backup eligibility nor backup state, else `Synced` | the authenticator says both; a credential that may sync is not bound to a device, even before it has synced |
| Password | `true` | `NotApplicable` | a memorized secret is the person's knowledge |
| LDAP bind | `true` | `NotApplicable` | a password verified against the directory |
| TOTP, HOTP | `false` | `NotApplicable` | the code proves possession of the seed, not who holds it |
| Email OTP | `false` | `NotApplicable` | the code proves access to the inbox |
| Recovery code | `false` | `NotApplicable` | a look-up secret is something you have |
| Federated (OIDC) | `false` | `NotApplicable` | axess does not read how the identity provider verified the user (`acr`, `amr`) |

`trust_anchor` is set only by the attested-passkey ceremony, and only when
the stored credential's attestation still verifies, at the moment of the
assertion, against the trust anchor of that name the provider holds now
(`AttestedPasskey::verify_attestation`). A trust anchor the provider no
longer holds, or one that no longer covers the authenticator, records
`None`: the login succeeds and a policy that asks for attestation denies.

### Where it lives

The record is part of the authenticated state, like the LDAP groups and the
impersonation marker: `AuthState::Authenticating` and
`AuthState::Authenticated` gain `assurance: Vec<FactorAssurance>`. A handler
cannot write it, the custom-data cap cannot drop it, and it ends with the
state (logout, a new login, `set_authenticated`). A step-up carries it into
the `Authenticating` state and back. `AuthState::assurance()` and
`AuthSession::assurance()` read it.

The list holds the most recent proof of each factor kind: a step-up that
verifies a kind again replaces that kind's entry. That bounds the record to
one entry per kind (a few hundred bytes for the largest session), and it is
what a policy reads anyway. A later, weaker proof of a kind hides an earlier,
stronger one; the effect is a denial and a step-up, never an allow.

The session is stored as MessagePack with field names
(`rmp_serde::to_vec_named`) by every encrypted backend and kept as a value by
the in-memory one, and the field is skipped when empty, so a session written
by 0.17 reads with an empty list and a session with no proof costs nothing.
Each backend's tests round-trip a session carrying assurance (SQLite and the
in-memory store always, Postgres, MySQL and Valkey against live servers).

### Sessions from before the change

A session created before this release has no `assurance` field and reads as
an empty list. An empty list emits an `assurance` record with no factor in
it, so every policy that asks for a factor (`context.assurance has fido2`)
is false and denies: such a session satisfies no assurance policy until it
steps up. Impersonation, signup completion and every other direct
transition to `Authenticated` record nothing either, for the same reason.

## What Cedar sees

`AssuranceContext::from_session(&assurance, now)` builds the record and
`to_expression()` the Cedar value. The attribute is `context.assurance`, a
record with one optional attribute per factor kind:

| Attribute | Factor |
|---|---|
| `password` | `FactorKind::Password` |
| `totp` | `FactorKind::Totp` |
| `hotp` | `FactorKind::Hotp` |
| `email_otp` | `FactorKind::EmailOtp` |
| `fido2` | `FactorKind::Fido2` |
| `ldap_bind` | `FactorKind::LdapBind` |
| `recovery_code` | `FactorKind::RecoveryCode` |
| `federated` | any `FactorKind::Federated` provider |

Each present attribute is a record:

| Attribute | Cedar type | Meaning |
|---|---|---|
| `user_verified` | `Bool` | as above |
| `credential` | `String` | `"device_bound"`, `"synced"` or `"not_applicable"` |
| `attested` | `Bool` | `trust_anchor` is present |
| `trust_anchor` | `String`, optional | the trust anchor's name |
| `age_seconds` | `Long` | whole seconds from the proof to `now` |

`now` is the caller's clock reading. A proof dated after `now` is left out:
a clock that went backwards proves nothing fresh.

### The schema fragment

`ASSURANCE_SCHEMA_FRAGMENT` is the JSON of two Cedar common types,
`AxessFactorAssurance` and `AxessAssurance`, for a namespace's
`commonTypes`. `merge_assurance_schema(&mut schema_json, namespace)` adds
them to a parsed schema. An action whose policies read assurance declares
the attribute as required:

```json
"context": {
  "type": "Record",
  "attributes": { "assurance": { "type": "AxessAssurance" } }
}
```

Required, because a policy that guards an optional `assurance` with
`context has assurance` and treats absence as allowed would permit when the
provider forgot it.

### Getting it into the context

- `AssuranceContextProvider::new(clock)` is a `RequestContextProvider` for
  `require_authz!` that emits `assurance` alone.
- `StandardRequestContext::with_assurance(AssuranceContext)` adds it beside
  `mfa_verified`, `ip_address` and `timestamp`, for an `AuthzSession` or a
  provider of your own.

### The rule

```cedar
@step_up("passkey")
permit (
    principal in App::Role::"approver",
    action == App::Action::"ApprovePayment",
    resource
) when {
    context.assurance has fido2 &&
    context.assurance.fido2.user_verified &&
    context.assurance.fido2.credential == "device_bound" &&
    context.assurance.fido2.age_seconds <= 300
};
```

It permits a session whose latest passkey was user-verified, device-bound
and verified within five minutes, and denies a password-only session, one
whose passkey is six minutes old and one whose passkey is synced; the test
`a_fresh_device_bound_passkey_is_the_only_session_the_rule_permits` holds
each case. Add `&& context.assurance.fido2.trust_anchor == "vendor-roots"`
(after `context.assurance.fido2 has trust_anchor`) to require an attested
authenticator.

## Asking for a step-up

A denial is either a denial or a shortfall. To tell them apart without
reading the policy, the gate asks Cedar a second question: would this
request be permitted if the session had just completed a given step-up?

- A policy names the step-up that satisfies it with the annotation
  `@step_up("<name>")`. `PolicyStore` parses every annotation when it is
  built or reloaded, and refuses the set with
  `AuthzError::PolicyValidation` naming the policy and the value when a
  name is not one of the step-ups below.
- On a deny, and only when the set carries annotations and the request's
  context carries `assurance`, the store re-evaluates the request once per
  annotated step-up, weakest first, with the `assurance` attribute replaced
  by the session's own plus the best proof that step-up can yield, aged
  zero. The first that permits is the answer. Nothing else in the request
  changes, so a role, a resource or a `forbid` that denied still denies,
  and the answer stays a plain deny.
- The re-evaluations are silent: they emit no decision event and do not
  count as decisions. The decision event of the real request is the deny.

| Step-up name | Factor | Best proof assumed |
|---|---|---|
| `password` | password | verified, not applicable |
| `ldap_bind` | LDAP bind | verified, not applicable |
| `totp`, `hotp`, `email_otp`, `recovery_code` | that factor | not verified, not applicable |
| `security_key:discouraged` | FIDO2, security-key ceremony, UV discouraged | not verified, device-bound |
| `security_key:preferred` | FIDO2, security-key ceremony, UV preferred | verified, device-bound |
| `passkey` | FIDO2, passkey ceremony | verified, device-bound |
| `attested_passkey:<anchor>` | FIDO2, attested-passkey ceremony against `<anchor>` | verified, device-bound, attested by `<anchor>` |

The best proof is what the ceremony can yield, not what it will: a passkey
step-up may come back synced, and the gate then names it again. A rule whose
annotation cannot satisfy its own condition (a `security_key:discouraged`
annotation on a rule that needs `user_verified`) gets a plain deny, never a
prompt that cannot succeed: the annotation and the condition cannot drift
into an answer that misleads.

### How it surfaces

- `require_authz!` answers 403 with
  `{"error": "step_up_required", "step_up": "passkey"}` (the
  `AuthzRefusal::StepUpRequired` response) instead of
  `{"error": "Access denied"}`.
- `AuthzSession::require_with_step_up(action, resource)` returns
  `Err(AuthzRefusal::StepUpRequired(StepUp))` or
  `Err(AuthzRefusal::Denied)`; `require` and `is_permitted` are unchanged.
- `PolicyEvaluator::step_up_for` is the question itself, defaulted to
  `None` for evaluators that are not a `PolicyStore`.

The answer names the step-up and nothing else: no policy id, no condition,
no attribute. It tells the caller only that this request is reachable after
that step-up, which is what the prompt has to say anyway.

The application turns it into a prompt: parse the name
(`StepUp::from_str`) and call `RequestAuthnService::begin_step_up_for`. The
name comes back from the client, and a client may send a weaker one; that
gains nothing, because the action is decided again by Cedar on the
assurance the step-up actually recorded.

## Choosing the ceremony

WebAuthn fixes user verification and attestation in the challenge, before
the ceremony. `webauthn-rs` 0.6.2 makes that choice a typed ceremony, and
`Fido2Ceremony` names the three axess runs:

| `Fido2Ceremony` | `webauthn-rs` | User verification | Credentials it offers at login |
|---|---|---|---|
| `Passkey` | `start_passkey_*` | required | passkeys and attested passkeys |
| `SecurityKey(SecurityKeyVerification::Preferred)` | `start_securitykey_*` | preferred | security keys |
| `SecurityKey(SecurityKeyVerification::Discouraged)` | `start_securitykey_*` on a presence-only instance | discouraged | security keys |
| `AttestedPasskey { trust_anchor }` | `start_attested_passkey_*` with the named `AttestationCaList` | required | attested passkeys registered against that anchor |

A credential keeps the type of the ceremony that registered it
(`Fido2Key::Passkey`, `Fido2Key::SecurityKey`,
`Fido2Key::AttestedPasskey { key, trust_anchor }`), because `webauthn-rs`
authenticates each type with its own ceremony and converts only an attested
passkey to a passkey. A login ceremony offers the user's credentials it can
authenticate (`Fido2Ceremony::accepts`) and is refused with
`AuthnError::NoFlow` when there are none. Nothing is built on
`webauthn-rs-core`'s `WebauthnCore::new_unsafe_experts_only`, whose
signature may change within minor versions and whose invariants would
become axess's, and axess enables no danger feature of `webauthn-rs`
beyond the state serialisation it already used.

`DefaultFido2Provider` holds the trust anchors by name
(`with_trust_anchor(name, AttestationCaList)`); a ceremony naming one it
does not hold is refused at its start. UV-discouraged security keys need a
`Webauthn` built with `webauthn-rs`'s
`danger_set_user_presence_only_security_keys`, which the adopter enables in
their own build and hands over with `with_presence_only_security_keys`; the
provider checks that the instance really discourages verification and
refuses it otherwise, and a discouraged ceremony on a provider without one
is refused.

### Per operation

- **Registration**: `Fido2Options::registration_ceremony`, or one call's
  choice with `begin_fido2_registration_with(user, session, ceremony)`.
- **Login**: `Fido2Options::login_ceremony`, for the FIDO2 step of a login
  method. The discoverable (passwordless) ceremony is its own operation and
  keeps its own ceremony.
- **Step-up for a named action**: the `@step_up` annotation on the rule that
  requires the assurance. The refusal names it, and
  `begin_step_up_for(session, &step_up)` begins the step-up for that factor
  with that ceremony. The ceremony is kept with the step-up's state and
  dropped when the session leaves it; a plain `begin_step_up` or a new
  login uses `login_ceremony`.

Both options default to `Fido2Ceremony::Passkey`, the only ceremony 0.17
ran, so nothing changes until you choose. The step-up is the one operation
that is a Cedar action, which is why only its ceremony comes from the
policy: what the rule asks for and what is prompted come from one place.
Registration and login are not Cedar actions, so their ceremonies are one
explicit mapping in `Fido2Options` beside the timeout they already held.

## Invariants

- A proof is recorded only by the code path that verified the factor, from
  the verifier's own result; nothing a client sends sets a field.
- Every time comes from the injected `Clock`.
- An empty record satisfies no assurance policy.
- A step-up is named only when the policy set, re-evaluated with that
  step-up's best proof and nothing else changed, permits.
- The refusal body names a step-up and nothing of the policy.
- A ceremony's state records which ceremony began it, so a finish cannot
  complete it as another.

## Failure modes

| What happens | Result |
|---|---|
| a session from before this release | empty record; assurance policies deny and name their step-up |
| the context provider omits `assurance` where the schema requires it | the request is invalid and denied, as for any required attribute |
| an unknown `@step_up` value | the policy set is refused at build and at reload, naming policy and value |
| an attested ceremony names a trust anchor the provider lacks | the ceremony is refused at its start (`NoFlow`) |
| the attestation no longer verifies at login | the login succeeds, `trust_anchor` is `None`, attested policies deny |
| a discouraged security-key ceremony without a presence-only instance | refused at its start |
| a login ceremony that fits none of the user's credentials | `NoFlow` |
| an attested registration whose CA list does not fit the session's custom data | `NoFlow`; keep CA lists to the roots you trust |
| a ceremony begun by 0.17 and finished by 0.18 | refused (its state is the untyped form); begin again |

## Migration

- `Fido2Provider::start_registration` and `start_authentication` take a
  `&Fido2Ceremony` first; registration and authentication state are
  `Fido2Registration` and `Fido2Authentication`; `finish_registration`
  returns a `Fido2Key`; `start_authentication` takes `&[Fido2Key]`; the new
  `attests` defaults to `None`.
- `Fido2Credential::passkey` is `Fido2Credential::key: Fido2Key`;
  `Fido2Credential::new` takes anything that converts into one, so a
  `Passkey` still works. A stored passkey row reads unchanged, and a passkey
  is still written in the form 0.17 reads.
- `Fido2Options` gains `registration_ceremony` and `login_ceremony`.
- `AuthState::Authenticating` and `AuthState::Authenticated` gain
  `assurance`; `StandardRequestContext` gains `assurance`.
- `require_authz!` answers `step_up_required` instead of `Access denied`
  for a request the annotations say a step-up would permit; without
  `@step_up` annotations nothing changes.
