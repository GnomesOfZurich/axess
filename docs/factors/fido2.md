# FIDO2 and WebAuthn passkeys

FIDO2 defends against real-time phishing. Every other second-factor
mechanism in this book (TOTP, HOTP, email OTP, recovery codes) is vulnerable to
an attacker who proxies the user's input through a fake login page to
the real server in real time. WebAuthn, the browser-side standard
that FIDO2 implements, binds each authentication to the origin where
the credential was registered, and a credential registered against
`accounts.example.com` cannot be exercised against
`accounts-example-com.attacker.example`. The defence is structural,
not behavioural: the browser refuses to use the credential at the
wrong origin, regardless of what the user clicks.

The feature flag is `fido2` (off by default), enabled with
`features = ["fido2"]` on the `axess` facade.

## The two ceremonies

WebAuthn has two ceremonies, and an integration touches both. The
first is registration: the user has authenticated to your application
by some other means (signup with email verification, an
already-logged-in session, an OAuth callback) and is registering a
new authenticator. The second is authentication: the user already has
a registered credential, is logging in, and the WebAuthn ceremony
proves possession.

Each is a begin and a finish on the request-scoped service
(`AuthnService::with_audit_context` gives the `RequestAuthnService`). For
registration, `begin_fido2_registration(user, session)` runs the provider's
`Fido2Provider::start_registration` and answers the
`CreationChallengeResponse` as JSON. The page passes it to
`navigator.credentials.create()` and posts back the
`RegisterPublicKeyCredential` the browser produces, and
`finish_fido2_registration(user, response, name, session)` verifies it
against the ceremony the session holds through
`Fido2Provider::finish_registration`, claims the credential id for the user
(`FactorStore::claim_fido2_credential`), adds the credential to the user's
stored list and writes a `FactorSetup` audit row. What the application
persists itself is the WebAuthn user handle: for a user with no
`User::webauthn_id`, `begin_fido2_registration` mints one and returns it,
and the application stores it on the user row before the next ceremony,
since every credential of a user carries the same handle.

Authentication is a factor step. `begin_login` answers
`LoginOutcome::FactorRequired(FactorKind::Fido2)` when the user's method
starts with one; `prepare_factor` runs `Fido2Provider::start_authentication`
over the user's credentials and answers `PrepareOutcome::Fido2Challenge`, a
`RequestChallengeResponse` listing their credential ids. The page passes it
to `navigator.credentials.get()` and posts back the `PublicKeyCredential`,
and `verify_factor(&FactorCredential::fido2_assertion(&credential)?, session)`
verifies the signature against the stored public key through
`Fido2Provider::finish_authentication`, records the use on the stored
credential and completes the step. A step-up runs the same step on an
authenticated session (`begin_step_up_for`), and the passwordless login
below is its own pair of calls.

The ceremony's state is what the session carries between the two halves.
The begin stores it under the session's custom data, one key per ceremony
(registration, authentication, passwordless), with the time it began. A
challenge is answered at most once. A begin first retires the ceremony of
its kind the session held, whether or not the begin then succeeds, so the
challenge an earlier begin handed out can no longer be finished and a begin
that fails leaves none at all. The finish takes the state in the same step
that reads it, so two parallel finishes cannot both use it, and a refused
finish leaves nothing to retry with. A state older than
`Fido2Options::ceremony_timeout` (five minutes by default, on the service's
`Clock`) is refused, and a missing or unreadable start time counts as
expired. The ceremony itself does not move the session's authentication
state; only a finish that succeeds does.

The challenge bytes come from `webauthn-rs`, which draws them from its own
random number generator; it cannot be handed the service's `SecureRng`, so
`DefaultFido2Provider` is a declared exception to the injected randomness
the rest of axess uses (a test that needs a reproducible ceremony
substitutes the provider). The user handle a registration mints comes from
the service's `SecureRng`.

## Relying-party configuration

The relying party is the server that owns the credentials. WebAuthn
identifies the relying party by an origin (scheme, host and
port) and by a relying-party id (an effective domain suffix of the
origin). Both are set on the `webauthn-rs` instance the provider wraps:

```rust,ignore
let origin = Url::parse("https://accounts.example.com")?;
let webauthn = WebauthnBuilder::new("example.com", &origin)?
    .rp_name("Example Inc.")
    .build()?;
let authn = AuthnService::builder(identity, factors)
    .with_fido2(DefaultFido2Provider::new(webauthn))
    .with_fido2_options(Fido2Options::default())
    .build();
```

The relying-party id is a string equal to or a suffix of the host part of
the origin. Setting it to the apex domain (`example.com` rather than
`accounts.example.com`) lets credentials registered on the accounts
subdomain be used across other subdomains of the same apex
(`app.example.com`, `admin.example.com`), which is usually what you want.
Setting it to the full hostname scopes credentials to that hostname alone,
which is appropriate when other subdomains belong to other applications you
do not trust. Every credential is bound to it, so it should not change once
users have registered: a provider reload that changes it is refused unless
acknowledged (see below).

The origin is where the ceremonies happen. `webauthn-rs` checks the origin
the browser reports in each response against it and refuses a response from
any other; `WebauthnBuilder::append_allowed_origin` adds origins, and
`allow_subdomains` and `allow_any_port` widen the match. Wildcards are not
allowed.

What the instance does not hold is how much a ceremony asks of the
authenticator. User verification, attestation and whether the credential
is stored on the authenticator are fixed in each challenge, so axess sets
them per operation:

- **User verification and attestation** come from the ceremony an operation
  runs (next section): the passkey ceremony requires user verification and
  asks for no attestation; the security-key ceremony prefers or discourages
  user verification; the attested-passkey ceremony requires both user
  verification and a direct attestation that chains to a trust anchor you
  name. Attestation identifies the authenticator's vendor and model, which
  some regulatory frameworks require for hardware keys and which is
  otherwise a privacy cost.
- **A stored (discoverable) credential**, what lets a passkey sign in with
  no username, is `Fido2Options::discoverable_credential`, described under
  the passwordless login below.

The passkey-or-not choice is the most consequential for usability.
Passkeys are what users mean today when they say "biometric login":
the user clicks a button, touches the fingerprint sensor, and is signed in.
Credentials the authenticator does not store require the user to enter a
username first, which is the older WebAuthn flow and what most existing
TOTP-style second factors look like.

## Choosing the ceremony

User verification and attestation are not settings of the `Webauthn`
instance; `webauthn-rs` makes their choice a typed ceremony, and
`Fido2Ceremony` names the one an operation runs:
`Passkey` (verification required, the default), `SecurityKey` with
`SecurityKeyVerification::Preferred` or `Discouraged`, and `AttestedPasskey`
against a trust anchor `DefaultFido2Provider::with_trust_anchor` holds by
name. Registration runs `Fido2Options::registration_ceremony` (or one call's
choice through `begin_fido2_registration_with`), a login's FIDO2 step runs
`Fido2Options::login_ceremony`, and a step-up for a named action runs the
ceremony its policy's `@step_up` annotation names. A credential is stored as
the `Fido2Key` its ceremony registered, and a login offers only the
credentials its ceremony accepts. Each assertion records what it proved
(user verification, synced or device-bound, an attestation trust anchor) on
the session, where Cedar reads it: see
[Authentication assurance and ceremonies](../authorization/assurance.md).

## Passwordless login and its prompt

A passkey can sign a user in with no username: the authenticator holds the
credential and names the user. That login is its own ceremony, apart from
the FIDO2 step of a login method. `begin_discoverable_login_with(session,
login)` begins it and returns the challenge for the browser;
`finish_discoverable_login(assertion, user, credentials, session)` verifies
the assertion against the keys stored for the user and lets the user's own
method decide how far the passkey goes. The assertion must name its user:
its user handle (`response.userHandle`) has to be present and equal to
`User::webauthn_id` of the user it is finished for, or the finish refuses
it as a failed assertion. The handle is not signed and proves nothing by
itself; it is the check WebAuthn asks for when the request named no
credential, and it catches a lookup that resolved a credential id to the
wrong account. Keep the handle a registration mints on the user record:
without it no passkey of that user finishes a passwordless login.

A `DiscoverableLogin` says two things about the ceremony:

- `tenant`: the tenant it may finish in. A passkey names a user and says
  nothing of tenants, so a login page that belongs to a tenant names it
  (`DiscoverableLogin::default().in_tenant(tenant_id)`), and a user of
  another tenant is refused with `AuthnError::CrossTenant`.
- `prompt`: how the browser presents it, a `DiscoverablePrompt`.

| `DiscoverablePrompt` | The challenge | The browser |
|---|---|---|
| `Autofill` (default) | `mediation: "conditional"` | offers passkeys in a field marked `autocomplete="username webauthn"`, with no dialog |
| `Modal` | no `mediation` | opens its dialog at once, for a "sign in with a passkey" button |
| `CrossDevice` | no `mediation`, `hints: ["hybrid"]` | opens its dialog on the QR code for another device |

`begin_discoverable_login(session)` binds no tenant, and
`begin_discoverable_login_in_tenant(tenant_id, session)` binds one; neither
takes a prompt, and both send the challenge as the provider issued it,
which for `DefaultFido2Provider` is conditional mediation, as `webauthn-rs`
issues it.

A passkey signs in this way only if the authenticator stored it (a
discoverable credential). `Fido2Options::discoverable_credential` decides
what a passkey or attested-passkey registration asks for:
`DiscoverableCredential::Discouraged` (the default, what `webauthn-rs`
asks) leaves it to the authenticator, so a passkey registered that way may
not be stored and then signs in only after a username; `Preferred` asks for
a stored credential where the authenticator can make one; `Required` makes
the browser fail a registration on an authenticator that cannot, so every
passkey can sign in with no username. A passkey meant for the passwordless
login needs `Required`, whatever the authenticator. The option reaches the
authenticator as the challenge's `residentKey` and changes nothing the finish
verifies. The security-key
ceremony registers a non-discoverable credential whatever the option says.

The prompt is a choice of user interface. It changes the request options
the browser reads and nothing the server keeps or checks: the ceremony
state, its timeout and the finish are the same for all three, and user
verification is required in each.

### Cross-device authentication

Cross-device authentication is signing in on one device with a passkey
held on another: a laptop that holds no passkey shows a QR code, the phone
that scans it proves over Bluetooth that it is nearby, and the passkey on
the phone signs the challenge. FIDO calls the transport *hybrid*.

The QR code and the Bluetooth link run between the browser and the phone.
The relying party sees an ordinary assertion, so there is no separate
ceremony to begin or finish: `DiscoverablePrompt::CrossDevice` on the
passwordless login is the whole of its part.

```rust,ignore
let login = DiscoverableLogin::default()
    .in_tenant(tenant_id)
    .with_prompt(DiscoverablePrompt::CrossDevice);
let challenge = authn.begin_discoverable_login_with(&session, login).await?;
```

Three things follow from the relying party seeing only the assertion.

- **A hint, not a requirement.** `hints` belongs to WebAuthn Level 3. A
  browser that reads it leads with the QR code; one that does not shows its
  usual dialog, in which another device is one of the choices. Either way
  the user may pick any authenticator that holds a passkey for the site.
- **Nothing signed says which transport carried the assertion.** A policy
  cannot ask for, or exclude, a cross-device login. What a policy can ask
  is what the assertion itself proved: user verification, and whether the
  credential is synced or bound to one device (see
  [Authentication assurance and ceremonies](../authorization/assurance.md)).
  A passkey on a phone is normally a synced one.
- **The browser reports where the authenticator is, unsigned.** The
  credential it returns carries `authenticatorAttachment`, `platform` for
  this device and `cross-platform` for another. It is good for one thing:
  after a `cross-platform` login, offer to register a passkey on this
  device, so the phone is not needed next time. Read it from the posted
  JSON before parsing the assertion, and rest no decision on it.

A login that names its credentials (the FIDO2 step of a login method, a
step-up) needs no prompt to reach a phone. Its challenge lists each
credential with the transports it registered, and the browser offers the
QR code for one that registered `hybrid`.

The attested-passkey ceremony is the one place cross-device authentication
does not reach: a passkey that syncs cannot be attested, so `webauthn-rs`
hints that ceremony at this device and at security keys only.

## A worked example

[`examples/fido2/`](https://github.com/GnomesOfZurich/axess/tree/main/examples/fido2)
is a runnable application with the browser side included: the JavaScript
that turns a challenge into `navigator.credentials` options and the
authenticator's answer back into JSON, registration through each ceremony,
the username-first and passwordless logins, a passkey on another device,
and a payment whose Cedar policy answers `step_up_required` until the page
has run the passkey step-up it names. It needs no database and no identity
provider.

## Storage

A user's credentials are one row in the factor store: a
`FactorConfig::Fido2(Fido2Config)` under the user's scope (the natural
per-user scope from the chapter *Scope hierarchy*), whose `credentials` list
holds one `Fido2Credential` per authenticator. Every change to the list (a
registration, a deletion, the counter a login updates) is a compare-and-swap
on that row, so two concurrent changes never overwrite one another. Each
`Fido2Credential` carries:

- `key`, the `Fido2Key` typed by the ceremony that registered it, wrapping
  the `webauthn-rs` credential: the credential id, the public key, the
  signature counter, the transports the browser reported (USB, NFC,
  internal, hybrid), whether registration verified the user, the backup
  flags, and the attestation when the ceremony asked for one.
- `name`, the label the user gave it, `registered_at` and `last_used_at`.

A user with several authenticators (a phone passkey plus a hardware key,
say) has several entries; an authentication offers those its
ceremony accepts, and the user's authenticator (or the browser, for a
passkey) picks one.

The signature counter is what catches a cloned authenticator. An
authenticator that implements it increments it on each signature; when
either the assertion's counter or the stored one is non-zero, `webauthn-rs`
refuses an assertion whose counter is not greater than the stored one, and
axess counts it as a failed attempt (the failure counter and an audit row,
as for a wrong code) and leaves the credential in place. Deleting the
credential is the application's decision. An authenticator that does not
implement the counter, which includes most synced passkeys, reports zero
every time and is not checked.

Registration refuses a credential id the user already holds, and one
that another user of the same tenant holds (the WebAuthn rule that one
credential belongs to one account). The cross-user answer comes from
`FactorStore::claim_fido2_credential(tenant_id, user_id, credential_id)`,
the claim `finish_fido2_registration` takes before it stores. It answers
`Fido2CredentialClaim::Claimed`, or `HeldBy` naming the user who holds the
id, read in the step that refused the claim, so the answer does not depend
on which of two racing registrations wrote first. The refusal is
`AuthnError::NoFlow`, nothing is stored, and the second case leaves a failed
`FactorSetup` audit row whose reason comes from the claim's answer and from
no second read. A failed claim fails the registration; it is never read as
"nobody holds it".

The claim and its `release_fido2_credential` are required methods: a store
that does not make the claim atomically cannot keep two accounts from
holding one id, so it does not compile until it says what it does. A
registration whose credential write fails keeps its claim for the user. The
in-tree stores implement both: the mock store from `axess::testing`;
`InMemoryBackend`, which forwards to it; and the SQLite example. The SQLite
example looks through the tenant's stored `fido2` rows for a passkey stored
without a claim, then claims in its `fido2_credential_claims` table with one
insert that returns the row already there on a conflict. A store that
deletes a user releases the user's claims with the user, so an orphaned
claim does not block the id for the rest of the tenant. A store of your own
that keeps passkeys inside one opaque or sealed config row keeps an index of
`(tenant_id, credential_id, user_id)` with a unique key on the first two,
claims with one statement that returns the holder on a conflict, and can run
`axess::testing::store_contract::assert_fido2_claim_contract` against
itself: the check fails a store whose refused claim does not name its
holder. Without the claim, a duplicate cannot log in as another user,
because every login looks credentials up per user and verifies the assertion
against that user's stored public key; it only confuses an inventory.

`finish_discoverable_login` matches the assertion on credential id and
public key against the credentials stored for the user, never on the id
alone. The step before it, turning the assertion's credential id or user
handle into a `User`, is yours, and it must be tenant-scoped: a credential
id is not unique across tenants, so an unscoped lookup can name another
tenant's user (the tenant rail then refuses the login, but the lookup should
not have crossed).

## Who may enrol and delete

`begin_fido2_registration`, `finish_fido2_registration` and
`delete_fido2_credential` take the `User` the passkey belongs to, and a
`User` value is only what the caller built or fetched: a handler that
looks one up by a request parameter has not shown the request is that
user's. So each of the three also takes the session and requires it to be
`Authenticated` as that user (same id and tenant), or pending signup for
that user, so a signup can enrol its first passkey. Deleting needs full
authentication, so a signup session cannot delete. An impersonated
session is refused whoever it is authenticated as, unless the service was
built with `with_impersonated_credential_changes_allowed`: an
administrator does not change a user's credentials in their name, and the
refusal answers `AuthnError::Impersonated` with the administrator as actor.
Any other session is refused with `AuthnError::NoFlow`. Each refusal
writes a failed `FactorSetup`, `FactorEnabled` or `FactorDisabled` audit
row naming the reason (`enrolment_context`, `impersonated` or
`authn_too_old`). Finishing a
registration re-checks, so a session that was swapped between begin and
finish cannot complete a ceremony it did not start.

A recent-authentication rule is `Fido2Options::max_authn_age`, set
through `AuthnServiceBuilder::with_fido2_options`: a session whose
authentication is older than it is refused all three changes and must
step up first (`begin_step_up`), so a session left open on a shared
machine cannot enrol an attacker's passkey hours later. The default is
five minutes (`DEFAULT_FIDO2_MAX_AUTHN_AGE`); a deployment that wants
no limit sets `max_authn_age: None` explicitly. A service built under a
security profile is held to the profile's five minutes. There the
opt-out is that `None` together with the named waiver,
`waive_profile_floor(ProfileSetting::Fido2MaxAuthnAge)`; a `None`
assigned on the profile's values leaves the limit in force. Nothing else
lifts it.

## Adding passkeys to an existing flow

A common rollout is to keep an existing password-and-TOTP method
and to offer passkey enrolment as an opt-in. The method shape:

```rust,ignore
let passkey_or_password = AuthMethod {
    name: "passkey-or-password".into(),
    scope: AuthnScope::Tenant(tenant_id),
    steps: vec![
        FactorStep::AnyOf(vec![
            FactorKind::Fido2,
            FactorKind::Password,
        ]),
        // When Password is chosen, demand a second factor.
        // Implementing this conditional path takes a richer state
        // machine; the common simplification is two methods.
    ],
};
```

The conditional in the second step (require TOTP only if the user
took the password branch) is the part axess does not natively
support, because `FactorStep` does not nest. Two methods
handle the case: one method
(`passkey-only`, single-step FIDO2) for users with a registered
passkey, and another method (`password-then-totp`, two-step
password-and-TOTP) for users without one. The scope hierarchy
chooses the right method per user. When a user enrols a passkey,
the application updates their user-scoped method to
`passkey-only`; if the passkey is later revoked, the application
reverts to `password-then-totp`.

The pattern keeps both flows in production simultaneously, lets
each user transition independently, and avoids the conditional in
the state machine. The audit log records which method ran for which
user, so the rollout is observable.

## Changing the provider on a running service

`reload_fido2_as(actor, candidate)`, on `authn.with_audit_context(audit)`,
swaps the FIDO2 provider as the administrator it names. The candidate parses the
relying party (`WebauthnBuilder::build`), so an invalid RP id or origin is
refused before the swap and the previous provider keeps serving. Every
registered passkey is bound to the RP id, so a candidate whose
`relying_party_id()` differs from the provider in force is refused as
`RpIdChanged`;
`reload_fido2_with_as(actor, candidate, ReloadFido2::allow_rp_id_change())`
is the explicit acknowledgement, and it is counted
(`fido2_rp_id_changed`) and logged with both ids. `remove_fido2_as(actor)`
takes the provider out. A ceremony begun against the old provider and finished against
a different RP id fails verification. The new provider refuses the origin if
it no longer allows it, and otherwise the authenticator data, which carries
the hash of the old RP id (`InvalidRPOrigin` and `InvalidRPIDHash` in
`webauthn-rs`). See
[live provider reload](../authentication/live-provider-reload.md).

## Threat model

A passkey login is robust against the classes of attack that
password-and-TOTP is weak against. Real-time phishing is defeated
because the credential is origin-bound at registration. Credential
stuffing is defeated because the credential is unique to the
relying party. Server-side breach is defeated because what is
stored is a public key, not a secret.

Three things remain in the attack surface.

**A compromised endpoint.** An attacker with full control
of the user's device can ask the authenticator to perform any
authentication the device permits. The defence here is
user verification: the authenticator must verify the user
(biometric or PIN), not only their presence. For a deployment where this matters, run
a ceremony that requires user verification (the passkey or the
attested-passkey ceremony) and have the policy for the sensitive action
read `context.assurance.fido2.user_verified`.

**Account recovery.** A user who loses their passkey
needs to recover access; the recovery path becomes the weakest
link in the chain. Enrol at least two passkeys (a primary on the phone, a backup on a
hardware key, say), and offer a step-up administrative recovery flow with strong
identity verification rather than a password-reset email. The
recovery flow gets attacked because the primary login is robust;
make sure the recovery is at least as strong.

**Sync-fabric credentials.** A passkey synced through
Apple iCloud Keychain, Google Password Manager, or 1Password is
available on every device the user has signed into that sync
fabric. This is what makes passkeys usable; it also means a
breach of the sync fabric compromises the credential. The
implication is operational, not architectural: deployments that
must defend against sync-fabric compromise pair the passkey with a
device-bound credential (a hardware key, an attestation-bound
device passkey), and require the device-bound credential for the
highest-sensitivity actions through Cedar policy.

## Troubleshooting

Three failures recur during a first integration.

| Symptom | Usually | What to do |
|---|---|---|
| "The relying party ID is not a registrable suffix of the page origin" | `rp_id` does not match the page origin. `example.com` works from a page on `accounts.example.com`; `attacker.com` does not | Check the host part of the URL the browser is actually on |
| Authentication works on one device, fails on another | The credential is bound to the first device and was never synced; some authenticators register credentials that do not sync | Sign in on the second device with the passkey on the first (cross-device authentication, above), then register a passkey there |
| A legitimate user's assertion is refused although the key is theirs | The authenticator's signature counter did not increase (it was restored, or another copy of the credential signed meanwhile), which `webauthn-rs` refuses as a possible clone | Treat it as a possible clone: have the user delete the credential and register the authenticator again |

The counter check is not configurable through axess: an assertion whose
counter goes backwards fails, and an authenticator that reports zero is
never checked.

## Further reading

*Factors and methods* covers the composition machinery this chapter
exercises. *Device identity* covers the device-bound trust ladder
that complements passkeys for high-assurance deployments.
[Authentication assurance and ceremonies](../authorization/assurance.md)
covers how a policy demands a FIDO2 assertion for a specific action
(`context.assurance has fido2`, with its user verification, binding and
age) and names the step-up that satisfies it.
