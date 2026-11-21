# axess-example-fido2

FIDO2 and WebAuthn end to end: the page that talks to the authenticator and
the server that begins and finishes each ceremony. It runs with no outside
service; the account, its credentials and the sessions live in memory.

```bash
cargo run -p axess-example-fido2
```

Open <http://localhost:3000> and sign in as `alice` with `Sample2+`. Use the
name `localhost`, not `127.0.0.1`: a WebAuthn relying party is a domain, and
a browser treats `localhost` as a secure context, so the ceremonies work
over plain HTTP there and nowhere else.

You need an authenticator: the platform's (Touch ID, Windows Hello, a phone's
screen lock), a hardware security key, or a browser's virtual authenticator
(Chrome DevTools, *WebAuthn* tab, with resident keys and user verification
switched on), which is the quickest way to try every button.

## What each button runs

| Button | Server call | Ceremony |
|---|---|---|
| Add a passkey | `begin_fido2_registration_with` | `Fido2Ceremony::Passkey`: user verification required, no attestation, a credential the authenticator stores |
| Add a security key | `begin_fido2_registration_with` | `Fido2Ceremony::SecurityKey(Preferred)`: user verification preferred |
| Add an attested passkey | `begin_fido2_registration_with` | `Fido2Ceremony::AttestedPasskey`: direct attestation, verified against your roots |
| Sign in with a security key | `begin_login`, `prepare_factor_choice(Fido2)`, `verify_factor` | `Fido2Options::login_ceremony`, the security-key ceremony with user verification preferred |
| Sign in with a passkey | `begin_discoverable_login_with`, `finish_discoverable_login` | the passwordless ceremony: no username, user verification required |
| Use a passkey on another device | the same two calls, with `DiscoverablePrompt::CrossDevice` | the same ceremony, hinted at the hybrid transport |
| Approve payment 42 | `require_authz!`, then `begin_step_up_for`, `prepare_factor`, `verify_factor` | the ceremony the policy's `@step_up` names: `passkey` |

A credential keeps the type of the ceremony that registered it, and a login
offers only the credentials its ceremony accepts. So the security-key
sign-in lists the account's security keys and not its passkeys, and the
payment step-up, which runs the passkey ceremony, is answered by a passkey
and not by a security key.

A passkey is registered as a credential the authenticator stores
(`Fido2Options::discoverable_credential` set to
`DiscoverableCredential::Required` in `src/app.rs`). `webauthn-rs` leaves
that to the authenticator by default (`residentKey: "discouraged"`), and a
passkey the authenticator did not store can never sign in without a
username, so a passkey meant for the passwordless sign-in needs `Required`.
The security-key ceremony stays a non-discoverable one.

## The step-up

`policies/payments.cedar` is the whole rule:

```cedar
@step_up("passkey")
permit (principal, action == Bank::Action::"ApprovePayment", resource)
when {
    context.assurance has fido2 &&
    context.assurance.fido2.user_verified &&
    context.assurance.fido2.age_seconds <= 300
};
```

A session that signed in with the password asks to approve the payment and
is answered `403 {"error": "step_up_required", "step_up": "passkey"}`. The
page's `withStepUp` (in `static/app.js`) handles that answer for every
route: it posts the name to `/api/step-up/begin`, has the authenticator sign
the challenge, posts the assertion to `/api/step-up/finish`, and sends the
first request again. The name travels through the browser and nothing rests
on it: the second request is decided by the policy again, on what the
step-up recorded.

Two properties of a step-up are worth seeing in the page:

- Until its factor is verified the session is not signed in. Dismiss the
  browser's dialog and the page shows the sign-in form with *Continue it*,
  which prepares the open step again.
- A step-up that no credential can answer would leave the session there for
  good, so `/api/step-up/begin` refuses it before the session moves
  (`no_credential_for_step_up`). Try approving the payment with only a
  security key registered.

Adding or deleting a credential uses the same answer. The service refuses a
credential change on a session that authenticated more than five minutes ago
(`Fido2Options::max_authn_age`), and the route says so as
`step_up_required` with `password`, so the one handler covers it.

## Cross-device authentication

*Use a passkey on another device* signs in on a machine that holds no
passkey, with one on a phone: the browser shows a QR code, the phone that
scans it proves it is nearby over Bluetooth, and the passkey on the phone
signs the challenge. All of that runs between the browser and the phone. The
relying party's part is one option on the ordinary passwordless ceremony:

```rust,ignore
let login = DiscoverableLogin::default()
    .in_tenant(tenant_id)
    .with_prompt(DiscoverablePrompt::CrossDevice);
let challenge = authn.begin_discoverable_login_with(&session, login).await?;
```

The challenge then carries `"hints": ["hybrid"]` and no `mediation`, so a
browser that reads WebAuthn hints opens its dialog on the QR code; one that
does not shows its usual dialog, where another device is one of the choices.
The finish is `finish_discoverable_login`, unchanged.

After such a sign-in the page offers to create a passkey on this device, so
the phone is not needed next time. It knows to offer because the browser
reports `authenticatorAttachment: "cross-platform"` beside the assertion.
No signature covers that field, so the server uses it for the offer and for
nothing else.

A sign-in that names its credentials (the security-key sign-in, the
step-up) needs no prompt to reach a phone: its challenge lists each
credential with the transports it registered, and the browser offers the QR
code for one that registered `hybrid`.

## Attested registration

*Add an attested passkey* appears when the server is started with an
attestation root:

```bash
FIDO2_ATTESTATION_ROOT=/path/to/vendor-root.pem cargo run -p axess-example-fido2
```

The registration then asks for direct attestation and is refused unless the
authenticator's attestation chains to that root; an authenticator that syncs
its keys is refused too. Without a root there is nothing to verify an
attestation against, so the button is not shown and the route answers `404`.
A deployment that names authenticator models one by one builds its
`AttestationCaList` with `webauthn-rs`'s `AttestationCaListBuilder` instead.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `FIDO2_ORIGIN` | `http://localhost:3000` | the origin the browser shows; every credential is bound to it |
| `FIDO2_RP_ID` | the origin's host | the relying-party id: the host or a registrable suffix of it |
| `FIDO2_ATTESTATION_ROOT` | unset | PEM root certificate for the attested registration |
| `AXESS_DEV_INSECURE_COOKIES` | unset | `1` sends the session cookie without `Secure`, for a browser that refuses `Secure` cookies on `http://localhost` |

The server always listens on `127.0.0.1:3000`; behind a TLS terminator, set
`FIDO2_ORIGIN` to the public origin.

## What to copy, and what not to

Copy the handlers (`src/login.rs`, `src/passkeys.rs`, `src/payments.rs`) and
the four translation functions at the top of `static/app.js`.

Do not copy the storage. `InMemoryBackend` comes from the `testing` feature
and forgets everything at exit, which is why a release build of this crate
is refused. `examples/sqlite` shows a store of your own, including the two
credential-id methods of `FactorStore` that a passkey registration needs
(`claim_fido2_credential` and `release_fido2_credential`). The index of
which account holds each credential id, where a passwordless sign-in
starts, is the application's own (`AppState::passkey_holders`, written
after each registration and deletion): in a database it is a table keyed by
tenant and credential id, written with the credential.

Five things in the handlers keep a sign-in from saying more than it should,
being tried twice or being left open, and they belong in your copy too:

- The password form is one call, `login_with_password`. It answers every
  refusal alike and ends the login it began, so the session and its cookie
  are the same after a wrong password for a real account as after any
  password for an unknown one. The handler adds nothing to that.
- A refused sign-in that the handlers themselves began (the security-key
  login, a passwordless ceremony) clears the session (`refuse_sign_in` in
  `src/login.rs`), on every refusal: a credential nobody registered, a body
  that is no assertion, a store that does not answer. A challenge is
  answered once, and no login is left open to try again.
- The step-up routes act on a step-up only (`AuthSession::step_up_pending`
  in `src/payments.rs`). A security-key login in progress is also a session
  waiting for a factor, and its step would take the password; sent to a
  step-up route it is ended and refused, and the security-key finish takes
  an assertion only. The password form is the one route that takes a
  password for a login.
- The routes that finish a sign-in or a step-up are rate limited like the
  ones that begin one.
- A sign-in the page abandons is ended on the server. When the browser's
  dialog is dismissed, or the browser refuses the request or lets it time
  out, the page posts to `/api/login/cancel` and the session becomes a
  fresh guest: no login in progress, no challenge left to answer. A page
  that never gets to say so leaves nothing open for long: the service
  refuses a challenge five minutes after it was issued
  (`Fido2Options::ceremony_timeout`) and a login in progress ten minutes
  after it began (`AuthnServiceBuilder::with_flow_ttl`).

Three choices here are a demo's and need a decision in your application:

- The account's login method is one step, the password **or** a FIDO2
  credential. That is what lets one account show three ways in; it also
  means the password alone signs in. The payment policy is what asks for
  more.
- The username-first security-key sign-in tells its caller whether a
  username has a security key, because the challenge must list the key ids.
  The passwordless sign-in does not.
- The user is created with its WebAuthn handle (`User::webauthn_id`). If
  yours are not, `begin_fido2_registration` returns the handle it minted and
  you store it on the user before the next ceremony.

## Tests

```bash
cargo test -p axess-example-fido2
```

`tests/flows.rs` drives every route as the page does. The ceremonies are
begun by `webauthn-rs`, so the challenges are the ones a browser receives;
the authenticator in `tests/support` stands in for the signature check
alone, as the library's own FIDO2 tests do. `build_router_on` takes the
clock and the FIDO2 provider, which is how a test moves time past the
five-minute limits and answers a ceremony without a browser.
