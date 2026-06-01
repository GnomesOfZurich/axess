# FIDO2 and WebAuthn passkeys

FIDO2 is the answer to real-time phishing. Every other second-factor
mechanism in this book (TOTP, HOTP, email OTP, SMS) is vulnerable to
an attacker who proxies the user's input through a fake login page to
the real server in real time. WebAuthn, the browser-side standard
that FIDO2 implements, binds each authentication to the origin where
the credential was registered, and a credential registered against
`accounts.example.com` cannot be exercised against
`accounts-example-com.attacker.example`. The defence is structural,
not behavioural: the browser refuses to use the credential at the
wrong origin, regardless of what the user clicks.

This chapter walks through the integration: the two-ceremony model,
relying-party configuration, storage, the resident-key choice, and
the rollout patterns for shipping passkeys alongside an existing
password-and-TOTP flow.

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

Registration is the more involved of the two because it is where the
relying-party configuration matters. The server starts the ceremony
by calling `Fido2Provider::begin_registration`, which returns a
`CreationChallengeResponse`. The handler serialises that to JSON and
returns it to the browser, which calls
`navigator.credentials.create()` with the JSON deserialised. The
browser produces a `RegisterPublicKeyCredential`, which the page
posts back to the server. The server calls
`Fido2Provider::finish_registration`, which verifies the response
against the challenge stored in the session, and on success returns
the credential public key and metadata. The application persists this
to the factor store under the user's scope, indexed by the credential
id.

Authentication mirrors registration. The server calls
`Fido2Provider::begin_authentication`, which returns a
`RequestChallengeResponse` listing the credential ids the user has
registered. The browser calls `navigator.credentials.get()` with the
serialised challenge. The browser produces a
`PublicKeyCredential`, the page posts it back, and the server calls
`Fido2Provider::finish_authentication`, which verifies the signature
against the stored public key.

The challenge in both ceremonies is the part the session machinery
threads through. The server generates the challenge from `SecureRng`
at `begin`, stores it in the session (in a typed field on
`SessionData::custom` or a dedicated extension), and reads it back at
`finish`. The challenge is one-shot; it is consumed at `finish`,
regardless of success, to prevent replay. The whole ceremony lives
inside the typed state machine: a `begin` without a subsequent
`finish` leaves the session in a state where the next call expects
the `finish`, and any other call returns an error.

## Relying-party configuration

The relying party is the server that owns the credentials. WebAuthn
identifies the relying party by an origin (the host plus scheme plus
port) and by a relying-party id (an effective domain suffix of the
origin). The two pieces of configuration that matter at registration
time are:

```rust,ignore
pub struct Fido2Config {
    pub rp_id: String,            // e.g. "example.com"
    pub rp_name: String,          // human-readable, "Example Inc."
    pub rp_origin: Url,           // e.g. "https://accounts.example.com"
    pub user_verification: UserVerificationPolicy,
    pub attestation: AttestationConveyancePreference,
    pub resident_key: ResidentKeyRequirement,
}
```

`rp_id` is the relying-party id, a string equal to or a suffix of the
host part of the origin. Setting it to the apex domain
(`example.com` rather than `accounts.example.com`) lets credentials
registered on the accounts subdomain be used across other subdomains
of the same apex (`app.example.com`, `admin.example.com`), which is
usually what you want. Setting it to the full hostname scopes
credentials to that hostname alone, which is appropriate when other
subdomains belong to other applications you do not trust.

`rp_origin` is the full origin where the registration happens. The
browser cross-checks this against the page's actual origin and
refuses the registration if they do not match. Wildcards are not
allowed; multi-region deployments register credentials under each
region's specific origin.

`user_verification` controls whether the authenticator must verify
the user's presence (a fingerprint, a PIN, a face scan) at
authentication time, in addition to proving possession of the
authenticator. `Required` is the right setting for high-assurance
deployments; `Preferred` is the right setting for usability when
some authenticators do not support verification.

`attestation` controls how much detail the authenticator reports
about itself at registration. `None` is the right default unless you
have a specific reason to track which authenticator models your
users register (some regulatory frameworks require this for
hardware-key deployments). `Direct` records the attestation
statement; the trade-off is privacy (the authenticator vendor is
identifiable from the attestation).

`resident_key` controls whether the authenticator stores the
credential identifier on-device (a resident key, or "passkey"), or
whether the credential id is server-side and the authenticator only
stores the key material. `Required` is what makes a passkey: the
user does not have to type a username, because the authenticator
holds the credential id and surfaces it directly to the browser.
`Preferred` allows either, with the device's preference deciding.
`Discouraged` is the legacy mode where the server provides the
credential id list.

The passkey-or-not choice is the most consequential for usability.
Passkeys are what users mean today when they say "biometric login":
the user clicks a button, taps their fingerprint, and they are in.
Non-resident credentials require the user to enter a username
first, which is the older WebAuthn flow and what most existing
TOTP-style second factors look like. New deployments should default
to passkeys; older deployments adopting WebAuthn alongside existing
flows often start with non-resident and migrate.

## Storage

Each registered credential is one row in the factor store. The row
carries:

- The credential id (a byte string, base64-encoded for storage).
- The public key (the bytes WebAuthn returns at registration).
- The signature counter (used to detect credential cloning).
- The attestation statement (if `attestation` was set above `None`).
- The user verification flag from registration.
- The authenticator transports list (USB, NFC, internal, hybrid).

The signature counter is the part that catches credential cloning.
WebAuthn authenticators increment the counter on each successful
signature. The server stores the counter at registration and updates
it at each authentication. A counter that fails to increase
between authentications indicates the credential has been cloned
(the clone's counter started from the same value as the original
and diverged on first use). The defence is conservative: revoke the
credential and require re-registration.

The credential is scoped per user (each user has zero or more
registered credentials), which is the natural per-user scope from
the chapter *Scope hierarchy*. A user with multiple authenticators
(a phone passkey plus a hardware key, say) has multiple credentials
under their scope; the authentication ceremony enumerates them and
the user's authenticator (or the browser, in the passkey case)
picks one.

## Adding passkeys to an existing flow

A common rollout is to keep an existing password-and-TOTP method
and to offer passkey enrolment as an opt-in. The method shape:

```rust,ignore
let passkey_or_password = Method {
    name: "passkey-or-password".into(),
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
support, because `FactorStep` does not nest. Two parallel methods
handle the case more cleanly: one method
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

## Threat model

A passkey login is robust against the classes of attack that
password-and-TOTP is weak against. Real-time phishing is defeated
because the credential is origin-bound at registration. Credential
stuffing is defeated because the credential is unique to the
relying party. Server-side breach is defeated because what is
stored is a public key, not a secret.

The remaining attack surface is:

The first is a compromised endpoint. An attacker with full control
of the user's device can ask the authenticator to perform any
authentication the device permits. The defence here is
user-verification: the authenticator must prove the user is
present (biometric or PIN). For a deployment where this matters,
`user_verification: Required` is non-negotiable.

The second is account recovery. A user who loses their passkey
needs to recover access; the recovery path becomes the weakest
link in the chain. The recommendation is to enrol at least two
passkeys (a primary on the phone, a backup on a hardware key, say),
and to offer a step-up administrative recovery flow with strong
identity verification rather than a password-reset email. The
recovery flow gets attacked because the primary login is robust;
make sure the recovery is at least as strong.

The third is sync-fabric credentials. A passkey synced through
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

A few failures recur during initial integration.

If the browser rejects the registration with "The relying party ID
is not a registrable suffix of the page origin", the `rp_id` does
not match the page origin. Setting `rp_id` to `example.com` while
the registration page is on `accounts.example.com` works; setting
it to `attacker.com` does not. Check the host part of the actual
URL the browser is on.

If authentication succeeds on one device and fails on another, the
likely cause is that the credential is a passkey on one device but
not synced to the other. Some authenticators register
non-syncable credentials by default; check the
`resident_key: Required` setting and the device's documentation.

If the signature counter check fails for legitimate users, the
authenticator may not implement the counter (some legacy hardware
keys do not). The fix is to log the counter mismatch and let the
authentication proceed, sacrificing clone detection for usability
on those specific authenticators. The decision is policy, and the
application surfaces it explicitly.

## Further reading

*Factors and methods* covers the composition machinery this chapter
exercises. *Device identity* covers the device-bound trust ladder
that complements passkeys for high-assurance deployments. *Cedar
policy fundamentals* covers how a policy demands FIDO2 for specific
actions (the `factors_completed.contains("Fido2")` check).
