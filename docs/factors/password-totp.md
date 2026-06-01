# Password and TOTP

The four factors `axess-factors` ships by default (`password`, `totp`,
`hotp`, `email_otp`) are the ones most adopters reach for first. They
require no external IdP, no specialised hardware, no extra
infrastructure. This chapter walks through password (Argon2id) and
TOTP (RFC 6238), the two most common combination in practice, with
references to HOTP and email OTP at the end. The pattern these
factors illustrate generalises to every other factor in the library.

The feature flags `password`, `totp`, `hotp`, `email_otp` are all on
by default in `axess-factors`. No `Cargo.toml` change is needed to
use them.

## Password (Argon2id)

The password factor verifies a user-supplied secret against a stored
Argon2id hash. The choice of Argon2id rather than bcrypt or PBKDF2 is
the standard one for new systems built today; the parameter tuning is
the operational lever you reach for first.

The configuration struct is `PasswordConfig`. It carries the Argon2id
parameters (memory cost, time cost, parallelism), the minimum and
maximum password length, and the optional pepper. Defaults are
calibrated for a server class that can spare about fifty milliseconds
of CPU per verification, which is what current guidance considers an
appropriate cost ceiling for an interactive login.

```rust,ignore
pub struct PasswordConfig {
    pub argon: Argon2idParams,    // memory, time, parallelism
    pub min_length: usize,        // default 8
    pub max_length: usize,        // default 128
    pub pepper: Option<Vec<u8>>,  // optional, see below
}
```

The pepper is an optional secret stored outside the database (in the
secrets manager that holds the session signing key). When set, the
hash is HMAC-SHA256(pepper, password) before Argon2id processes it.
The defence-in-depth benefit is the same one refresh-token peppers
provide: a database breach alone does not enable an offline
brute-force attack against the password hashes, because the pepper
is not in the database.

The maximum password length matters for DoS protection. Argon2id is
deliberately expensive; an attacker who can submit a megabyte of
password text per request can wedge the server with a handful of
concurrent attempts. The cap is one hundred and twenty-eight
characters by default, which is generous for legitimate users (no
password manager generates more than that) and bounded enough that
the worst case per request stays under a hundred milliseconds.

The minimum is eight characters, which is below the modern
recommendation but matches what most users encounter elsewhere. A
deployment serious about password quality lifts this to twelve or
fourteen, alongside a length-and-character-class meter on the signup
form. Axess does not enforce password complexity rules beyond the
length range; complexity meters live in the registration UI, where
they can produce real feedback.

## TOTP (RFC 6238)

The TOTP factor verifies a six-digit code derived from a shared
secret and the current time window. The shared secret is twenty
bytes of cryptographic randomness, generated at enrolment time and
stored alongside the user's other factor configurations.

The configuration struct is `TotpConfig`:

```rust,ignore
pub struct TotpConfig {
    pub secret: ZeroizedString,   // base32-encoded 20-byte secret
    pub digits: u32,              // default 6
    pub period: Duration,         // default 30 s
    pub algorithm: HmacAlgorithm, // default Sha1 (RFC 6238)
    pub drift_window: u32,        // default 1
}
```

`secret` is zeroized in memory on drop. The string is base32-encoded
because that is what TOTP apps expect when scanning a QR code or
pasting a manual key; the bytes underneath are twenty cryptographically
random bytes from `SecureRng`. Adopters serialise the secret to and
from their factor store however the store's encryption envelope
prefers.

`digits` is six in line with every TOTP authenticator in production
use. RFC 6238 admits up to eight, but no widely deployed TOTP app
generates eight-digit codes, so the field exists for symmetry rather
than for variability.

`period` is the time window each code is valid for. Thirty seconds is
the RFC default and what every authenticator app expects. Increasing
the period (to sixty seconds, say) reduces the chance that a user
typing slowly enters a code that has just expired, at the cost of
doubling the window an intercepted code remains valid. The
recommendation is to keep this at thirty unless you have a specific
reason to change it.

`algorithm` is the HMAC primitive used to derive the code. SHA-1 is
the RFC 6238 default and remains universally compatible. SHA-256 is
the harder-to-collide choice; some authenticator apps do not yet
support it. Stay on SHA-1 unless you have control over the
authenticator app the users will use.

`drift_window` is the count of adjacent time windows the verifier
accepts. A drift window of one means the verifier accepts codes from
the current window plus one window on either side, covering a
ninety-second total acceptance range against a thirty-second period.
The drift accommodates a few seconds of clock skew between server and
authenticator. Lifting it to two or three reduces user friction at
the cost of slightly increasing the brute-force attack surface; the
default of one is the right trade for most deployments.

## Composing password and TOTP

A method that combines password and TOTP is two `FactorStep`s:

```rust,ignore
use axess::{FactorKind, FactorStep, Method};

let password_plus_totp = Method {
    name: "password-then-totp".into(),
    steps: vec![
        FactorStep::Required(FactorKind::Password),
        FactorStep::Required(FactorKind::Totp),
    ],
};
```

The method is stored at whatever scope the deployment wants (Global
default, Tenant override, User override; see *Scope hierarchy*). At
`begin_login` time the resolver loads the method, the session
transitions to `Authenticating` with `remaining = [Password, Totp]`,
and the login flow walks the two factors in order.

The application's login page renders the password prompt while the
session is in `Authenticating` with `remaining[0] == Password`, and
the TOTP prompt while in `Authenticating` with `remaining[0] == Totp`.
A successful TOTP verification calls `advance_factor`, which returns
`Completed`, and the orchestrator transitions the session to
`Authenticated`. The user is logged in.

A common variant offers TOTP plus another second factor as a choice:

```rust,ignore
let password_plus_2fa_choice = Method {
    name: "password-then-2fa-choice".into(),
    steps: vec![
        FactorStep::Required(FactorKind::Password),
        FactorStep::AnyOf(vec![
            FactorKind::Totp,
            FactorKind::Fido2,
            FactorKind::EmailOtp,
        ]),
    ],
};
```

The login page after the password step shows three options. The user
picks one; the application calls `verify_factor` with the appropriate
credential; on success, the session is authenticated.

## TOTP enrolment

Enrolment is a separate ceremony from login. The user is already
authenticated (often immediately after signup), and the application
walks them through registering a TOTP device. The shape is uniform
across deployments.

The server generates a new TOTP secret through `SecureRng`. It
serialises the secret as a base32 string and as an
`otpauth://totp/<issuer>:<account>?secret=<base32>&issuer=<issuer>`
URI suitable for embedding in a QR code. The UI displays the QR code
(scanned by the user's TOTP app) and offers a copy of the base32
secret for users whose apps prefer manual entry.

The user enters a six-digit code from their app, the server verifies
it against the same TOTP algorithm that login uses, and on success
the server persists the secret to the factor store under the user's
scope. The user is now enrolled. Their next login that demands TOTP
will succeed.

Two operational details matter at enrolment.

The first is that the verification at enrolment must succeed before
the secret is persisted. A user who scans the QR code but mistypes
the verification code (or scans into the wrong app) should not be
left with a stored secret that they cannot reproduce. The standard
pattern is: generate the secret in memory, display the QR code, hold
the secret in a short-lived enrolment record (in the session
`custom` field, for example), verify the user's code, persist on
success, discard on failure.

The second is recovery codes. A user who loses access to their TOTP
device cannot log in with a method that requires TOTP. The
deployment must offer a recovery path: either a recovery code printed
at enrolment time (a long random string the user stores in a password
manager), an email-OTP fallback factor, or an administrative reset
flow with identity verification. Axess does not opinionate which path
to take; the choice depends on the deployment's risk profile. The
common pattern is to generate a recovery code at enrolment, treat it
as a one-shot factor stored under the user's scope, and offer it as
an alternative second factor.

## HOTP and email OTP, briefly

The HOTP factor is the counter-based variant of TOTP. Instead of
deriving the code from the current time window, the verifier derives
it from a monotonically-increasing counter that advances on every
successful verification. HOTP is the right choice for hardware tokens
that have no clock (some YubiKey configurations, for instance). The
configuration mirrors `TotpConfig` with a counter field instead of a
period.

The email OTP factor verifies a six-digit code delivered to the user
out of band, typically by email. The configuration carries the code
length, the validity window (default fifteen minutes), and the count
of allowed attempts before the code is revoked. The delivery is the
application's responsibility; axess provides the verification side,
the application provides the email send. The chapter *Audit events*
covers the events emitted at email-OTP issuance and verification.

## Threat model

A password-plus-TOTP login is robust against three common attacks
and weak against one.

It is robust against a password leak (an attacker with the password
alone cannot complete login without the TOTP code), against a TOTP
secret leak (an attacker with the TOTP secret alone cannot complete
login without the password), and against credential stuffing (an
attacker reusing leaked credentials from another service is
unlikely to also have the user's TOTP secret).

It is weak against a real-time phishing attack: a fake login page
that prompts the user for their password, forwards it to the real
server, prompts the user for their TOTP code, forwards that to the
real server, and steals the resulting session. FIDO2 (covered in
*FIDO2 and WebAuthn passkeys*) is the standard defence against
this class of attack, because the WebAuthn ceremony binds the
authentication to the origin and cannot be replayed against a
different origin.

For applications where real-time phishing is a credible threat
(financial services, healthcare, anything that handles regulated
data), the recommendation is to offer FIDO2 as the second factor
and treat TOTP as a fallback for users who do not yet have a
passkey. The combination is what most regulators are asking for
today.

## Troubleshooting

A few failures recur often enough to be worth naming.

If TOTP verification fails consistently, the most likely cause is
clock skew between the server and the authenticator app. The
`drift_window` config accommodates a few seconds; larger drift
points to a misconfigured NTP setup on either side. Logging the
generated and accepted windows at `debug` level surfaces the offset
quickly.

If TOTP verification fails for some users but not others, the
likely cause is that the affected users scanned the QR code into an
app that defaults to SHA-256 (some less common authenticators do),
while the server defaults to SHA-1. The fix is to either align the
server to SHA-256 (and re-enrol users), or to ensure the QR code
URI explicitly specifies SHA-1.

If password verification is slow under load, the Argon2id
parameters are probably set higher than the server class can
support at the offered concurrency. The fix is to either lower the
memory cost or to add CPU. Lower the memory cost first; below
sixty-four megabytes you are out of the modern recommendation, and
sixty-four megabytes is what current guidance suggests as a
minimum.

If password verification is fast but logins occasionally take
multiple seconds, the bottleneck is somewhere else (the factor
store, the session store, an outbound network call in the login
handler). Inspect the trace.

## Further reading

*Factors and methods* covers the composition machinery this chapter
exercises. *FIDO2 and WebAuthn passkeys* covers the WebAuthn second
factor that supplants TOTP for the highest-assurance deployments.
*Identity store implementation* covers how the password hash and
TOTP secret are persisted alongside the user. *Audit events* covers
the events emitted at every step of the password and TOTP flow.
