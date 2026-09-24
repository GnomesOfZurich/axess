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

The configuration struct is `PasswordConfig`, and it is smaller than
you might expect:

```rust,ignore
pub struct PasswordConfig {
    /// Argon2id PHC hash string, zeroized on drop.
    pub hash: ZeroizedString,
    /// Strength rules applied when setting a new password.
    pub rules: PasswordRules,
}
```

There are no Argon2 parameters to set, and no pepper. Hashing is the
`password_auth` crate's `generate_password_hash` / `verify_password`
pair, which picks recommended Argon2id parameters, generates a fresh
random salt per hash, and encodes the parameter set into the stored
hash itself, in PHC string format (the Password Hashing Competition's
`$argon2id$v=19$m=...` encoding). Verification reads the parameters back out of the stored hash,
so raising the cost later is a matter of upgrading the crate and
rehashing on next login. Old hashes keep verifying against the
parameters they were made with.

That also means the cost is not yours to tune from axess, and the
answer to "can I use a pepper" is that you would have to apply it
yourself before calling `generate_password_hash`, storing the result in
`hash`. Nothing in the type stops you; nothing in the type helps you
either.

What *is* configurable is the strength rules:

```rust,ignore
pub struct PasswordRules {
    pub min_length: usize,        // default 12
    pub require_uppercase: bool,  // default true
    pub require_lowercase: bool,  // default true
    pub require_digit: bool,      // default true
    pub require_special: bool,    // default false
    pub history_count: usize,     // default 0, no reuse check
}
```

So axess does enforce complexity, and the defaults are stricter than
the habitual eight-character minimum: twelve characters with upper,
lower and a digit. `require_special` is off by default because the
character-class requirement that most reliably produces `Password1!` is
the one that demands punctuation.

`history_count` is the reuse check, and it is off by default because it
costs something to turn on: a non-zero value makes the flow call
`IdentityPasswordHistory::password_history` and `record_password_hash`, both of
which `unimplemented!()` until your backend provides them. Set it to
`12` for the SOC2-shaped "cannot reuse the last twelve" rule, and
implement those two methods at the same time.

Rules are resolved per tenant, through
`IdentityLookup::password_rules_for_tenant`, which defaults to
`PasswordRules::default()`. A deployment with one policy can ignore
it; a deployment that sells a stricter tier can override it per tenant
without touching the login path.

There is no maximum length in the rules. You should want one, because
Argon2id is deliberately expensive and an unbounded password field is a
cheap way to burn server CPU. Impose it at the
edge, where the request is parsed, before the value reaches the hasher.

## TOTP (RFC 6238)

The TOTP factor verifies a six-digit code derived from a shared
secret and the current time window. The shared secret is twenty
bytes of cryptographic randomness, generated at enrolment time and
stored alongside the user's other factor configurations.

The configuration struct is `TotpConfig`:

```rust,ignore
pub struct TotpConfig {
    pub secret: ZeroizedString,      // raw bytes; base32 for provisioning URIs
    pub digits: u8,                  // default 6
    pub period_secs: u32,            // default 30
    pub algorithm: OtpAlgorithm,     // Sha1 | Sha256 | Sha512, default Sha1
    pub past_window: u32,            // default 1
    pub future_window: u32,          // default 1
    pub last_step: Option<u64>,      // last validated counter; blocks replay
}
```

Two fields there are not decoration. The drift window is *two* numbers,
not one: `past_window` for a client behind the server and
`future_window` for one ahead of it. Both default to 1, because a
phone's clock runs ahead as often as behind. NTP-synced devices drift
forward across time-zone changes, and a handset's OS clock is commonly
a few hundred milliseconds early, so a one-sided window rejects valid
codes from those users.

`last_step` is the replay defence. It records the counter of the last
code accepted, so a code that already worked cannot be used again
inside its remaining validity. That makes `TotpConfig` mutable state,
not just configuration: your factor store must persist the updated
value after a successful verification, or the same intercepted code
stays usable for the rest of its window.

`secret` is zeroized in memory on drop. It holds the raw bytes, twenty
cryptographically random ones from `SecureRng`; base32 is the encoding
applied when the secret goes into a provisioning URI for a QR code or a
manual key, not how it is stored. Adopters serialise it to and from
their factor store however the store's encryption envelope prefers.

`digits` is six in line with every TOTP authenticator in production
use. RFC 6238 admits up to eight, but no widely deployed TOTP app
generates eight-digit codes, so the field exists for symmetry rather
than for variability.

`period_secs` is the time window each code is valid for. Thirty is
the RFC default and what every authenticator app expects. Increasing
the period (to sixty seconds, say) reduces the chance that a user
typing slowly enters a code that has just expired, at the cost of
doubling the window an intercepted code remains valid. The
recommendation is to keep this at thirty unless you have a specific
reason to change it.

`algorithm` is an `OtpAlgorithm`: `Sha1`, `Sha256` or `Sha512`. SHA-1
is the RFC 6238 default and the only one guaranteed to interoperate.
Most modern authenticator apps handle SHA-256; few handle SHA-512.
Stay on SHA-1 unless you control which app the users will use.

`past_window` and `future_window` count the adjacent time steps the
verifier accepts on each side. One and one, against a thirty-second
period, gives a ninety-second total acceptance range. Lifting either
reduces friction for users with a drifting clock at the cost of
widening the window an intercepted code stays usable, and widening
`past_window` in particular gives a brute-force attempt more valid
targets per guess. The defaults are the right trade for most
deployments.

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

It is robust against either credential leaking on its own. The
password alone does not complete a login without the TOTP code, and
the TOTP secret alone does not complete one without the password. That
also covers credential stuffing: an attacker replaying credentials
leaked from another service is unlikely to hold the user's TOTP secret
as well.

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
