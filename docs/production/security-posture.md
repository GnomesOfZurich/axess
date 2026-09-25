# Security posture

What axess chooses for you, what it leaves to you, and what an auditor
will ask about. Read it before launch, not after the questionnaire
arrives.

## Crypto backends

Axess uses [RustCrypto](https://github.com/RustCrypto) for every
primitive it implements itself, unconditionally: AES-256-GCM
(the session envelope), HMAC-SHA256 (cookie signing, fingerprint
binding), Argon2id (password hashing), TOTP and HOTP (RFC 6238
and RFC 4226), and SHA-256 (refresh token hashing). These are
plain dependencies. There is no feature that swaps them for
another implementation, and no `cfg` in the source that selects
between backends.

The one backend an adopter chooses is for **JWT signature
verification**, because `jsonwebtoken` takes its provider from a
cargo feature and will not pick one for you. Anything enabling
`jwt` names one of:

```toml
[dependencies]
# Pure Rust, builds anywhere. The default choice.
axess = { version = "0.7.0", features = ["jwt", "jwt-rust-crypto"] }

# aws-lc-rs: wraps the FIPS-validated aws-lc, needs a C toolchain
# (and NASM on Windows), and does not build on every target.
axess = { version = "0.7.0", features = ["jwt", "jwt-aws-lc"] }
```

Naming neither is a compile error. Naming both is allowed,
because cargo can enable the second one when another crate in
the build asks for it, and axess installs one provider rather
than letting `jsonwebtoken` panic.

[ring](https://github.com/briansmith/ring) still appears in the
dependency graph through TLS-adjacent crates (`rustls` and its
consumers), not through axess's own code.

## FIPS targeting

**Axess does not today offer a FIPS-validated build.** A
deployment that needs one should read this section as a
statement of the gap rather than a route through it.

The reason is the first of the three things a FIPS 140-3
deployment requires: every cryptographic operation must run
through a validated module. Axess's own primitives are
RustCrypto, which is not validated, and they are not
switchable. The `jwt-aws-lc` feature routes JWT signature
verification through aws-lc-rs, and that is the only operation
it covers. The session envelope, password hashing, refresh-token
hashing and HMAC fingerprint binding do not move with it.

The second requirement is that the compile and link chain
introduces no non-validated crypto. Cargo's dependency graph is
the source of truth: `cargo tree` and inspecting for non-aws-lc
crypto crates (rustls, ring, the RustCrypto crates) shows what
the deployment actually pulls in.

The third is that the validation certificate covers the
platform the deployment runs on. NIST publishes FIPS validation
certificates per platform-binary combination; a certificate for
Linux x86-64 does not cover macOS ARM. The deployment's
compliance evidence must include the certificate matching the
production platform.

Closing the gap means making the remaining primitives
selectable, which is a design change and not a feature flag.
Raise it as an adopter requirement if you need it.

## PII classification

The application records PII across several stores. The
classification matters for GDPR (the data subject's rights), for
SOC 2 (the control objectives), and for the retention sweep
(*Device identity*'s `device_retention_days`). The classification:

| Class | What | Where | Retention |
|---|---|---|---|
| Primary | Identifier (email, username), password hash, TOTP secret, FIDO2 credentials, the IP seen at authentication, device fingerprint | Identity store, device store | Yours to choose, within whatever regulatory bounds apply |
| Secondary | The audit-event log, which reaches the primary through `user_id`, `tenant_id`, `device_id` and `client_ip` | Audit store | *Audit pipeline*. The usual GDPR pattern keeps it longer than primary PII but scrubs or hashes the IPs once the hot window closes |
| Pseudonymous | Session id, refresh-token hash, device id (a UUID that names no user) | Session store, device store | Longer than primary PII, with no GDPR implication |

Pseudonymous is a claim about the data on its own. Each of those values
becomes PII the moment it is joined to the primary set, and the join needs
access to the identity store, so that store's access control is what keeps
the classification true.

The GDPR right-to-erasure verb is `IdentityAdmin::delete_user`, and
what it does is your implementation's decision rather than a cascade
axess runs. The trait states the contract: delete or irreversibly
anonymise the user row, every factor config under `AuthnScope::User`,
the refresh tokens, the persisted sessions, the password history, and
any application rows whose retention basis was the consent now
withdrawn. After `Ok(())`, `get_user`, `find_user` and `account_status`
must report the user gone, and any in-flight session must fail its next
`is_valid` check.

Its default body panics rather than returning an error, so a backend
that never overrode it fails loudly the first time an erasure request
arrives instead of reporting success and deleting nothing. The audit-event entries
that reference the user are not removed (the audit trail is
load-bearing for compliance); the user's identifier in the
events is hashed to a pseudonymous token, which makes the events
non-PII without losing the ability to correlate them.

## Compliance touch-points

The deployment will face one or more of these regulatory frames.
Axess does not provide compliance on its own; it provides the
controls each framework requires. The touch-points:

| Frame | What axess gives you | What stays yours |
|---|---|---|
| GDPR (EU data protection) | The erasure verb above, audit retention configuration, IP scrubbing in the cold-tier archive, `DeviceStore::sweep` against your `SweepConfig` thresholds | Data subject notices, the privacy policy, the legal basis for processing |
| SOC 2 (operational controls) | The audit catalogue, the lockout policy against credential stuffing, session and refresh-token security, the operational metrics | Policy and procedure documentation |
| PCI-DSS (card data) | Strong authentication for administrative access, audit retention of at least one year, session data encrypted at rest | The cardholder data environment. Axess covers the authentication boundary into it, not the environment |
| HIPAA (US healthcare) | Strong authentication for access to protected health information, audit retention of at least six years, session data encrypted at rest and in transit | The HIPAA-covered systems, on the same boundary split |

One gap in that first column is easy to miss under SOC 2: every
*authentication* decision produces an `AuthEvent`, but *authorisation*
decisions go to a `tracing` target instead. They are not in the catalogue,
so an evidence pipeline that reads only `AuthEvent` rows will not have
them. Wire the target separately.

For the mechanism behind a specific control: *Session lifecycle and crypto
envelope* for encryption at rest, *Audit pipeline* for retention, *Refresh
tokens and session continuity* for refresh-token hygiene, *Multi-tenancy*
for the lockout policy.

## Failing closed

Two stores sit behind the login path, and what happens when each one is
down is a decision rather than an accident.

The lockout counter is the first. `record_failed_attempt` is a write,
and the read-replica split this library encourages puts reads on a
replica and writes on the primary, so a primary outage leaves logins
working and the counter dead. `LockoutPolicy::on_counter_unavailable`
decides what happens then. It defaults to `CounterUnavailable::Lock`,
which treats the attempt as locked and keeps brute force bounded.
`CounterUnavailable::Allow` keeps those users logging in and leaves
lockout disabled until the counter returns. Alert on
`AuthnMetrics::factor_counter_store_outage` either way: under `Lock` it
explains the support calls, and under `Allow` it is the only signal
that a control is off.

The audit store is the second, and it fails closed with no switch. If
`IdentityAuthnLog::record_event` returns an error, the flow returns
`AuthnError::Store` and the login does not succeed. An authentication
that leaves no evidence has not, for evidence purposes, happened, and a
catalogue offered as SOC 2 or PCI-DSS evidence cannot be allowed to
develop holes quietly.

The cost is availability, and it is not small: **logins fail while the
audit store does.** Put the sink behind something durable. Write
locally and ship asynchronously, so `record_event` only fails when a
local write fails, rather than calling a remote service on the request
path. `AuthnMetrics::audit_store_outage` fires on this path and should
page rather than feed a dashboard, because every login is failing while
it does.

One consequence is worth stating, because the obvious implementation
gets it wrong. Every path that rejects a login emits before it returns,
including the ones where the tenant or the identifier does not exist.
That is what stops an audit outage from becoming a user-enumeration
oracle: if only known users triggered an audit write, an attacker who
could degrade the audit store would see `Err` for real accounts and an
ordinary rejection for everything else, and could read off which
identifiers are registered. Both paths write, so both fail identically.

The same change closes a blind spot that had nothing to do with
outages: a credential-stuffing run against a list of addresses, none of
which are registered, previously left no audit rows at all. Those
attempts now appear as `LoginAttempt` / `Failure` with an `error` of
`unknown_tenant` or `unknown_identifier`, unattributed or attributed to
the tenant only.

## Disclosure protocol

The vulnerability disclosure protocol lives in the canonical
[`SECURITY.md`](https://github.com/GnomesOfZurich/axess/blob/main/SECURITY.md)
at the repo root. The summary:

Vulnerability reports go through the private channel described
in `SECURITY.md` (typically a security email or GitHub Security
Advisories). Do not file vulnerabilities on the public issue
tracker.

The maintainers acknowledge reports within a few business days
and triage to a severity level. Critical and high-severity
issues get a private fix in a security branch, a coordinated
disclosure window, and a CVE if the issue warrants one. Lower
severity issues fix in the normal development cycle.

Adopters are expected to keep their `axess` dependency current.
Vulnerability fixes ship in the next patch release; the changelog
notes which fixes are security-relevant. Deployments behind on
patches accept the risk of the unfixed vulnerabilities.

## Canonical SECURITY.md

The rest of this chapter is the canonical `SECURITY.md` from the
repo root, included so the production checklist is in one place.

{{#include ../../SECURITY.md}}

## Further reading

*Operations runbook* covers the production-launch checklist
(key rotation, multi-instance considerations, graceful shutdown).
*Audit events* and *Audit pipeline* cover the audit
mechanisms the compliance frames depend on. *Migration guide*
covers cross-version upgrade paths, including security-relevant
breaking changes.
