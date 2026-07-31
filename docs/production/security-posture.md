# Security posture

This chapter is the production-readiness chapter. It covers the
crypto choices axess makes by default, the production integration
requirements an adopter has to meet before launch, the
compliance touch-points (GDPR, SOC 2, PCI-DSS, HIPAA) the
deployment will face, and the disclosure protocol for handling
the inevitable vulnerability report.

The chapter has two halves. The first half is axess-specific and
covers the crypto backends, the FIPS-routing notes, and the PII
classification. The second half is the canonical [`SECURITY.md`](https://github.com/GnomesOfZurich/axess/blob/main/SECURITY.md)
from the repo root, included verbatim so the production
checklist lives in one place rather than two.

## Crypto backends

Axess uses three crypto backends, chosen per operation:

[RustCrypto](https://github.com/RustCrypto) is the default for
most cryptographic primitives. The implementations are pure
Rust, with no system-library dependency, and the project's
audit history is good. Axess uses RustCrypto for AES-256-GCM
(the session envelope), HMAC-SHA256 (cookie signing, fingerprint
binding), Argon2id (password hashing), TOTP and HOTP (the
RFC 6238 and RFC 4226 implementations), and SHA-256 (refresh
token hashing).

[aws-lc-rs](https://github.com/aws/aws-lc-rs) is an alternative
for deployments that need FIPS 140-3 validated crypto. The
backend wraps the FIPS-validated `aws-lc` library; selecting it
through a Cargo feature redirects the relevant primitives to
the validated implementations. The trade-off is binary size
(the FIPS module adds a few megabytes) and platform support
(`aws-lc` does not build on every target).

[ring](https://github.com/briansmith/ring) is a third option,
used historically for TLS-adjacent primitives. The project is
mature but the maintenance cadence has slowed; axess uses ring
in a few legacy spots and is migrating away. New code uses
RustCrypto by default and aws-lc-rs when FIPS is required.

The selection is a Cargo feature, configured per crate:

```toml
[dependencies]
axess = { version = "0.3.0", features = ["crypto-aws-lc"] }
```

The default is `crypto-rust` (which is the same as not specifying
a backend); `crypto-aws-lc` is the FIPS variant. The crates that
depend on a specific backend gate their implementations on the
feature; the build refuses if the application requests
incompatible backends (a deployment cannot simultaneously enable
RustCrypto and aws-lc-rs for the same operation).

## FIPS targeting

A FIPS 140-3 validated deployment requires three things to be
true.

The first is that every cryptographic operation runs through a
validated module. Axess's `crypto-aws-lc` feature routes the
relevant operations through aws-lc-rs. The choice satisfies the
"validated module" requirement.

The second is that the deployment's compile and link chain does
not introduce non-validated crypto. Cargo's dependency graph is
the source of truth here; running `cargo tree` and inspecting
for non-aws-lc crypto crates (rustls, ring, the older
RustCrypto crates) shows what the deployment actually pulls in.
Anything that introduces non-validated crypto needs to be
replaced or compiled out.

The third is that the validation certificate covers the
platform the deployment runs on. NIST publishes FIPS validation
certificates per platform-binary combination; a certificate for
Linux x86-64 does not cover macOS ARM. The deployment's
compliance evidence must include the certificate matching the
production platform.

The deployment's compliance team owns the end-to-end FIPS
validation; axess provides the crypto-backend lever. The
chapters that depend on specific crypto choices (session
envelope, refresh-token hashing, HMAC fingerprint) all use the
configured backend automatically.

## PII classification

The application records PII across several stores. The
classification matters for GDPR (the data subject's rights), for
SOC 2 (the control objectives), and for the retention sweep
(*Device identity*'s `device_retention_days`). The classification:

Primary PII includes the user's identifier (email, username, or
similar), their hashed password, their TOTP secret, their FIDO2
credentials, their IP address as seen during authentication, and
their device fingerprint. This data lives in the identity store
and the device store; the retention is the application's choice
within whatever regulatory bounds apply.

Secondary PII includes the audit-event log (which references the
primary PII through `user_id`, `tenant_id`, `device_id`, and
`client_ip`). The audit retention covered in *Audit pipeline*
applies here; for GDPR the typical pattern is to retain audit
data longer than the primary PII but to scrub or hash the IP
addresses after the operational hot window.

Pseudonymous data includes the session id, the refresh token
hash, and the device id itself (a UUID that does not name the
user directly). These can be retained longer than the primary
PII without GDPR implications; they only become PII when joined
to the primary data, and the join requires access to the
identity store.

The GDPR right-to-erasure verb (`IdentityAdmin::erase_user`)
cascades through every store: the user's primary PII is removed
from the identity store, the user's device records are
removed from the device store, the user's sessions are removed
from the session store, and the user's refresh tokens are
removed from the refresh-token store. The audit-event entries
that reference the user are not removed (the audit trail is
load-bearing for compliance); the user's identifier in the
events is hashed to a pseudonymous token, which makes the events
non-PII without losing the ability to correlate them.

## Compliance touch-points

The deployment will face one or more of these regulatory frames.
Axess does not provide compliance on its own; it provides the
controls each framework requires. The touch-points:

GDPR (EU data protection): the right-to-erasure verb (above),
the audit trail's retention configuration, the IP-address
scrubbing in the cold-tier archive, the per-tenant
`device_retention_days`. The deployment owns the data subject
notices, the privacy policy, and the legal basis for processing;
axess provides the technical mechanisms.

SOC 2 (operational controls): the audit catalogue (every
authentication and authorisation decision produces an event),
the lockout policy (defends against credential stuffing), the
session and refresh-token security (covered in earlier chapters),
the operational metrics (covered in *Operations runbook*). The
deployment owns the policy and procedure documentation; axess
provides the operational evidence.

PCI-DSS (payment card data, if applicable): the strong
authentication for administrative access, the audit retention
of at least one year, the cryptographic protection of session
data at rest. The deployment owns the cardholder data
environment; axess covers the authentication boundary into it.

HIPAA (US healthcare data, if applicable): the strong
authentication for protected health information access, the
audit retention of at least six years, the encryption of
session data at rest and in transit. The deployment owns the
HIPAA-covered systems; axess covers the authentication
boundary.

The chapters that cover the relevant mechanisms are the place to
look up specific controls: *Session lifecycle and crypto envelope*
for the at-rest encryption, *Audit pipeline* for the retention,
*Refresh tokens and session continuity* for the refresh-token
hygiene, *Multi-tenancy* for the lockout policy. The compliance
documentation maps the framework's requirements to the relevant
chapters.

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
