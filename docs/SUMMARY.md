# Summary

[Welcome](intro/welcome.md)

# Part I: Foundations

- [Architecture at a glance](intro/architecture.md)
- [Getting started](intro/getting-started.md)

# Part II: Authentication

- [The session state machine](authentication/session-state-machine.md)
- [Factors and methods](authentication/factors.md)
- [Scope hierarchy](authentication/scope.md)
- [Refresh tokens and session continuity](authentication/refresh-tokens.md)

# Part III: Authn protocols and verifiers

- [Password and TOTP](factors/password-totp.md)
- [FIDO2 and WebAuthn passkeys](factors/fido2.md)
- [OAuth 2.0 and OIDC](factors/oauth.md)
- [FAPI 2.0](factors/fapi.md)
- [LDAP bind](factors/ldap.md)
- [mTLS-based authentication](factors/mtls.md)

# Part IV: Authorization

- [Cedar policy fundamentals](authorization/cedar-fundamentals.md)
- [Entity providers and request context](authorization/cedar-providers.md)
- [RBAC, ReBAC, and ABAC patterns](authorization/cedar-patterns.md)

# Part V: Sessions and storage

- [Session lifecycle and crypto envelope](sessions/lifecycle.md)
- [Backends: SQLite, Postgres, MySQL, Valkey](sessions/backends.md)
- [Cookies, fingerprinting, hijack detection](sessions/security.md)
- [Schema migration](sessions/migration.md)

# Part VI: Identity and tenancy

- [The principal model](authentication/principal.md)
- [Device identity](identity/device.md)
- [Multi-tenancy](identity/tenancy.md)
- [Identity store implementation](identity/store.md)

# Part VII: Workload and delegated access

- [Overview](workload-identity/README.md)
  - [Inbound: JWT-SVID](workload-identity/jwt-svid.md)
  - [Inbound: mTLS-SVID](workload-identity/mtls-svid.md)
  - [Inbound: federation](workload-identity/federation.md)
  - [Cloud STS exchange](workload-identity/cloud-sts.md)
  - [Outbound: OAuth](workload-identity/outbound-oauth.md)
  - [Outbound: mTLS](workload-identity/outbound-mtls.md)
- [Delegated and OBO access](identity/delegated-obo.md)
- [Local IdP](factors/local-idp.md)

# Part VIII: Production

- [Audit events](production/audit-events.md)
- [Audit pipeline](production/audit-pipeline.md)
- [Rate limiting](production/rate-limiting.md)
- [Security posture](production/security-posture.md)
- [Operations runbook](production/operations.md)
- [Migration guide](production/migrating.md)

# Part IX: Project

- [Contributing](project/contributing.md)
- [Publishing runbook](project/publishing.md)
