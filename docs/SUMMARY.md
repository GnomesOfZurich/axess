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
- [Live provider reload](authentication/live-provider-reload.md)

# Part III: Authn protocols and verifiers

- [Password and TOTP](factors/password-totp.md)
- [FIDO2 and WebAuthn passkeys](factors/fido2.md)
- [OAuth 2.0 and OIDC](factors/oauth.md)
- [FAPI 2.0](factors/fapi.md)
- [Conformance](factors/conformance.md)
- [LDAP bind](factors/ldap.md)

# Part IV: Authorization

- [Cedar policy fundamentals](authorization/cedar-fundamentals.md)
- [Entity providers and request context](authorization/cedar-providers.md)
- [RBAC, ReBAC, and ABAC patterns](authorization/cedar-patterns.md)
- [Live policy reload](authorization/live-policy-reload.md)

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
  - [Walkthrough: Azure](workload-identity/azure.md)
  - [Walkthrough: AWS](workload-identity/aws.md)
  - [Outbound: OAuth](workload-identity/outbound-oauth.md)
  - [Outbound: mTLS](workload-identity/outbound-mtls.md)
  - [Shared secrets: the last resort](workload-identity/shared-secrets.md)
- [Delegated and OBO access](identity/delegated-obo.md)
- [Local IdP](factors/local-idp.md)

# Part VIII: Production

- [Audit events](production/audit-events.md)
- [Audit pipeline](production/audit-pipeline.md)
- [Rate limiting](production/rate-limiting.md)
- [Observability and metrics](production/observability.md)
- [Security posture](production/security-posture.md)
- [Behind an mTLS terminator](production/mtls.md)
- [Operations runbook](production/operations.md)
- [Migration guide](production/migrating.md)
  - [0.16.0 to 0.17.0](production/migrating/0.16.0-to-0.17.0.md)
  - [0.15.0 to 0.16.0](production/migrating/0.15.0-to-0.16.0.md)
  - [0.14.0 to 0.15.0](production/migrating/0.14.0-to-0.15.0.md)
  - [0.13.0 to 0.14.0](production/migrating/0.13.0-to-0.14.0.md)
  - [0.12.0 to 0.13.0](production/migrating/0.12.0-to-0.13.0.md)
  - [0.11.0 to 0.12.0](production/migrating/0.11.0-to-0.12.0.md)
  - [0.10.0 to 0.11.0](production/migrating/0.10.0-to-0.11.0.md)
  - [0.9.0 to 0.10.0](production/migrating/0.9.0-to-0.10.0.md)
  - [0.8.1 to 0.9.0](production/migrating/0.8.1-to-0.9.0.md)
  - [0.7.0 to 0.8.0](production/migrating/0.7.0-to-0.8.0.md)
  - [0.6.0 to 0.7.0](production/migrating/0.6.0-to-0.7.0.md)
  - [0.5.0 to 0.6.0](production/migrating/0.5.0-to-0.6.0.md)
  - [0.4.0 to 0.5.0](production/migrating/0.4.0-to-0.5.0.md)
  - [0.2.2 to 0.3.0](production/migrating/0.2.2-to-0.3.0.md)
  - [0.2.0 to 0.2.1](production/migrating/0.2.0-to-0.2.1.md)
  - [0.1.x to 0.2.0](production/migrating/0.1.x-to-0.2.0.md)

# Part IX: Project

- [Contributing](project/contributing.md)
- [Publishing runbook](project/publishing.md)
