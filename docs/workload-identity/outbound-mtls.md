# Outbound: mTLS

This chapter covers the case where the application presents an
X.509 client certificate during the outbound TLS handshake to a
downstream service that requires mTLS. The credential is the
application's workload identity in X.509 form, typically an
X.509-SVID issued by SPIRE or an equivalent. The downstream
validates the certificate against its trust anchor and accepts
or rejects the connection.

The feature flag is `outbound-mtls` (off by default).

## When to use it

Outbound mTLS is the right pattern for service-to-service traffic
within a federation that uses mTLS as the standard authentication
mechanism (a SPIFFE-based service mesh, an intra-organisation
network where everything speaks mTLS, a partner integration where
both sides have agreed to mTLS). The application's certificate
identifies it as a workload to the downstream; no bearer token
needs to ride the request.

The pattern is operationally simpler than outbound OAuth because
the authentication happens once at connection setup rather than
per request. A long-lived TLS connection handles many requests
without re-authenticating; a short-lived connection re-authenticates
on the next request. The cost is the TLS handshake's CPU and
round-trip; the benefit is no per-request authentication state.

## Configuration

`OutboundMtlsClient` is the type that holds the certificate and
key, and provides them to the outbound TLS handshake. The
configuration:

```rust,ignore
use axess::workload::outbound::{OutboundMtlsClient, OutboundMtlsConfig};

let client = OutboundMtlsClient::new(OutboundMtlsConfig {
    client_cert_path: "/var/lib/axess/svid/cert.pem".into(),
    client_key_path: "/var/lib/axess/svid/key.pem".into(),
    ca_bundle_path: Some("/var/lib/axess/svid/ca.pem".into()),
    reload_interval: Some(Duration::from_secs(300)),
});
```

`client_cert_path` and `client_key_path` are filesystem paths to
the certificate and the private key. The conventional location is
where SPIRE writes them: SPIRE rotates the certificate on a
configurable schedule (typically every few hours), writes the new
files atomically, and the client picks them up on next read.

`ca_bundle_path` is the optional path to the trust anchor for the
downstream's server certificate. When set, the client validates
the downstream's server cert against this bundle; when unset, the
client uses the system trust store.

`reload_interval` controls how often the client checks the
certificate files for changes. The check is a stat call; an
unchanged file is a no-op, a changed file triggers a re-read. The
default (every five minutes) matches typical SPIRE rotation
schedules; deployments with faster rotation lower this.

## The TLS handshake

The client integrates with the application's HTTP client (typically
`reqwest`, but the pattern generalises) through a custom
`Connector`:

```rust,ignore
use axess::workload::outbound::OutboundMtlsClient;
use reqwest::Client;

let mtls = OutboundMtlsClient::new(/* ... */);

let http_client = Client::builder()
    .use_preconfigured_tls(mtls.rustls_client_config())
    .build()?;

let response = http_client
    .get("https://downstream.example/data")
    .send()
    .await?;
```

`rustls_client_config` returns a rustls `ClientConfig` with the
certificate, key, and trust anchor configured. The
`use_preconfigured_tls` integration on `reqwest` accepts this
directly; other HTTP clients have similar integration points.

The handshake validates the downstream's server certificate against
the configured trust anchor (or the system store), then presents
the client certificate. If the downstream requires the client
certificate and the application's certificate is missing or
invalid, the handshake fails. If the downstream does not require
the certificate, the handshake succeeds and the certificate is
ignored.

## Certificate rotation

The certificate rotation is what makes outbound mTLS sustainable
in production. A static certificate provisioned at deployment time
expires; the deployment has to redeploy to refresh it. A rotated
certificate refreshes itself; the deployment runs indefinitely.

SPIRE rotates X.509-SVIDs on a schedule the operator configures
(typically every few hours). The new certificate is written
atomically to the filesystem (a temporary file plus a rename, so
the in-progress reads see either the old or the new, never a
truncated file). The application's `OutboundMtlsClient` reads the
files at construction and on its reload interval.

The reload-interval choice matters. Too short, and the client
spends CPU on stat calls. Too long, and the client uses an
expired certificate, producing handshake failures. The
recommendation is to set the interval to about a third of the
certificate's lifetime, so a typical rotation leaves enough time
for the next reload to pick up the new files before expiry.

A reload that finds a malformed certificate logs the error and
keeps the previous certificate in memory. The client continues
to function until the previous certificate expires, by which
point either the malformed state is fixed or the handshake
fails. The graceful-degradation pattern is the right shape: a
botched rotation should not bring down the application
immediately.

## When the downstream is also axess

A common shape is two axess-instrumented services calling each
other over mTLS. The calling side presents its X.509-SVID through
the `outbound-mtls` machinery; the receiving side validates it
through the `mtls` resolver from *Inbound: mTLS-SVID*. The two
sides compose without any further integration: the same SPIFFE
identity flows through the TLS handshake, the receiving resolver
extracts it, the resulting principal is the calling service's
identity.

The pattern is what gives a SPIFFE-based deployment a fully
identity-aware service mesh at the application layer, without
requiring a sidecar proxy. The mesh's identity is the
application's identity; the audit trail records the same
identity at every hop.

## Threat model

Outbound mTLS shares the threat model of the X.509-SVID inbound
case from *Inbound: mTLS-SVID*. The key-storage problem is the
biggest concern: a workload whose private key is on disk is
vulnerable to filesystem compromise; a workload whose key lives
in a TPM, HSM, or KMS is much harder to compromise.

The additional concern for outbound is the downstream's trust
configuration. A misconfigured downstream that accepts any
client certificate from any CA (or that does not require client
certificates at all) defeats the authentication. The defence is
operational: ensure the downstream's trust configuration is
correct, monitor for unexpected accepted connections, audit the
configuration on a schedule.

## Troubleshooting

If the handshake fails with a certificate-validation error, the
downstream does not trust the application's CA. The downstream's
trust bundle needs to include the application's CA; this is the
downstream's configuration, not the client's.

If the handshake succeeds but the downstream returns 401 on every
request, the downstream is performing authorisation against the
certificate's identity rather than just authentication. Check
the downstream's authorisation policy: it may require a specific
SPIFFE path, a specific issuer, or a specific X.509 extension
that the application's certificate does not have.

If the reload fails silently and the application uses an
expired certificate, check the reload-interval configuration and
the application's log output. The reload errors are logged at
warn level; a missed reload typically surfaces as a
"failed to read certificate" message.

## Further reading

*Inbound: mTLS-SVID* covers the receiving side of the same
machinery. *Workload identity overview* covers the SPIFFE model
both sides use. *Cloud STS exchange* covers the alternative
pattern for downstreams that require bearer tokens rather than
mTLS. *Operations runbook* covers the certificate rotation and
the key-storage choices for production deployments.
