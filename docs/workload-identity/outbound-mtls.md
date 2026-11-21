# Outbound: mTLS

Your application presents an X.509 client certificate in the
outbound TLS handshake to a downstream service that requires mTLS. The credential is the
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
travels with the request.

The pattern is operationally simpler than outbound OAuth because
the authentication happens once at connection setup rather than
per request. A long-lived TLS connection handles many requests
without re-authenticating; each new connection authenticates again
in its handshake. The cost is the TLS handshake's CPU and
round-trip; the benefit is no per-request authentication state.

## Configuration

`OutboundMtlsClient` holds the certificate and key and provides
them to the outbound TLS handshake. The
configuration:

```rust,ignore
use axess_core::workload::outbound::mtls_client::OutboundMtlsClient;

// The client takes the material, not paths to it: reading and reloading
// the files is yours, which is what lets an SVID come from a SPIFFE
// Workload API socket rather than from disk.
let client = OutboundMtlsClient::new_from_pem(&cert_chain_pem, &private_key_pem)?
    .with_server_roots_pem(&ca_bundle_pem)?;
```

`new_from_pem` takes the certificate chain, leaf first, and the
matching private key, both as PEM bytes; `new_from_der` takes them as
DER. The client parses them at construction and holds the parsed
material, so the buffers they came from can be wiped.

`with_server_roots_pem` pins the trust anchor for the downstream's
server certificate, and `with_server_roots` takes a root store you
built. With neither, `rustls_client_config` refuses to build a
configuration and answers `MtlsClientError::ClientConfig`: rustls
requires explicit roots, and the client does not guess them.

Where the material comes from is the application's: files a sidecar
writes, a secret store, or a SPIRE agent's socket. For the last, the
`spire` feature builds the client from a fetched SVID
(`X509Svid::outbound_mtls_client`, with the server's roots pinned by
the caller); *SPIRE Workload API client* is its chapter.

## The TLS handshake

The client integrates with your HTTP client (typically
`reqwest`, but the pattern generalises) through the rustls
`ClientConfig` it builds:

```rust,ignore
use std::sync::Arc;

use axess::workload::outbound::mtls_client::OutboundMtlsClient;
use reqwest::Client;

let mtls = OutboundMtlsClient::new_from_pem(&cert_chain_pem, &private_key_pem)?
    .with_server_roots_pem(&ca_bundle_pem)?;
let config = mtls.rustls_client_config()?; // Arc<rustls::ClientConfig>

let http_client = Client::builder()
    .use_preconfigured_tls(Arc::unwrap_or_clone(config))
    .build()?;

let response = http_client
    .get("https://downstream.example/data")
    .send()
    .await?;
```

`rustls_client_config` returns an `Arc<ClientConfig>` with the
certificate, key, and trust anchor configured. `use_preconfigured_tls`
on `reqwest` takes the `ClientConfig` itself, not the `Arc` (with an
`Arc`, `build` fails), so the example unwraps it; other HTTP clients
have similar integration points.

The handshake validates the downstream's server certificate against
the trust anchor you pinned (there is no fallback to the system
store), then presents
the client certificate. If the downstream requires the client
certificate and yours is missing or
invalid, the handshake fails. If the downstream does not require
the certificate, the handshake succeeds and the certificate is
ignored.

## Certificate rotation

Certificate rotation makes outbound mTLS sustainable in production.
A static certificate provisioned at deployment time expires, and
replacing it takes a redeploy; a rotated certificate is replaced while
the deployment keeps running.

SPIRE rotates X.509-SVIDs on a schedule the operator configures
(typically every few hours). An `OutboundMtlsClient` holds the
certificate it was constructed with and does not reload: a rotation
means a new client, and a new `ClientConfig` from it, handed to the
HTTP client that makes the next connection. How the application
learns of a rotation depends on where its certificate comes from.

With certificates on disk, the writer replaces the files atomically
(a temporary file plus a rename, so a read sees the old pair or the
new, never a truncated file), and the application watches the files
or re-reads them on a schedule well inside the certificate's
lifetime. A re-read that finds a malformed certificate should keep
the previous client: it works until the previous certificate expires,
so a botched rotation does not bring the service down at once.

With a SPIRE agent, the `spire` feature's `X509Source` follows the
agent's rotation, and `X509Source::rustls_client_config` builds one
configuration that presents whatever SVID the source holds at each
handshake, so nothing is rebuilt. It verifies the server by its
SPIFFE ID rather than by a DNS name; *SPIRE Workload API client*
covers both that and the snapshot form for a downstream verified by
name.

## When the downstream is also axess

A common shape is two axess-instrumented services calling each
other over mTLS. The calling side presents its X.509-SVID through
the `outbound-mtls` machinery; the receiving side validates it
through the `mtls` resolver from *Inbound: mTLS-SVID*. The two
sides compose without any further integration: the same SPIFFE
identity flows through the TLS handshake, the receiving resolver
extracts it, and the resulting principal is the calling service's
identity.

This gives a SPIFFE-based deployment an identity-aware service
mesh at the application layer without a sidecar proxy. The mesh's identity is the
application's identity; the audit trail records the same
identity at every hop.

## Threat model

Outbound mTLS shares the threat model of the X.509-SVID inbound
case from *Inbound: mTLS-SVID*. Key storage is the
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

If the handshake fails with a certificate-validation error, first
see which side refused. An error your client raises (rustls reports
`Error::InvalidCertificate`, for instance `UnknownIssuer`) means the
downstream's server certificate does not chain to the roots you
pinned; fix the roots given to `with_server_roots_pem` or
`with_server_roots`. An alert from the downstream (rustls reports
`Error::AlertReceived`, for instance `UnknownCA` or `BadCertificate`)
means the downstream does not trust your CA. Its trust bundle must
include your CA; that is the downstream's configuration, not the
client's.

If the handshake succeeds but the downstream returns 401 on every
request, the downstream authorises the certificate's identity as well as
authenticating it, and the authorisation fails. Check
the downstream's authorisation policy: it may require a particular
SPIFFE path, issuer or X.509 extension that your certificate does
not have.

If handshakes start failing some hours after a deployment, the
certificate has expired and nothing replaced it: the client holds
the certificate it was built with. Check what rebuilds the client on
rotation. With the `spire` feature, a read of the source answers
`SpireError::Expired` in that state. The
`workload_credential_refresh_failed` counter counts the failed
refreshes by credential kind; its history in your metrics backend
shows when the agent stopped answering.

## Further reading

*Inbound: mTLS-SVID* covers the receiving side of the same
machinery. *Workload identity overview* covers the SPIFFE model
both sides use. *Cloud STS exchange* covers the alternative
pattern for downstreams that require bearer tokens rather than
mTLS. *SPIRE Workload API client* covers taking the certificate
from a local SPIRE agent. *Operations runbook* covers the certificate
rotation and the key-storage choices for production deployments.
