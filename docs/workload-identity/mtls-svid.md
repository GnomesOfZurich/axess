# Inbound: SPIFFE X.509-SVID via mTLS

A workload authenticates over mTLS by presenting a leaf X.509
certificate that carries its SPIFFE identity in a Subject
Alternative Name URI. The TLS handshake validates the certificate
against the trust-domain CA bundle, the application reads the
SPIFFE URI from the SAN, and the resulting identity becomes a
`Principal::Workload`. The mechanism is the right choice for
service-to-service traffic where mTLS is already in place (a
service mesh, a load balancer that preserves client certs, a
direct VPC peering).

The feature flag is `mtls` (off by default).

## The credential shape

An X.509-SVID is an ordinary X.509 leaf certificate with one
specific requirement: the Subject Alternative Name extension
contains a URI of the form `spiffe://<trust_domain>/<path>`. The
certificate is otherwise standard; deployments may put additional
information in the subject DN, the other SAN entries, or X.509
extensions, but the SPIFFE URI is the identity the resolver reads.

The certificate chain is signed by the trust domain's CA. The
chain validates the certificate's authenticity; the SAN URI
identifies the workload within the trust domain.

## Where the certificate comes from

Axess does not handle the TLS handshake. The handshake happens
where TLS terminates (rustls in the application process, a sidecar
proxy in a service mesh, a load balancer in front of the
application). The terminator validates the certificate chain
against the configured CA bundle, accepts or rejects the
connection, and on acceptance makes the certificate available to
the application.

The mechanism for making the certificate available depends on the
terminator. For rustls in process, the certificate is available
through `axum_server::tls_rustls::RustlsConnectInfo` or an
equivalent connector callback, which the resolver wires through
directly. For a sidecar proxy (Istio, Linkerd, Envoy in a service
mesh), the proxy forwards the certificate as a header (Istio uses
`X-Forwarded-Client-Cert`, Linkerd uses `l5d-client-id`), and the
resolver wires through a small adapter that parses the header
into a certificate. For a load balancer in passthrough TLS mode,
rustls handles the validation in-process; for a load balancer in
mTLS-terminating mode (AWS ALB with mTLS, Cloudflare with
client-cert auth, nginx with `ssl_verify_client`), the load
balancer forwards the certificate in a header whose name and
format depend on the product.

The application's job is to extract the certificate chain from
wherever the terminator put it, wrap it in `PeerCertChain`, and
insert it into the request extensions before the resolver runs.

```rust,ignore
use axess::workload::PeerCertChain;

async fn mtls_middleware<B>(
    mut req: Request<B>,
    next: Next<B>,
) -> Response {
    if let Some(chain) = extract_cert_from_terminator(&req) {
        req.extensions_mut().insert(PeerCertChain::from(chain));
    }
    next.run(req).await
}
```

The critical detail: the extraction must trust only sources the
deployment trusts. A request that arrives directly to the
application with a forged `X-Forwarded-Client-Cert` header must
not be accepted. Either run the application on a socket the
terminator owns and reject direct connections at the network
layer, or gate the header on a token the terminator injects
alongside the certificate.

## The resolver

`MtlsResolver` is the resolver that reads the chain from the
extensions, extracts the SPIFFE URI, validates against the
configured trust domain, and produces a `Principal::Workload`.

```rust,ignore
use axess::workload::{MtlsResolver, MtlsResolverConfig};

let resolver = MtlsResolver::new(MtlsResolverConfig {
    trust_domain: "prod.example.com".parse().unwrap(),
    tenant_resolver: Box::new(MyTenantResolver::new(/* ... */)),
});
```

The configuration is small because most of the validation work has
already happened. The terminator validated the certificate chain;
the resolver only needs to read the SAN URI, parse it as a SPIFFE
ID, and check that the trust domain matches the configured one.

`tenant_resolver` is the adopter-supplied piece that maps the
SPIFFE path to a `TenantId`. The path typically follows a
convention like `/svc/<service>/<tenant_slug>`, and the resolver
looks up the tenant id from the slug. The convention is the
deployment's; axess just provides the trait surface.

## The validation flow

The resolver's `resolve` method runs five steps.

The first step is reading the peer certificate chain from request
extensions. Absence here is a configuration error (the extraction
middleware did not run), and the resolver returns
`MtlsError::NoPeerCert`.

The second step is parsing the leaf certificate. The chain may
contain intermediate certificates; the leaf is the first one. The
resolver extracts the SAN extension and looks for a URI value
matching the SPIFFE format. Absence of a SPIFFE URI in the SAN
produces `MtlsError::NoSpiffeId`.

The third step is parsing the SPIFFE URI. The URI must be
well-formed (a `spiffe://` scheme, a trust domain, a path). A
malformed URI produces `MtlsError::MalformedSpiffeId`.

The fourth step is the trust-domain match. The parsed trust
domain must equal the configured one. A mismatch produces
`MtlsError::TrustDomainMismatch`.

The fifth step is the tenant resolution. The path is fed to the
configured `TenantResolver`, which returns a `TenantId`. The
resolver assembles the `WorkloadPrincipal` with the SPIFFE id, the
trust domain, the issuer (`Issuer::Mtls`), and the tenant id, and
returns it.

## What the principal looks like

A successful validation produces:

```rust,ignore
Principal::Workload(WorkloadPrincipal {
    workload_id: WorkloadId::new("spiffe://prod.example.com/svc/billing/tenant-acme"),
    trust_domain: TrustDomain::new("prod.example.com"),
    issuer: Issuer::Mtls,
    tenant_id: TenantId::parse("acme").unwrap(),
    tenant_slug: "acme".into(),
    service_name: "billing".into(),
    attributes: { /* X.509 fields the deployment exposes */ },
})
```

The `attributes` map carries any X.509 fields the deployment
chooses to surface (the certificate's serial number for audit, the
certificate's expiry for short-lived-cert tracking, custom
extensions). The choice is the deployment's; the resolver exposes
the chain so the adopter can read what they need.

## Combining with other resolvers

A common shape is mTLS as the transport-level proof of identity
plus a session cookie or a JWT as the application-level proof of
who the user behind the workload is. The two layers compose: the
mTLS resolver runs first and establishes the workload's identity;
the session or JWT layer runs second and establishes the human's
identity inside the workload. Cedar policies can match on both.

The composition is what gives a deployment "the calling service is
authenticated AND the user inside the call is authenticated", which
is the right shape for delegated workflows. *Delegated and OBO
access* covers the pattern from the OBO side.

## Threat model

mTLS is robust against the standard attacks when the issuing CA
is secure.

Against token theft: there is no token. The credential is a
private key the workload holds; an attacker without the key cannot
present the certificate.

Against in-flight tampering: the TLS layer protects against it.
The certificate is bound to the TLS session; an attacker on the
wire cannot substitute a different certificate without breaking
the handshake.

Against replay: the certificate is short-lived (SPIRE typically
rotates SVIDs every few hours) and bound to a TLS session. Replay
across sessions requires the private key, which the attacker does
not have.

The remaining attack surface is the issuing CA. A compromised CA
can issue compromised certificates, and the validation cannot
detect it. The defence is operational: secure the issuing CA,
monitor the issuance log, rotate the CA's signing key on a
schedule.

The other remaining surface is the workload's private-key
storage. A workload that stores its key in a file on disk is
vulnerable to file-system compromise; a workload that stores its
key in a hardware enclave (TPM, HSM, KMS) is much harder to
compromise. SPIRE supports both shapes through its workload-API
attestation; the choice is the deployment's.

## Troubleshooting

If the resolver returns `NoPeerCert` for connections that should
work, the extraction middleware is not running, or the terminator
is not forwarding the certificate. Inspect the request extensions
before the resolver runs.

If the resolver returns `NoSpiffeId`, the certificate does not
carry a SPIFFE URI in the SAN. Inspect the certificate
(`openssl x509 -in cert.pem -text`) to see what SAN entries are
present. The issuer's configuration may need to be updated to
include the SPIFFE URI.

If the resolver returns `TrustDomainMismatch`, a workload from a
different trust domain has connected. If this is intentional,
configure federation (covered in *Inbound: federation*).

If the resolver succeeds but the tenant resolution fails, the
path convention is not matching the workload's actual SPIFFE
path. Inspect the path and update the tenant resolver to handle
the actual format.

## Further reading

*Workload identity overview* covers the SPIFFE model and the
unified `Principal` type. *Inbound: JWT-SVID* covers the bearer
token variant for deployments where mTLS is impractical. *Inbound:
federation* covers cross-trust-domain patterns. *mTLS-based
authentication* in Part III covers mTLS for human authentication;
the validation mechanics are the same, but the interpretation of
the certificate differs.
