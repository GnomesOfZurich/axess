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

## The credential

An ordinary X.509 certificate, with the identity in one SAN entry.

### The credential shape

An X.509-SVID is an ordinary X.509 leaf certificate with one
specific requirement: the Subject Alternative Name extension
contains a URI of the form `spiffe://<trust_domain>/<path>`. The
certificate is otherwise standard; deployments may put additional
information in the subject DN, the other SAN entries, or X.509
extensions, but the SPIFFE URI is the identity the resolver reads.

The certificate chain is signed by the trust domain's CA. The
chain validates the certificate's authenticity; the SAN URI
identifies the workload within the trust domain.

### Where the certificate comes from

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
use axess::federation::mtls::PeerCertChain;

async fn mtls_middleware<B>(
    mut req: Request<B>,
    next: Next<B>,
) -> Response {
    // `chain` is a `Vec<CertificateDer<'static>>`, leaf first.
    if let Some(chain) = extract_cert_from_terminator(&req) {
        req.extensions_mut().insert(PeerCertChain::new(chain));
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

## Wiring it up

Reading the tenant out of the leaf comes first, and that read validates nothing.

### The resolver

`MtlsResolver` reads the SPIFFE URI out of the leaf certificate,
checks it against the configured trust domain, and produces a
`Principal::Workload`.

```rust,ignore
use axess::federation::mtls::{MtlsResolver, PeerCertChain, peek_spiffe};
use axess_identity::PrincipalResolver;

// Which tenant this is, from the SPIFFE ID, before the resolver is
// built: `peek_spiffe` is a plain function over the leaf certificate
// and does no validation beyond parsing the SAN URI.
let leaf = chain.leaf().ok_or(MtlsError::EmptyChain)?;
let components = peek_spiffe(leaf)?;
let tenant_id = my_directory.tenant_for(&components.tenant_slug)?;

let resolver = MtlsResolver::from_chain(
    &chain,
    "prod.example.com".parse()?,
    tenant_id,
)?;
let principal = resolver.resolve().await?;   // Principal::Workload
```

`from_chain` takes the leaf and returns `MtlsError::EmptyChain` if
there is none. Where you already hold a leaf, from a terminator that
hands you one certificate rather than a chain, `MtlsResolver::new` takes it
directly and is infallible.

Either way the resolver holds the leaf, the trust domain it accepts,
and the tenant. There is no configuration struct and no tenant-resolver
trait: mapping a SPIFFE path to a `TenantId` is the adopter's, done
before construction with `peek_spiffe`, because the convention is the
deployment's.

The work is small because most of the validation already happened: the
terminator validated the chain, and the resolver parses the SAN URI and
checks the trust domain.

### The validation flow

Two error types are in play, and which one you see depends on where
you are standing.

`peek_spiffe` is the parsing step, and it reports `MtlsError`. It
parses the leaf's DER, where a failure is `MtlsError::CertParse`, then
reads the Subject Alternative Name extension. A certificate with no
SAN yields `MtlsError::NoSan`; one whose SAN carries no `spiffe://`
URI yields `MtlsError::NoSpiffeUri`. The URI is then parsed as a
SPIFFE ID and decomposed into
`spiffe://<trust_domain>/<service>/<tenant_slug>`; a URI that is
malformed, or whose path does not match that shape, yields
`MtlsError::Identity`, which carries the underlying `IdentityError`.
`MtlsError::EmptyChain` comes from `MtlsResolver::from_chain` rather
than from parsing, and means the chain held no leaf at all.

`resolve` is the `PrincipalResolver` step, and it reports
`IdentityError`, because that is what the trait returns for every
resolver. It re-runs `peek_spiffe` on the leaf, cheaply and
deliberately, so the cryptographic claim flows through one path rather
than through whatever the middleware peeked at earlier, then compares
the presented trust domain against the configured one. A mismatch is
`IdentityError::InvalidSpiffeId`, naming both domains, and is logged at
`warn`. Every other parse failure collapses to
`IdentityError::NotAuthenticated`, with the specific `MtlsError` logged
at `debug`.

That collapse is deliberate: a caller presenting a bad certificate
learns only that it was rejected, while the operator reading the logs
learns which of `CertParse`, `NoSan` or `NoSpiffeUri` it was. When you
want the distinction in your own code, call `peek_spiffe` yourself,
which the tenant lookup means you are doing anyway.

The resolver does not resolve tenants. The tenant is
decided before it is built, and `resolve` copies the `TenantId` it was
given into the principal.

### What the principal looks like

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

`attributes` is always empty here. `MtlsResolver` puts nothing in it,
and the certificate is not carried on the principal, so X.509 detail
you want downstream (the serial number for audit, the expiry for
short-lived-cert tracking, a custom extension) has to be read from
the leaf in your own middleware and carried in your own request
extension. The field exists on `WorkloadPrincipal` for resolvers that
do populate it from claims.

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

If the chain is empty (`EmptyChain`, or `PeerCertChain::leaf`
returning `None`) for connections that should work, the terminator
is not requesting a client certificate, or your middleware is not
recording the one it received. Inspect what the terminator reports
before the resolver runs.

If `resolve` returns `IdentityError::NotAuthenticated`, the debug log
carries the real reason. `NoSan` or `NoSpiffeUri` means the certificate
does not carry a SPIFFE URI in its Subject Alternative Name. Inspect
it with `openssl x509 -in cert.pem -text` to see what SAN entries are
present, and update the issuer's configuration to include the SPIFFE
URI. `CertParse` means the bytes are not a certificate at all, which
usually means the middleware picked up the wrong header or forwarded a
PEM where DER was expected.

If `resolve` returns `IdentityError::InvalidSpiffeId`, read the
message. "trust domain mismatch" means a workload from another trust
domain connected; if that is intentional, see *Inbound: federation*.
Anything else means the SPIFFE path does not have the
`/<service>/<tenant_slug>` shape axess decomposes, and the issuer's
path convention needs to change, because axess does not make the shape
configurable.

If `peek_spiffe` succeeds but your own tenant lookup then fails, the
`tenant_slug` in the path is not one your directory knows. That is
your mapping to fix, not axess's; the resolver never sees it.

## Further reading

*Workload identity overview* covers the SPIFFE model and the
unified `Principal` type. *Inbound: JWT-SVID* covers the bearer
token variant for deployments where mTLS is impractical. *Inbound:
federation* covers cross-trust-domain patterns. *mTLS-based
authentication* in Part III covers mTLS for human authentication;
the validation mechanics are the same, but the interpretation of
the certificate differs.
