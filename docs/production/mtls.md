# Behind an mTLS terminator

Mutual TLS authenticates the client to the server at the transport
layer, before your handler sees the request. The client presents
an X.509 certificate during the TLS handshake, the server validates
the certificate against a trust anchor, and the resulting connection
carries a known identity. For service-to-service traffic between
parties that own both sides of the connection, mTLS is the strongest
practical authentication: there is no credential to phish, no token
to leak, no replay window after the handshake.

A certificate identifies a machine. What you do with that depends on
whether a machine is the whole answer.

Where the caller is a service, it is. *Inbound: mTLS-SVID* covers that
case: `MtlsResolver` reads a SPIFFE URI from the validated leaf and
produces a `Principal::Workload`, so the certificate is the subject.

Where the caller is a person at a kiosk or an internal admin host, the
certificate says which machine and nothing about who is using it. This
chapter is that case: where the certificate reaches your process from,
how to gate on it, and what it leaves for the factor flow behind the
gate to establish.

The feature flag is `mtls` (off by default), enabled with
`features = ["mtls"]` on the `axess` facade.

## Where the certificate comes from

Axess does not handle the TLS handshake. Axum sits behind a TLS
terminator (rustls in process, or nginx, HAProxy, AWS NLB, or
Cloudflare in front), and the certificate validation happens at the
terminator. The validated certificate reaches your process with the
request, and your own middleware reads it; on the path this chapter
describes, axess extracts no identity from it.

The extraction is a Tower middleware the adopter wires in. It reads
the certificate from wherever the terminator put it:

- For rustls in process, the application reads the chain the
  handshake recorded (`ServerConnection::peer_certificates()` under
  tokio-rustls, or an equivalent connector callback).
- For nginx, the certificate is passed through as the
  `X-SSL-Client-Cert` header (the exact header is the deployment's
  choice).
- For HAProxy, the convention is `X-Client-Cert` or similar.
- For AWS NLB with TLS passthrough, rustls handles the validation;
  for AWS ALB with mTLS, the certificate is in
  `X-Amzn-Mtls-Clientcert`.

The middleware checks that the certificate came from a trusted source:
the certificate is present, the header arrived only from the trusted
terminator, and clients cannot inject the header directly. It then wraps
the certificate chain in a `PeerCertChain` and inserts it into the Axum
request extensions:

```rust,ignore
use axess::federation::mtls::PeerCertChain;

async fn mtls_middleware(
    mut req: Request,
    next: Next,
) -> Response {
    // `new` takes the chain leaf first, as the client presented it.
    // Cloning a `PeerCertChain` is cheap; it holds an `Arc<[..]>`.
    if let Some(chain) = extract_cert_from_terminator(&req) {
        req.extensions_mut().insert(PeerCertChain::new(chain));
    }
    next.run(req).await
}
```

The trusted-terminator check is the critical step. If the
deployment accepts the certificate header from anywhere, an
attacker who can reach your service directly (bypassing the
terminator) can spoof any identity by setting the header
themselves. The defence is to listen only on a socket the terminator owns, or to
gate the extraction on a token the terminator injects alongside the
certificate.

## The trust anchor

The TLS terminator validates the certificate against a trust anchor:
a set of CA certificates it considers authoritative. A client certificate is accepted only if it chains
back to one of those CAs.

For service-to-service mTLS within an organisation, the trust
anchor is typically the organisation's own internal CA: it issues
certificates to known clients, the terminator trusts it, and only
certificates the organisation has signed are accepted.

For broader deployments (a partner integration where the partner
runs their own CA), the trust anchor is the partner's CA or a
short list of CAs, and the validation accepts clients signed by
any of them.

For consumer-facing deployments where clients might use any
certificate, mTLS is the wrong factor. Use OAuth or another flow
where the client does not need to provision a certificate.

## The gate

The certificate identifies the machine and the factor flow identifies
the person. Run them as two separate things: a gate in front, an
ordinary method behind.

The gate is your middleware, not an axess type. It reads the
`PeerCertChain` the extraction layer inserted, decides whether this
certificate may reach the login routes at all, and rejects the request
before any handler sees it:

```rust,ignore
use axess::federation::mtls::PeerCertChain;

async fn require_org_certificate(req: Request, next: Next) -> Response {
    let Some(chain) = req.extensions().get::<PeerCertChain>() else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let Some(leaf) = chain.leaf() else {
        return StatusCode::FORBIDDEN.into_response();
    };
    // Your policy: which CA, which CN or SAN, which expiry window.
    if !issued_by_org_ca(leaf) {
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(req).await
}
```

Behind that gate, the user authenticates with whatever method the tenant
configures: password plus TOTP, a passkey, an OAuth provider. Only a
provisioned machine reaches the login page, and only the right person
finishes, which is the pairing a high-assurance admin interface wants.

Two consequences follow from the split. The certificate is not part of
the authentication, so no audit row mentions it: record the gate's
decision yourself if you need evidence that a particular machine was
used. And the session is not bound to the certificate, so one issued
behind the gate lasts until it expires, whatever becomes of the
certificate. Pair short session lifetimes with short-lived certificates
where that matters.

## Threat model

mTLS is robust against the standard authentication attacks:
credential reuse, credential stuffing, password phishing, replay.
The certificate is hard to steal without compromising the device
that holds the private key, and a compromised private key is no
easier to use than a compromised password (both require some
attacker action and both can be revoked).

It is weak against three specific attacks.

**Private-key theft from a compromised device.** An
attacker with full filesystem access to a client can copy the
private key, install it on their own machine, and use the
certificate. The defence is to store the private key on hardware
the operating system protects (a TPM, a hardware security module,
a smartcard) rather than in a file. Hardware-backed keys cannot
be exported and survive even a full filesystem compromise.

**CA compromise.** An attacker who can issue
certificates from a CA you trust can authenticate as
anyone. The defence is operational: keep the issuing CA offline,
use short-lived certificates so revocation is automatic, and
monitor the CA's audit log. For service-to-service mTLS, a SPIFFE
control plane handles this with rotating, short-lived certificates
backed by an attested root.

**Missing revocation.** When a certificate is revoked
(employee leaves, machine is lost), you need to know.
The TLS terminator checks revocation through OCSP (the Online
Certificate Status Protocol, which asks the issuer about one
certificate), a CRL (a certificate revocation list, which the issuer
publishes in bulk), or a short-lived-certificate strategy that lets
revocation happen by expiry. Without a check, a revoked certificate
keeps working. The defence is to enable revocation checking at the
terminator and monitor the revocation lifecycle.

## Troubleshooting

If the middleware never sees a certificate, the most likely cause
is that the TLS terminator is not requiring client certificates.
Some terminators require explicit configuration to request the
client certificate at handshake time; others accept the handshake
without a certificate and silently let the request through. Check
the terminator's configuration.

If certificates are present but your gate's policy matches none of
them, the certificate may carry its name in a SAN (a DNS name or a
URI) rather than in the CN, or the reverse. Inspect the
certificate (`openssl x509 -in cert.pem -text`) to see what fields
are present, and match the gate's policy on the field the
certificate carries.

If the terminator accepts a certificate the application does not
expect, its trust store may include a CA the deployment did not
intend to trust. Check the
terminator's CA-bundle configuration and remove anything that
should not be there. Use a dedicated trust store for client
certificates rather than reusing the server's general CA bundle.

## Further reading

*Workload identity overview* covers the workload-side use of mTLS,
where the certificate identifies a service rather than a human.
*Inbound: mTLS-SVID* covers the SPIFFE X.509-SVID profile that is
the standard shape for service-to-service mTLS today. *Security
posture* covers the production crypto requirements that apply to
mTLS deployments, including FIPS-routing notes for regulated
contexts.
