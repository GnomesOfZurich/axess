# mTLS-based authentication

Mutual TLS authenticates the client to the server at the transport
layer, before the application sees the request. The client presents
an X.509 certificate during the TLS handshake, the server validates
the certificate against a trust anchor, and the resulting connection
carries a known identity. For service-to-service traffic between
parties that own both sides of the connection, mTLS is the strongest
practical authentication: there is no credential to phish, no token
to leak, no replay window after the handshake.

This chapter covers using mTLS as a factor for human or human-adjacent
flows (a kiosk machine, an internal admin host). The other use of
mTLS in axess, where the certificate identifies a workload rather
than a human, is covered in *Workload identity overview* and
specifically in *Inbound: mTLS-SVID*. The mechanism is the same; the
interpretation of the certificate differs.

The feature flag is `mtls` (off by default), enabled with
`features = ["mtls"]` on the `axess` facade.

## Where the certificate comes from

The most important detail about an mTLS integration is that axess
does not handle the TLS handshake. Axum sits behind a TLS
terminator (rustls in process, or nginx, HAProxy, AWS NLB, or
Cloudflare in front), and the certificate validation happens at the
terminator. Axess receives the validated certificate as part of the
request, extracts an identity from it, and proceeds.

The extraction is a Tower middleware the adopter wires in. The
middleware reads the certificate from wherever the terminator put it:

- For rustls in process, the certificate is in
  `axum_server::tls_rustls::RustlsConnectInfo` or an equivalent
  connector callback.
- For nginx, the certificate is passed through as the
  `X-SSL-Client-Cert` header (the exact header is the deployment's
  choice).
- For HAProxy, the convention is `X-Client-Cert` or similar.
- For AWS NLB with TLS passthrough, rustls handles the validation;
  for AWS ALB with mTLS, the certificate is in
  `X-Amzn-Mtls-Clientcert`.

The middleware reads the certificate, validates that it came from a
trusted source (the certificate must be present, the header must
have arrived only from the trusted terminator, the deployment must
not allow clients to inject the header directly), wraps the
certificate chain in a `PeerCertChain`, and inserts it into the
Axum request extensions:

```rust,ignore
use axess::factors::mtls::PeerCertChain;

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

The trusted-terminator check is the critical line. If the
deployment accepts the certificate header from anywhere, an
attacker who can reach the application directly (bypassing the
terminator) can spoof any identity by setting the header
themselves. The defence is to either configure the application to
listen only on a socket the terminator owns, or to gate the
extraction on a token the terminator injects alongside the
certificate.

## The trust anchor

The certificate validation that the TLS terminator performs uses a
trust anchor: a set of CA certificates the terminator considers
authoritative. A client certificate is accepted only if it chains
back to one of those CAs.

For service-to-service mTLS within an organisation, the trust
anchor is typically the organisation's own internal CA. The CA
issues certificates to known clients, the terminator trusts the
CA, and the validation works on the closed set of certificates the
organisation has signed.

For broader deployments (a partner integration where the partner
runs their own CA), the trust anchor is the partner's CA or a
short list of CAs, and the validation accepts clients signed by
any of them.

For consumer-facing deployments where clients might use any
certificate, mTLS is the wrong factor. Use OAuth or another flow
where the client does not need to provision a certificate.

## From certificate to user

After the middleware inserts the `PeerCertChain` into the
extensions, the application's login handler reads it back and maps
the certificate to a user identity. The mapping depends on the
deployment's conventions.

The simplest mapping is from the certificate's Subject Common Name
(CN) to a username. The CA issues certificates with CNs that match
the deployment's usernames, the login handler reads the CN, and
the application looks up the user under that CN.

```rust,ignore
use axess::factors::mtls::PeerCertChain;
use axum::Extension;

async fn mtls_login(
    session: AuthSession,
    State(service): State<Arc<AuthnService<...>>>,
    Extension(chain): Extension<PeerCertChain>,
) -> impl IntoResponse {
    let leaf = chain.leaf().expect("validated chain has at least one cert");
    let cn = extract_common_name(leaf).expect("validated cert has a CN");

    match service.begin_login(&session, &cn, "default-tenant").await {
        Ok(_) => {}
        Err(e) => return (StatusCode::UNAUTHORIZED, format!("{e}")).into_response(),
    }

    use axess::FactorCredential;
    match service
        .verify_factor(&session, FactorCredential::Mtls { chain })
        .await
    {
        Ok(_) => Redirect::to("/dashboard").into_response(),
        Err(e) => (StatusCode::UNAUTHORIZED, format!("{e}")).into_response(),
    }
}
```

A more structured mapping uses a SPIFFE URI in the certificate's
Subject Alternative Name (SAN). The CA issues certificates with
SAN URIs of the form `spiffe://<trust_domain>/<path>`, and the
application's login handler parses the URI to extract the trust
domain, the path, and any embedded identifiers. This shape is what
the workload identity chapter covers, and it remains the right
shape even for human-adjacent flows because it is more structured
than a CN.

The verification on the axess side is straightforward. The
`FactorCredential::Mtls { chain }` variant carries the cert chain
through `verify_factor`. The verifier checks that the chain is
present (a sanity check, since the middleware put it there), that
the leaf certificate has not expired, and that the certificate
matches the user's stored mTLS configuration (which CA it should
be signed by, which CN or SAN it should have). Verification
success advances the state machine; failure returns
`InvalidCredential`.

## Composing mTLS with other factors

mTLS as a sole factor is appropriate for service-to-service traffic
where the certificate's possession is itself the authentication
event. For human flows, mTLS pairs with another factor in a method.

A common shape for a high-assurance admin interface is mTLS
followed by FIDO2. The user's machine presents a certificate
issued by the organisation's CA (so only employees whose machines
have been provisioned can even reach the login page); the user
then authenticates with a passkey (so a stolen machine is not
enough, the user themselves must be present). The combination is
strong against both remote attackers (they have no certificate)
and local attackers (they have no passkey).

A variation uses mTLS as a tenant-scoping factor and OAuth as the
user-identification factor. The certificate identifies which
tenant the request is for (a partner integration's certificate
maps to the partner's tenant); the OAuth flow identifies which
user within that tenant. The method composes the two.

## Threat model

mTLS is robust against the standard authentication attacks:
credential reuse, credential stuffing, password phishing, replay.
The certificate is hard to steal without compromising the device
that holds the private key, and a compromised private key is no
easier to use than a compromised password (both require some
attacker action and both can be revoked).

It is weak against three specific attacks.

The first is private-key theft from a compromised device. An
attacker with full filesystem access to a client can copy the
private key, install it on their own machine, and use the
certificate. The defence is to store the private key on hardware
the operating system protects (a TPM, a hardware security module,
a smartcard) rather than in a file. Hardware-backed keys cannot
be exported and survive even a full filesystem compromise.

The second is CA compromise. An attacker who can issue
certificates from a CA the application trusts can authenticate as
anyone. The defence is operational: keep the issuing CA offline,
use short-lived certificates so revocation is automatic, and
monitor the CA's audit log. For service-to-service mTLS, a SPIFFE
control plane handles this with rotating, short-lived certificates
backed by an attested root.

The third is missing revocation. When a certificate is revoked
(employee leaves, machine is lost), the application needs to know.
The TLS terminator checks revocation through OCSP or CRL or a
short-lived-certificate strategy; an unchecked revocation lets
the old certificate continue to work. The defence is to wire
revocation checking at the terminator and to monitor the
revocation lifecycle.

## Troubleshooting

If the middleware never sees a certificate, the most likely cause
is that the TLS terminator is not requiring client certificates.
Some terminators require explicit configuration to request the
client certificate at handshake time; others accept the handshake
without a certificate and silently let the request through. Check
the terminator's configuration.

If certificates are present but the CN extraction returns nothing,
the certificate may use a SAN URI instead of a CN. Inspect the
certificate (`openssl x509 -in cert.pem -text`) to see what fields
are present. Updating the extraction to read the SAN URI is the
fix; the structured-mapping pattern above is the right shape.

If the trust-anchor configuration accepts a certificate the
application does not expect, the terminator's trust store may
include a CA the deployment did not intend to trust. Check the
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
