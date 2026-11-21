# SPIRE Workload API client

A workload on a node that runs a SPIRE agent keeps no credential on
disk. It asks the agent, over a local socket, for its own SVIDs and
for the trust bundles it verifies its peers with, and the agent
rotates all of them. `SpireClient` is the client for that socket: it
fetches X.509 and JWT SVIDs, fetches and follows trust bundles, has
the agent validate a JWT SVID, and keeps everything current as the
agent rotates it.

The feature flag is `spire` (off by default, and in no umbrella: it
needs an agent). The pieces that pass what the agent serves to the
rest of axess also need the feature of the part they feed: `outbound-mtls` for
the rustls and outbound mTLS pieces, `jwt` for the key sets a
`JwtVerifier` is built on.

## What the client does

The Workload API has five methods. For each, the client has one call
and, where the answer changes over time, one source.

| Workload API method | One call | Kept current |
|---|---|---|
| `FetchX509SVID` (stream) | `fetch_x509_context`, `fetch_x509_svid` | `watch_x509`, an `X509Source` |
| `FetchX509Bundles` (stream) | `fetch_x509_bundles` | `watch_x509_bundles`, an `X509BundleSource` |
| `FetchJWTSVID` | `fetch_jwt_svid` | `watch_jwt_svid`, a `JwtSvidSource` |
| `FetchJWTBundles` (stream) | `fetch_jwt_bundles` | `watch_jwt_bundles`, a `JwtBundleSource` |
| `ValidateJWTSVID` | `validate_jwt_svid` | none: it is a question about one token |

## Connecting

The client is built for an endpoint and a trust domain.

```rust,ignore
use axess::workload::spire::{Endpoint, SpireClient};
use axess_identity::TrustDomain;

let client = SpireClient::builder(
    Endpoint::from_env()?,                    // SPIFFE_ENDPOINT_SOCKET
    TrustDomain::new("prod.example.com")?,
)
.build();
```

`Endpoint::from_env` reads `SPIFFE_ENDPOINT_SOCKET`, and
`Endpoint::parse` reads the same value from anywhere else. Two forms
are accepted: `unix:///run/spire/sockets/agent.sock` for a Unix
domain socket, and `tcp://127.0.0.1:8081` for TCP on the loopback
interface. A `unix` address has no host and an absolute path; a `tcp`
address has an IP address (not a host name), a port and no path;
neither has a query, a fragment or user information. An unset
variable is refused: the client does not guess a socket path.
`Endpoint::unix` and `Endpoint::tcp_loopback` build the same two
endpoints from a path and from a socket address, with the same
checks. An `Endpoint` cannot be made any other way, so every
`Endpoint` has passed them.

The client speaks to the agent in clear text and authenticates
nobody: the socket is the boundary. A Unix domain socket is guarded
by the permissions of the directory it lies in. A TCP port is guarded
by nothing, so a TCP address off the loopback interface is refused,
whether parsed or built. `Endpoint::tcp_clear_text` is the one way around,
for an agent reached over a path that is protected by other means,
such as a shared network namespace or a tunnel that authenticates
both ends. It gives up two things. Whoever answers on the address is
taken for the agent, and hands the workload its identity and the
authorities its verifiers trust. Whoever can read the path sees the
X.509 SVID's private key, every JWT SVID and the bundles in transit.
No URI and no environment variable selects it: it is a call in the
deployment's own code. A loopback address keeps the bytes on the
host, but a local process that binds the port before the agent does
can take the agent's place; prefer the Unix domain socket where there
is one.

The trust domain is the one this workload belongs to. The client
refuses an SVID the agent issues for any other trust domain, for the
same reason the resolvers pin one: an identity from the wrong namespace is
a misconfiguration to stop at, not to serve.

Every request carries the metadata `workload.spiffe.io: true`. The
Workload API requires it so that the agent refuses a request forged
through a server-side request forgery hole, which cannot set a header.

The builder's settings, with their defaults:

| Setting | Default | What it decides |
|---|---|---|
| `with_clock` | the system clock | every expiry, and every point at which the agent is asked |
| `with_rng` | the operating system's | the jitter of the back-off |
| `with_metrics` | no-op | where the watchers count |
| `with_listener` | no-op | who hears each watcher event |
| `with_svid_selector` | the first identity | which of the workload's identities the client is for, X.509 and JWT alike |
| `with_call_timeout` | 10 s | how long a call may take to its first message |
| `with_check_interval` | 1 s | how often a watcher reads the clock |
| `with_backoff` | 1 s rising to 30 s | the waits between failed attempts |
| `with_jwt_refresh_percent` | 50 | how far into a JWT SVID's lifetime the next is asked for |
| `with_recheck_percent` | 75 | when a source asks beside its open stream: a share of an X.509 SVID's lifetime, and of the maximum bundle age |
| `with_max_bundle_age` | 1 h | how long a bundle set is served after the agent last confirmed it |
| `with_withdrawal_grace` | zero | how long what the agent refuses with `PERMISSION_DENIED` is still served, never past its expiry |
| `with_max_message_bytes` | 4 MiB | the largest message read |

An agent returns one SVID for each registration entry that matches
the workload. `SvidSelector` says which of those identities the
client is for: the first (the agent's default), the one with a given
SPIFFE ID, or the one carrying the hint the operator gave its entry.
It decides every SVID the client hands out, X.509 and JWT alike. A
request for a JWT SVID names the selected SPIFFE ID to the agent, and
the client checks the answer itself: a client built for one identity
never presents another's token, and an answer without the selected
identity is refused with nothing taken in its place. A selector that
names a SPIFFE ID in a trust domain other than the client's is
refused before the agent is asked. A workload that acts under two
identities builds two clients.

## One call

A `fetch_*` method asks the agent once and returns what it holds now.

```rust,ignore
let svid = client.fetch_x509_svid().await?;
println!("{} until {}", svid.spiffe_id(), svid.not_after());

let token = client.fetch_jwt_svid(["https://api.partner.example"]).await?;
```

An agent that has no identity for the workload answers
`PERMISSION_DENIED`, which arrives as `SpireError::Status` with
`GrpcCode::PermissionDenied`. That is the usual answer in the first
seconds of a workload's life, before its registration entry has
reached the agent, and the reason a long-running workload uses a
source instead.

## Sources

A `watch_*` method starts a task on the current tokio runtime and
returns a source: a handle on what the task last accepted from the
agent. Called outside a runtime it answers `SpireError::NoRuntime`.

```rust,ignore
let x509 = client.watch_x509()?;
x509.ready().await;                 // the first SVID has arrived

let svid = x509.svid()?;            // the current one, at once
```

A source makes four promises.

**A read never waits for the agent.** `svid()`, `context()`,
`bundles()` and `token()` clone an `Arc` out of the source. They are
synchronous and safe on a request path.

**The SVID is replaced before it expires.** An agent pushes a rotated
X.509 SVID on the open stream, and the source takes it as it arrives.
The agent's setting, not the client's, decides when the agent rotates. A
SPIRE agent's default is about half the SVID's lifetime; the tests here
do not measure that figure against a real agent. The source
does not rely on the push alone. Past the recheck point of the SVID
it holds (three quarters of its lifetime, unless
`with_recheck_percent` says otherwise) it asks the agent on a second
request, beside the open stream. The point lies clearly after the
agent's own, so it does not fire while the agent rotates on time, and
it leaves a quarter of the lifetime to recover in. The open stream is
kept while the second request runs. The new stream takes over only when
it brings an SVID the open stream had not delivered, which is the
mark of a stream that has stalled. An agent set to rotate later than
the recheck point is asked a few times more than it needs to be, and
nothing else.

A JWT SVID is never pushed: the source asks for the next one at half
the token's lifetime (`with_jwt_refresh_percent`). When the agent
answers with what the source already holds, the source asks again
after a wait that grows up to the back-off's maximum. The expiry overrides the wait: when the token the source holds runs
out, the source asks at once.

**A failed refresh keeps serving what is valid.** While the agent is
down, the stream is broken, or the agent's answer is refused, the
source goes on serving the SVID it holds, reports the failure, and
retries with back-off. A failed refresh replaces nothing. A stream that was delivering and is cut is reopened at
once, as the Workload API standard asks of a client (section 4.2),
at most once for each check of the clock; the back-off paces what follows a
failed attempt.

**What the agent withdraws is served no longer.** Two answers are not
failures to wait out. When the agent answers `PERMISSION_DENIED`, or
with SVIDs and none for the identity the client selects, it has
redacted what the source holds, and the standard has a client cease
to use it (sections 5.2 and 6.2): the source is emptied, a read
answers `SpireError::Withdrawn`, and the watcher goes on asking, so a
registration entry that comes back is picked up. An agent that has
never issued the workload anything answers the same code, and that is
the ordinary wait before the first SVID. When the agent answers
`INVALID_ARGUMENT` or `UNIMPLEMENTED`, asking again cannot help, and
the Workload Endpoint standard has a client report it and not retry
(section 6): the watcher asks no more, reports `Stopped`, and what it
holds is served until it runs out.

This is the default: it takes the fail-closed reading of the standard,
which says a client SHOULD cease using what the agent has redacted. It has a cost: the agent's `PERMISSION_DENIED` does not
say why. A registration entry that tooling deletes and creates again
a moment later reads the same as one an operator removed, and a
healthy workload is without its identity until the agent issues it
again. A deployment that would rather ride that out has one option,
`with_withdrawal_grace` on the builder: a duration, zero
unless set. With a grace, what the source
holds when the agent answers `PERMISSION_DENIED` is served on,
counted from the first such answer, and withdrawn when the grace has
passed. The identity returning inside the grace clears it. Nothing
is served past its expiry, or a bundle set past its maximum age, on
the strength of a grace. The grace covers that one answer only:
an answer that arrives with SVIDs and none for the selected identity
is the agent's positive statement, and is honoured at once, grace or
not. While a source serves under a grace it says so, with the
`WithdrawalDeferred` event, which carries the instant the grace
ends, and the `workload_credential_withdrawal_deferred` count.
**The option departs from the standard's SHOULD**: for the length of
the grace, a workload whose identity an operator deleted on purpose
goes on presenting it.

**Nothing past its end is served.** Each read compares the SVID's expiry with the clock, so the promise
holds between two checks of the task as well. From the instant of expiry a read answers
`SpireError::Expired` until a new SVID arrives. The workload's other
X.509 SVIDs, in `context().svids()`, are held to the same rule: one
that has expired is not admitted, and one that expires while held is
left out of the next read.

A trust bundle has no expiry of its own, and a source that cannot
reach its agent cannot learn that an authority or a key was
withdrawn. So the client bounds it: a bundle set is served for the
maximum bundle age (`with_max_bundle_age`, one hour unless set) after
the agent last sent or confirmed it. At the recheck point of that age, 45 minutes by default, a source
asks the agent to confirm the set on a second request beside the open
stream; that request also finds a bundle stream that has stalled. Past the age a read answers
`SpireError::Stale`, and verification built on the source fails
closed until the agent answers again: the rustls verifiers refuse the
handshake with that error, and the key sets made from a JWT bundle
source are emptied at the watcher's next check. The bundles that come
with an X.509 SVID are held to the same age: `bundles()` and
`context()` of an `X509Source` answer `SpireError::Stale` while
`svid()` goes on serving the SVID, which has its own expiry.
`confirmed_at()` on a source says when the agent last sent what it
holds. Keep the age well above the check interval and the call
timeout: the confirmation is asked for at the first check at or after
the recheck point, and has to arrive in what remains of the age (a
quarter of it by default).

`ready()` waits for the first value. `generation()` counts the
changes, and `updated(after)` waits for the next one, which is how a
component that has to rebuild something on rotation learns of it. The
task stops when the last clone of the source is dropped.

### Rotation and the clock

A watcher bases every decision about time on the `Clock`
the client was built with: whether an SVID is due, whether it has
expired, whether an SVID the agent just sent is already too old to
keep. The waits between checks and between attempts are `tokio::time`
timers, and the jitter of the back-off comes from the client's
`SecureRng`.

A test of an application's rotation handling therefore needs no SPIRE
and no waiting for a real expiry: build the client on a `MockClock`
with a short check interval, move the clock past the point at which
the source asks, and the watcher asks at its next check. *Testing without SPIRE*,
below, has the fixture.

### What a watcher reports

A watcher reports each thing twice, as *Observability and metrics*
prescribes: a count without identity, and an event with it.

The counts go to the rotation concern of `MetricSinks`, labelled with
a `WorkloadCredentialKind` (`x509_svid`, `jwt_svid`, `x509_bundles`,
`jwt_bundles`) and nothing else.

| `RotationMetrics` method | Fires when | Alert on |
|---|---|---|
| `workload_credential_rotated(kind)` | the source took a new SVID or bundle set | a rate of zero over an SVID's lifetime |
| `workload_credential_refresh_failed(kind)` | a refresh failed and will be retried | a rate that does not fall back to zero |
| `workload_credential_expired(kind)` | the source stopped serving what it held with no replacement: an SVID expired, a bundle set went stale, or the agent withdrew it | any count: the workload has no identity, or cannot verify its peers |
| `workload_credential_withdrawal_deferred(kind)` | the agent answered `PERMISSION_DENIED` for what the source holds, and the source serves it on under the withdrawal grace | any count: what is served is something the agent no longer issues |
| `workload_bundle_skipped(kind)` | a bundle of another trust domain did not read and was left out | any count: that trust domain's peers cannot be verified |

The events go to a `WorkloadApiListener` and to `tracing`, on the
target `axess::workload::spire`. A `WorkloadApiEvent` carries: for a rotation, the SPIFFE ID and the
expiry; for a failed refresh, the error, the next wait and whether the
source is still serving; for an expiry or a bundle set going stale, the
instant; for a withdrawal grace, the instant it ends; for a bundle
entry that was left out, its key and the error.

```rust,ignore
let client = SpireClient::builder(endpoint, trust_domain)
    .with_metrics(sinks.clone())
    .with_listener(Arc::new(my_listener))
    .build();
```

## Where the credentials go

Each thing the client fetches has a place in the rest of axess.

### Outbound mTLS with the X.509 SVID

`X509Source::rustls_client_config` builds a rustls client
configuration that presents the source's SVID and verifies servers
against the source's bundles.

```rust,ignore
use axess::workload::spire::installed_provider;

let config = x509.rustls_client_config(
    installed_provider()?,
    [TrustDomain::new("prod.example.com")?],   // the servers admitted
)?;
let http = reqwest::Client::builder()
    .use_preconfigured_tls(config)
    .build()?;
```

The configuration is built once and follows the agent: it reads the
source at every handshake, so the next connection presents a rotated SVID and verifies against
a changed bundle. Certificate
validity is judged by the client's `Clock`, through
`ClockTimeProvider`.

The configuration resumes no TLS session, and the server
configuration below sends no session ticket. Nobody verifies a resumed
session: rustls restores the peer's certificate from the
session and asks no verifier, so a session resumed after the peer's
SVID expired, or after its authority left the bundle, would be
accepted on a check made earlier. Every connection is therefore a
full handshake against the bundles of that moment. A configuration
built by hand around `SvidCertResolver` and the two verifiers has to
turn resumption off as well; the module's own documentation lists the
settings.

An authority in a bundle is a trust anchor until its own `notAfter`.
rustls does not read the validity of a root it is handed, so the
bundle does: `X509Bundle::valid_at` gives the authorities that have
not expired, the verifiers build their roots from those at every
handshake, and a bundle with none left is refused with
`SpireError::AuthoritiesExpired`. A peer whose chain ends in an
expired authority is refused although the bundle still lists it.

A SPIFFE peer is identified by the SPIFFE ID in its certificate, not
by a DNS name. `SpiffeServerCertVerifier` verifies the server's chain
against the bundle of the trust domain its SPIFFE ID names, and that
the trust domain is one the caller admits; it does not compare the
certificate with the name that was dialled.
`SpiffeServerCertVerifier::with_peer_id` narrows that to one SPIFFE
ID, for a client that calls one known service.

`OutboundMtlsClient` takes the SVID as well, for a downstream that is
verified the way a web server is, by its DNS name:
`X509Svid::outbound_mtls_client` gives the client certificate, and
the caller pins the server's roots on it. Those roots are the
caller's own, not a trust domain's bundle: the Workload API standard
has a workload use the bundles it is served to authenticate X.509
SVIDs and nothing else (section 5.2), which is what the verifiers
above do. That client is a snapshot of one SVID; rebuild it when
`updated` reports a rotation, or use the rustls configuration above,
which needs no rebuilding.

### Presenting a JWT SVID

A JWT SVID is a bearer credential for the audience it was minted for.
`JwtSvidSource::token` gives the current one wherever the outbound
paths take a token.

```rust,ignore
let partner = client.watch_jwt_svid(["https://api.partner.example"])?;
partner.ready().await;

// As a bearer token:
let response = http
    .get("https://api.partner.example/v1/reports")
    .bearer_auth(partner.token()?.as_str())
    .send()
    .await?;

// As the workload's own token in a cloud STS exchange:
let request = AssumeRoleWithWebIdentityRequest::new(
    "arn:aws:iam::123456789012:role/billing-api-prod",
    "billing-api",
    partner.token()?.as_str(),
);
```

`GcpStsClient::exchange_token` and `AzureFicRequest::new` take the
token the same way. One source serves one audience: a token is only
good for the audience in its `aud`, so a workload that calls three
services watches three.

### Verifying JWT SVIDs on the agent's keys

`JwtBundleSource::key_set` gives the JWT signing keys of one trust
domain as the shared key set a `JwtVerifier` is built on. The watcher
rewrites the set with every bundle set the agent sends, so a verifier
built once follows the agent's key rotation.

```rust,ignore
use axess::jwt::{svid::JwtSvidResolver, verifier::JwtVerifier};

let bundles = client.watch_jwt_bundles()?;
bundles.ready().await;

let verifier = Arc::new(
    JwtVerifier::new(bundles.key_set(&trust_domain))
        .with_issuer("https://spire.prod.example.com")
        .with_audience("https://api.example.com"),
);

// Per request, as in *Inbound: JWT-SVID*:
let principal = JwtSvidResolver::new(verifier.clone(), trust_domain.clone(), token)
    .with_tenant_lookup(|slug| tenants.id_of(slug))
    .resolve()
    .await?;
```

Verification itself is unchanged; it is the `JwtVerifier` and the
`JwtSvidResolver` of *Inbound: JWT-SVID*. What changes is where the
keys come from. Points to know:

- `JwtSvidResolver` requires a verifier that pins the audience, and
  that pins the issuer or waives it by name. The JWT-SVID standard
  defines `sub`, `aud` and `exp` and no `iss` (section 3), so an SVID
  may carry none; what names its signer is the key set of the trust
  domain in its `sub`. On a key set from the agent, build the verifier
  with `allow_any_issuer()` in place of `with_issuer(..)` unless the
  issuing server is known to set the claim.
- The standard leaves the `kid` header optional (section 2.2).
  `JwtSvidResolver` verifies a JWT SVID without one against each key
  of the trust domain's set (at most 32 keys; a larger set is refused
  for such a token), and one with a `kid` against that key alone.
  Every other JWT path of axess still requires a `kid`.
  `AgentJwtSvidResolver`, below, leaves the matter to the agent.
- A token signed with an algorithm the standard does not list
  (section 2.1 lists RS256, RS384, RS512, ES256, ES384, ES512, PS256,
  PS384 and PS512) is refused by `JwtSvidResolver`, whatever the
  verifier's own allowlist admits. `ES512` is refused too: the JOSE
  library has no such algorithm.
- A key set holds no key until the source has a bundle for its trust
  domain, none again when the agent stops serving one, and none while
  the source's bundle set is stale. Tokens of a trust domain without
  keys are refused.
- A key the JOSE library cannot verify with (a key type it does not
  know, a key with a parameter missing) is left out and logged, and
  the bundle's other keys are kept.

A SPIFFE bundle marks a key's purpose in `use` with values a JOSE
library does not know. The client takes them out before a verifier
sees the keys: a key marked `jwt-svid` is kept without the mark, a
key marked `sig` or not marked is kept as it is, and a key marked for
anything else (`x509-svid`, `wit-svid`, a use the client does not
know) is left out, since it signs no JWT SVID.

A key with no `use` is kept on purpose. The rule that every key
carries a `use` is a rule of the SPIFFE bundle document (Trust
Domain and Bundle standard, section 4.2.2). What the Workload API
hands a workload is not that document: its JWT bundles are JWK Sets
as RFC 7517 defines them, holding the JWT SVID signing keys of a
trust domain and no key with another use (Workload API standard,
section 6.2.2), and in a JWK Set `use` is optional. The crate reads
no SPIFFE bundle document anywhere, from a file or from a bundle
endpoint: every bundle it holds came from the Workload API. A reader
of bundle documents, were one added, would hold each key to the
strict rule.

### Verifying X.509 SVIDs in the terminator

`MtlsResolver` reads the SPIFFE ID out of a client certificate and
leaves the chain to whatever terminated TLS, which has to verify each
certificate against the bundle of the trust domain it names (see
*Inbound: mTLS-SVID*, on the root store). `SpiffeClientCertVerifier`
is that verifier for rustls, on the agent's bundles.

```rust,ignore
let config = x509.rustls_server_config(
    installed_provider()?,
    [TrustDomain::new("prod.example.com")?],   // the clients admitted
)?;
```

The configuration presents the source's SVID as the server
certificate, requires a client certificate, and verifies it in three
steps: the certificate is an X.509 SVID (one URI name, a SPIFFE ID,
and not a certificate authority); its trust domain is one of those
admitted; its chain leads to an authority in that trust domain's
bundle, as the source holds it at the handshake. A certificate that
names one trust domain and was signed by another's authority fails
the third step, whichever bundles are held. After the handshake the
application hands the peer certificate to `MtlsResolver` as before.

A service that presents no X.509 SVID of its own builds the verifier
on an `X509BundleSource` instead:
`SpiffeClientCertVerifier::new(Arc::new(bundles), provider, admitted)`.

### Validation by the agent

`SpireClient::validate_jwt_svid` asks the agent to validate a token:
the agent checks the signature against the bundle of the token's
trust domain, the audience and the expiry, and answers with the
SPIFFE ID and the claims. `AgentJwtSvidResolver` turns that into a
`Principal::Workload`.

```rust,ignore
use axess::workload::spire::AgentJwtSvidResolver;
use axess_identity::PrincipalResolver;

let principal = AgentJwtSvidResolver::new(
    client.clone(),
    "https://api.example.com",          // the audience this service is
    trust_domain.clone(),               // the trust domain admitted
    token,
    move |slug| tenants.id_of(slug),
)
.resolve()
.await?;
```

The process then holds no key set at all, and the token needs no
`iss`. The cost is a call to the agent for every token, over a local
socket. After the agent's check the resolver does what the other
SVID resolvers do: it pins the trust domain, reads
`spiffe://<trust_domain>/<service>/<tenant_slug>` out of the SPIFFE
ID, takes the tenant from the lookup, and refuses a `tid` claim that
names another tenant. Every refusal by the agent, and an agent that
cannot be reached, is `IdentityError::NotAuthenticated`, with the
cause logged at `debug`.

An agent that does not offer the method answers `UNIMPLEMENTED`
(`GrpcCode::Unimplemented`), which the resolver reports as any other
refusal. Use the key-set path there.

## Federation

A bundle set holds the workload's own trust domain and every trust
domain the operator federated with it: the federated bundles arrive
with the X.509 SVID, and on the two bundle streams. Holding a bundle
admits nobody. Each place a bundle is used takes the trust domains it
admits by name:

- `rustls_client_config`, `rustls_server_config` and the two
  verifiers take the list of admitted trust domains, and a peer of
  any other is refused although its bundle is held.
- `JwtBundleSource::key_set` is asked for one trust domain, and a
  verifier built on it checks tokens against that trust domain's
  keys alone. Verifying a partner's tokens is one more verifier, on
  the partner's key set, with a `JwtSvidResolver` that expects the
  partner's trust domain.
- `AgentJwtSvidResolver` is built for one trust domain. The agent
  validates a token of any trust domain it holds a bundle for; the
  resolver refuses those it was not built for.

When the operator ends a federation, the agent stops serving the
bundle, the sources drop it, and the verifiers refuse that trust
domain from the next handshake and the next token on.

## What is refused

The agent is the workload's root of trust, so the client does not
verify signatures on what the agent hands it. It does refuse what
could not be a valid answer:

- an SVID for a trust domain other than the client's
  (`SpireError::TrustDomainMismatch`);
- an SVID that has expired by the client's clock, and one whose
  validity ends before it begins (a leaf whose `notAfter` is before
  its `notBefore`, a token whose `iat` is after its `exp`);
- an X.509 SVID whose leaf does not carry exactly one URI name, whose
  URI name is not the SPIFFE ID the agent states, or whose leaf may
  sign certificates;
- an X.509 SVID whose private key is not the key of its leaf
  certificate, or is not a PKCS#8 key: the SVID a source holds is kept,
  since the one refused could present nothing;
- a JWT SVID whose `sub` is not the SPIFFE ID the agent states, whose
  `aud` lacks an audience that was asked for, or that has no `exp`;
- a response with no SVID; one with SVIDs and none for the identity
  the client's selector names is the agent withdrawing that identity
  (`SpireError::NotIssued`, and see the promises above);
- an X.509 SVID whose leaf names no workload: a SPIFFE ID with no
  path is a trust domain's, which only a signing certificate carries
  (X509-SVID standard, sections 3.1 and 5.2), and the verifiers refuse
  such a peer as well;
- an answer to a validation that holds no claims, and a validation
  asked for with no token;
- a bundle of the workload's own trust domain that does not read, or
  in which every authority has expired
  (`SpireError::AuthoritiesExpired`);
- a bundle answer with no bundle for the workload's own trust domain,
  an empty answer included: an agent always serves a workload its own
  trust domain's bundle, so such an answer never replaces the set a
  source holds;
- a message that does not decode, a message over the size limit, a
  compressed message.

A bundle of another trust domain that does not read (a bundle with no
certificate, a JWT bundle that is not a key set, an entry filed under
a name that is not a trust domain) does not refuse the answer: one
partner's broken bundle would otherwise stop the workload's own SVID
and bundle from being followed. It is left out, listed in the set's
`skipped()`, counted by `workload_bundle_skipped` and reported as a
`BundleSkipped` event, so the trust domain does not go missing
silently.

Text the agent wrote (a status message, a SPIFFE ID, a parser's
complaint) is escaped and cut to 256 bytes before it is put into an
error, so a `SpireError` can be logged as it is. A message is read up
to the configured limit and no further, and a response with more than
64 SVIDs, 256 bundles or 64 certificates in a chain is refused.

The private key is checked in two ways. The public key a PKCS#8
private key carries is compared with the certificate's, which needs
no cryptography. With `outbound-mtls` in the build the key is also
loaded by the TLS stack that will sign with it, which refuses bytes
that are not a usable key and derives the public key of a key that
carries none. A build without `outbound-mtls` has nothing to derive
it with, and refuses a key that carries no public key: it cannot be
shown to be the certificate's.

A private key is held in memory that is wiped when the SVID is
dropped, and so are the copies the client makes on the way to it: the
buffer a message is assembled in, the message, and the request that
carries a token to the agent for validation. The buffers of the
HTTP/2 layer, on the way in and on the way out, are outside the
client's reach and are not wiped. Neither a key nor a token appears
in `Debug` output.

## The wire

The client speaks gRPC over HTTP/2 directly, on the `h2` crate, and
reads the Workload API's messages with a small protobuf reader of its
own. `h2` is already in the workspace's lockfile, where `hyper` brings
it in for the features that make HTTP requests, so `spire` adds no
crate to the lockfile and none to vet; a build that had no `hyper`
before compiles `h2` and its few dependencies once `spire` is on. The
alternatives were the upstream SPIFFE crates or generated code on
`tonic` and `prost`; both bring a gRPC stack new to the lockfile for
five messages that are each a few strings and byte strings.

Each call opens its own connection to the socket: a call is either one
long-lived stream or rare, and a connection that carries one stream
has one thing that can fail.

## What the tests cover

The test suite proves the client against `FakeSpireAgent`, an
in-process agent that speaks the Workload API on a real socket, a
Unix domain socket or a loopback TCP port. The fake writes the method
paths and the metadata key itself and takes neither from the client,
and two tests hold both sides to those names written out as literals:
one compares the constants of each, one reads what the client puts on
the wire. The fake's encoders and the client's decoders each write
the field numbers below for themselves.

The names, the field numbers and the rules in the list below are
those of the SPIFFE standards, compared clause by clause with the
code: the Workload API standard and its `workloadapi.proto`, the
Workload Endpoint standard, and the SPIFFE-ID, X.509-SVID, JWT-SVID
and Trust Domain and Bundle standards. The last item of the
list, and the timing of the push in the item before it, are how an
agent behaves and are not in the standards; *Against
a real agent*, below, is where an agent is asked. What the client and
the fake agree on is this:

- The service is `SpiffeWorkloadAPI`, declared without a protobuf
  package, so a method is called at `/SpiffeWorkloadAPI/<Method>`.
- The field numbers: `X509SVIDResponse` has `svids` 1, `crl` 2,
  `federated_bundles` 3; `X509SVID` has `spiffe_id` 1, `x509_svid` 2,
  `x509_svid_key` 3, `bundle` 4, `hint` 5; `X509BundlesResponse` has
  `crl` 1, `bundles` 2; `JWTSVIDRequest` has `audience` 1,
  `spiffe_id` 2; `JWTSVIDResponse` has `svids` 1; `JWTSVID` has
  `spiffe_id` 1, `svid` 2, `hint` 3; `JWTBundlesResponse` has
  `bundles` 1; `ValidateJWTSVIDRequest` has `audience` 1, `svid` 2;
  `ValidateJWTSVIDResponse` has `spiffe_id` 1, `claims` 2, a
  `google.protobuf.Struct`.
- An X.509 SVID's chain and a bundle are DER certificates end to end,
  leaf first in a chain, and the private key is unencrypted PKCS#8.
- The key of a bundle map is the trust domain's name or its SPIFFE
  ID (`example.org` or `spiffe://example.org`); both are read.
- The metadata key is `workload.spiffe.io` with the value `true`, and
  an agent answers `INVALID_ARGUMENT` without it.
- An agent answers `PERMISSION_DENIED` when it has no identity for
  the workload.
- The endpoint address rules under *Connecting*, and the name of the
  environment variable.
- The `use` values of a SPIFFE bundle's keys are `jwt-svid` and
  `x509-svid`.
- An agent answers a `FetchJWTSVID` request that names a SPIFFE ID
  with that identity's SVIDs alone, and with `PERMISSION_DENIED` when
  the workload has no such identity.
- An agent pushes a rotated X.509 SVID and changed bundles on the open
  streams, each message the full set. When it does so is its own
  matter: the standard says only that the timing is the
  implementation's.
- A SPIRE agent rotates an X.509 SVID at about half its lifetime. The
  default recheck point is set against that figure, which is not in
  the standards: it is SPIRE's own rule, half the lifetime give or
  take a tenth of that half unless the agent is configured with an
  availability target, as the source of SPIRE 1.16.0 has it.

### Against a real agent

A second suite runs the client against a SPIRE server and agent: the
ignored tests of `axess-core/tests/spire_live.rs`. CI's SPIRE
Workload API job runs them on Linux with the SPIRE release it names
by version and digest, and the release gate needs that job.
`scripts/spire-live.sh` starts the server and the agent, registers
two identities for the uid it runs as, runs the tests through
`scripts/check-live-stores.sh spire`, and deletes a registration
entry each time a test asks for it. The tests

- take an X.509 SVID with the bundle of its trust domain, compare
  that bundle with the one `fetch_x509_bundles` answers, and run a
  mutual TLS handshake in which each end presents the SVID and
  verifies the other against the agent's bundle;
- take a JWT SVID for an audience, have the agent validate it for
  that audience and refuse it for another, and verify it against the
  keys of the agent's JWT bundle with `JwtVerifier`;
- follow one rotation of an X.509 SVID that lives two minutes: the
  source is never without an SVID on the way, and the handshake
  succeeds with the new one;
- have an entry deleted while the workload keeps another: the agent
  goes on answering, without that identity, and the source built for
  it answers `SpireError::Withdrawn`;
- have the workload's last entry deleted: the agent answers
  `PERMISSION_DENIED`, the source answers `SpireError::Withdrawn`,
  and a request for a JWT SVID is refused with the same code.

No test reads the machine's clock: each runs on the time the agent's
host stamps on a token minted as the test starts, carried forward by
a stopwatch. The suite does not measure when in an SVID's lifetime
the agent rotates, it has no federated trust domain, and it sets no
withdrawal grace. It runs where a SPIRE agent runs beside the tests:
SPIRE publishes Linux binaries, and an agent attests a workload on
its own host, so the release preflight on another system leaves it
to CI. On a Linux host:

```sh
./scripts/spire-live.sh /path/to/spire/bin
```

Run the client against your own agent before relying on it. The
`spire` binary in `examples/workload-identity` does exactly that:
`cargo run -p axess-example-workload-identity --bin spire`.

## What is not built

- **Windows named pipes.** A SPIRE agent on Windows serves the
  Workload API on a named pipe. The client connects to a Unix domain
  socket (on Unix) or to TCP (anywhere); `Endpoint` has no named-pipe
  form.
- **The WIT-SVID profile.** The Workload API standard has a third,
  optional profile, which serves WIT-SVIDs and their bundles. The
  client does not call it.
- **`ES512` JWT SVIDs.** The JWT-SVID standard lists `ES512` among
  the algorithms a validator supports (section 2.1); the JOSE library
  the verifier is built on has none, so `JwtSvidResolver` refuses a
  JWT SVID signed with it. The agent's own validation is not
  affected. The roadmap has the entry, under *Awaiting upstream*.
- **Revocation lists.** The agent may send certificate revocation
  lists with the bundles. They are handed on by
  `X509BundleSet::crls`; the verifiers of this module do not consult
  them. An SVID's short lifetime is the revocation mechanism SPIFFE
  relies on.

## Testing without SPIRE

`FakeSpireAgent` (features `spire` and `testing`, on Unix) serves the
Workload API inside the test process, on a Unix domain socket or,
started with `FakeSpireAgent::start_tcp`, on a loopback TCP port. It
attests nobody and signs nothing: the test hands it the SVIDs and the
bundles to serve, changes them to play a rotation, drops its
connections to play a restart, and reads back what the client asked
for.

```rust,ignore
use axess::testing::spire_agent::{FakeSpireAgent, FakeJwtSvid};
use axess::testing::MockClock;

#[tokio::test]
async fn the_partner_token_is_rotated() {
    let dir = tempfile::tempdir().unwrap();
    let agent = FakeSpireAgent::start(dir.path().join("agent.sock")).unwrap();
    let clock = MockClock::at_reference();
    let client = SpireClient::builder(agent.endpoint(), trust_domain())
        .with_clock(Arc::new(clock.clone()))
        .with_check_interval(Duration::from_millis(10))
        .build();

    agent.set_jwt_svids(&[FakeJwtSvid { spiffe_id: id(), token: first(), hint: String::new() }]);
    let source = client.watch_jwt_svid(["https://api.partner.example"]).unwrap();
    source.ready().await;

    agent.set_jwt_svids(&[FakeJwtSvid { spiffe_id: id(), token: second(), hint: String::new() }]);
    clock.advance_secs(200);            // past the refresh point
    source.updated(1).await;
    assert_eq!(source.token().unwrap().as_str(), second());
}
```

The fixture refuses a call without the `workload.spiffe.io` metadata,
as an agent does, answers `PERMISSION_DENIED` until it is given
something to serve, and can be told to answer any method with a gRPC
status, with a message that does not decode, or with a broken frame.
`hold_updates` stalls the open streams, for a test of the request a
source makes beside them. `open_calls` says how many calls of a
method are open, and `jwt_subjects` which identity each `FetchJWTSVID`
call named; given SVIDs for several identities, the fixture answers a
call that names one with that identity's alone.

A test on a paused tokio runtime (`start_paused`) needs one more
thing. Paused,
tokio moves its time to the next timer whenever it has nothing to run,
and a task waiting for the fake agent's socket counts as nothing to
run: one exchange can move the time far enough to fire the client's
call timeout. Keep a short timer running beside the test, a task that
sleeps 10 ms in a loop, so that no single move is longer than that.
The library's own tests do this.

## Troubleshooting

**`SpireError::Connect`.** No agent is listening where the endpoint
points: the socket path is wrong, the agent is not running, or the
socket is not mounted into the container. A source keeps retrying and
reports each attempt.

**`PERMISSION_DENIED`, "no identity issued".** The agent attested the
process and found no registration entry for it, or the entry has not
reached the agent yet. Check the entry's selectors against what the
agent sees of the workload.

**`SpireError::TrustDomainMismatch`.** The agent issued an SVID for
a trust domain other than the one the client was built for. One of the two is
configured wrongly.

**`SpireError::Expired` from a read.** The source could not replace
the SVID before it ran out. The `workload_credential_refresh_failed`
counter and the `RefreshFailed` events from before the expiry say
why.

**`SpireError::Stale` from a read, or in a handshake error.** The
agent has not sent or confirmed the bundle set within the maximum
bundle age, and the source stopped serving it. The `RefreshFailed`
events from before say why the agent could not be asked.
`with_max_bundle_age` sets the age: a longer one is a longer time
that a withdrawn authority or key stays trusted while the agent is
away.

**`SpireError::Endpoint`, "off the loopback interface".** The
endpoint is a TCP address on an interface other than loopback, which
the client refuses because the connection is clear text.
*Connecting* says what `Endpoint::tcp_clear_text` gives up.

**Handshakes fail after a federation change.** The verifiers read the
bundles at every handshake, so they follow the agent at once. A peer
refused after the change is a peer of a trust domain the agent no
longer serves a bundle for, or one the configuration never admitted.

## Further reading

*Workload identity overview* covers SPIFFE's vocabulary. *Inbound:
JWT-SVID* and *Inbound: mTLS-SVID* cover the resolvers the key sets
and the verifiers feed. *Outbound: mTLS* and *Cloud STS exchange*
cover the paths the fetched SVIDs are presented on. *Observability
and metrics* covers the metric traits.
