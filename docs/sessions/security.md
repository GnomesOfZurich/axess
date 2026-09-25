# Cookies, fingerprinting, hijack detection

The session cookie is the credential a browser presents on every
request. If an attacker captures it, they can act as the user
until the session expires or is revoked. The defences are layered:
cookie attributes constrain how the browser handles the cookie,
HMAC signing detects tampering, fingerprint binding catches replay
from a different browser, and trusted-proxy configuration controls
how the application reads the request's IP. This chapter covers
each layer.

## Cookie attributes

The session cookie carries five attributes the deployment cares
about. Most have defaults that are right for production; one
(`Secure`) needs to be set explicitly.

`Path=/` makes the cookie apply to the whole application. The
alternative (a narrower path) is occasionally useful for embedded
deployments where the application lives under a sub-path of a
larger site; for most deployments, the root path is right.

`HttpOnly` prevents client-side JavaScript from reading the
cookie. The attribute defeats one class of cross-site scripting
attack: an attacker who injects JavaScript into the page cannot
read the session cookie through `document.cookie` and exfiltrate
it. The attribute is on by default and there is rarely a reason to
turn it off.

`SameSite` controls when the browser sends the cookie on
cross-origin requests. There are three values:

- `Strict` means the cookie is sent only on same-site requests. A
  link from an external site to your application produces a
  guest-state request even if the user is logged in; the user
  must navigate from within your site for the session to be
  recognised.
- `Lax` (the default) means the cookie is sent on top-level
  cross-site navigations (a link click) but not on cross-site
  sub-requests (an embedded image, an XHR). The combination
  defeats most CSRF attacks while preserving the user experience
  of "click an external link, arrive logged in."
- `None` means the cookie is sent on every cross-site request.
  This is the right setting when the application is embedded in
  iframes on third-party sites; it is the wrong setting otherwise.

The recommendation is `Lax` for most deployments. Switch to
`Strict` for the highest-sensitivity actions; the cost is the
user-experience friction of cross-site link arrivals not being
logged in.

`Secure` requires HTTPS. The cookie is sent only on TLS-protected
connections; a misconfigured load balancer that accepts cleartext
HTTP does not see the cookie. The attribute is non-negotiable for
production but breaks `localhost` development against `http://`,
which is why `SessionLayer::with_secure(false)` exists as a
development concession.

The `Max-Age` (the cookie's lifetime in seconds) matches the
session TTL from `SessionLayer::with_ttl`. The browser stops
sending the cookie after the lifetime expires; the server-side
session has its own expiry that the lifecycle layer also enforces.

## HMAC signing

The cookie carries an HMAC signature computed from the session id
and the deployment's signing key. The format is:

```text
<base64(session_id)>.<base64(hmac_sha256(signing_key, session_id))>
```

The signature defeats forgery and tampering. An attacker who
guesses a session id (or who tries to mutate an existing cookie)
cannot produce a valid signature without the signing key. The
server rejects any cookie whose signature does not validate; the
session is not loaded and the request proceeds as `Guest`.

The HMAC verification is constant-time. The constant-time
comparison defeats a timing attack where an attacker could
distinguish "valid signature for invalid id" from "invalid
signature for valid id" by measuring response latency.

The signing key rotation is the operational lever for replacing the
signing key without invalidating active sessions. The pattern is
covered in *Operations runbook*. The short version is:
`SessionLayer::with_previous_signing_key` accepts the old key, sessions
signed with it continue to validate, and the key passed to
`SessionLayer::new` signs everything new. After enough time for all old
cookies to expire, the previous key is removed.

## The fingerprint binding

The fingerprint is the additional signal that catches session
replay from a different browser. The mechanism takes a few coarse
features of the request (the user agent, the IP address, sometimes
the accept-language), HMACs them together with a deployment-level
pepper, and stores the result alongside the session.

```rust,ignore
pub trait SessionBinding: Send + Sync + 'static {
    /// The raw binding material. `None` means the signal is absent for
    /// this request, and binding is skipped rather than failed.
    fn extract(&self, req: &Request<Body>) -> Option<Vec<u8>>;
}

// The one that ships:
let layer = SessionLayer::new(store, signing_key)
    .with_binding(UserAgentBinding);
```

`UserAgentBinding` returns the `User-Agent` header. The layer
HMAC-SHA256s whatever `extract` returns, keyed with the **session
signing key**, and stores the digest on the session. There is no
separate pepper to configure: the signing key is the secret, which is
what stops an attacker who can read session rows out of the store from
recomputing a valid fingerprint.

That key choice has one consequence worth knowing. Because the
fingerprint is keyed, rotating the signing key changes every
fingerprint, so the layer computes the current-key and previous-key
values together and accepts either during a rotation window.

Implement the trait yourself for anything richer: the user agent
combined with an IP prefix, a TLS channel-binding value, a client hint
your front end sets. The contract is small on purpose: return the raw
material, and let the layer do the keying and the constant-time
compare.

## What a mismatch does

There is no policy to configure, and no tolerance to tune. The
fingerprint either matches or it does not, and a mismatch resets the
session to `Guest`. The user is logged out; their other sessions are
untouched, because the fingerprint lives on the session, not on the
user.

That is a deliberately blunt instrument, and it is why the binding
signal should be one that does not change under a legitimate user.
`User-Agent` qualifies: it survives a network change, a wifi-to-cellular
switch, and a page reload, and it changes on a browser update, which
logs the user out once, at an unsurprising moment. An IP-derived
binding does not qualify on a mobile network, which is why nothing
ships with one.

If you want a softer response, the place to put it is your own
`SessionBinding` implementation: return `None` when the signal is
absent or when you would rather not judge, and binding is skipped for
that request.

## When the check runs

The fingerprint is recomputed and compared **once per HTTP request**, at
`SessionLayer` entry. It is set at the earliest transition out of
`Guest`: `set_identifying` when the username is submitted,
`begin_authenticating` when a multi-factor flow starts,
`set_authenticated` when authentication completes. So even a pre-MFA
session cannot be replayed from another device. Once set it is never
overwritten.

Once per request is the whole of it, and the gap is persistent
connections. A WebSocket or an SSE stream is checked at the upgrade and
never again, so a connection that outlives the binding's validity is
not re-examined. Where that matters, re-check on the messages
themselves rather than relying on the layer.

## Reading the client IP

Nothing in the session layer reads a forwarded header, because nothing
in the default binding uses the IP. Your own code does, though: a
Cedar policy conditioned on `ip_address`, a rate-limit key, an audit row.
That is where the spoofing risk lives, and since 0.7.0 the answer is to
resolve once with `client_ip::layer` and read `ClientIp` everywhere
instead of asking each consumer to work it out.

Reading `X-Real-IP`, or the first entry of `X-Forwarded-For`, means
taking a value **any client can set**. Doing that on an
internet-facing service means an attacker chooses the IP your
policies see, and the name says so at every call site.

The same applies to your audit trail, and there it matters more.
`extract_audit_context` takes the client IP as an argument for the same
reason. Hand it an address you resolved yourself, or `None`: a null
`ip_address` is honest and a forged one is not. The header-reading form
is `extract_audit_context_untrusted`, and the name is the warning.

This matters more than it used to. A failed audit write now fails the
login, so those rows are guaranteed to exist, which makes a forged
address in them worse rather than better: evidence written by the
subject of the evidence.

The defence is to require that the request's actual peer be a proxy you
trust before believing anything it forwarded:

```rust,ignore
use axess::client_ip::{self, TrustedProxies};

// Addresses, CIDR ranges, or both. `TrustedProxies::loopback_only()`
// covers a same-pod sidecar like Envoy or NGINX.
let trusted = TrustedProxies::from_cidrs(["10.0.0.0/8"])?
    .with_cidrs(["2001:db8::/32"])?;

// Resolve once, outside every route, where the peer is still known.
let app = client_ip::layer(app, trusted);
```

Handlers then take a `ClientIp`, and the audit context takes itself:

```rust,ignore
async fn login_route(session: AuthSession, audit: AuditContext, ip: ClientIp) {
    let service = state.authn.with_audit_context(audit);
    // `ip.get()` where a policy or a key needs the address.
}
```

An empty `TrustedProxies` trusts nothing and always returns the peer,
which is the right default for a service with no proxy in front of it.

The extraction walks `X-Forwarded-For` **from the right**, and the
reason is worth understanding, because the obvious alternative is
broken. The header is append-only: each hop adds the address it saw.
So a client can send its own value and a correctly configured proxy
will faithfully append the real one after it:

```text
client sends:  X-Forwarded-For: 192.0.2.5
proxy appends:                  192.0.2.5, 203.0.113.9
                                ^^^^^^^^^  ^^^^^^^^^^^
                                attacker   real client
```

Reading the leftmost entry hands back whatever the attacker chose,
through a proxy that did its job. So the walk starts at the right,
skips hops that are themselves trusted proxies, and returns the first
address that is not. Everything to the left of that is client-supplied
and discarded.

Two edge cases follow from the same reasoning. A malformed entry stops
the walk and yields the peer, because once one hop's contribution
cannot be read, which hop wrote what is no longer knowable. And if
every entry is a trusted proxy, the request originated inside your
perimeter, so the peer is the answer.

`X-Real-IP` is consulted only when `X-Forwarded-For` is absent. It is a
single value with no chain to audit, so a proxy that forwards a
client-supplied one is indistinguishable from a proxy that set it, and
it is honoured only when exactly one such header line is present. More
than one means something appended rather than overwrote, which makes the
first of them whatever the client sent.

Which kind your proxy is, is worth checking rather than assuming, because
the header is not one a proxy sets by default. nginx sets it only where
the configuration says `proxy_set_header X-Real-IP $remote_addr`; without
that line a client's value passes through. Caddy never sets it at all, so
behind Caddy the value is always the client's. That costs nothing there,
because Caddy does set `X-Forwarded-For` on every proxied request and this
walk prefers it, leaving the `X-Real-IP` branch unreachable. It costs
something behind a proxy that sets neither, or that sets `X-Real-IP` alone:
name that proxy in the trusted set and its forwarded value is believed. If
you cannot say which your proxy does, strip the header at the edge and let
the walk use the chain.

Every `X-Forwarded-For` line is joined before the walk, in order, for the
same reason. RFC 9110 §5.3 makes repeated field lines equivalent to one
comma-joined list, but reading only the first would let a client that
sends its own header, to a proxy that adds a separate line rather than
appending, put the entire walk on ground it controls.

A CIDR with bits set below its prefix is rejected rather than widened.
`10.0.0.5/8` reads like one host and means sixteen million, and this is
the list that decides whose headers are believed; write `10.0.0.0/8` or
`10.0.0.5/32`.

### Getting the address onto the event

Resolving the address is half of it. The event still has to carry it,
and since 0.7.0 that is an extractor rather than something the route
assembles:

```rust,ignore
async fn login_route(session: AuthSession, audit: AuditContext, /* ... */) {
    // The request-scoped handle. Cheap: the collaborators are shared,
    // only the context differs.
    let service = state.authn.with_audit_context(audit);
    service.begin_login(&identifier, tenant, &session).await?;
    service.verify_factor(&credential, &session).await?;
}
```

`AuditContext` reads the address the layer resolved, plus the user-agent,
request id and session id from the request it is already looking at.
There is no argument through which a header-derived address could reach
it.

Both calls go through `service` because there is no other way to make
them. `begin_login` and `verify_factor` are on `RequestAuthnService`, the type
`with_audit_context` returns, and not on the `AuthnService` in
application state. Until 0.7.0 they were on both, and a handler that
derived the handle and then reached back to `state.authn` for
`verify_factor` left the failed-password rows blank, which are the rows a
brute-force query counts.

`RequestAuthnService` derefs to the service, so the application-scoped calls
(`check_session`, the revocation methods, the capability predicates) are
reachable through the one handle.

Derive it per request and let it die with the request. Holding one in
application state pins a single client's address onto every later event,
which is worse than a blank one: the rows look complete.

A blank address is still possible, and still honest, where the client-IP
layer is not installed or the transport has no address to offer. It is
not silent: the row records `ip_source = 'unknown'`, and *Audit events*
has the query that finds them. Where the tenant has an IP policy it is
not merely recorded but refused, because a policy that cannot be
evaluated has not been satisfied.

## Defending against XSS

The cookie's `HttpOnly` attribute defeats one class of XSS attack
(reading the cookie). It does not defeat all of them.

An attacker with JavaScript execution in the page can:

- Submit requests on the user's behalf (the browser sends the
  cookie automatically). The defence is CSRF protection: most
  axess deployments use `tower-http`'s CSRF middleware, which
  requires a CSRF token on state-changing requests, and the
  token is not readable from JavaScript.

- Manipulate the page the user sees to phish credentials or to
  trick the user into actions. The defence is Content Security
  Policy (CSP) headers, which constrain what JavaScript the page
  can load and execute. CSP is an application-side concern, not a
  session-layer concern, but it composes with the session
  layer's defences.

The session layer's role is to constrain the cookie. The
application's role is to constrain what JavaScript can do in the
page. Both layers are needed; the session layer alone does not
defend against XSS.

## CSRF defences

The session cookie is sent on cross-origin top-level navigations
because `SameSite=Lax` allows it. An attacker can craft a link
that, when clicked from an external site, triggers a state change
in the user's session (the classic CSRF attack).

The `SameSite=Lax` default narrows the attack: it works only on
top-level GETs and on the `Form` element, not on XHR or `fetch`
calls. The defences against the remaining surface:

- Use POST (or PUT, DELETE, PATCH) for state-changing requests.
  GET requests should be safe.
- Mount [`axess_core::middleware::csrf::CsrfLayer`] inside the
  session layer. It implements the signed double-submit cookie
  pattern: the token is HMAC-bound to the current session id, so a
  token minted under one session fails validation once the session
  regenerates (on login, MFA add, tenant switch). The middleware
  accepts the token from the `X-CSRF-Token` header (AJAX) or the
  `_csrf` form field (HTML forms: `application/x-www-form-urlencoded`
  only; JS-driven multipart uploads should use the header). Adopters
  who need cross-origin/deferred use cases can layer `tower-http`'s
  middleware instead.
- Enable Origin/Referer validation as defence in depth via
  [`CsrfConfig::require_origin`]. Off by default (would break
  server-to-server bearer-token clients hitting browser routes); on
  when configured, state-changing requests must present an `Origin`
  (or `Referer`-derived) that matches one of the allowed origins,
  AND pass the token check.
- For applications that need cross-origin embedded use,
  `SameSite=None` plus a strict CSRF token check is the
  combination. `SameSite=None` requires `Secure`, so the
  combination is only deployable on HTTPS.

## What goes wrong, and how to tell

Three failure modes recur during initial deployment.

**A cookie the browser refuses to send.** The
symptom is sessions that disappear between requests; the cause is
almost always either `Secure=true` on an `http://` connection
(the browser refuses to send), `SameSite=Strict` on a cross-site
navigation that should have been recognised, or a `Path` that
does not match the request URL. Inspect the cookie's attributes
in the browser's dev tools.

**A fingerprint that diverges for the legitimate user.**
The symptom is a `Warn` log every few sessions or a `Reauth` that
fires on every wifi-to-cellular switch. The cause is usually the
tolerance being too strict; widen the IP prefix or relax the
user-agent match. The right tolerance is the smallest one that
does not produce noise on legitimate traffic.

**A trusted-proxy configuration yielding the wrong IP.**
The symptom is a fingerprint that matches when it should not (an
attacker successfully replaying a cookie), or that diverges when
it should match (a legitimate user being asked to re-authenticate).
The cause is either an unintentionally trusted source (a debug
endpoint left open, a VPN allowed to spoof the header) or an
unintentionally untrusted proxy (the deployment forgot to add a
new proxy's IP to the trusted list).

The pattern across all three: turn on the diagnostic logs, let the
deployment run for a week, look at the warning rate, calibrate.

## Further reading

*Session lifecycle and crypto envelope* covers the cookie shape
and the orchestration that issues it. *Backends* covers the
storage backends that persist the fingerprint alongside the
session. *Security posture* covers the production crypto
requirements that apply to the session layer, including the
signing-key length and the FIPS-routing notes. *Operations
runbook* covers signing-key, envelope-key, and fingerprint-pepper
rotation.
