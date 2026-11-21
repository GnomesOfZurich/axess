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

The session cookie carries five attributes. All default to production values; only `Secure` has to be turned off for development over plain HTTP.

`Path=/` makes the cookie apply to the whole application. A narrower path suits an application embedded under a sub-path of a larger site; most deployments keep the root path.

`HttpOnly` prevents client-side JavaScript from reading the
cookie. It defeats one class of cross-site scripting attack: JavaScript injected into the page cannot read the session cookie through `document.cookie` and exfiltrate it. It is on by default, and there is rarely a reason to turn it off.

`SameSite` controls when the browser sends the cookie on
cross-origin requests. There are three values:

- `Strict` means the cookie is sent only on same-site requests. Following a link from an external site produces a guest request even when the user is logged in; the session is recognised only on navigation from within your site.
- `Lax` (the default) means the cookie is sent on top-level
  cross-site navigations (a link click) but not on cross-site
  sub-requests (an embedded image, an XHR). This defeats most CSRF attacks and still lets a user who follows an external link arrive logged in.
- `None` means the cookie is sent on every cross-site request.
  This is the right setting when the application is embedded in
  iframes on third-party sites; it is the wrong setting otherwise.

The recommendation is `Lax` for most deployments. Switch to
`Strict` (`SessionLayer::with_same_site`) for a deployment whose actions are all high-sensitivity: the attribute is set once, on the one session cookie, so it applies to every route. The cost is that a user who arrives by a cross-site link is not logged in.

`Secure` requires HTTPS. The cookie is sent only on TLS-protected
connections; a misconfigured load balancer that accepts cleartext
HTTP does not see the cookie. The attribute is on by default and required in production. It breaks `localhost` development over `http://`, which is what `SessionLayer::with_secure(false)` is for.

`Max-Age` (the cookie's lifetime in seconds) matches the
session TTL from `SessionLayer::with_ttl`. The browser stops
sending the cookie after the lifetime expires; the server-side
session has its own expiry that the lifecycle layer also enforces.

## HMAC signing

The cookie carries an HMAC signature computed from the session id
under a key derived from the deployment's signing key (an HKDF
sub-key for cookies, so the fingerprint below is keyed apart from it).
The format is:

```text
<base64(session_id)>.<base64(hmac_sha256(cookie_key, session_id))>
```

The signature defeats forgery and tampering. An attacker who guesses a session id, or alters an existing cookie, cannot produce a valid signature without the signing key. The
server rejects any cookie whose signature does not validate; the
session is not loaded and the request proceeds as `Guest`.

The id is the bearer value, and the cookie is the only place it is
kept. Once the signature has verified, the layer hashes the id to the
session's key (`SessionKey`: SHA-256 over a fixed tag and the sixteen id
bytes), and every store, registry, audit record and log line names the
session by that key. Reading the session table, a backup of it or a log therefore yields no value a cookie could carry: forging a cookie needs both the signing key and the id, and the digest does not give the id back.

The HMAC verification is constant-time, and it runs before any store lookup. A rejected cookie
takes the same time however many bytes of its tag were right, so an attacker
cannot recover a valid tag for a chosen id byte by byte by measuring
response latency.

Signing-key rotation replaces the signing key without invalidating active sessions. *Operations runbook* covers the procedure; in short:
`SessionLayer::with_previous_signing_key` accepts the old key, sessions
signed with it continue to validate, and the key passed to
`SessionLayer::new` signs everything new. Once every cookie signed with the old key has expired, remove the previous key.

## The fingerprint binding

The fingerprint catches session replay from a different browser. The layer takes the material a `SessionBinding` reads from the request (the stock binding reads the user agent; nothing in the layer reads the IP address), HMACs it under a key derived
from the signing key, and stores the result on the session. No binding
is configured unless you add one:

```rust,ignore
pub trait SessionBinding: Send + Sync + 'static {
    /// The raw binding material. `None` means the signal is absent for
    /// this request: the session is bound to a fixed "no material" value,
    /// so a replay that does present material fails the binding.
    fn extract(&self, req: &Request<Body>) -> Option<Vec<u8>>;
}

// The one that ships:
let layer = SessionLayer::new(store, signing_key, registry, authn.session_end_audit())
    .with_binding(UserAgentBinding);
```

`UserAgentBinding` returns the `User-Agent` header. The layer
HMAC-SHA256s whatever `extract` returns, keyed with a sub-key derived
from the **session signing key**, and stores the digest on the session.
There is no separate pepper to configure: the signing key is the secret,
which is what stops an attacker who can read session rows out of the
store from recomputing a valid fingerprint.

Because the fingerprint is keyed from the signing key, rotating that key changes every fingerprint, so the layer computes the current-key and previous-key
values together and accepts either during a rotation window.

Implement the trait yourself for anything richer: the user agent
combined with an IP prefix, a TLS channel-binding value, a client hint
your front end sets. The contract is deliberately small: return the raw material; the layer does the keying and the constant-time comparison.

## What a mismatch does

There is no policy to configure and no tolerance to tune. A mismatch makes the request a guest's: the handler runs under a new, empty session and the
response replaces the cookie, so that client is logged out. The stored session is not deleted: the client it is bound to keeps it until it expires or is revoked. The user's other sessions are untouched, because the fingerprint lives on the session, not on the user. The
mismatch is logged at `warn` and counted on the session metrics; it
writes no audit row.

The check is deliberately blunt, so the binding material should not change under a legitimate user.
`User-Agent` qualifies: it survives a network change, a wifi-to-cellular
switch, and a page reload, and it changes on a browser update, which
logs the user out once, at an unsurprising moment. An IP-derived
binding does not qualify on a mobile network, which is why nothing
ships with one.

A request for which the binding yields no material (`extract` returns `None`, for example when the `User-Agent` header is missing) is not skipped. The layer binds the
session to a fixed value that stands for "no material", so a session
that logged in without the header fails the binding on a replay that
sends one, and a bound session fails on a request that omits it. For a softer response, implement your own `SessionBinding`: it decides what material a request yields.

## When the check runs

The fingerprint is recomputed and compared **once per HTTP request**, at
`SessionLayer` entry. It is set at the earliest transition out of
`Guest`: `set_identifying` when the username is submitted,
`begin_authenticating` when a multi-factor flow starts,
`set_authenticated` when authentication completes. So even a pre-MFA
session cannot be replayed from another device. Once set, it is rewritten in one case only: during a rotation, a fingerprint that matched under the previous signing key is rewritten to the value under the current key.

A session past `Guest` that stores no fingerprint (stored before you
turned binding on, or on a path that bound nothing) is bound to the
client of its next request, and checked against that from then on. That request is trusted, since nothing is stored to compare it with; where you can, turn binding on before the sessions you care about exist. There
is no fail-open setting: when binding is configured every request yields
a fingerprint (see above), so there is no request it cannot be checked
against.

The check runs once per request and at no other time, which leaves a gap for persistent connections. A WebSocket or an SSE stream is checked at the upgrade and
never again, so a connection that outlives the binding's validity is
not re-examined. Where that matters, re-check on the messages
themselves rather than relying on the layer.

## Reading the client IP

Nothing in the session layer reads a forwarded header, because nothing
in the default binding uses the IP. Your own code does, though: a
Cedar policy conditioned on `ip_address`, a rate-limit key, an audit row.
That is where the spoofing risk lives. Resolve the address once with `client_ip::layer` and read `ClientIp` everywhere, rather than letting each consumer work it out.

Reading `X-Real-IP`, or the first entry of `X-Forwarded-For`, means
taking a value **any client can set**. Doing that on an
internet-facing service means an attacker chooses the IP your
policies see. axess has no function that reads either header without
checking the peer: `client_ip::layer` believes a forwarded value only
from a peer your `TrustedProxies` trusts.

The same applies to your audit trail, and there it matters more.
`AuditContext` takes no address as an argument. It reads the `ClientIp`
in the request's extensions: the one `client_ip::layer` resolved, or one
your own middleware inserted with `ClientIp::resolved` for an address
axess cannot check (its `ip_source` then reads `supplied`). A route with
neither records none. A null `ip_address` is honest and a forged one is
not.

A failed audit write fails the login, so those rows are guaranteed to exist; a forged address in them is evidence written by the subject of the evidence.

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

Handlers then take a `ClientIp` and an `AuditContext`, which reads the resolved address itself:

```rust,ignore
async fn login_route(session: AuthSession, audit: AuditContext, ip: ClientIp) {
    let service = state.authn.with_audit_context(audit);
    // `ip.get()` where a policy or a key needs the address.
}
```

An empty `TrustedProxies` trusts nothing and always returns the peer,
which is the right default for a service with no proxy in front of it.

The extraction walks `X-Forwarded-For` **from the right**, because the obvious alternative, reading from the left, is broken. The header is append-only: each hop adds the address it saw.
A client can therefore send its own value, and a correctly configured proxy appends the real one after it:

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

`X-Real-IP` is not read unless you assert, with
`TrustedProxies::proxy_overwrites_real_ip`, that the proxy in front
overwrites it, and even then only when `X-Forwarded-For` is absent.
Without the assertion the peer is the answer. It is a single value with
no chain to audit, so a proxy that forwards a client-supplied one is
indistinguishable from a proxy that set it, and it is honoured only when
exactly one such header line is present. More than one means something
appended rather than overwrote, which makes the first of them whatever
the client sent.

Check which kind your proxy is before making the assertion: a proxy does not set this header by default. nginx sets it only where
the configuration says `proxy_set_header X-Real-IP $remote_addr`; without
that line a client's value passes through. Caddy never sets it at all, so
behind Caddy the value is always the client's. That costs nothing there,
because Caddy does set `X-Forwarded-For` on every proxied request and this
walk prefers it, leaving the `X-Real-IP` branch unreachable. It costs
something behind a proxy that sets no `X-Forwarded-For` and passes a
client's `X-Real-IP` through: assert `proxy_overwrites_real_ip` for it and
the client's value is believed. If you cannot say which your proxy does,
leave the assertion off, and configure the proxy to set `X-Forwarded-For`
so the walk can use the chain.

Every `X-Forwarded-For` line is joined before the walk, in order, for the
same reason. RFC 9110 §5.3 makes repeated field lines equivalent to one comma-joined list. Reading only the first line would put the whole walk on ground the client controls: the client sends its own header, and a proxy that adds a separate line rather than appending leaves that header first.

A CIDR with bits set below its prefix is rejected rather than widened.
`10.0.0.5/8` reads like one host and means sixteen million, and this is
the list that decides whose headers are believed; write `10.0.0.0/8` or
`10.0.0.5/32`.

### Getting the address onto the event

Resolving the address is half the work. The event still has to carry it, and an extractor does that, not the route:

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
application state. Were they on both, a handler that derived the handle and then reached back to `state.authn` for `verify_factor` would leave the address blank on the failed-password rows, the rows a brute-force query counts.

`RequestAuthnService` derefs to the service, so the application-scoped calls
(`check_session`, the revocation methods, the capability predicates) are
reachable through the one handle.

Derive it per request and let it die with the request. Holding one in
application state pins a single client's address onto every later event,
which is worse than a blank one: the rows look complete.

A blank address is still possible, and still honest, where the client-IP
layer is not installed or the transport has no address to offer. It is
not silent: the row records `ip_source = 'unknown'`, and *Audit events*
has the query that finds them. Where the tenant has an IP policy, such a request is refused, not only recorded: a policy that cannot be evaluated has not been satisfied.

## Defending against XSS

The cookie's `HttpOnly` attribute defeats one class of XSS attack
(reading the cookie). It does not defeat all of them.

An attacker with JavaScript execution in the page can:

- Submit requests on the user's behalf (the browser sends the
  cookie automatically). The defence against a request forged from
  another site is CSRF protection (`CsrfLayer`, below), which requires
  a token on state-changing requests. Script running in your own page
  can read that token and send it, so against XSS itself the defence
  is the next one.

- Manipulate the page the user sees to phish credentials or to
  trick the user into actions. The defence is Content Security
  Policy (CSP) headers, which constrain what JavaScript the page
  can load and execute. CSP belongs to the application, not the session layer, but it composes with the session layer's defences.

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
top-level navigations that use GET (a link, or a form with
`method="get"`), not on a cross-site POST form, XHR or `fetch`
call. The defences against the remaining surface:

- Use POST (or PUT, DELETE, PATCH) for state-changing requests.
  GET requests should be safe.
- Mount [`axess_core::middleware::csrf::CsrfLayer`] inside the
  session layer. It implements the signed double-submit cookie
  pattern: the token is HMAC-bound to the current session's key (the
  digest of its id that names it in the store), so a token minted under
  one session fails validation once the session regenerates (at login and step-up,
  and wherever the application rotates it: a factor added, a password
  changed, a tenant switched). The middleware
  accepts the token from the `X-CSRF-Token` header (AJAX) or the
  `_csrf` form field (HTML forms: `application/x-www-form-urlencoded`
  only; JS-driven multipart uploads should use the header). Adopters with cross-origin or deferred use cases layer their own CSRF middleware instead.
- Enable Origin/Referer validation as defence in depth via
  [`CsrfConfig::require_origin`]. It is off by default, because it would break server-to-server bearer-token clients that call browser routes. When it is on, a state-changing request must present an `Origin` (or one derived from `Referer`) that matches an allowed origin, and must also pass the token check.
- An application embedded cross-origin needs `SameSite=None` and a strict CSRF token check. `SameSite=None` requires `Secure`, so the combination works only over HTTPS.

## What goes wrong, and how to tell

Three failure modes recur during initial deployment.

**A cookie the browser refuses to send.** The
symptom is sessions that disappear between requests; the cause is almost always `Secure=true` on an `http://` connection, `SameSite=Strict` on a cross-site
navigation that should have been recognised, or a `Path` that
does not match the request URL. Inspect the cookie's attributes
in the browser's dev tools.

**A fingerprint that diverges for the legitimate user.**
The symptom is users logged out with a `session fingerprint mismatch`
line at `warn` and a rising binding-mismatch count. There is no
tolerance to widen: the comparison is exact. The cause is binding
material that changes under a legitimate user, which the stock
`UserAgentBinding` does only on a browser update. A `SessionBinding` of
your own that reads an address, or a header a proxy rewrites, diverges
on every network change; return material that is stable for one client,
or bucket it yourself before returning it.

**A trusted-proxy configuration yielding the wrong IP.**
The symptom is audit rows, rate-limit keys and IP policies that see the
proxy's address, or an address the client chose. The session layer's
stock binding does not read the address, so the session itself is not
affected unless your own `SessionBinding` reads `ClientIp`. The cause is either a source trusted by mistake (a debug endpoint left open, a VPN allowed to spoof the header) or a proxy missing from the trusted list (a new proxy's IP never added).

For all three: turn on the diagnostic logs, run the deployment for a week, read the warning rate, and fix the configuration the lines point at.

## Further reading

*Session lifecycle and crypto envelope* covers the cookie shape
and the orchestration that issues it. *Backends* covers the
storage backends that persist the fingerprint alongside the
session. *Security posture* covers the production crypto
requirements that apply to the session layer, including the
signing-key length and the FIPS-routing notes. *Operations runbook* covers signing-key and envelope-key rotation. The session fingerprint has no pepper of its own and rotates with the signing key; the per-tenant pepper the runbook describes belongs to the device fingerprint.
