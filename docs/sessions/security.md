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
`SessionLayer::with_previous_key` accepts the old key, sessions
signed with the old key continue to validate, sessions signed
with the new key (which is now what the layer uses for new
signings) are the new default. After enough time for all old
cookies to expire, the previous key is removed.

## The fingerprint binding

The fingerprint is the additional signal that catches session
replay from a different browser. The mechanism takes a few coarse
features of the request (the user agent, the IP address, sometimes
the accept-language), HMACs them together with a deployment-level
pepper, and stores the result alongside the session.

```rust,ignore
let fingerprint = hmac_sha256(
    fingerprint_pepper,
    format!("{}|{}|{}",
        user_agent,
        client_ip,
        accept_language,
    ),
);
```

The choice of features is deliberate. They are coarse enough that
the legitimate user's browser produces the same fingerprint across
ordinary requests (the user agent does not change between requests,
the IP is within the same prefix, the accept-language is stable),
and specific enough that an attacker replaying the cookie from a
different machine produces a different fingerprint.

The tolerance is the operational lever. Strict matching produces
too many false positives (a user switching from wifi to cellular
sees their IP change, a browser auto-update changes the user
agent string). Coarse matching produces too few signals to detect
replay. The default tolerance:

- IP: same /24 for IPv4, same /64 for IPv6.
- User agent: same major version of the same browser.
- Accept-language: same primary language.

A request that matches within the tolerance passes. A request
that diverges beyond it produces an event the policy decides what
to do with.

The policy has three options:

- `FingerprintPolicy::Warn` logs the mismatch and lets the
  request proceed. This is the right setting during initial
  rollout when the tolerance is being calibrated; the logs show
  how often legitimate users trigger mismatches, and the tolerance
  can be adjusted.

- `FingerprintPolicy::Reauth` returns 401 and clears the session.
  The user has to log in again. This is the right setting for
  high-sensitivity actions; the user accepts the friction of
  re-authentication in exchange for the assurance that a captured
  cookie does not get away with the session.

- `FingerprintPolicy::Revoke` deletes the session entirely. The
  user is logged out, and their other sessions remain. This is
  the right setting when fingerprint mismatch is a strong signal
  of compromise; the deployment treats it as the user being
  hijacked and ends the session immediately.

The default is `Warn`. Lift to `Reauth` once the warn rate is
below your tolerance.

The pepper is a deployment-level secret stored alongside the
session signing key. It defeats fingerprint synthesis: an attacker
who knows the features (the user's IP, their user agent) cannot
construct the fingerprint without the pepper, so they cannot
adjust their replay to match.

## Trusted-proxy configuration

The fingerprint depends on the request's IP being accurate. In
many deployments the application sits behind one or more proxies
(a load balancer, a CDN, a WAF), and the request's source IP is
the proxy's IP, not the user's. The user's IP is in a forwarded
header like `X-Forwarded-For`.

Reading the forwarded header is necessary but dangerous. A
deployment that trusts the header without checking the source can
be spoofed: a request directly to the application with a forged
`X-Forwarded-For` header will be treated as if it came through
the proxy.

The defence is the trusted-proxy configuration. The application
configures which source IPs are trusted to set the header; the
session layer reads the header only when the immediate request
came from one of those IPs.

```rust,ignore
let layer = SessionLayer::new(store, signing_key)
    .with_trusted_proxies(vec![
        "10.0.0.0/8".parse().unwrap(),    // internal load balancer
        "172.16.0.0/12".parse().unwrap(), // VPN range
    ])
    .with_forwarded_header(ForwardedHeader::XForwardedFor);
```

The configuration accepts a list of CIDR ranges that the
deployment trusts. Requests from inside any range have their
`X-Forwarded-For` read; requests from outside any range use the
immediate connection's IP.

The forwarded-header choice is the application's. The standard is
`X-Forwarded-For` (a comma-separated list of IPs, the first being
the original client), but some deployments use `Forwarded` (RFC
7239) or a proxy-specific header. Axess supports all three;
configure the one the deployment uses.

For multi-hop proxy chains, the rule is the same. The request
came through `lb → cdn → application`; the application's immediate
peer is the CDN, the CDN's `X-Forwarded-For` lists `lb` and the
original client. If both the CDN and the LB are in trusted ranges,
the application takes the leftmost IP from the header (the
original client). If only the immediate peer is trusted, the
application takes the rightmost IP from the header (the next hop
back).

The configuration is deployment-specific. Get it wrong in either
direction (trust too much, get spoofed; trust too little, see only
proxy IPs) and the fingerprint binding becomes either fragile or
useless.

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
- Add a CSRF token to state-changing forms. The token is set in
  the session and read from a hidden form field; the server
  checks that they match. Axess does not include a CSRF middleware
  out of the box; the convention is to use `tower-http`'s
  middleware or to write a small one.
- For applications that need cross-origin embedded use,
  `SameSite=None` plus a strict CSRF token check is the
  combination. `SameSite=None` requires `Secure`, so the
  combination is only deployable on HTTPS.

## What goes wrong, and how to tell

Three failure modes recur during initial deployment.

The first is a cookie that the browser refuses to send. The
symptom is sessions that disappear between requests; the cause is
almost always either `Secure=true` on an `http://` connection
(the browser refuses to send), `SameSite=Strict` on a cross-site
navigation that should have been recognised, or a `Path` that
does not match the request URL. Inspect the cookie's attributes
in the browser's dev tools.

The second is a fingerprint that diverges for the legitimate user.
The symptom is a `Warn` log every few sessions or a `Reauth` that
fires on every wifi-to-cellular switch. The cause is usually the
tolerance being too strict; widen the IP prefix or relax the
user-agent match. The right tolerance is the smallest one that
does not produce noise on legitimate traffic.

The third is the trusted-proxy configuration getting the wrong IP.
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
