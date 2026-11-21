# Rate limiting

A rate limiter caps how many requests an identified caller may make per unit
time. On an authentication surface it is a central layer of defence in depth:
the lockout policy catches failed credentials against one account, and the
rate limiter catches brute force and credential stuffing spread across many
accounts. This chapter covers the `RateLimitLayer` Tower
middleware, the key-extraction strategies that determine what is
rate-limited, the tuning patterns for different endpoints, and the
SLI signal the layer produces.

## Why rate limiting matters

The lockout policy in *Multi-tenancy* catches one specific
pattern: many failures against one identifier. A rate limiter
catches a wider pattern: a high volume of requests against an
endpoint, regardless of identifier, regardless of success.

The rate limiter catches these attacks:

Credential stuffing. An attacker with a list of credentials tries
each one against the login endpoint. Each individual attempt fails
on its own credentials (no lockout against any single user), but
the aggregate rate is far above legitimate traffic. The rate
limiter on the login endpoint, keyed by source IP, drops the
attack to a trickle.

Account-existence enumeration. An attacker probes the signup
endpoint to find which usernames are taken. Each request might
succeed (the username is unique) or fail (the username is taken),
and the response leaks the information. The rate limiter caps the
enumeration rate; combined with response-shaping (return the same
shape for both cases), the attack becomes impractical.

Token-replay forwarding. An attacker who has captured a valid
session cookie forwards it through many connections to evade
fingerprint detection. Each request looks legitimate on its own;
the aggregate volume is the giveaway. A rate limiter keyed by
user (`UserId`) catches the pattern.

Workload misbehaviour. A workload caught in a tight loop calls the API over
and over. Authentication validates its token on every request, and the rate
limiter stops the loop before it overwhelms the service.

## Configuring the limiter

What to install, what it counts requests against, and how to size it.

### The layer

`RateLimitLayer` is a Tower layer with a small configuration:

```rust,ignore
use axess::{RateLimitLayer, RateLimitConfig, KeyExtractor};
use std::time::Duration;

let layer = RateLimitLayer::new(
    RateLimitConfig::builder()
        .max_requests(10)
        .window(Duration::from_secs(60))
        .key(KeyExtractor::PeerIp)
        .build(),
);
```

The configuration says "no more than ten requests per minute,
keyed by the peer IP." The layer counts requests against each
distinct peer IP; when a key has hit the limit within the window,
subsequent requests get a 429 (`Too Many Requests`) with a
`Retry-After` header.

The window is a sliding-window counter. Each key keeps the number of
requests admitted in the current fixed window and in the one before it. A
request is admitted when the previous count, weighted by how much of it still
overlaps the trailing window, plus the current count leaves room under
`max_requests`. A burst that straddles a window boundary therefore gets no second allowance: with a limit of five per minute, five requests at the end of one minute
are followed by a refusal, not by five more at the start of the next, and the
allowance comes back gradually as the old requests age out. `Retry-After` is
the number of whole seconds until the request would be admitted.

Keys are bounded so no one caller controls how many buckets exist. Every
key starts with its kind (`ip:`, `user:`, `login:`), so a value a caller
chooses, such as a login name, can never equal a sentinel or another kind's
key. A key longer than 187 bytes is cut to a fixed 256 bytes ending in a
digest of the whole, so long identifiers that share a prefix keep separate
buckets and no uncut key can be crafted to equal a cut one. An IPv6 client is
keyed by its /64 prefix. An address that carries an IPv4 client (NAT64
`64:ff9b::/96`, IPv4-translated, IPv4-compatible, 6to4 or Teredo) is keyed and
grouped as that IPv4 client, as the login throttle keys it, so each client
behind one translator or relay has its own bucket. An address under the locally
used NAT64 prefix (`64:ff9b:1::/48`) is keyed whole. `KeyExtractor::Header` maps a user's header
values onto 16 sub-buckets, so one authenticated user cannot fill the table by
sending distinct values. An authenticated user who sends no header, or one that
is not text, holds one further fixed slot of their own; a request with no
authenticated user is keyed on its peer address.

A request that lacks the identity a `UserId`, `TenantId` or `LoginIdentifier`
limiter reads (the layer that inserts it is missing or runs after the limiter)
is answered 500, and the limiter logs an error at most once a minute per worker
thread. A limiter that cannot read a peer address (`PeerIp` without
`into_make_service_with_connect_info`) answers 500 too, and logs an error at
most once a second per worker thread. Both are wiring mistakes, and a limiter
that guessed a bucket for them would either charge everyone to one budget or
quietly stop limiting. `allow_shared_bucket()` on the config builder is the
named opt-out: a request without the identity is keyed on its own peer address
under an `anon:` prefix, and a request without a peer address goes to one
`ip:unknown` bucket (so one client can exhaust the limit for all). `ClientIp`
without `client_ip::layer` still shares one bucket and logs a warning.

A /64 per client still leaves one IPv6 allocation able to mint 65,536 buckets
in a /48. Each IPv4 /24 and IPv6 /48 therefore holds at most 1,024 live
buckets; a further client of that prefix shares the prefix's overflow bucket
and is limited together with the other overflow clients. The prefix budget is
a fixed constant. A very large site (a university behind one /48) can be
squeezed into the overflow bucket by its own scale; where that matters, key on
something the site controls (`UserId`) instead of its address. The budget does
not stop an attacker who holds many separate /48s (an IPv6 /40 holds 256 of
them, and 256 full budgets of 1,024 buckets are exactly the hard cap of
262,144 buckets), so once the table is
three quarters full a new address folds into its prefix's overflow bucket
instead of taking a slot, and a client in an unrelated prefix is still
admitted. The hard cap stays as the last bound.

Login identifiers are minted by unauthenticated callers, so once the table is
three quarters full a new identifier folds into one of 1,024 overflow
buckets, picked by a digest of the identifier, instead of taking a slot.
The bucket depends on the identifier alone, never on where the request came
from, so every origin that names one account draws on the same budget and
the limiter works the same with or without `client_ip::layer`. Identifiers
that already have a bucket keep it.
The overflow buckets are shared by every origin, so an attacker who fills the
table and then drains them limits new identifiers for everyone: that is the
cap's own alarm, and the signal to raise the cap or find the source.

The debug log for a refused request carries a short fingerprint of the key,
not the key. It is an HMAC under a random key drawn when the layer is built
(from the `SecureRng` given to the builder, the system generator by default),
so a log line cannot be matched against a dictionary of email addresses, and
two layer instances fingerprint the same key differently.

The remaining-requests header (`x-ratelimit-remaining`) is sent only when the
bucket belongs to the caller (an address, a user, a header slot). A
login-identifier, tenant or shared bucket is drawn on by other people, and its
remaining count would tell the caller how many attempts other people made, so it is
left out; so is the count of a group's overflow bucket, which an address draws
on once its /24 or /48 holds its budget of buckets.

A clock that steps backwards does not strand buckets: a bucket whose window
starts in the future is re-anchored at the next sweep and ages out two windows
later.

The buckets live in this process, in a `Mutex<HashMap>`, and there is no
option to put them anywhere else. That is a deliberate scope
line rather than a missing backend: with N instances behind a load
balancer, each one enforces the configured limit independently, so a caller that
spreads its requests across them gets N times the configured budget.

Distributed rate limiting belongs at the gateway, against a shared
store (Valkey, Redis, or whatever your ingress already offers). Use
this layer for the per-process defence: the burst that would exhaust a
connection pool, the per-username budget that keeps a lockout attack
from succeeding. Set the volumetric limit upstream.

### Key extraction

The key is what the rate limiter counts against. The
`KeyExtractor` enum carries the choices:

```rust,ignore
pub enum KeyExtractor {
    ClientIp,          // what client_ip::layer resolved. Behind a proxy.
    PeerIp,            // SocketAddr from ConnectInfo. The default.
    UserId,            // RateLimitUserId request extension
    TenantId,          // RateLimitTenantId request extension
    LoginIdentifier,   // RateLimitLoginIdentifier request extension
    Header(String),    // an arbitrary header, e.g. an API key
}
```

The three extension-backed variants read a value you put
into the request extensions, which is what makes them composable with
any authentication scheme: axess does not need to know how you
established the user, only that you named it. Set the extension in a
layer that runs before the rate limiter.

There is no custom-closure variant and no composite. One limiter keys
on one thing; layering two concerns means stacking two
`RateLimitLayer`s, which is also what makes each one's configured
budget legible on its own.

The choice of key determines which attack the limiter catches.
`PeerIp` catches single-source volumetric attacks and is right where
nothing sits in front of you. `ClientIp` is the one to use behind a
proxy: it reads the address `client_ip::layer` resolved and consults no
header, so a caller cannot pick its own bucket.

Configuring that layer means naming the proxies you trust, and usually
you can: managed front ends publish their ranges, and a sidecar is
loopback. The list can be the weak link: a rotating range has to be kept in sync, and a
stale one quietly resolves every request to the proxy. In that case,
`TrustedProxies::private_transport()` asserts a different fact: nothing
reaches this process except through your own infrastructure. That assertion does not go stale. It is the
weaker of the two, and a direct caller reaching a process configured that
way has its headers believed in full, so check that the listener is not
reachable rather than assuming it. No extractor reads `X-Real-IP` or the
leftmost `X-Forwarded-For` entry and believes it: rotating either would
mint a fresh bucket per request.

`UserId` catches a per-user runaway loop, `TenantId` a
per-tenant one, which is as often a noisy neighbour as an attack.

`LoginIdentifier` needs the most care. Per-IP limiting alone does
not defend a login route: an attacker spreading attempts across many
IPs stays under every per-IP budget while hammering one username, and
with a lockout policy in place that is a denial of service against that
account rather than a break-in attempt. Keying on the submitted
identifier bounds the attempts per account, wherever they come from. The
identifier is normalised (Unicode NFKC, lowercase, zero-width and other
invisible format characters removed), so `Alice`, `alice` and a spelling with a
hidden character share a bucket. A store may fold more than that (a case-insensitive
collation, a dotted local part), so where it does, add a second limiter on the
resolved user id.

In a multi-tenant application build the extension with
`RateLimitLoginIdentifier::new_in_tenant`: the same address in two tenants is
then two buckets, and repeated logins naming `ceo@victim.com` against another
tenant cannot exhaust the victim tenant's budget. `new` keys on the identifier
alone and is for single-tenant applications. Put a `LoginIdentifier` limiter on every login-class route, and
layer a `PeerIp` one beside it for the volumetric case.

The extension has to be on the request when the limiter reads it, and a
handler runs after every layer around it, so a login handler that "injects the
identifier" sets it too late: every login would fall into the one shared
anonymous bucket. Put the injector in a layer outside the limiter.
`inject_login_identifier` buffers the body (up to a limit you give, `413`
beyond it), calls your parser on it, inserts the `RateLimitLoginIdentifier` and
returns a request with the same body. Layers added later wrap earlier ones, so
it goes last:

```rust,ignore
// ignore: the book compiles no crate; the same wiring is a doc test on
// `inject_login_identifier`.
use axess_core::middleware::ratelimit::{
    KeyExtractor, RateLimitConfig, RateLimitLayer, RateLimitLoginIdentifier,
    inject_login_identifier,
};
use axum::{
    body::Body, http::Request, middleware::{from_fn, Next}, response::IntoResponse,
    routing::post,
};
use std::time::Duration;

fn username_of_form(body: &[u8]) -> Option<RateLimitLoginIdentifier> {
    let (_, name) = url::form_urlencoded::parse(body).find(|(key, _)| key == "username")?;
    RateLimitLoginIdentifier::new(name)
}

# async fn login_handler() {}
let per_username = RateLimitLayer::new(
    RateLimitConfig::builder()
        .max_requests(10)
        .window(Duration::from_secs(60))
        .key(KeyExtractor::LoginIdentifier)
        .build(),
);
let login_route: axum::Router = axum::Router::new()
    .route("/login", post(login_handler))
    .layer(per_username)
    .layer(from_fn(|request: Request<Body>, next: Next| async move {
        match inject_login_identifier(request, 16 * 1024, username_of_form).await {
            Ok(request) => next.run(request).await,
            Err(status) => status.into_response(),
        }
    }));
```

### Per-endpoint rate limits

Different endpoints have different sensitivities. A login
endpoint needs only a few requests per minute per IP, because
real users do not log in often; a search endpoint accepts hundreds
per second because real users browse. Limits are therefore usually set per endpoint:

```rust,ignore
let auth_routes = Router::new()
    .route("/login", post(login))
    .route("/signup", post(signup))
    .route("/reset-password", post(reset_password))
    .layer(RateLimitLayer::new(
        RateLimitConfig::builder()
            .max_requests(10)
            .window(Duration::from_secs(60))
            .key(KeyExtractor::PeerIp)
            .build(),
    ));

let api_routes = Router::new()
    .route("/data", get(get_data))
    .layer(RateLimitLayer::new(
        RateLimitConfig::builder()
            .max_requests(300)
            .window(Duration::from_secs(60))
            .key(KeyExtractor::UserId) // reads RateLimitUserId, set by your auth layer
            .build(),
    ));

let app = Router::new()
    .merge(auth_routes)
    .merge(api_routes)
    .layer(session_layer);
```

Layer each limit on the routes it applies to, with the tightest limits on the
most sensitive endpoints: a tight per-IP limit on login, a per-user limit on
token refresh.

The trusted-proxy configuration covered in *Cookies, fingerprinting,
hijack detection* applies to the `ClientIp` extractor here as well.
`client_ip::layer` reads the IP from the forwarded header only when the
immediate peer is a trusted proxy; otherwise the rate limiter could be
spoofed.

#### The IdP logout routes

The back-channel logout route is unauthenticated: it reads the issuer out of
the token before any signature is checked, and with tenant providers each
request that names a configured issuer costs a read of the tenant source and
may rebuild or revalidate the providers it returns. Put a `PeerIp` limit in
front of it, as in front of the front-channel route, and keep it low: an IdP
sends a few tokens a minute, from a few addresses. The handler remembers, for 30 seconds, an
issuer that no provider is configured for
(`BackChannelLogoutHandler::with_unknown_issuer_memory`), which bounds a loop
of made-up issuers; only the limit bounds a loop that names a real one.

### Per-tenant rate limits

For multi-tenant deployments, the rate limit configuration can
be per-tenant. A tenant with a higher SLA gets a higher rate
limit; a tenant with a lower SLA gets a tighter one. There is
no composite key, so the mechanism is stacking: a `TenantId`
limiter (it reads the `RateLimitTenantId` extension) caps each
tenant beside the per-address `PeerIp` or `ClientIp` limiter.
One layer has one `RateLimitConfig`, so each tenant tier needs its
own `TenantId` layer, on routes that serve only that tier.

The pattern is operationally complex (one configuration per
tenant tier), so most deployments use a single shared limit and
calibrate to the deployment-wide envelope. The per-tenant shape
is for deployments where the SLA differences are explicit and
the operational overhead is justified.

### Tuning the windows

No single setting fits every deployment; these are starting points.

For login endpoints: 10 requests per minute per IP is the
conservative starting point. Real users log in at most a few
times a day from any one IP. Credential-stuffing attacks need
hundreds per minute to be efficient; 10 is well below that.
Tune up only if the reject rate is too high on legitimate traffic
(many users behind a corporate NAT, for instance).

For signup endpoints: 5 requests per minute per IP. Signup is
even less frequent for legitimate users than login, and account enumeration
calls for a tight limit.

For password reset: 3 requests per hour per IP. A reset is a
once-in-a-while operation. Attackers spam reset to exhaust the
victim's inbox; the tight limit is the defence.

For token refresh: matched to the session TTL. A session that
refreshes every hour should have a rate limit of a few refreshes
per hour per user (`UserId`); an attacker who steals a session cannot
extract value through rapid refresh.

For data endpoints: matched to your expected use
pattern. An API for human-driven dashboards sees a few requests
per minute per user; an API for programmatic clients sees
hundreds per second per workload.

Measure first. `RequestGuardMetrics::rate_limit_rejected` (covered below)
gives the real reject rate; then set the limit just above the
legitimate-traffic envelope.

## Behaviour at the limit

What a rejected caller sees, and how to read a spike.

### What happens at the limit

A request that hits the rate limit gets:

A 429 status code. The standard HTTP response for "Too Many
Requests."

A `Retry-After` header. The value is the number of seconds the
client should wait before retrying. The header is read by
browsers and well-behaved clients; attackers ignore it.

An empty body, and no `x-ratelimit-remaining` header. That header
goes only on admitted responses, and only from a bucket the caller
owns (see *The layer* above).

The rejection is recorded through `RequestGuardMetrics::rate_limit_rejected`,
which the application wires to its Prometheus or OpenTelemetry counter.

### Distinguishing attack from misconfiguration

A high rate of 429s has one of two causes: an attack being throttled, or a
limit set too low for legitimate traffic.

The signals that distinguish them:

A rate of 429s heavily concentrated on a small set of source IPs,
with the IPs not matching legitimate user patterns (datacenter
IPs, VPN exit nodes, residential ASNs from countries the
application does not typically serve) suggests attack.

A rate of 429s spread across many IPs, matching legitimate user
patterns (residential ASNs from served countries, mixed mobile
and home connections), suggests misconfiguration.

The rate limiter emits no audit event. It rejects the request and
returns, and nothing reaches the audit trail, so distinguishing these
patterns means logging the rejection yourself with the source IP and
the endpoint at the point you install the middleware.

### Composing with the lockout policy

The rate limiter and the lockout policy compose: the rate limiter catches
volume, and the lockout policy catches repeated failures against one account.

Against credential stuffing, the rate limiter is the first line of defence. It drops the attack to a
trickle before any individual user's lockout policy can fire.
The lockout policy then catches the few attempts that get
through, marking the targeted user accounts as locked.

A deployment that has rate limiting but no lockout policy is
vulnerable to slow attacks that stay below the rate limit. A
deployment that has lockout but no rate limiting is vulnerable
to high-volume attacks that distribute across many users. Together they cover both attack shapes.

## Operating it

What to watch, and where the limiter sits relative to everything else.

### Metrics

The layer emits two metrics through `RequestGuardMetrics`, attached
with `RateLimitLayer::with_metrics(MetricSinks)`:

`rate_limit_rejected` is incremented on each 429. The metric is
the primary signal for tuning and for attack detection.

`rate_limit_allowed` is incremented on every request the layer lets
through. The ratio of rejected to the sum of both is the reject
rate; below 0.1% typically means the limit is set well, above 1%
suggests either attack or misconfiguration.

The metric implementation is yours (see
[Observability and metrics](observability.md)); it
typically routes to Prometheus, OpenTelemetry, or whatever
metrics system the deployment uses. The
[`examples/sqlite/`](https://github.com/GnomesOfZurich/axess/tree/main/examples/sqlite)
reference application shows a simple `AtomicU64`-based
implementation suitable for adapting to a real metrics system.

### Where the limiter sits in the stack

The rate limiter runs before the authentication logic. Without it, a
deployment is exposed to volume-based attacks that the authentication logic
alone cannot prevent; with it, that volume defence complements lockout.

## Further reading

*Multi-tenancy* covers the lockout policy that pairs with the
rate limit. *Audit events* covers the trail the rate limiter does not
write to. *Cookies, fingerprinting, hijack
detection* covers the trusted-proxy configuration that
determines how `ClientIp` reads the source IP. *Operations
runbook* covers the metrics dashboards and the SIEM rules that
turn the rate-limit signal into alerts.
