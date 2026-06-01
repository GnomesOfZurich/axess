# Rate limiting

A rate limiter is the layer that caps how many requests an
identified caller may make per unit time. For an authentication
surface, the rate limiter is one of the most consequential pieces
of operational defence in depth: the lockout policy catches the
specific case of failed credentials, but the rate limiter catches
the broader case of brute-force and credential-stuffing
distribution. This chapter covers the `RateLimitLayer` Tower
middleware, the key-extraction strategies that determine what is
rate-limited, the tuning patterns for different endpoints, and the
SLI signal the layer produces.

## Why rate limiting matters

The lockout policy in *Multi-tenancy* catches one specific
pattern: many failures against one identifier. A rate limiter
catches a wider pattern: a high volume of requests against an
endpoint, regardless of identifier, regardless of success.

The shapes of attack the rate limiter catches:

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
the aggregate volume is the giveaway. The rate limiter keyed by
session id catches the pattern.

Workload misbehaviour. A workload that for some reason has
entered a tight loop calling the application's API. The
authentication side validates the workload token on each request;
the rate limiter catches the runaway pattern before it overwhelms
the service.

## The layer

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

The window is a sliding token bucket. The math: each key has a
bucket of `max_requests` tokens; each request consumes one;
tokens regenerate at a rate of `max_requests` per `window`. A
burst of more than `max_requests` requests within a short
interval consumes all the tokens; subsequent requests are
rejected until enough tokens have regenerated.

The state of the buckets lives in memory by default
(`BucketStore::InMemory`). For multi-instance deployments where
the same caller can reach any instance, the rate limit needs to
be aggregated across instances; `BucketStore::Valkey { client }`
shifts the state to a shared Valkey instance.

## Key extraction

The key is what the rate limiter counts against. The
`KeyExtractor` enum carries the choices:

```rust,ignore
pub enum KeyExtractor {
    PeerIp,                              // request source IP (read through trusted-proxy)
    SessionId,                           // present session id
    UserId,                              // authenticated user
    TenantId,                            // authenticated tenant
    WorkloadId,                          // authenticated workload
    Custom(Arc<dyn KeyExtractorFn>),     // application-supplied
    Composite(Vec<KeyExtractor>),        // multi-key (one bucket per combination)
}
```

The choice of key determines which attack the limiter catches.
`PeerIp` catches single-source attacks; `SessionId` catches
session-replay attacks; `UserId` catches per-user runaway loops;
`TenantId` catches per-tenant runaway (which can be a noisy
neighbour rather than an attack).

The `Composite` choice creates one bucket per combination of
the named keys. A rate limit keyed by `(PeerIp, UserId)` lets a
single legitimate user from one IP do their normal work while
catching a single attacker IP that is rotating through many
users (the composite key is unique per `(ip, user)` pair, so the
attacker exhausts each pair's bucket once per user, but the
total request rate stays bounded).

The `Custom` choice is the escape hatch for keys axess does not
know about: the OAuth client id, a custom request header, the
authenticated session's tenant slug. The application provides
the extraction function; the layer uses it to derive the key.

## Per-endpoint rate limits

Different endpoints have different sensitivities. A login
endpoint can tolerate a few requests per second per IP because
real users do not log in fast; a search endpoint accepts hundreds
per second because real users browse. The configuration shape is
typically per-endpoint:

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
            .key(KeyExtractor::SessionId)
            .build(),
    ));

let app = Router::new()
    .merge(auth_routes)
    .merge(api_routes)
    .layer(session_layer);
```

The pattern is to layer the rate limit on the specific routes it
applies to, with the most restrictive limits on the most
sensitive endpoints. A login endpoint with a tight per-IP limit
is the canonical case; a token-refresh endpoint with a
per-session limit is the second canonical case.

The trusted-proxy configuration covered in *Cookies, fingerprinting,
hijack detection* applies to the `PeerIp` extractor here as well.
Read the IP from the forwarded header only when the immediate
peer is a trusted proxy; otherwise the rate limiter can be
spoofed.

## Tuning the windows

Tuning the rate limit is more art than science, but a few
guidelines hold up.

For login endpoints: 10 requests per minute per IP is the
conservative starting point. Real users log in at most a few
times a day from any one IP. Credential-stuffing attacks need
hundreds per minute to be efficient; 10 is well below that.
Tune up only if the warn rate is too high on legitimate traffic
(many users behind a corporate NAT, for instance).

For signup endpoints: 5 requests per minute per IP. Signup is
even less frequent for legitimate users than login; account
enumeration is best stopped tight.

For password reset: 3 requests per hour per IP. A reset is a
once-in-a-while operation. Attackers spam reset to exhaust the
victim's inbox; the tight limit is the defence.

For token refresh: matched to the session TTL. A session that
refreshes every hour should have a rate limit of a few refreshes
per hour per session id; an attacker who steals a session cannot
extract value through rapid refresh.

For data endpoints: matched to the application's expected use
pattern. An API for human-driven dashboards sees a few requests
per minute per session; an API for programmatic clients sees
hundreds per second per workload. The pattern is
deployment-specific.

The default to start with is to measure first. The metrics from
`AuthnMetrics::rate_limit_rejected` (covered below) tell you the
real reject rate; the calibration is then to set the limit just
above the legitimate-traffic envelope.

## What happens at the limit

A request that hits the rate limit gets:

A 429 status code. The standard HTTP response for "Too Many
Requests."

A `Retry-After` header. The value is the number of seconds the
client should wait before retrying. The header is read by
browsers and well-behaved clients; attackers ignore it.

A short JSON body explaining the limit. The body is generic
("rate limit exceeded") rather than specific (no "you have 0
of 10 requests remaining"); the latter leaks the limit
configuration, which lets an attacker calibrate their attack to
just under the limit.

The application's metrics record the rejection. The
`AuthnMetrics::rate_limit_rejected` method is the metric;
applications wire it to their Prometheus or OpenTelemetry
counter.

## Distinguishing attack from misconfiguration

A high rate of 429s is operationally interesting. The cause is
either an attack (real attacker getting throttled) or a
misconfiguration (legitimate traffic hitting a limit that was
set too low).

The signals that distinguish them:

A rate of 429s heavily concentrated on a small set of source IPs,
with the IPs not matching legitimate user patterns (datacenter
IPs, VPN exit nodes, residential ASNs from countries the
application does not typically serve) suggests attack.

A rate of 429s spread across many IPs, matching legitimate user
patterns (residential ASNs from served countries, mixed mobile
and home connections), suggests misconfiguration.

The audit events the rate limiter produces (a `RateLimitRejected`
event per drop) carry the source IP, the endpoint, and the
timestamp; SIEM queries against these distinguish the patterns
quickly.

## Per-tenant rate limits

For multi-tenant deployments, the rate limit configuration can
be per-tenant. A tenant with a higher SLA gets a higher rate
limit; a tenant with a lower SLA gets a tighter one. The
mechanism is the same `RateLimitLayer`, with a `Custom` key
extractor that composes the standard key (typically `PeerIp`)
with the tenant id, and with separate `RateLimitConfig`s per
tenant tier.

The pattern is operationally complex (one configuration per
tenant tier), so most deployments use a single shared limit and
calibrate to the deployment-wide envelope. The per-tenant shape
is for deployments where the SLA differences are explicit and
the operational overhead is justified.

## Metrics

The layer emits two metrics through the `AuthnMetrics` trait:

`rate_limit_rejected` is incremented on each 429. The metric is
the primary signal for tuning and for attack detection.

`rate_limit_evaluated` (optional, off by default) is incremented
on every request the layer sees, regardless of outcome. The
ratio of rejected to evaluated is the reject rate; below 0.1%
typically means the limit is set well, above 1% suggests either
attack or misconfiguration.

The `AuthnMetrics` implementation is the application's; it
typically routes to Prometheus, OpenTelemetry, or whatever
metrics system the deployment uses. The
[`examples/sqlite/`](https://github.com/GnomesOfZurich/axess/tree/main/examples/sqlite)
reference application shows a simple `AtomicU64`-based
implementation suitable for adapting to a real metrics system.

## Composing with the lockout policy

The rate limiter and the lockout policy are different defences
that compose. The rate limiter catches volume; the lockout policy
catches credential pattern. Both fire on attacks, in different
shapes.

The pattern that emerges: the rate limiter is the first line of
defence against credential stuffing. It drops the attack to a
trickle before any individual user's lockout policy can fire.
The lockout policy then catches the few attempts that get
through, marking the targeted user accounts as locked.

A deployment that has rate limiting but no lockout policy is
vulnerable to slow attacks that stay below the rate limit. A
deployment that has lockout but no rate limiting is vulnerable
to high-volume attacks that distribute across many users. Both
together cover both attack shapes.

## What this enables

The rate limiter is the operational layer that sits between
"the request was sent" and "the authentication logic runs." A
deployment without it is vulnerable to a class of attack that
the authentication logic alone cannot prevent; a deployment
with it has the broader defence against volume-based attacks
that complements the credential-pattern defence of lockout.

## Further reading

*Multi-tenancy* covers the lockout policy that pairs with the
rate limit. *Audit events* catalogues the `RateLimitRejected`
event the layer emits. *Cookies, fingerprinting, hijack
detection* covers the trusted-proxy configuration that
determines how `PeerIp` reads the source IP. *Operations
runbook* covers the metrics dashboards and the SIEM rules that
turn the rate-limit signal into alerts.
