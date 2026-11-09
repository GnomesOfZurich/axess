# The strict security profile

A deployment that holds money or regulated data wants a tighter set of
settings than a library can ship as defaults: a default has to suit the demo
and the intranet app as well. `SecurityProfile::Strict` is that tighter set,
named once, readable, and applied through one call per configuration type.

It is additive. It adds no default and removes none; an adopter who never
mentions it gets exactly what they got before. `SecurityProfile::Standard`
restates today's defaults as the same set of values, so the two can be read
side by side and a test can prove that applying `Standard` changes nothing.

## Using it

```rust,ignore
use axess_core::profile::SecurityProfile;

let mut p = SecurityProfile::Strict.values();
p.device_cookie_max_age = std::time::Duration::from_secs(30 * 24 * 3600); // override one value

let session = p.session_config_builder().cookie_name("app.sid").build();
let refresh = p.refresh_config(RefreshTokenConfig::default());
let csrf = p.csrf_config(CsrfConfig::new(key), &["https://app.example"])?;
let authn = p.authn_service_builder(AuthnServiceBuilder::new(identity, factors));
```

`ProfileValues` is a plain struct with public fields: read a field to see
the value, assign to override it, then apply. Every `apply`-style method takes
the configuration it adjusts and hands it back, so peppers, cookie names,
keys and every other setting the profile does not name stay as the caller
set them.

## What it sets

| Setting | Standard (today) | Strict | Applied to |
|---|---|---|---|
| `session_idle_ttl` | 24 h, sliding | 15 min | `SessionConfig` through `session_config_builder` |
| `session_max_authenticated_age` | 7 days | 8 h | `SessionConfig` through `session_config_builder` |
| `refresh_ttl` | 30 days | 24 h | `RefreshTokenConfig` through `refresh_config` |
| `refresh_max_lifetime` | 90 days | 7 days | `RefreshTokenConfig` through `refresh_config` |
| `fido2_max_authn_age` | none | 5 min | `Fido2Options` through `fido2_options`, and the service builder |
| `jwt_leeway` | 60 s | 30 s | `JwtVerifier` through `jwt_verifier` |
| `jwt_expected_typ` | none | `at+jwt` | held for the verifier's `typ` option; not applied until the verifier has one |
| `logout_typ_required` | false | true | `OAuthProviderBuilder` through `oauth_provider` |
| `egress_screened` | false (unscreened for discovery) | true | `egress_policy()`, passed to the discovery entry points that take a policy |
| `device_cache_ttl` | 60 s | 5 s | `CachedDeviceStore` through `cached_device_store` |
| `device_cookie_max_age` | 400 days | 90 days | `DeviceCookieConfig` through `device_cookie_config` |
| `csrf_origin_check_required` | false | true | `CsrfConfig` through `csrf_config` |
| `ws_max_lifetime` | 24 h | 8 h | `WatchOptions` through `watch_options` |
| `argon2_cost` | 19 MiB, t=2, p=1 | 64 MiB, t=2, p=1 | `AuthnServiceBuilder` through `authn_service_builder` |
| `password_reset_ttl` | none | 30 min | `AuthnServiceBuilder` through `authn_service_builder` |
| `max_password_reset_ttl` | 7 days | 1 h | `AuthnServiceBuilder` through `authn_service_builder` |
| `impersonation_max_authn_age` | none | 15 min | `AuthnServiceBuilder` through `authn_service_builder` |
| `auth_rate_limit_max_requests` per window | 100 per 60 s | 15 per 60 s | `RateLimitConfigBuilder` through `auth_rate_limit_builder` |

## Why each value

- **Idle lifetime 15 min, authenticated cap 8 h.** A session left open on a
  shared machine, or a stolen cookie, is useful for as long as the session
  lives. Fifteen idle minutes is the figure regulated deployments commonly
  audit against, and eight hours is one working day: the person signs in
  again the next morning.
- **Refresh 24 h sliding, 7 days absolute.** Rotation and reuse detection
  already make a 30-day refresh token defensible, and the standard profile
  keeps it. A deployment that wants every device to prove itself weekly
  takes the shorter pair; the absolute cap must stay at least the sliding
  lifetime, which `RefreshTokenConfig::validate` checks.
- **Passkey changes within 5 minutes of authenticating.** Enrolling or
  removing a passkey is the step that turns a short-lived foothold into a
  permanent one, so it asks for a recent authentication.
- **JWT leeway 30 s.** Every token stays valid for the leeway after `exp`.
  Thirty seconds covers real clock drift between servers that run NTP and
  halves the replay window for a stolen bearer token.
- **Access-token `typ` of `at+jwt`.** RFC 9068 gives access tokens their own
  type so that an ID token, a logout token or a DPoP proof signed by the same
  key is not accepted as one.
- **Logout `typ` required.** The default accepts a missing or generic `typ`
  because some identity providers send one; a deployment that knows its
  provider sends `logout+jwt` should refuse everything else.
- **Screened egress.** The server fetches discovery documents and key sets
  from URLs a tenant may supply; a screened policy refuses reserved
  addresses and, under it, the egress client never follows a proxy named in
  the environment. An adopter that can reach only an internal provider names
  the opt-out (`EgressPolicy::unscreened`) in its own code.
- **Device cache 5 s.** A device revoked on one process stays usable on the
  others until their cached row expires, since there is no invalidation bus.
  Five seconds bounds that exposure.
- **Device cookie 90 days.** The device is recognised for as long as the
  browser keeps the cookie, so this is how long a trusted browser stays
  trusted without a visit. The standard 400 days is the browser maximum.
- **CSRF origin check required.** The signed token is checked everywhere; the
  profile adds the `Origin`/`Referer` allow-list as a second layer. The
  profile cannot know the application's origins, so `csrf_config` refuses to
  run with none rather than leave the check off, and refuses an entry that
  is not an origin rather than drop it.
- **WebSocket lifetime 8 h.** A socket should not outlive the session cap it
  was upgraded under.
- **Argon2id 64 MiB.** The standard cost is the OWASP minimum. A leaked hash
  database is cracked offline at whatever cost the hashes carry; 64 MiB
  raises that at the price of memory per concurrent login, which the
  service's hashing pool bounds. Stored hashes made under another cost are
  rehashed at the next successful login.
- **Password reset 30 min, capped at 1 h.** A reset link is a password for as
  long as it lives. The cap makes a caller's mistake (a ttl of days) fail
  loudly instead of quietly.
- **Impersonation after a recent administrator login.** A stolen
  administrator cookie otherwise becomes every user's session. The
  administrator is asked to step up first.
- **Authentication routes 15 per minute.** The generic limit of 100 suits a
  page; a login or reset route wants a budget in single digits to low tens.
  The profile gives the budget; the adopter keys it per route.

## What the profile leaves to you

- **`SameSite`.** `Strict` is better for a deployment with no OIDC callback,
  and breaks one that has it, since the callback arrives as a cross-site
  top-level navigation. The profile leaves `Lax`; set `Strict` yourself when
  nothing returns from another site.
- **Refresh and session lifetimes are yours to tighten further.** The values
  above are a starting point, not an audit position.
- **A breached-password check, peppers and encryption keys.** These need
  secrets or a data set the library cannot supply; see the security posture
  page.
- **DPoP proof replay cache.** A full cache refuses every client. Size it for
  the deployment; the profile names no value for it.
- **`jwt_expected_typ`.** The profile holds the value, and applying it is
  one line once the verifier has a `typ` option.

## Where it is tested

The integration test `security_profile` asserts that `Standard` equals the
default of every type it touches, that `Strict` yields exactly the table
above, that each `apply` method writes the value it names and nothing else,
and that the CSRF check refuses an empty or malformed origin list.
