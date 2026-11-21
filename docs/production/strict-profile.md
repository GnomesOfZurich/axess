# The strict security profile

A deployment that holds money or regulated data wants a tighter set of
settings than a library can ship as defaults: a default has to suit the demo
and the intranet app as well. `SecurityProfile::Strict` is that tighter set,
named once, readable, and applied through one call per configuration type.

It is opt-in: it changes no default, and an adopter who never mentions it
gets exactly what they got before. `SecurityProfile::Standard`
restates the defaults as the same set of values, so the two can be read
side by side and a test can prove that applying `Standard` to the defaults
changes nothing.

## Using it

```rust,ignore
use axess_core::profile::SecurityProfile;

let mut p = SecurityProfile::Strict.values();
p.device_cookie_max_age = std::time::Duration::from_secs(30 * 24 * 3600); // override one value

let session = p.session_config_builder().cookie_name("app.sid").build();
let refresh = p.refresh_config(RefreshTokenConfig::default());
let csrf = p.csrf_config(CsrfConfig::new(key), &["https://app.example"])?;
let authn = p
    .authn_service_builder(AuthnService::builder(identity, factors))
    .try_build()?; // refuses a setting looser than the profile, by name
```

`ProfileValues` holds every setting as a public field: read a field to see
the value, assign to override it, then apply. Every `apply`-style method takes
the configuration it adjusts and hands it back, so peppers, cookie names,
keys and every other setting the profile does not name stay as the caller
set them. `authn_service_builder` reads the FIDO2 options the builder holds
(`AuthnServiceBuilder::fido2_options`) and changes only the passkey-change
recency, so an attested ceremony or a shorter ceremony timeout configured
before the profile survives it.

## Applying it never loosens

Where a method takes a configuration that already holds a value, the result
is the tighter of the configuration's value and the profile's, for every
setting that has an order. A value tightened
before the profile is applied survives it, applying a profile twice is
applying it once, and a tightening can be written before or after. What
"tighter" means for each kind of setting:

| Kind of setting | Tighter | Settings |
|---|---|---|
| a lifetime, a window, a clock-skew tolerance | the shorter | `refresh_ttl`, `device_cookie_max_age`, `device_key_proof_ttl`, `device_key_challenge_ttl`, `jwt_leeway`, `password_reset_ttl`, `max_password_reset_ttl` |
| a limit that may be absent (`None` is no limit) | any limit over none; of two limits the shorter | `refresh_max_lifetime`, `fido2_max_authn_age`, `ws_max_lifetime`, `impersonation_max_authn_age` |
| a requirement that is on or off | on | `logout_typ_required`, `csrf_origin_check_required` |
| the Argon2id cost | the larger memory and the larger number of passes of the two, with the builder's own lanes | `argon2_cost` |

Two settings have no order, and the profile's value is assigned: the `typ`
of `access_token_verifier` (of two types neither is tighter, which is why the
method is named for the token it retypes to) and the CSRF origin list, which
`csrf_config` takes at the call. A default password reset lifetime is
optional: a builder with none takes the profile's, and the result is never
left above the cap in force. The two device-key lifetimes are each
the shorter of the two, so a configuration valid on both sides stays valid;
the acceptance grace stays the configuration's own, and where the profile's
pair leaves no room for it (`Strict`'s five and ten minutes against a grace
of five minutes) `DeviceKeyService::new` refuses the result rather than
lengthen a lifetime to fit. The methods that build a configuration
from nothing (`session_config_builder`, `auth_rate_limit_builder`,
`cached_device_store`, `egress_policy`) have no earlier value to compare
with and carry the profile's.

## The service holds its profile

`authn_service_builder` also records the profile on the builder, and from
then on the profile is a property of the service, not of that one call. The
authentication service holds five of the profile's settings itself:

| `ProfileSetting` | The service is built only when |
|---|---|
| `Argon2Cost` | the cost has at least the profile's memory and passes |
| `MaxPasswordResetTtl` | the cap on reset lifetimes is at most the profile's |
| `PasswordResetTtl` | the default reset lifetime, when there is one, is at most the profile's |
| `ImpersonationMaxAuthnAge` | there is a limit, at most the profile's (when the profile names one) |
| `Fido2MaxAuthnAge` | there is a limit, at most the profile's |

`AuthnServiceBuilder::try_build` checks each against the value of the
profile the values came from (`SecurityProfile::Strict.values()`, regardless of what
was assigned on a `ProfileValues` field since) and refuses a looser one with
`AuthnBuildError::BelowProfileFloor`, which names the profile and the
setting. It does not matter which setter wrote the value or when: a
`with_argon2_cost` after the profile, a `with_fido2_options` that drops the
recency, and a field loosened on the values before applying all meet the same
refusal. `build` is `try_build` for the start-up path and stops the process
with that message; `validate` asks without building. Two profiles applied
to one builder leave it under the stricter.

The one way below a profile's value is a waiver the caller writes out, per
setting:

```rust,ignore
let authn = SecurityProfile::Strict
    .values()
    .authn_service_builder(AuthnService::builder(identity, factors))
    // No recency requirement for passkey changes, and it says so.
    .with_fido2_options(Fido2Options { max_authn_age: None, ..Fido2Options::default() })
    .waive_profile_floor(ProfileSetting::Fido2MaxAuthnAge)
    .try_build()?;

assert_eq!(authn.security_profile(), Some(SecurityProfile::Strict));
assert_eq!(authn.profile_deviations(), [ProfileSetting::Fido2MaxAuthnAge]);
```

A waived setting that is below the profile's value is logged once at `warn`
when the service is built, with its value and the profile's, and listed by
`AuthnService::profile_deviations`. A waiver for a setting that holds its
value changes nothing and is not listed. So a service that says it runs a
profile (`AuthnService::security_profile`) either holds it or says exactly
where it does not, and a start-up check or a health endpoint can read both.

A `fido2_max_authn_age` of `None` assigned on the profile's values is not
that opt-out: it names no limit, leaves the five minutes the options hold,
and the service is still held to the profile's five minutes.

Independently of any profile, `try_build` refuses a default reset lifetime
above the cap on reset lifetimes (`AuthnBuildError::PasswordResetTtlAboveCap`,
naming both settings): every reset under the default would be refused when
requested, so the pair is refused when the service is built.

The other settings a profile names are applied to values the service never
sees: the session layer's configuration, the refresh configuration handed
to each refresh, the CSRF and rate-limit layers, a JWT verifier, the device
cookie, a socket's options. For those the guarantee is the one in
*Applying it never loosens*: the method leaves the tighter of the two at the call, and
what is written on the returned value afterwards is the caller's own.

## What it sets

| Setting | Standard (today) | Strict | Applied to |
|---|---|---|---|
| `session_idle_ttl` | 24 h, sliding | 15 min | `SessionConfig` through `session_config_builder` |
| `session_max_authenticated_age` | 7 days | 8 h | `SessionConfig` through `session_config_builder` |
| `refresh_ttl` | 30 days | 24 h | `RefreshTokenConfig` through `refresh_config` |
| `refresh_max_lifetime` | 90 days | 7 days | `RefreshTokenConfig` through `refresh_config` |
| `fido2_max_authn_age` | 5 min | 5 min | `Fido2Options` through `fido2_options`, and the service builder, which is held to it; the opt-out is the named waiver |
| `jwt_leeway` | 60 s | 30 s | `JwtVerifier` through `access_token_verifier` or `jwt_leeway_only` |
| `jwt_expected_typ` | none | `at+jwt` | the access-token verifier, through `access_token_verifier` (`JwtVerifier::with_typ`); a verifier of ID, logout or DPoP tokens goes through `jwt_leeway_only` and keeps its own `typ` |
| `logout_typ_required` | false | true | `OAuthProviderBuilder` through `oauth_provider` |
| `egress_screened` | true | true | `egress_policy()`, passed to the discovery entry points that take a policy; `false` is the named opt-out |
| `device_cache_ttl` | 60 s | 5 s | `CachedDeviceStore` through `cached_device_store` |
| `device_cookie_max_age` | 400 days | 90 days | `DeviceCookieConfig` through `device_cookie_config` |
| `csrf_origin_check_required` | false | true | `CsrfConfig` through `csrf_config` |
| `ws_max_lifetime` | 24 h | 8 h | `WatchOptions` through `watch_options` |
| `argon2_cost` | 19 MiB, t=2, p=1 | 64 MiB, t=2, p=1 | `AuthnServiceBuilder` through `authn_service_builder` |
| `password_reset_ttl` | none | 30 min | `AuthnServiceBuilder` through `authn_service_builder` |
| `max_password_reset_ttl` | 7 days | 1 h | `AuthnServiceBuilder` through `authn_service_builder` |
| `impersonation_max_authn_age` | none | 15 min | `AuthnServiceBuilder` through `authn_service_builder` |
| `auth_rate_limit_max_requests` per window | 100 per 60 s | 15 per 60 s | `RateLimitConfigBuilder` through `auth_rate_limit_builder` |
| `device_key_proof_ttl` | 10 min | 5 min | `DeviceKeyConfig` through `device_key_config` (`device-keys` feature) |
| `device_key_challenge_ttl` | 20 min | 10 min | `DeviceKeyConfig` through `device_key_config`; the profile never sets the key-binding policy |

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
  permanent one, so it asks for a recent authentication. This is the
  library default too; the profile restates it, and a service under either
  profile is held to it when it is built. The opt-out is `max_authn_age:
  None` on the builder's options with the named waiver,
  `waive_profile_floor(ProfileSetting::Fido2MaxAuthnAge)`; a `None` assigned
  on the profile's values leaves the limit in force.
- **JWT leeway 30 s.** Every token stays valid for the leeway after `exp`.
  Thirty seconds covers real clock drift between servers that run NTP and
  halves the replay window for a stolen bearer token.
- **Access-token `typ` of `at+jwt`.** RFC 9068 gives access tokens their own
  type so that an ID token, a logout token or a DPoP proof signed by the same
  key is not accepted as one. The method is named for the access token,
  `access_token_verifier`, because a verifier of another kind passed through
  it would be retyped; `jwt_leeway_only` sets the leeway on those.
- **Logout `typ` required.** The default accepts a missing or generic `typ`
  because some identity providers send one; a deployment that knows its
  provider sends `logout+jwt` should refuse everything else.
- **Screened egress.** The server fetches discovery documents and key sets
  from URLs a tenant may supply; a screened policy refuses reserved
  addresses and, under it, the egress client never follows a proxy named in
  the environment. This is the library default too; the profile restates it
  so an adopter who assigns `false` sees the opt-out they are taking. An
  adopter that can reach only an internal provider names the opt-out
  (`EgressPolicy::unscreened`) in its own code.
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
  long as it lives. The cap makes a caller's mistake (a lifetime of days) fail
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
  secrets or a data set the library cannot supply. The check is a trait the
  deployment implements (see *Breached passwords* on the
  [Password and TOTP](../factors/password-totp.md) page); each pepper or key
  is set on the component that uses it, such as
  `RefreshTokenConfig::hash_pepper`.
- **DPoP proof replay cache.** A full cache refuses every client. Size it for
  the deployment; the profile names no value for it.

## Where it is tested

The integration test `security_profile` asserts that `Standard` equals the
default of every type it touches, that `Strict` yields exactly the table
above, that each `apply` method writes the value it names and nothing else,
and that the CSRF check refuses an empty or malformed origin list. Its
property tests draw a profile and a configuration at random for the refresh
configuration, the service builder, the passkey options, the JWT verifier,
the device cookie and the socket options. They assert that each ordered
setting comes out as the tighter of the two, that none comes out looser
than the configuration had it (no component of an Argon2id cost falls, and
a default reset lifetime never ends above the cap), and that a second
application changes nothing. The two on-or-off settings have a test each:
a profile never turns the CSRF origin check or the logout-token `typ`
requirement off. For the service it asserts that a builder put under either
profile holds it whatever it held before, that every setting the service
holds is refused by name when a later setter or an edited value loosens it,
that the named waiver builds the service and is read back from it, and that
a default reset lifetime above the cap is refused in a sentence naming both
settings.
