# Live provider reload

A running `AuthnService` can replace, add and remove its OAuth/OIDC, FIDO2
and LDAP providers without a restart. Before this, providers were attached at
construction (`with_oauth_provider`, `with_fido2`, `with_ldap`) and could not
be swapped, so a rotated client secret, a moved IdP or a tenant that started
federating meant rebuilding the service and rewiring Axum state. This page is
the design: what holds, the API, the invariants, how it fails, and what an
adopter changes.

It reuses the machinery of [live policy reload](../authorization/live-policy-reload.md):
a lock-free swap slot, validation before the swap, a refusal that leaves the
previous value in force and names itself, and a coordinator whose notice is a
hint and never a payload.

## What you get

- `reload_oauth_provider(name, candidate)` makes a validated provider the one
  that `begin_oauth_login(name, ..)` uses from the next call on, and
  `remove_oauth_provider(name)` takes a provider out.
- `reload_tenant_oauth_provider(tenant, name, candidate)` and
  `remove_tenant_oauth_provider(tenant, name)` do the same for a provider a
  tenant brought, in a registry keyed by `(tenant, name)`.
- `reload_fido2(candidate)` and `reload_ldap(candidate)` replace the single
  FIDO2 and LDAP provider, and `remove_fido2()` and `remove_ldap()` take it
  out: the FIDO2 ceremony steps then answer `AuthnError::NoFlow`, a factor
  chain with `LdapBind` answers `InvalidCredential`, and registered passkeys
  stay in the store.
- A reload that fails leaves the previous provider in force and answers with
  a named `ProviderReloadError`.
- With a coordinator and a `ProviderSource`, one change reaches every
  instance. A receiving instance re-reads its source and builds the provider
  itself; the notice carries nothing it applies.

## The slots

`AuthnService` holds each category in an `arc_swap` slot:

| Category | Slot | Read on the request path |
|----------|------|--------------------------|
| global OAuth | `ArcSwap<OAuthProviderRegistry>` | `load()` for a lookup by name |
| tenant OAuth | `ArcSwap` of a map keyed by tenant, then name, in `LiveTenantOAuthProviders` | `load()` inside `TenantOAuthProviders::provider` |
| FIDO2 | `ArcSwapOption` of the provider | a snapshot at the top of a ceremony step |
| LDAP | `ArcSwapOption` of the provider | a snapshot before the bind |

A request takes a snapshot (a read that takes no lock and does not wait on a reload) and keeps
it for the one step it is doing. A reload builds the next map off to the side
and installs it with `rcu`, so two concurrent reloads of different names both
land. `arc-swap` is the dependency live policy reload already added; nothing
new enters the tree.

A map snapshot is immutable. `AuthnService::oauth_providers()` therefore
returns an `Arc<OAuthProviderRegistry>` (the registry as of the call) and not
a reference into the service; `provider_names()` returns owned names.

## Validate before swap

The candidate is a future that builds the provider. The service awaits it
under a deadline (`DEFAULT_PROVIDER_VALIDATION_TIMEOUT`, 30 seconds, changed
with `with_provider_validation_timeout`), then checks what the type can say,
and only then swaps:

- **OAuth.** The candidate is what `OAuthProviderConfig::discover(..).build()`
  yields, so the discovery fetch, the issuer check that binds the document to
  the issuer it was fetched from, the HTTPS rule and the key-set transport
  check all run inside the candidate. An unreachable or inconsistent discovery
  document is a `Build` refusal. The service adds that the provider's
  `name()` equals the `name` argument (`NameMismatch`), since a provider
  swapped in under the wrong key would answer logins meant for another IdP.
- **FIDO2.** The candidate parses the relying party (`WebauthnBuilder::build`),
  so an invalid RP id or origin is a `Build` refusal. Changing the RP id
  orphans every registered credential, because a passkey is bound to its RP
  id, so `Fido2Provider::relying_party_id()` is a required method and a
  candidate whose id differs from the provider in force is refused as
  `RpIdChanged`. The caller who means it passes
  `reload_fido2_with(candidate, ReloadFido2::allow_rp_id_change())`; the
  change is counted (`ProviderRegistryMetrics::fido2_rp_id_changed`) and logged with both ids. A source states
  the same intent by building `BuiltProvider::Fido2AllowingRpIdChange`; the
  plain `BuiltProvider::Fido2` with another id is refused at every follower.
  Why a required trait method and not a field of a config: `Webauthn` does not
  expose its id, and a provider is the only value every reload path (a direct
  call, a source) holds, so the comparison needs the id from the provider
  itself. `DefaultFido2Provider::new` reads it from the instance it wraps
  (the challenge a discoverable authentication would send names it), so it
  cannot disagree with the ceremonies.
- **LDAP.** The candidate builds the provider; the service then calls
  `LdapProvider::check_reachable` under the deadline. For
  `LdapProviderConfig` that is a connection with the configured transport
  (TLS or StartTLS, and the cleartext refusal) and an unbind, with no
  credential sent. A provider that does not override the method answers a
  configuration error, so a custom provider is refused by name rather than
  swapped unchecked; an adopter who wants that writes the override.

Every refusal is a `ProviderReloadError` naming the step: `Build`,
`TimedOut`, `NameMismatch`, `Unreachable`, `RpIdChanged`, `NotFound` (remove),
`NoTenantRegistry`.
Each increments `provider_reload_refused(category)` and logs a `warn!` on
`axess::authn::provider_reload` with the category and the error, and the
previous provider keeps serving.

## A login in flight across a swap

The ceremony state lives in the session: the CSRF state, the nonce, the PKCE
verifier and the issuer of the provider that began it. Decision: **a login
begun against the old provider finishes against the new one only when the
issuer is the same; otherwise it is refused by name.** This is the rail that
already existed (`verify_provider_issuer_matches`, audited as
`ProviderMismatch`), and the reload relies on it instead of adding a second.

Why not honour the old provider's state to the end? The authorization code
the IdP issues is for the old authorization endpoint and the old client.
Presenting it to a different issuer's token endpoint is a confused-deputy
shape (a code from IdP A sent to IdP B), and no verifier minted by the old
provider makes that safe. The same issuer with a rotated client secret or new
scopes is the ordinary case, and the code is still good: the token request
uses the new credentials, the IdP validates the code against the client id,
and a changed client id fails at the IdP with `invalid_grant`, closed. The
user restarts the login either way; nothing stays half-open because the
failure clears the ceremony.

A provider removed mid-ceremony fails the callback with `UnknownProvider`
(audited `ProviderUnavailable`), as before. FIDO2 and LDAP hold no state
across a swap that the new provider would honour wrongly: a FIDO2 ceremony
state finished by a provider with a different RP id fails webauthn's origin
check, and an LDAP bind is one request.

## The tenant-supplied IdP

`LiveTenantOAuthProviders` is a `TenantOAuthProviders` over
`(TenantId, name)`. Hand it to
`AuthnServiceBuilder::with_live_tenant_oauth_providers` (which also installs
it as the service's tenant source) and call
`reload_tenant_oauth_provider(tenant, name, ..)`. The key includes the
tenant, so a reload for tenant A replaces exactly `(A, name)`: tenant B's
provider of the same name is a different map entry and is never rebuilt or
read. `providers_for_issuer` serves the back-channel logout path from the same
snapshot. `StoredTenantOAuthProviders` (a store, rebuilt when a record's
revision moves) is unchanged and is the choice when the configuration lives in
a database that the service reads on demand; the live registry is for an
adopter that pushes a built provider, or that follows a `ProviderSource`.

## Across instances

`with_provider_coordinator(coordinator)` reuses `ReloadCoordinator` from live
policy reload on its own channel: each coordinator is one channel, so the
provider channel is a second coordinator value (`InProcessCoordinator::new`
for tests, `ValkeyReloadCoordinator::start_named(.., "provider-reloaded", ..)`
for Valkey, on the channel `{prefix}:provider-reloaded`). The two channels do not cross, and a live Valkey test
(`provider_reload_valkey`, run with `--ignored`) shows both that a notice
reaches a second service and that a policy notice is not a provider notice.
The coordinator types
moved to `axess::reload` and are still re-exported from `axess::authz::reload`.
After a local reload or removal the service announces a label of the key (`oauth:tenant:name`, `fido2`, `ldap`)
for logs.

`follow_provider_reloads(source, poll_every)` starts the receiving side. The
adopter supplies a `ProviderSource`:

- `desired()` lists `ProviderEntry { key, revision }`, cheap and with no
  network: the keys the instance should run and an opaque revision per key;
- `build(key)` builds one provider (discovery included), only called for a
  key whose revision differs from the one the follower last applied.

`ProviderFollower::reads(ReadCause)` counts the reads by why they happened
(`Start`, `Notice`, `Lagged`, `Poll`), so a deployment can see whether notices
reach it or only the poll does.

On a notice, a lagged receiver, and every `poll_every`, the follower calls
`desired()`, builds and installs what moved, and removes a provider of any
category that it installed earlier and that the source no longer lists. It applies
nothing from a notice, never removes a provider the source never named (the
ones registered at construction stay), and a build or validation failure is
counted and logged and retried at the next notice or poll. An entry the source stops listing
is removed only if the follower installed it, so a FIDO2 or LDAP provider
attached at construction stays even when the source never names it.

## Metrics

On the provider-registry concern (`ProviderRegistryMetrics`), with a closed
`ProviderCategory` (`oauth`, `fido2`, `ldap`): `provider_reloaded(category)`,
`provider_removed(category)` and `provider_reload_refused(category)`,
exported as `axess_provider_reloads_total`, `axess_provider_removals_total`
and `axess_provider_reload_refusals_total`, with `category` as the only label.
The provider name and the tenant are not labels; they are in the event.

## Invariants

1. A provider is in a slot only after its candidate built, its name matched
   and, for LDAP, the directory answered.
2. The request path takes no lock and never awaits on a reload.
3. A failed reload leaves every slot as it was.
4. A tenant's reload touches that tenant's entry only.
5. A notice never installs anything; the receiver builds from its source.
6. A login in flight across a swap finishes only against the same issuer.

## Failure modes

| Failure | Result |
|---------|--------|
| discovery unreachable, issuer mismatch, bad RP id | `Build`; previous provider serves |
| candidate slower than the deadline | `TimedOut`; previous provider serves |
| LDAP directory down or provider cannot be probed | `Unreachable`; previous provider serves |
| name differs from the provider's | `NameMismatch` |
| FIDO2 candidate with another relying-party id, not acknowledged | `RpIdChanged`; previous provider serves |
| tenant method with no live registry | `NoTenantRegistry` |
| coordinator down at announce | reload stands, `announced` is false, the followers' poll covers it |
| notice lost or receiver lagged | the follower re-reads the source; convergence by poll |
| source unreadable | warn, previous providers serve |
| the background JWKS refresh loop | it reads the live registry at every pass, so a reloaded provider's key set is the one refreshed and a removed provider is no longer polled |

## Migration

For an adopter that never reloads, behaviour is unchanged. The compile
breaks: `AuthnService::oauth_providers()` returns `Arc<OAuthProviderRegistry>`
and `OAuthProviderRegistry::provider_names()` returns `Vec<Arc<str>>`;
`ProviderRegistryMetrics` gains three defaulted methods; `LdapProvider` gains
`check_reachable`, defaulted to a refusal that only `reload_ldap` consults; and
`Fido2Provider` gains the required `relying_party_id()`.
The 0.16.0-to-0.17.0 page carries the bullets.
