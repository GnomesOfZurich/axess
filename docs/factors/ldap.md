# LDAP bind

LDAP bind suits enterprise deployments where the
authoritative user store is Active Directory, OpenLDAP, or a similar
directory server. The application does not own user passwords; the
directory does. Axess verifies the user with a simple bind against the directory,
using the user's distinguished name and password; a successful bind
authenticates the user.

The feature flag is `ldap` (off by default), enabled with
`features = ["ldap"]` on the `axess` facade.

## When LDAP fits

LDAP fits when three conditions hold:

- The authoritative user identities live in an LDAP directory you can
  reach.
- The directory administrators have agreed to allow simple binds from
  your deployment network.
- The directory speaks LDAP, rather than a protocol that wraps LDAP
  semantics. OIDC goes through the OAuth factor instead; SAML federation
  is not supported.

When those conditions hold, LDAP gives you authentication as a service
from the directory, and you never store a user password. New employees
added to the directory can log in immediately, and an employee removed
from the directory can no longer log in. A session they already hold is
not checked against the directory again: it stays valid until it
expires or is ended, for example by `invalidate_user_sessions`. The
directory is the source of truth for every login.

When those conditions do not hold (a SaaS deployment where users
come from many organisations, a directory you cannot
reach over a stable network, an authoritative store that is not LDAP),
use OAuth or OIDC against an IdP that the organisation
supports.

## Configuration

`LdapProviderConfig` carries the connection details:

```rust,ignore
pub struct LdapProviderConfig {
    pub url: String,                          // ldaps://ad.example.com:636
    pub bind_dn_template: String,             // "uid={user},ou=people,dc=example,dc=com"
    pub starttls: bool,                       // upgrade ldap:// to TLS via STARTTLS
    pub connection_timeout: Duration,         // default 5 seconds
    pub group_search: Option<LdapGroupSearch>,
    pub allow_cleartext: bool,                // see allow_cleartext() below
}
```

`url` is the directory's URL. The `ldaps://` scheme means TLS is
established at the transport layer (port 636 by default); the
`ldap://` scheme means cleartext, possibly upgraded to TLS via
STARTTLS. Cleartext without STARTTLS is refused: a bind to a host
other than exactly `localhost`, `127.0.0.1` or `[::1]` returns
`LdapError::Config` before any connection is opened, because a simple bind
sends the password in the clear. (The check parses the host: `ldap://localhost.example.com`
is not loopback.) A trusted segment where you accept that risk opts in with
`LdapProviderConfig::allow_cleartext()`; production deployments use one of
the encrypted forms.

`bind_dn_template` is the pattern axess uses to construct a user's
distinguished name from their login identifier. The string `{user}`
in the template is replaced with the user's login identifier, escaped
for a DN (RFC 4514), so a comma or plus sign in the identifier cannot
change which entry the bind names. The
example above turns the username `alice` into the DN
`uid=alice,ou=people,dc=example,dc=com` for the bind request.

`starttls` upgrades the cleartext connection to TLS once it is
established. Use it when the directory accepts both cleartext and TLS
on the same port (usually 389). When the directory exposes a separate
TLS port (usually 636), use `ldaps://` instead and leave this false.

`connection_timeout` bounds connecting and each step after it (the
bind, then the group search). The default is five seconds, and five
to ten is typical. Longer timeouts admit slow failure modes
into the login path; shorter timeouts produce spurious failures
when the directory is briefly slow. Tune to match the directory's
observed latency.

`group_search` is optional. When it is set, axess searches for the
user's group memberships after a successful bind. The provider returns them in `LdapBindResult`, and the
service keeps them in the session's authenticated state rather than in
the custom data, so a handler cannot overwrite them and the custom-data
cap does not apply. Read them with `AuthSession::ldap_groups()` on any
later request and map them to roles or Cedar entities. They are the groups of the login that
produced the session; a change in the directory is seen at the next
login. Without a group search the list is empty, and a session that
did not authenticate through an LDAP bind has none.

```rust,ignore
pub struct LdapGroupSearch {
    pub base_dn: String,           // "ou=groups,dc=example,dc=com"
    pub filter_template: String,   // "(member={dn})"
    pub group_attr: String,        // "cn" -- attribute identifying the group
}
```

`filter_template` interpolates `{dn}` (the bound user's DN) or
`{user}` (the original identifier) into an LDAP filter. The example
filter `(member={dn})` matches groups that list the user's DN in
their `member` attribute, which is the OpenLDAP convention. Active
Directory also lists a user's groups in `memberOf` on the user entry,
but axess does not read attributes of the user entry: the groups come
only from the group search. An Active Directory deployment therefore
still configures one. Its group objects carry `member` too, but
`member` holds full DNs and `{dn}` is the bind DN, so `(member={dn})`
matches only when the bind DN is the user's full DN: a template that
builds it, or a per-user `bind_dn` in `LdapBindFactorConfig`. A bind DN
of the form `{user}@corp.example.com` or `CORP\{user}` matches no group.

## The verification flow

The user submits a username and password to your handler, which calls
`RequestAuthnService::verify_factor` with the LDAP bind credential. Axess
expands the bind DN template with the username, opens a connection
to the directory (TLS for `ldaps://` or with `starttls`, cleartext only
where the refusal above allows it), performs a simple bind with the
constructed DN and the user's password, optionally searches for
groups, and unbinds.

A successful bind transitions the session as any factor would: the
state machine calls `advance_factor`, which returns `Completed` if
LDAP was the last required factor or `StillAuthenticating` if more
factors are required. A failed bind returns
`FactorOutcome::InvalidCredential`, and the user sees the standard
failed-login message.

Each bind attempt opens a fresh connection, binds, and closes
it; there is no connection pooling. The trade-off is operational simplicity (no pool to size,
no idle-connection management) against per-attempt latency (a new
connection, and on TLS a handshake, on each login). For most deployments the latency is
acceptable; busy directories with thousands of binds per second
benefit from a connection pool at the network layer (HAProxy,
nginx) rather than in your process.

## Mixing LDAP with other factors

LDAP can be the only factor in a method (the directory's bind is
the entire authentication), or it can be one factor in a chain.

A common shape in enterprise deployments is LDAP followed by TOTP.
The user enters their LDAP credentials, the directory verifies them,
and then axess prompts for the user's TOTP code. The TOTP secret is
stored in axess's own factor store (not in LDAP), under the user's
scope. The combination gives directory-managed passwords with an
application-managed second factor; the directory does not need to
know about TOTP, and you do not need to know about
the password.

A variation is LDAP followed by `AnyOf(vec![Totp, Fido2])`,
allowing the user to register a passkey alongside or instead of
TOTP. The flow is otherwise unchanged.

## Changing the provider on a running service

`reload_ldap_as(actor, candidate)`, on `authn.with_audit_context(audit)`,
swaps the LDAP provider as the administrator it names. It swaps only after
the candidate's `check_reachable` has connected to the directory with the
configured transport (TLS or STARTTLS, and the cleartext refusal) and unbound,
without sending a credential, within `with_provider_validation_timeout`. A directory that does not
answer, or a custom provider that does not implement the check, is refused by
name and the previous provider keeps serving. See
[live provider reload](../authentication/live-provider-reload.md).

## Threat model

An LDAP bind is a password factor, verified by the directory instead
of against a stored hash. Axess holds no password hash, so none can be
stolen from the application and brute-forced offline (the hash never
leaves the directory). Like any password, it does not resist a password
reused from another service or guessed from a common-password list;
pair it with a second factor (see above) where that matters.

It is weak against attacks the directory itself is weak against. A
directory that allows anonymous binds is vulnerable to attribute
enumeration. A directory whose bind path is misconfigured to accept
empty passwords for any DN is catastrophically vulnerable. The
defence is operational: configure the directory correctly, audit
periodically, and treat the LDAP factor's security as a function of
the directory's security posture.

The bind password must never appear in application logs at any
level, including trace. Axess does not log it; adopters' own login handlers
need to make the same guarantee. The standard pattern is to mark
the password field as zeroized and to route it directly into the
verifier without touching it again.

## Troubleshooting

| Symptom | Usually | What to do |
|---|---|---|
| "Invalid credentials" for passwords you know are good | The bind DN template. Active Directory usually expects `userPrincipalName` (an email address) or `sAMAccountName` (a short login name), not a constructed DN | Try `{user}@example.com` in place of `uid={user},ou=people,dc=example,dc=com` |
| The connection opens, then the bind times out | The directory is loaded, or a middlebox is inspecting the connection and buffering slowly. The timeout fires and the user sees a generic failure | Inspect the network path |
| The group search comes back empty | A wrong `filter_template`, or a bound user without permission to read group membership. OpenLDAP often wants an explicit ACL for a user to enumerate their own groups; Active Directory usually grants it | Run the same search through a known-good LDAP client |
| TLS fails on certificate validation | The directory's certificate is signed by a private CA your trust store does not carry | Add the CA through `SSL_CERT_FILE` or `SSL_CERT_DIR` |

## Further reading

*Factors and methods* covers the composition machinery this chapter
exercises. *Identity store implementation* covers how user records
referenced by LDAP are provisioned in your identity
store (typically just-in-time on first successful LDAP login).
*Multi-tenancy* covers the case where different tenants federate to
different directories.
