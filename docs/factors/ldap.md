# LDAP bind

LDAP bind is the right factor for enterprise deployments where the
authoritative user store is Active Directory, OpenLDAP, or a similar
directory server. The application does not own user passwords; the
directory does. The verification mechanism is a simple bind against
the directory with the user's distinguished name and password; if
the bind succeeds, the user has authenticated.

The feature flag is `ldap` (off by default), enabled with
`features = ["ldap"]` on the `axess` facade.

## When LDAP fits

LDAP fits when three conditions hold. The first is that the
authoritative user identities live in an LDAP directory the
application can reach. The second is that the directory administrators
have agreed to allow simple binds from the application's deployment
network. The third is that the directory speaks LDAP, not some other
protocol that wraps LDAP semantics (SAML, OIDC) which would route
through the OAuth factor instead.

When those conditions hold, LDAP gives the application
authentication-as-a-service from the directory without the
application ever storing a user password. New employees added to the
directory can log into the application immediately; departed
employees removed from the directory lose access immediately. The
directory is the source of truth.

When those conditions do not hold (a SaaS deployment where users
come from many organisations, a directory the application cannot
reach over a stable network, an authoritative store that is not LDAP),
the right answer is OAuth or OIDC against an IdP that the
organisation does support.

## Configuration

`LdapProviderConfig` carries the connection details:

```rust,ignore
pub struct LdapProviderConfig {
    pub url: String,                          // ldaps://ad.example.com:636
    pub bind_dn_template: String,             // "uid={user},ou=people,dc=example,dc=com"
    pub starttls: bool,                       // upgrade ldap:// to TLS via STARTTLS
    pub connection_timeout: Duration,         // typical 5-10 seconds
    pub group_search: Option<LdapGroupSearch>,
}
```

`url` is the directory's URL. The `ldaps://` scheme means TLS is
established at the transport layer (port 636 by default); the
`ldap://` scheme means cleartext, possibly upgraded to TLS via
STARTTLS. Cleartext without STARTTLS is acceptable only on a private
network where the directory traffic does not leave a trusted segment;
production deployments use one of the encrypted forms.

`bind_dn_template` is the pattern axess uses to construct a user's
distinguished name from their login identifier. The string `{user}`
in the template is replaced with the identifier the user typed. The
example above turns the username `alice` into the DN
`uid=alice,ou=people,dc=example,dc=com`, which is then used in the
bind request.

`starttls` triggers a STARTTLS upgrade after the initial cleartext
connection establishes. The mechanism is widely supported and is the
right choice when the directory accepts both cleartext and TLS on
the same port (usually 389). When the directory exposes a separate
TLS port (usually 636), use `ldaps://` instead and leave this false.

`connection_timeout` bounds how long a bind attempt may take. Five
to ten seconds is typical. Longer timeouts admit slow failure modes
into the login path; shorter timeouts produce spurious failures
when the directory is briefly slow. Tune to match the directory's
observed latency.

`group_search` is optional. When set, after a successful bind axess
performs an additional search to enumerate the user's group
memberships. The result is returned alongside the bind outcome and
can be used by the application to populate the user's authorisation
attributes.

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
Directory typically uses `memberOf` on the user record itself
instead, in which case the group search is unnecessary because the
groups are already attributes of the user.

## The verification flow

The verification flow is straightforward. The user submits a username
and password to the application. The application calls
`AuthnService::verify_factor` with the LDAP bind credential; axess
expands the bind DN template with the username, opens a TLS
connection to the directory, performs a simple bind with the
constructed DN and the user's password, optionally searches for
groups, and unbinds.

A successful bind transitions the session as any factor would: the
state machine calls `advance_factor`, which returns `Completed` if
LDAP was the last required factor or `StillAuthenticating` if more
factors are required. A failed bind returns
`FactorOutcome::InvalidCredential`, and the user sees the standard
failed-login message.

The connection model is per-attempt. Each bind opens a fresh TLS
connection, performs the bind, and closes. There is no connection
pooling. The trade-off is operational simplicity (no pool to size,
no idle-connection management) against per-attempt latency (a TLS
handshake on each login). For most deployments the latency is
acceptable; busy directories with thousands of binds per second
benefit from a connection pool at the network layer (HAProxy,
nginx) rather than inside the application.

## Mixing LDAP with other factors

LDAP can be the only factor in a method (the directory's bind is
the entire authentication), or it can be one factor in a chain.

A common shape in enterprise deployments is LDAP followed by TOTP.
The user enters their LDAP credentials, the directory verifies them,
and then axess prompts for the user's TOTP code. The TOTP secret is
stored in axess's own factor store (not in LDAP), under the user's
scope. The combination gives directory-managed passwords with an
application-managed second factor; the directory does not need to
know about TOTP and the application does not need to know about
the password.

A variation is LDAP followed by `AnyOf(vec![Totp, Fido2])`,
allowing the user to register a passkey alongside or instead of
TOTP. The flow is otherwise unchanged.

## Threat model

LDAP bind is robust against the same attacks any second-factor
method is robust against: credential reuse from other services,
local password lists, offline brute-forcing of a stolen hash (the
hash never leaves the directory).

It is weak against attacks the directory itself is weak against. A
directory that allows anonymous binds is vulnerable to attribute
enumeration. A directory whose bind path is misconfigured to accept
empty passwords for any DN is catastrophically vulnerable. The
defence is operational: configure the directory correctly, audit
periodically, and treat the LDAP factor's security as a function of
the directory's security posture.

The application also has to be careful about what it logs. The bind
password should never appear in application logs at any level,
including trace. Axess does not log it; adopters' own login handlers
need to make the same guarantee. The standard pattern is to mark
the password field as zeroized and to route it directly into the
verifier without touching it again.

## Troubleshooting

If binds fail consistently with "invalid credentials" for known-good
passwords, the bind DN template is most likely wrong. Active
Directory typically expects `userPrincipalName` (the user's email
address) or `sAMAccountName` (a short login name) in the bind, not
a constructed DN. The template might need to be `{user}@example.com`
rather than `uid={user},ou=people,dc=example,dc=com`.

If the connection succeeds but the bind times out, the directory is
under load or the connection is being inspected by a middlebox that
buffers slowly. The connection timeout fires; the user sees a
generic failure. Inspect the network path.

If the group search returns nothing, the filter template might be
wrong or the bound user might not have permission to read group
membership. OpenLDAP often requires explicit ACLs for the bound
user to enumerate groups they are members of; Active Directory
usually grants this by default. Run the same search through a
known-good LDAP client to verify.

If TLS fails with a certificate-validation error, the directory's
certificate is probably signed by a private CA that the application's
trust store does not include. Add the CA to the rustls trust store
via the standard `SSL_CERT_FILE` or `SSL_CERT_DIR` environment
variables.

## Further reading

*Factors and methods* covers the composition machinery this chapter
exercises. *Identity store implementation* covers how user records
referenced by LDAP get provisioned in the application's identity
store (typically just-in-time on first successful LDAP login).
*Multi-tenancy* covers the case where different tenants federate to
different directories.
