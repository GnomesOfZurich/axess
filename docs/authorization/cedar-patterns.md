# RBAC, ReBAC, and ABAC patterns

The three letter-soup acronyms RBAC, ReBAC, and ABAC name the three
standard styles of authorisation. Cedar is one of the few policy
languages that admits all three in the same set of rules. This
chapter walks through each style with worked examples, then shows
how to compose them in a single policy set without the rules
fighting each other. The examples are concrete enough that you
should be able to paste them into a `.cedar` file and have them
type-check against a corresponding schema.

## RBAC: roles as groups

Role-based access control assigns users to roles and assigns
permissions to roles. The model has been the workhorse of
enterprise authorisation since the 1990s and remains the right
starting point for most applications.

The schema declares roles and the action permissions they hold:

```cedar,ignore
entity User {
    tenant_id: String,
};

entity Role;

entity Document {
    tenant_id: String,
    owner: User,
};

action read appliesTo {
    principal: [User],
    resource: [Document],
};

action edit appliesTo {
    principal: [User],
    resource: [Document],
};
```

The policy grants the role-action mappings:

```cedar,ignore
permit (
    principal in Role::"viewer",
    action == Action::"read",
    resource
);

permit (
    principal in Role::"editor",
    action in [Action::"read", Action::"edit"],
    resource
);
```

The entity provider, on each request, attaches the user's role
memberships as parent entities. A user in `Role::"viewer"` has
that role in their `parents` list; a user in `Role::"editor"` has
that role in their `parents` list and inherits `read` permission
through the second policy's action set.

The shape works for most applications until two situations arise.
The first is when permissions need to depend on the relationship
between the principal and the resource (a user can edit their own
documents but not others'), which is the ReBAC case below. The
second is when permissions need to depend on the request context
(MFA must be present for sensitive actions), which is the ABAC
case below.

## ReBAC: relationships as paths

Relationship-based access control assigns permissions based on the
relationship between the principal and the resource, not on a
role label. The classic example is ownership: a user can edit a
document they own.

The schema does not change much; the relationship is already on
the entity:

```cedar,ignore
entity Document {
    tenant_id: String,
    owner: User,
    shared_with: Set<User>,
};
```

The policy expresses the relationship:

```cedar,ignore
permit (
    principal,
    action == Action::"edit",
    resource
) when {
    resource.owner == principal
};

permit (
    principal,
    action == Action::"read",
    resource
) when {
    resource.owner == principal
    || principal in resource.shared_with
};
```

The first rule grants edit to the owner. The second rule grants
read to the owner or to anyone in the resource's `shared_with`
set. The set membership `principal in resource.shared_with` is the
ReBAC primitive: the principal is in some set on the resource, and
the policy matches on that.

More elaborate relationships involve multi-hop paths. Consider a
"team" model where a user belongs to a team, the team owns
projects, and the projects contain documents. The schema:

```cedar,ignore
entity Team;

entity Project {
    owner_team: Team,
};

entity Document {
    project: Project,
};

entity User in [Team];
```

The policy that says "anyone in the team that owns the project
that contains this document can read the document":

```cedar,ignore
permit (
    principal,
    action == Action::"read",
    resource
) when {
    principal in resource.project.owner_team
};
```

The `in` operator follows the entity graph: `resource.project`
yields a `Project` entity, `.owner_team` yields a `Team` entity,
and `principal in Team` checks the principal's `parents` list. The
entity provider populates the graph: the document with its project
parent, the project with its owner_team attribute, the user with
their team memberships. Cedar walks the graph at evaluation time.

The pattern generalises to any depth, though policies that walk
more than two or three hops start to feel hard to review. When the
depth gets uncomfortable, extract the relationship into an
intermediate entity (a "can_view" set on the document that the
application's data layer computes ahead of time) and let the
policy match on the simpler shape.

## ABAC: attributes as conditions

Attribute-based access control adds context to the decision. The
attributes might be on the principal (MFA status, last
authentication time), on the resource (sensitivity level), or on
the request (IP address, time of day). A policy applies only when
the attributes match.

The schema declares the attribute shapes:

```cedar,ignore
entity User {
    tenant_id: String,
    mfa_completed: Bool,
    last_authn_at: Long,  // unix seconds
};

entity Document {
    tenant_id: String,
    classification: String, // "public" | "internal" | "secret"
};

type Context = {
    ip: String,
    now: Long,
};
```

The policy combines attribute conditions:

```cedar,ignore
permit (
    principal,
    action == Action::"read",
    resource
) when {
    principal.tenant_id == resource.tenant_id
    && (
        resource.classification == "public"
        || (
            resource.classification == "internal"
            && principal.mfa_completed
        )
        || (
            resource.classification == "secret"
            && principal.mfa_completed
            && context.now - principal.last_authn_at < 900  // last 15 min
        )
    )
};
```

The rule grants read access in three tiers: public documents to
anyone in the tenant, internal documents to anyone in the tenant
with MFA completed, secret documents to anyone in the tenant with
MFA completed in the last fifteen minutes. The attributes drive
the gradations; the policy expresses them in one statement.

ABAC is the right tool for time-sensitive, location-sensitive, and
context-sensitive policies. It is the wrong tool for static
permissions (use RBAC) or for relationship checks (use ReBAC). When
in doubt, write the policy and read it back: if the rule says
"users in X role can perform Y," it is RBAC; if it says "users with
relationship Z to this resource can perform Y," it is ReBAC; if it
says "users can perform Y when condition W," it is ABAC.

## Composing the three styles

A real production policy set mixes the three. A user who has the
`editor` role (RBAC) can edit any document, but a user who owns a
document (ReBAC) can edit it regardless of role, and a user trying
to edit a `secret` document must have MFA completed (ABAC).

```cedar,ignore
// RBAC layer: editors get full access.
permit (
    principal in Role::"editor",
    action in [Action::"read", Action::"edit", Action::"delete"],
    resource
);

// ReBAC layer: owners get full access to their own.
permit (
    principal,
    action in [Action::"read", Action::"edit", Action::"delete"],
    resource
) when {
    resource.owner == principal
};

// ReBAC layer: shared-with users get read access.
permit (
    principal,
    action == Action::"read",
    resource
) when {
    principal in resource.shared_with
};

// ABAC layer: secret documents require fresh MFA, forbid otherwise.
forbid (
    principal,
    action,
    resource
) when {
    resource.classification == "secret"
    && (
        !principal.mfa_completed
        || context.now - principal.last_authn_at > 900
    )
};
```

The `forbid` rule overrides any `permit` that would otherwise
match. The structure works because Cedar evaluates all rules: if
any `permit` matches and no `forbid` matches, the decision is
`Allow`; if any `forbid` matches, the decision is `Deny`
regardless of what `permit`s also match.

The pattern is to express the broad grants through `permit` rules
in increasing specificity (role, relationship, context), then to
express the absolute constraints through `forbid` rules. The
`forbid` rules are typically about high-sensitivity resources or
about high-risk principal states; they are the small set of cases
where a positive grant is not enough.

## Tenant isolation as a structural rule

Multi-tenant applications need a structural rule that no policy
should ever leak data across tenants. The right shape is a single
top-level `forbid`:

```cedar,ignore
forbid (
    principal,
    action,
    resource
) when {
    principal.tenant_id != resource.tenant_id
};
```

The rule applies to every action on every resource. Any later
`permit` that would have allowed a cross-tenant access is
overridden. The rule is the structural defence against the worst
class of authorisation bug a multi-tenant application can have: an
operator from tenant A accessing tenant B's data because of a
mistake in another policy.

The rule is also the right place to validate that the principal
has a tenant id at all. A workload principal might be in a global
trust domain (no tenant), in which case the comparison fails the
type system and the rule denies. The policy authoring style is to
treat tenant id as a required attribute on every multi-tenant
entity, and to let this `forbid` catch any drift.

## Step-up as a policy concern

Step-up authentication is the pattern where a user is asked to
re-prove identity (or to prove with a stronger factor) before
performing a sensitive action. The mechanism is in the state
machine (see *Factors and methods* §"Step-up authentication"); the
policy expresses when step-up is required.

The shape:

```cedar,ignore
forbid (
    principal,
    action == Action::"delete-account",
    resource
) when {
    !("Fido2" in principal.factors_completed)
};
```

The rule denies the account-deletion action unless FIDO2 is in the
user's completed factors. The user reaches the action with a
password-and-TOTP session, gets denied, and the application offers
step-up: the user completes the FIDO2 ceremony, the session's
`factors_completed` now includes `Fido2`, the next request to the
delete-account action passes the policy.

The pattern composes with the other styles. A `permit` rule says
who can delete an account (RBAC: the user themselves, ReBAC: the
admin who owns the user). The `forbid` rule adds the contextual
requirement (ABAC: FIDO2 in `factors_completed`). The three rules
together produce a policy that says "the user themselves can
delete their own account, but only after completing FIDO2 in this
session."

## Anti-patterns

The two patterns most likely to mislead are worth naming.

The first is duplicating ReBAC as RBAC. The temptation is to
materialise the ownership relationship as a per-resource role
("owner of document 123"), then write an RBAC policy that grants
edit to the role. The shape works but produces an explosion of
roles (one per resource), is hard to invalidate when ownership
changes, and obscures the relationship that the policy is actually
expressing. The right shape is to express ownership as an
attribute (`resource.owner == principal`) and write the ReBAC
policy directly.

The second is encoding state machines in policies. A workflow that
allows transitions only from certain states is a state machine,
not a policy. Writing it as a Cedar rule (`permit ... when {
resource.state == "draft" && action == "submit" }`) admits the
rule but makes the policy set the source of truth for what the
state machine allows. The right shape is to put the state machine
in code (or in a typed state machine in the application), and to
use Cedar only for "who can invoke this transition" rather than
"which transition is valid right now."

## Schema discipline

The most consequential decision in any Cedar integration is the
schema. The schema names every entity type, every attribute on
every entity, every action that applies to every principal-resource
pair, every required and optional context key. Getting the schema
right is most of the work; getting the policies right is what
follows naturally from a good schema.

Three rules help:

The first is to name entities by their domain meaning, not by the
table they live in. `User` is the right name; `usersRow` is the
wrong name. The policies that read like English are the ones that
let reviewers do their job.

The second is to declare attributes as required only when every
production deployment guarantees the attribute is present. An
attribute declared as required forces the entity provider to
return it on every load, which often forces the application to
add an `INSERT` default. Optional attributes are the right default;
require only when the policy logically depends on it.

The third is to update the schema whenever a policy expression
needs an attribute that is not yet declared. The validator catches
the inconsistency at load time; the alternative is a runtime deny
that is hard to debug. The schema is not optional; treat it as
part of the policy set.

## Further reading

*Cedar policy fundamentals* covers the policy lifecycle and the
evaluator surface. *Entity providers and request context* covers
the data-loading contract the policies in this chapter depend on.
*Audit events* covers the `AuthzEvent` variants the evaluator
emits, including the policy id that produced each decision. The
[Cedar documentation](https://docs.cedarpolicy.com/) covers the
language in full detail and is the authoritative reference for
syntax and semantics.
