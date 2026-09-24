# Two findings that should block 0.6.0, with options

Written for: whoever decides whether 0.6.0 publishes. Both findings come from
reviewing the 0.6.0 changes as an attacker and as an enterprise reviewer. Neither
is a regression in the ordinary sense: the first is work that was never
connected, the second is a new attack path created by two correct fixes meeting.

---

## Finding 1: the client-metadata chain is not wired to anything

### What is true

```
ip_from_headers_trusted → extract_audit_context → AuditContext → with_audit_context → AuthEvent.ip_address
                                                                          ↑
                                                            called only by its own unit tests
```

- `AuthEventBuilder::with_audit_context` exists and works. Its only callers are
  four assertions in `authn/event/tests.rs`.
- `extract_audit_context` is called only by its own sibling wrappers
  (`extract_audit_context_untrusted`, `extract_audit_context_async`) and by tests.
- **No path in `authn/service/` or `federation/` attaches a context to an event**,
  and `AuthnService` has no context field or per-request mechanism to carry one.

So the seam is not dead code in the compiler's sense: it is exercised, just never
by the authentication flow whose events it was built to stamp.

Therefore every audit row axess writes carries `ip_address: None`,
`user_agent: None`, `request_id: None`. This release hardened the resolution of a
value the service never stores, and then made its type stricter.

### Why it matters more than an unused function usually would

`SECURITY.md` offers the audit catalogue as SOC 2 and PCI-DSS evidence. An
auditor reading the 0.6.0 changelog sees "the audit trail's client IP was
attacker-controlled" listed as fixed. What shipped is a trail with no client IP
at all. That is safer than a forged one, and it is not what the document implies.

It also explains the one gap in the examples: none of them resolves a client IP,
because there is no seam to resolve it into.

### Options

**A. Thread an `AuditContext` through the authn entry points.**
`begin_login`, `verify_factor` and the OAuth ceremony steps take
`Option<&AuditContext>`, and `emit_audit` applies it. Explicit, testable, no
hidden state. Costs a parameter on the public surface of roughly a dozen methods,
which is a breaking change: free today, not after publication.

**B. Hold the context on the service per request.**
`AuthnService::with_context(&ctx)` returning a cheap borrowed view that carries
the context into the events it emits. Keeps existing signatures. Adds a second
way to call everything.

**C. Task-local.**
A `tokio::task_local!` the axum layer sets, read by `emit_audit`. No signature
churn at all, and invisible: a caller outside a request, or on a spawned task
that did not inherit the local, silently reverts to `None`. Hard to test, easy to
get wrong.

**D. Ship as is, and document it.**
State plainly that axess does not populate client metadata on the events it
emits, that `AuditContext` is for adopter-constructed events only, and drop the
SOC 2 / PCI-DSS framing to match. Honest, and cheap. Leaves the type doing
nothing for the flows that matter.

**E. A context-carrying copy of the service.**
`AuthnService::with_audit_context(ctx) -> Self`, holding the context in a new
field that `emit_audit_at` applies to every builder. The adopter writes:

```rust
let svc = state.authn.with_audit_context(ctx);
svc.begin_login(/* unchanged arguments */).await?;
```

Zero changes to any existing signature, one change at the single point all
thirty emit sites funnel through, and **additive rather than breaking**. It is
explicit: the method exists, returns a value, and a test can assert an event
carried the address.

Costs: `AuthnService` must become `Clone`, which means a manual impl (the `I`
and `F` parameters sit behind `Arc`, so a derive would add wrong bounds) and a
`Clone` derive on `OAuthProviderRegistry`. The clone is cheap but not free
every field is an `Arc` or a small value except that registry, which is a
`HashMap` of `Arc`s, so the cost is O(providers) per request. And
`add_oauth_provider` on a per-request copy would register into the copy alone,
which needs saying.

### Resolution

**Done, as E with the handle shape.** `AuthnService` is now
`{inner: Arc<Inner>, audit: Option<Arc<AuditContext>>}`, so `Clone` is four
lines and O(1), `with_audit_context` returns a copy per request, and
`emit_audit_at`: the single point all thirty emit sites funnel through
applies it. Construction moved to `AuthnService::builder(..).build()`,
which makes customising an already-shared service impossible by
construction rather than by a panic.

The silent-omission worry is answered by `AuditContextPolicy::Required`,
which refuses to write an event carrying no client metadata. It defaults to
`Optional`, and it is itself a fail-closed path, so it is opt-in.

Wiring it turned up two further gaps, both the same shape as the original:
the `axess` facade exported `ip_from_headers_untrusted` but **not**
`ip_from_headers_trusted` or `TrustedProxies`, so an adopter on the facade
could reach only the spoofable helper; and no example resolved a client
address at all. Both fixed; `examples/sqlite` now does the full resolution
in `post_login`.

**Original reasoning, kept because the measurement is the point:**

**Revised recommendation: E, not A.**

The first draft of this document recommended A. Measuring it changed the answer:
`authn/service/` has **44 public entry points**, and A means a new parameter on
every one that emits, plus the thirty emit sites. That is a large breaking change
to land late, and it taxes every caller: including the ones with no HTTP request
in hand and nothing to pass.

E gets the same property for a fraction of the diff and breaks nobody, which
also means it is not gated on publishing 0.6.0 first. The argument for A was
"breaking is free before publication"; that argument is worth less than not
needing to break anything at all.

C remains rejected for the reason given, and D remains the honest fallback if
neither is built.

---

## Finding 2: unauthenticated audit writes can take authentication down

### The chain

Three true statements that compose badly:

1. Every failed login now writes an audit row, including for identifiers that do
   not exist. This was deliberate: it is what stops an audit-store outage from
   becoming an enumeration oracle, and it closes a credential-stuffing blind spot.
2. A failed audit write now fails the login. Also deliberate: an authentication
   that leaves no evidence has not, for evidence purposes, happened.
3. Rate limiting is an adopter-applied tower layer. Nothing inside
   `AuthnService` enforces it.

So an unauthenticated attacker sending logins for random identifiers forces one
audit-store write per request, with no ceiling the library imposes. Exhaust the
store: disk, IOPS, quota, connection pool, and step 2 converts that into
**every login failing, for every user**.

Before 0.6.0 this did not exist, because a failed audit write was swallowed.

### What it is not

Not an argument to revert either change. Fail-open on audit and a silent
enumeration oracle are both worse. The gap is that the amplification was not
reasoned about when the two were introduced.

### Options

**A. A global token bucket on unattributed failure events.**
Bounds writes from identifiers that resolve to no user. Must be global, never
per-identifier: a per-identifier limit reintroduces the oracle, because the
attacker learns which identifiers are cheap. Over the limit, the event is
counted in a metric and dropped, and the login still fails.
Cost: a dropped event is a gap in the trail, which is what the release just spent
its budget closing. The gap is bounded and observable, which the previous one was
not.

**B. Enforce rate limiting inside the service.**
`AuthnService` refuses before the store is touched. Removes the "adopter forgot
the layer" failure mode entirely. Cost: the service needs a clock-driven limiter
and a key it can trust, which is the client IP: see Finding 1.

**C. Separate "store unavailable" from "store full".**
Fail closed on an outage, shed unattributed events on a capacity signal. Most
precise, and needs a richer error from `IdentityAuthnLog` than it has.

**D. Document the requirement and the metric.**
State that the rate-limit layer is mandatory in front of login routes, and that
`audit_store_outage` is a paging alert. Cheapest; leaves a library whose safe
operation depends on a step an adopter can skip silently.

### Resolution

**Done, and not as B.** Building a limiter into `AuthnService` would have
duplicated the rate-limit middleware and put capacity policy in the wrong
place: the *sink* owns the storage, so the sink owns the policy. What it
lacked was a way to say so. `record_event` now returns `AuditOutcome`, so a
sink can report `Shed`: dropped deliberately, flow continues, metric fires
distinctly from `Err`, which still fails the login.

The trap, documented on the trait: shedding must key on something
identifier-independent. A per-identifier shed decision is observable per
identifier and rebuilds the oracle that unattributed events closed.

`NoopAuthnLog` now reports `Shed`, which is what it always did; before, it
returned `Ok(())` and claimed writes it discarded.

**Original analysis:**

**Note the dependency:** B needs a key it can trust to limit on, and the only
sane key is the client IP, which Finding 1 says the service cannot currently
see. B is therefore gated on Finding 1, whichever shape that takes.

**Recommendation: B, with D immediately.** D is done: `SECURITY.md` now states
that the rate-limit layer is required in front of login routes, why, and what
happens without it. B is where this belongs: a security
library should not have a documented-but-unenforced prerequisite for its own
availability. A is a reasonable interim if B does not fit 0.6.0, but note that it
trades evidence completeness for availability, and that trade should be recorded
rather than absorbed.

---

## Finding 3: three panicking trait defaults remain, and one is unconditional

0.6.0 fixed `store_reset_token`, whose `unimplemented!()` default turned
"forgot password" into an enumeration oracle. Three defaults with the same
shape, and the same stated rationale ("panics so a missing override surfaces
loudly"), were not part of that fix:

| method | reached when | severity |
|---|---|---|
| `IdentityPasswordHistory::record_password_hash` | **every password change**, unguarded | guaranteed panic for any backend without an override |
| `IdentityPasswordHistory::password_history` | only when `history_count > 0` | panics for adopters who configure the rule |
| `IdentityAdmin::delete_user` | admin erasure | documented in the migration guide |

`record_password_hash` is the one that matters. `password_reset.rs` carries the
comment "Record old hash in password history (if backend supports it)", but
there is no support check. The `if let Some(FactorConfig::Password(..))` beside
it tests whether an *old password exists*, not whether the backend implements
the method, and the second call site at line 253 has no guard at all. An adopter
who reads the trait, sees a defaulted method, and moves on gets a panic the first
time any user changes a password.

`password_history` is genuinely guarded (`history_count == 0` returns early), so
it fires only for adopters who opted into the rule, which is the population most
likely to have implemented it, though not certainly.

### Why the rationale does not hold

"Panic so the omission is loud" is the argument 0.6.0 already rejected once. A
panic is loud in development and is an outage in production, and it arrives on
whichever unlucky user changes their password first. The fix applied to password
reset works here unchanged: move the pair to a trait with no default bodies, and
bound the password-change flow on it. The omission then fails at compile time,
naming both methods, instead of at runtime naming one user.

`delete_user` is a weaker case: erasure is an administrative action, it is
already documented as panicking, and a backend that cannot erase arguably should
not silently succeed. Returning a "not supported" error is still better than
unwinding through an admin handler.

### Resolution

**Done.** `record_password_hash` and `password_history` now live on
`IdentityPasswordHistory`, with no default bodies, carved out exactly as
`IdentityPasswordReset` was, and the password flow is bounded on it. The table
above names their new owner. `delete_user` is left as it was: no axess flow
calls it, so the panic fires only for an adopter calling a method they chose not
to implement. Breaking, and free before publication.
At minimum, delete the "(if backend supports it)" comment, which is false and is
the sentence most likely to stop a reader from looking further.

## Finding 4: the timing equalisation rests on an unstated store assumption

`find_user_with_timing_equalization` is the defence the whole enumeration story
rests on, and it is structurally right: on the unknown-identifier path it runs
`account_status` and `available_methods` against a dummy id, so both paths issue
the same three store calls. axess itself caches none of them.

The dummy id is a **fresh random UUID**, which is the part worth stating out
loud. It can never hit a cache. An adopter whose `IdentityStore` caches
`find_user` or `account_status`: an obvious optimisation, and one the
`axess-cache` crate ships a primitive for: gets:

- known identifier → cache hit → fast
- unknown identifier → fresh UUID → guaranteed miss → slow

which does not merely weaken the equalisation, it **inverts it**, and repeated
probing of a known identifier warms its entry and widens the gap. The control
silently becomes an oracle in the deployments most likely to be under load.

This is not a defect in the function. It is a contract that exists and is not
written down: an `IdentityStore` implementation must not let lookup latency
depend on whether the key exists. Nothing in the trait docs says so, and an
adopter adding a cache has no reason to suspect they are dismantling a security
control.

`axess-cache`'s own module docs already warn that caching authentication state is
"widely flagged by PSD2/FAPI/SCA-style auditors": the right instinct, aimed at
compliance rather than at this.

### Recommendation

**Done.** The contract is now stated on `IdentityLookup::find_user`, naming
`account_status` alongside it, and in the `SECURITY.md` operator checklist: if
you cache, cache negative results on the same terms as positive ones.

Worth noting the equalisation is best-effort regardless: a database lookup for
an absent row is not guaranteed to cost what a present one costs, even
uncached. The function's value is in removing the *large* differences; this
finding is about not having a cache reintroduce one.

## The pattern underneath the first three

Each is a seam that exists but carries nothing: the context type with no producer,
the rate limit with no enforcement point, the trait method with no implementation
and a panic where the contract should be. All three fail by omission rather than
by doing something wrong, which is why the test suite and the gates are all green
around them.

Worth considering a gate that fails when a public builder method is called only
from its own tests. `with_audit_context` would have been caught the day it was
written, and a unit test asserting it works is precisely what made it look fine.

A note on how this finding was nearly mis-stated. The first pass searched for
`with_context`, found nothing, and concluded "zero callers anywhere": a stronger
claim than the truth, reached by grepping a method name that does not exist. The
documented-identifier gate rejected the draft of this very document for naming a
type the workspace does not have, which is how the error surfaced. The lesson is
the one already written down: a grep result is a candidate, not evidence, and a
search that returns nothing is the case most in need of a second look.
