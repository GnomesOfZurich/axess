# Shared secrets: the last resort

Some machine callers cannot do any of what the rest of this part
describes. A mail relay posting a bounce, an intake worker handing over
a document, a cron job poking an endpoint: often the only credential
such a caller can be given is a string both ends know. The
`service-secret` feature checks that string properly, so routes stop
comparing it by hand. It is off by default.

**A shared secret is the weakest machine credential axess offers.** Use
it only for a caller that cannot hold a key or fetch a token, and only
over TLS.

## How it compares

| | Presented secret | Signed request | JWT or mTLS |
|---|---|---|---|
| Layer | `ServiceSecretLayer::bearer`, `ServiceSecretLayer::header` | `ServiceSecretLayer::signed` | `jwt-svid`, `jwt`, `mtls` resolvers |
| What travels | The secret, on every request | A signature over time, method, path and body | A short-lived token, or a TLS handshake |
| A captured request lets an attacker | Call any route that accepts the secret, for as long as it is valid | Nothing; it is refused once replayed or too old | Nothing beyond the token's short lifetime |
| The server holds | A digest that cannot be presented | A key that can sign as the caller | Only public keys; it cannot impersonate the caller |
| Expiry | Only when someone rotates it | Only when someone rotates it | Built in |
| Identity | A configured name (`ServiceCaller`) | A configured name (`ServiceCaller`) | A `Principal::Workload` that Cedar policies see |

Read the table from right to left. When you control the caller, sign the
requests. When the caller can hold a key or reach an identity provider,
use the other chapters of this part instead.

`ServiceCaller` is a gate, not a principal: it tells the handler which
configured secret matched, and Cedar policies do not see it. A route
that needs per-caller authorization beyond "is one of these" wants a
workload identity.

## Signed requests

The caller and the route share a secret of at least `MIN_SECRET_LEN`
(32) bytes; `openssl rand -hex 32` makes a good one. Both sides load it
the same way. `ServiceSecret::from_env` reads the file named by
`{VAR}_FILE` when it is set, as container secret stores mount them, and
`{VAR}` otherwise.

The route:

```rust,ignore
use axess::service_secret::{ServiceSecret, ServiceSecretLayer, ServiceSecrets, SignedRequests};

let secrets: ServiceSecrets = ServiceSecret::from_env("intake", "INTAKE_WEBHOOK_SECRET")?
    .into_iter()
    .collect();
let router = router.layer(ServiceSecretLayer::signed(
    secrets,
    SignedRequests::default().audience("intake"),
)?);
```

The caller:

```rust,ignore
let signer = ServiceSecret::from_env("intake", "INTAKE_WEBHOOK_SECRET")?
    .expect("configured")
    .signer();
let header = signer.sign_for("intake", now_unix_seconds, &Method::POST, "/public/intake/bounce", &body);
client.post(url).header(SIGNATURE_HEADER, header).body(body).send().await?;
```

The route reads the body in full to check the signature (up to
`SignedRequests::max_body_bytes`, 1 MiB by default, `413` beyond it),
then hands it on unchanged. It refuses a signature whose timestamp is
more than `SignedRequests::tolerance` (five minutes by default) from
its clock in either direction, and one it has already accepted within
that window.

The replay memory is per process. Behind several instances, a request
replayed to a different instance inside the window is not caught.
Handlers that change state should still be idempotent.

A signature names its recipient. The route is configured with
`SignedRequests::audience("intake")`, the caller signs with
`ServiceSigner::sign_for("intake", ...)`, and the signature covers that name
(`v2`), so what one recipient receives does not verify at another service
that shares the secret. A `SignedRequests` with no audience is refused by
`ServiceSecretLayer::signed` with `ServiceSecretError::MissingAudience`.
Even so, give every recipient its own secret: a secret shared by two
recipients is one recipient's compromise away from being both's.

Callers written before the audience existed sign `v1`, which names no
recipient and can be replayed against any other service sharing the secret.
A route refuses `v1` unless it opts in for a migration window with
`SignedRequests::accept_unaddressed_until(instant)`, checked against the
route's clock. Move the callers to `sign_for` first, set the window to the
date by which they will have moved, and delete the setting afterwards (at the
instant the route stops reading `v1` whether or not it is deleted).

A caller not written in Rust can sign by following the recipe on
`SIGNATURE_HEADER`: an HMAC-SHA256 key derived from the secret, then an
HMAC-SHA256 over the version, timestamp, method, request target and
body, sent as `t=<seconds>,v2=<hex>`, with the audience between the request target and the body.

## Presented secrets

`ServiceSecretLayer::bearer` reads `Authorization: Bearer <secret>`;
`ServiceSecretLayer::header` reads a header you name. Use these only
for a caller you cannot change, one that can only be told to send a
fixed header. Rotate the secret on a schedule, keep the route's access
logs free of request headers, and do not accept the same secret on any
route that does more than the caller needs.

## In every mode

- **Rotation.** Secrets are named. Configure the new one beside the old
  (`ServiceSecrets::with`), move the caller over, then remove the old
  one. The name of the one that matched reaches the handler as
  `ServiceCaller`, so logs show which callers have not moved yet.
- **Timing.** Every configured secret is compared in constant time on
  every request, so neither a secret's length nor which caller matched
  shows in how long a refusal takes.
- **Nothing to leak from memory.** The secret itself is not kept, only
  values derived from it, and `{:?}` prints the caller's name alone.
- **Unconfigured routes are absent.** With no secret configured the
  route answers `404`, as if it did not exist, rather than `401` or,
  worse, letting requests through. A wrong or missing credential
  answers `401`.
