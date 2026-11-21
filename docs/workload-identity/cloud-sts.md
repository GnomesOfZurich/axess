# Cloud STS exchange

After an inbound resolver authenticates a workload, the application
may need to call AWS, GCP or Azure APIs on the workload's behalf. The
cloud-native way is to exchange the workload's identity for short-lived
cloud credentials at the provider's Security Token Service. All three
major clouds support this under similar names (AWS STS
`AssumeRoleWithWebIdentity`, GCP Workload Identity Federation, Azure
Federated Identity Credentials), and axess provides an adapter for each.

The feature flags are `aws-sts`, `gcp-wif`, and `azure-fic`, plus
an umbrella `cloud-sts` that enables all three. All are off by
default.

## The pattern

The pattern is the same on every cloud. The application holds a
validated workload identity (a JWT-SVID, a federated OIDC token, a
GitHub Actions OIDC token) and needs to call a cloud API on the
workload's behalf. Instead of giving the workload a long-lived cloud
key, it exchanges that identity at the cloud's STS endpoint for a
short-lived credential bound to one cloud role.

```text
   workload identity      STS exchange       short-lived cloud credential
        token        ───>      ───>          (15 minutes, role-scoped)
                                                    │
                                                    ▼
                                              cloud API call
```

The exchange happens at the application layer, server-side. The
workload's identity token goes only to the STS endpoint, never to
the cloud API; the short-lived cloud credential is what makes the
actual cloud API call. The benefit is that no long-lived cloud key
ever sits on the workload's filesystem, and a workload that can no
longer get identity tokens from its issuer can no longer get cloud
credentials once the tokens it holds expire, without any cloud-side
action. A credential already issued stays valid until it expires.

## The three clouds

The same exchange, spelled three ways.

### AWS STS

The AWS adapter calls `AssumeRoleWithWebIdentity`, the STS API for
identity federation. The configuration:

```rust,ignore
use axess_core::workload::outbound::cloud_sts::aws::{
    AssumeRoleWithWebIdentityRequest, AwsStsClient,
};

// Defaults to the global endpoint; `with_endpoint` pins a regional one
// (or LocalStack), `with_client_settings` names a User-Agent, a private
// root or an outbound-mTLS certificate; a proxy comes from HTTPS_PROXY.
// Every call times out after 30 s; `with_timeout` adjusts that. The
// constructor fails when the default HTTP client cannot be built, rather
// than fall back to one that follows redirects.
let client = AwsStsClient::new()?;

let request = AssumeRoleWithWebIdentityRequest::new(
    "arn:aws:iam::123456789012:role/billing-api-prod",
    "billing-api",   // the session name CloudTrail records
    token,           // the workload's own JWT
)
.with_duration(Duration::from_secs(900))?; // 15 minutes
```

The `role_arn` is the AWS role the credential assumes. The role's
trust policy, configured on the AWS side, specifies which web-identity
tokens may assume it; the application's workload-identity issuer must
match what the policy allows.

`with_duration` sets the lifetime of the resulting credential, a
whole number of seconds; left unset, AWS's default of one hour
applies. AWS allows between 15 minutes and 12 hours
(`MIN_DURATION`, `MAX_DURATION`), and `with_duration` refuses, with
`AwsStsError::InvalidDuration`, a duration outside that range or with a
fraction of a second; the role's maximum session duration can lower the
ceiling. Fifteen minutes is
the recommended setting; a longer duration saves re-exchanges at
the cost of some defence against credential theft.

The session name, the second argument, is how the resulting
session is named in CloudTrail and AWS audit logs: 2 to 64
characters from letters, digits and `_+=,.@-`. Naming the session
after the workload identity (its `WorkloadId`) makes the audit
trail readable.

The call returns the credentials as plain values (access key,
secret, session token and expiry), not as an AWS SDK credentials
provider, so the application builds the SDK's `Credentials` from
them:

```rust,ignore
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use std::time::SystemTime;

async fn call_aws(
    client: &AwsStsClient,
    principal: &Principal,
) -> Result<(), Error> {
    let assumed = client
        .assume_role_with_web_identity(&request_for(principal))
        .await?;
    let c = &assumed.credentials;
    let creds = Credentials::new(
        &*c.access_key_id,
        &*c.secret_access_key,
        Some(c.session_token.to_string()),
        SystemTime::try_from(c.expiration).ok(),
        "axess-sts",
    );

    let s3_client = aws_sdk_s3::Client::from_conf(
        aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("eu-central-1"))
            .credentials_provider(creds)
            .build(),
    );
    s3_client.list_buckets().send().await?;
    Ok(())
}
```

### GCP Workload Identity Federation

The GCP adapter calls Google Cloud's federated-credentials
endpoint, which exchanges a token from an external identity
provider for a Google Cloud access token. The configuration:

```rust,ignore
use axess_core::workload::outbound::cloud_sts::gcp::{
    GcpServiceAccountImpersonator, GcpStsClient, WorkloadIdentityPoolProvider,
};

let provider = WorkloadIdentityPoolProvider::new(
    123_456_789,            // project number
    "axess",                // pool id
    "external-oidc",        // provider id
);
let client = GcpStsClient::new()?;
let federated = client
    .exchange_token(
        token,              // the workload's own JWT
        &provider,
        &["https://www.googleapis.com/auth/cloud-platform"],
    )
    .await?;

let impersonator = GcpServiceAccountImpersonator::new()?;
let sa_token = impersonator
    .generate_access_token(
        &federated.access_token,
        "billing-api@my-project.iam.gserviceaccount.com",
        &["https://www.googleapis.com/auth/devstorage.read_only"],
        Some(900),          // lifetime in seconds; None means GCP's 3600
    )
    .await?;
```

The project number, pool id and provider id name the GCP-side
configuration that maps external identities to GCP identities.
`WorkloadIdentityPoolProvider` composes them into the audience
GCP's STS expects, with the location fixed at `global`;
`from_audience` takes an audience string already in that form. You
configure the pool and provider on the GCP side with the `gcloud`
CLI or Terraform; the adapter references them by name.

The exchange returns a federated token, which only the few GCP APIs
that accept workload identity principals take directly. For the
rest, a second call, `generate_access_token`, impersonates a GCP
service account, named by its email. The service account's IAM
bindings determine which GCP resources the resulting credential can
access.

The `scopes` argument, which both calls take, bounds what the
credential can be used for. The narrowest scope that works is the
one to request; `cloud-platform` is the broadest, for use only when
you need unrestricted access.

### Azure Federated Identity Credentials

The Azure adapter exchanges an external identity for an Azure AD
access token through the FIC (Federated Identity Credential)
mechanism. The configuration:

```rust,ignore
use axess_core::workload::outbound::cloud_sts::azure::{
    AzureFicClient, AzureFicRequest,
};

let client = AzureFicClient::new(
    "00000000-0000-0000-0000-000000000000",   // Azure AD tenant
    "11111111-1111-1111-1111-111111111111",   // managed identity / app id
)?;

let request = AzureFicRequest::new(token)
    .with_scope("https://storage.azure.com/.default");
let response = client.acquire_token(&request).await?;
```

The `tenant_id` is the Azure AD tenant. The `client_id` is the
managed identity or application registration in that tenant that
the exchange will authenticate as; the FIC binding on the managed
identity determines which external tokens may exchange for it.

The `scope` is the Azure AD resource the resulting token is bound
to. Azure tokens are audience-scoped; a token for storage cannot
be used against Key Vault. List the scopes you need;
use the `.default` suffix to inherit the managed identity's
configured permissions.

## Credential lifecycle

The credentials from all three STS endpoints carry an explicit
expiry, and the application's call path must respect it.

The simple shape is one exchange per cloud call. The application
exchanges, makes the call and discards the credential. The latency
overhead is one STS round-trip per call (typically 50 to 200 ms
depending on the cloud), which is acceptable for one-off
operations.

The optimised shape caches the exchanged credential while it is valid. The application exchanges once, caches
the credential, uses it for subsequent calls until it nears
expiry, then re-exchanges. The cache key is the workload identity
plus the target role; the cache value is the credential plus its
expiry.

The right shape depends on the call rate. Below a few calls per
minute, the simple shape is fine. Above that, the optimised
shape with a per-workload cache (a `ClockTtlCache` from
`axess-cache`) eliminates the per-call STS round-trip.

A credential that expires mid-call produces an authentication error
from the cloud SDK; catch it and re-exchange.
`ClockTtlCache` does no refreshing of its own: it applies one TTL to
every entry and returns nothing once an entry has expired. Set that
TTL shorter than the credential lifetime, so an entry expires, and
the next call re-exchanges, before the credential does.

## Multi-cloud deployments

A deployment that uses several clouds (for example, a workload that
calls both AWS and GCP) configures one client per cloud. The
two are independent; they share the workload identity as input
but produce cloud-specific credentials as output.

The application holds a workload principal and whichever of
`AwsStsClient`, `GcpStsClient` and `AzureFicClient` it needs; calls to
each cloud go through that cloud's client, with no cross-cloud coupling.

## Threat model

Cloud STS exchange limits the damage of credential theft: the
credentials it produces are short-lived, so a stolen one expires within
minutes whatever the attacker does.

The remaining attack surfaces:

**The workload identity itself.** A compromised workload
identity can be exchanged for fresh cloud credentials at any
time. The defence is to keep the workload identity short-lived
(SPIRE rotates SVIDs every few hours, GitHub OIDC tokens expire
within minutes), so a compromised identity has a bounded lifetime.

**The STS endpoint.** A compromised STS issues
compromised credentials. The defence is operational: the cloud
provider secures its STS. The adapters reach it only over HTTPS
and reject a response that does not parse as the expected shape,
but they check no signature on the credentials it returns, so you
cannot independently verify that the STS itself is honest.

**The role's trust policy.** A misconfigured trust
policy allows any workload to assume the role, defeating the
identity-based restriction. The defence is to review trust
policies at deployment time and grant least privilege.

## Audit

Each exchange produces a cloud-side audit event: CloudTrail for AWS,
Cloud Audit Logs for GCP, Activity Log for Azure. **Axess emits
nothing of its own here.** These clients are primitives you call
directly, with no audit sink on the call path, and the event
vocabulary has no name reserved for a token exchange. For the axess half of the picture, record each exchange where you
perform it, so you know which identity was exchanged, when, for which role,
and what cloud actions the resulting credential performed.

*Audit pipeline* covers retention. Keep STS-exchange events longer
than ordinary authentication events: they are the evidence for later
compliance reviews of cross-cloud actions.

## Troubleshooting

If the exchange returns `AccessDenied` from AWS STS, the role's
trust policy does not admit the token: check the policy's
`Principal.Federated` and its `aud` and `sub` conditions. If it returns
`InvalidIdentityToken`, the failure is earlier: the issuer is not a
registered IAM provider, or the token's audience is not in the provider's
client ID list. The [AWS walkthrough](aws.md) reproduces each.

If the exchange returns `INVALID_ARGUMENT` from GCP, the
workload identity pool or provider name is wrong, or the token's
shape does not match what the provider expects. Inspect the
provider configuration through `gcloud iam workload-identity-pools
providers describe`.

If the exchange returns `AADSTS70021` from Azure, the FIC binding
on the managed identity does not match the token's subject claim.
Update the FIC configuration to match what the workload identity
emits. The [Azure walkthrough](azure.md) reproduces this and its
neighbours (`AADSTS700211` for the issuer, `AADSTS700212` for the audience).

## Further reading

*Inbound: JWT-SVID* and *Inbound: federation* cover the resolvers
that produce the workload identity exchanged here.
*Outbound: OAuth* covers OAuth-based outbound credentials, which
are an alternative to cloud STS for some non-cloud downstreams.
*Audit pipeline* covers the retention configuration for
cross-cloud audit events.
