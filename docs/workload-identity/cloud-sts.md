# Cloud STS exchange

A workload that has been authenticated through one of the inbound
resolvers may need to call AWS, GCP, or Azure APIs on the
workload's behalf. The cloud-native pattern for this is to
exchange the workload's identity for short-lived cloud credentials
through the cloud provider's Security Token Service. The mechanism
is supported by all three major clouds under similar names (AWS
STS `AssumeRoleWithWebIdentity`, GCP Workload Identity Federation,
Azure Federated Identity Credentials), and axess provides adapters
for each.

The feature flags are `aws-sts`, `gcp-wif`, and `azure-fic`, plus
an umbrella `cloud-sts` that enables all three. All are off by
default.

## The pattern

The pattern is uniform across clouds. The application has a
validated workload identity (a JWT-SVID, a federated OIDC token, a
GitHub Actions OIDC token). The application wants to call a cloud
API on the workload's behalf. Instead of giving the workload a
long-lived cloud key, the application exchanges the workload's
identity at the cloud's STS endpoint for a short-lived credential
bound to a specific cloud role.

```text
   workload identity      STS exchange       short-lived cloud credential
        token        ───>      ───>          (15 minutes, role-scoped)
                                                    │
                                                    ▼
                                              cloud API call
```

The exchange happens at the application layer, server-side. The
workload's identity token never leaves the application; the
short-lived cloud credential is what makes the actual cloud API
call. The benefit is that no long-lived cloud key ever sits on
the workload's filesystem, and revocation of the workload's
identity (at the issuer) propagates to the cloud access without
any cloud-side action.

## AWS STS

The AWS adapter calls `AssumeRoleWithWebIdentity`, the STS API for
identity federation. The configuration:

```rust,ignore
use axess::workload::cloud_sts::{AwsStsExchanger, AwsStsConfig};

let exchanger = AwsStsExchanger::new(AwsStsConfig {
    role_arn: "arn:aws:iam::123456789012:role/billing-api-prod".into(),
    region: "eu-west-1".into(),
    session_duration: Duration::from_secs(900),  // 15 minutes
    role_session_name_strategy: SessionNameStrategy::WorkloadId,
});
```

The `role_arn` is the AWS role the credential will assume. The
role's trust policy specifies which web-identity tokens may
assume it; the policy is configured on the AWS side, and the
application's workload-identity issuer must match what the policy
allows.

The `session_duration` is the lifetime of the resulting
credential. AWS allows between 15 minutes and 12 hours (configurable
per role). Fifteen minutes is the recommended default; a longer
duration trades off some defence against credential theft against
the overhead of re-exchanging.

The `role_session_name_strategy` controls how the resulting
session is named in CloudTrail and AWS audit logs. Naming the
session after the workload identity (`WorkloadId`) makes the
audit trail readable; alternative strategies are available for
deployments with specific compliance requirements.

```rust,ignore
async fn call_aws(
    exchanger: &AwsStsExchanger,
    principal: &Principal,
) -> Result<(), Error> {
    let creds = exchanger
        .exchange(principal_to_token(principal))
        .await?;

    let s3_client = aws_sdk_s3::Client::from_conf(
        aws_sdk_s3::Config::builder()
            .credentials_provider(creds)
            .build()
    );
    s3_client.list_buckets().send().await?;
    Ok(())
}
```

## GCP Workload Identity Federation

The GCP adapter calls Google Cloud's federated-credentials
endpoint, which exchanges a token from an external identity
provider for a Google Cloud access token. The configuration:

```rust,ignore
use axess::workload::cloud_sts::{GcpWifExchanger, GcpWifConfig};

let exchanger = GcpWifExchanger::new(GcpWifConfig {
    workload_identity_pool: "projects/123/locations/global/workloadIdentityPools/axess".into(),
    workload_identity_provider: "external-oidc".into(),
    target_principal: "billing-api@project.iam.gserviceaccount.com".into(),
    scopes: vec!["https://www.googleapis.com/auth/cloud-platform".into()],
});
```

The `workload_identity_pool` and `workload_identity_provider` name
the GCP-side configuration that maps external identities to GCP
identities. The pool and provider are configured on the GCP side
through the `gcloud` CLI or Terraform; the application's adapter
references them by name.

The `target_principal` is the GCP service account the exchange
impersonates. The service account's IAM bindings determine which
GCP resources the resulting credential can access.

The `scopes` list bounds what the credential can be used for. The
narrowest possible scope is the recommendation; `cloud-platform`
is the broadest and should be used only when the application
genuinely needs unrestricted access.

## Azure Federated Identity Credentials

The Azure adapter exchanges an external identity for an Azure AD
access token through the FIC (Federated Identity Credential)
mechanism. The configuration:

```rust,ignore
use axess::workload::cloud_sts::{AzureFicExchanger, AzureFicConfig};

let exchanger = AzureFicExchanger::new(AzureFicConfig {
    tenant_id: "00000000-0000-0000-0000-000000000000".into(),
    client_id: "11111111-1111-1111-1111-111111111111".into(),
    scope: "https://storage.azure.com/.default".into(),
});
```

The `tenant_id` is the Azure AD tenant. The `client_id` is the
managed identity or application registration in that tenant that
the exchange will authenticate as; the FIC binding on the managed
identity determines which external tokens may exchange for it.

The `scope` is the Azure AD resource the resulting token is bound
to. Azure tokens are audience-scoped; a token for storage cannot
be used against Key Vault. List the scopes the application needs;
use the `.default` suffix to inherit the managed identity's
configured permissions.

## Credential lifecycle

The short-lived credentials returned by all three STS endpoints
have explicit expiry. The application's call path needs to
respect the expiry:

The simple shape is one exchange per cloud call. The application
exchanges, makes the call, discards the credential. The latency
overhead is one STS round-trip per call (typically 50 to 200 ms
depending on the cloud), which is acceptable for one-off
operations.

The optimised shape is to cache the exchanged credential for the
duration of its validity. The application exchanges once, caches
the credential, uses it for subsequent calls until it nears
expiry, then re-exchanges. The cache key is the workload identity
plus the target role; the cache value is the credential plus its
expiry.

The right shape depends on the call rate. Below a few calls per
minute, the simple shape is fine. Above that, the optimised
shape with a per-workload cache (a `ClockTtlCache` from
`axess-cache`) eliminates the per-call STS round-trip.

The expiry handling needs care. A credential that expires
mid-call produces an authentication error from the cloud SDK,
which the application catches and translates into a re-exchange.
The cache wraps the expiry check; calls that get a near-expired
credential refresh proactively.

## Multi-cloud deployments

A deployment that uses multiple clouds (a workload that calls
both AWS and GCP, say) configures one exchanger per cloud. The
two are independent; they share the workload identity as input
but produce cloud-specific credentials as output.

The pattern composes cleanly. The application has a workload
principal; it has one `AwsStsExchanger` and one `GcpWifExchanger`
in scope; calls to AWS go through the AWS exchanger, calls to
GCP go through the GCP exchanger. No cross-cloud coupling.

## Threat model

Cloud STS exchange is robust against credential theft because the
short-lived credentials it produces are time-bounded. A stolen
credential expires within minutes regardless of the attacker's
actions.

The remaining attack surfaces:

The first is the workload identity itself. A compromised workload
identity can be exchanged for fresh cloud credentials at any
time. The defence is to keep the workload identity short-lived
(SPIRE rotates SVIDs every few hours, GitHub OIDC tokens are
single-use), so a compromised identity has a bounded lifetime.

The second is the STS endpoint. A compromised STS issues
compromised credentials. The defence is operational: the cloud
provider secures their STS; the application validates the
returned credentials by their structure (signature, format) but
cannot independently verify that the STS itself is honest.

The third is the role's trust policy. A misconfigured trust
policy allows any workload to assume the role, defeating the
identity-based restriction. The defence is to review trust
policies carefully at deployment time; the principle of least
privilege applies.

## Audit

Each exchange produces an audit event (a
`DelegatedTokenExchanged` event in the axess audit pipeline) and
a cloud-side audit event (CloudTrail for AWS, Cloud Audit Logs
for GCP, Activity Log for Azure). The two together give a
complete picture: what identity was exchanged, when, for what
role, and what cloud actions the resulting credential performed.

The retention configuration is in *Audit pipeline*. The
recommendation is longer retention for STS-exchange events than
for ordinary authentication events, because the events defend
against future compliance review of cross-cloud actions.

## Troubleshooting

If the exchange returns `AccessDenied` from AWS STS, the role's
trust policy does not admit the token. Check the policy's
`Principal.Federated` and `Condition` blocks; the most common
issues are a wrong issuer URL, a wrong audience, or a missing
required claim.

If the exchange returns `INVALID_ARGUMENT` from GCP, the
workload identity pool or provider name is wrong, or the token's
shape does not match what the provider expects. Inspect the
provider configuration through `gcloud iam workload-identity-pools
providers describe`.

If the exchange returns `AADSTS70021` from Azure, the FIC binding
on the managed identity does not match the token's subject claim.
Update the FIC configuration to match what the workload identity
emits.

## Further reading

*Inbound: JWT-SVID*, *Inbound: federation* cover the resolvers
that produce the workload identity that gets exchanged here.
*Outbound: OAuth* covers OAuth-based outbound credentials, which
are an alternative to cloud STS for some non-cloud downstreams.
*Audit pipeline* covers the retention configuration for
cross-cloud audit events.
