# Walkthrough: a pipeline to a service to Secrets Manager, on AWS

This chapter follows a CI job through two exchanges on AWS, with the
configuration on both sides of each and the error each wrong setting produces.
The job assumes a role with its own ID token; it then calls a Rust service
protected by axess; the service, on EKS, exchanges its own projected token for
a role that can read a secret. It adds no code of its own: the code is
`examples/workload-identity/tests/cloud_aws.rs`, which compiles and runs under
`cargo test`, built on the GitLab recipe (module `gitlab` of the
workload-identity example, see [Inbound: federation](federation.md)) and the AWS adapter described in
[Cloud STS exchange](cloud-sts.md).

```text
 CI job                       Rust service on EKS                AWS STS        Secrets Manager
   │ A. ID token (aud=sts.amazonaws.com) ───────────────────────────►│                │
   │◄────────────── credentials for ledger-ci-deploy ────────────────┤                │
   │ B. ID token (aud=axess-platform)                                │                │
   ├────────────────────────────►│                                   │                │
   │                             │ C. verify the caller              │                │
   │                             │ D. projected pod token ──────────►│                │
   │                             │◄────── credentials for ledger-secret-reader ──────┤
   │                             │ E. GetSecretValue (SigV4) ───────────────────────►│
   │◄────── response ────────────┤◄───────────────────────────────────────────────────┤
```

The job and the service use two different tokens for two different audiences,
and the chapter keeps them apart. The token for AWS has the audience
`sts.amazonaws.com`; the token for the service has the audience the service is
configured for. A token minted for one is refused by the other.

The adapter needs the `aws-sts` feature (`cloud-sts` turns on all three
clouds). The example crate enables it for the tests.

## Step A: the job assumes a role

A GitHub Actions job declares `id-token: write`; a GitLab job declares
`id_tokens` with `aud: sts.amazonaws.com`. Either gets an ID token. A workflow
that only needs AWS credentials usually uses the
`aws-actions/configure-aws-credentials` action, which makes this same
`AssumeRoleWithWebIdentity` call. A job written in Rust makes it through the
adapter:

```rust,ignore
{{#include ../../examples/workload-identity/tests/cloud_aws.rs:job}}
```

The AWS side has two parts. First, an IAM OIDC identity provider for the
issuer, with `sts.amazonaws.com` in its client ID list. AWS checks the token's
`aud` against that list before it looks at any role:

```sh
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com
```

Second, the role's trust policy, which names the provider and conditions on the
token's `aud` and `sub`:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:gnomes/axess:ref:refs/heads/main"
      }
    }
  }]
}
```

The `sub` condition is what keeps every other repository on GitHub, and every
other branch of this one, out of the role. Without it, any workflow that can
obtain a token for `sts.amazonaws.com` can assume the role. For GitLab the
subject has the shape `project_path:<group>/<project>:ref_type:branch:ref:<name>`
and the issuer is the GitLab instance's URL, registered as its own IAM provider.
AWS conditions on the subject by path, which is mutable; the service in step C
keys on the immutable ids instead, which is why the two checks are separate.

## Steps B and C: the job calls the service, which verifies it

The job calls the service with a second token, minted for the service's
audience. Here the job is a GitLab one, whatever CI assumed the role in step A:

```yaml
call-service:
  stage: deploy
  environment: production
  id_tokens:
    AXESS_TOKEN:
      aud: axess-platform
  script:
    - >
      curl --fail --header "Authorization: Bearer ${AXESS_TOKEN}"
      https://ledger.example.com/ready
```

The service verifies it with the GitLab recipe block and the handler below. The
recipe keys the caller on `project_id` and `namespace_id`, and requires a
protected ref and the `production` environment.

```rust,ignore
{{#include ../../examples/workload-identity/tests/cloud_aws.rs:inbound_recipe}}
```

## Steps D and E: the service assumes its own role

```rust,ignore
{{#include ../../examples/workload-identity/tests/cloud_aws.rs:service}}
```

The handler refuses a request without a bearer token and resolves the token
through `WorkloadResolver`; only a caller that passes gets an exchange. The
exchange reads the projected token from `AWS_WEB_IDENTITY_TOKEN_FILE` on every
call, because the kubelet rotates it, and asks the regional STS endpoint for
credentials for `AWS_ROLE_ARN`. A failed exchange is logged with AWS's error
and answered with a generic 502.

The EKS side is the same two parts as before, with the cluster as the issuer.
Register the cluster's OIDC issuer as an IAM provider, then write a trust policy
whose `sub` is the service account:

```sh
ISSUER=$(aws eks describe-cluster --name ledger-cluster \
  --query cluster.identity.oidc.issuer --output text)
aws iam create-open-id-connect-provider --url "$ISSUER" \
  --client-id-list sts.amazonaws.com
```

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.eks.eu-central-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "oidc.eks.eu-central-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE:aud": "sts.amazonaws.com",
        "oidc.eks.eu-central-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE:sub": "system:serviceaccount:payments:ledger"
      }
    }
  }]
}
```

Give the role a permissions policy for one secret and nothing else:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "secretsmanager:GetSecretValue",
    "Resource": "arn:aws:secretsmanager:eu-central-1:123456789012:secret:ledger/db-password-*"
  }]
}
```

Then annotate the service account. The EKS pod identity webhook sees the
annotation and injects `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE` (a
projected token with the audience `sts.amazonaws.com`) and, with a region
configured, `AWS_REGION`:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ledger
  namespace: payments
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/ledger-secret-reader
```

`sts_from_env` in the code above builds the client from those variables. This
is IAM roles for service accounts, and it is the form the adapter serves: the
pod holds a web identity token and the service makes the
`AssumeRoleWithWebIdentity` call itself. The newer EKS Pod Identity feature
works differently: an agent on the node serves credentials from a local
container-credentials endpoint and the pod never calls STS, so there is nothing
for this adapter to do and the AWS SDK's default credential chain is the right
tool.

The last hop, `GetSecretValue`, is signed with SigV4, which axess does not
implement and the example crate does not depend on an SDK for. The tests stop
at the credentials; the call itself is the AWS SDK's, given the adapter's
output:

```rust,ignore
use aws_sdk_secretsmanager::config::{BehaviorVersion, Credentials, Region};

let assumed = secret_reader_credentials(&svc).await?;
let c = &assumed.credentials;
let config = aws_sdk_secretsmanager::Config::builder()
    .behavior_version(BehaviorVersion::latest())
    .region(Region::new("eu-central-1"))
    .credentials_provider(Credentials::new(
        &*c.access_key_id,
        &*c.secret_access_key,
        Some(c.session_token.to_string()),
        Some(c.expiration.into()),
        "axess-sts",
    ))
    .build();
let secret = aws_sdk_secretsmanager::Client::from_conf(config)
    .get_secret_value()
    .secret_id("ledger/db-password")
    .send()
    .await?;
```

The credentials last 900 seconds in this example. A service that reads a secret
per request should cache them until shortly before `expiration`, as described
in [Cloud STS exchange](cloud-sts.md).

## What each wrong setting produces

Each row is a test in `cloud_aws.rs` that reproduces it against a mock STS
holding the IAM configuration above. The mock applies AWS's three checks in
order: the issuer must be a registered IAM provider, the token's `aud` must be
in the provider's client ID list, and the role's trust policy must admit the
provider, `aud` and `sub`. It does not verify signatures, and it was written
from AWS's documentation, not recorded from a live account: the error codes
are the stable part, and the message wording may differ.

| Misconfiguration | Test | The adapter returns | Fix |
| --- | --- | --- | --- |
| The job runs on a branch the `sub` condition does not name | `trust_policy_sub_not_matching_the_job_is_access_denied` | `AwsStsError::StsError`, HTTP 403, `AccessDenied` ("Not authorized to perform sts:AssumeRoleWithWebIdentity") | Widen the condition deliberately (a `StringLike` pattern, an environment), or run the job where the policy expects |
| The token's `aud` is not in the provider's client ID list (the workflow asked for a custom audience) | `token_audience_missing_from_the_provider_client_ids_is_invalid_identity_token` | HTTP 400, `InvalidIdentityToken` ("Incorrect token audience") | Ask for `sts.amazonaws.com`, or add the audience to the provider's client IDs |
| The issuer was never registered as an IAM provider, or under a different URL | `issuer_without_an_iam_oidc_provider_is_invalid_identity_token` | HTTP 400, `InvalidIdentityToken` ("No OpenIDConnect provider found in your account for https://...") | Register the issuer URL exactly as it appears in the token's `iss` |

Note the pair: a wrong subject is `AccessDenied` and a wrong audience or issuer
is `InvalidIdentityToken`. The adapter's troubleshooting advice in
[Cloud STS exchange](cloud-sts.md) lumps them together; the code tells you
which check failed.

The third test also drives the whole service and asserts the 502. Two cases
belong to the service rather than to AWS: a pipeline token with the wrong
audience is refused with a 401 before any exchange
(`pipeline_token_for_another_audience_never_reaches_aws`), and a role whose
permissions policy lacks `secretsmanager:GetSecretValue` assumes fine and
fails at step E with `AccessDeniedException` from Secrets Manager, which is the
SDK's answer, not the adapter's, and is not reproduced here.

## Running it

```sh
cargo test -p axess-example-workload-identity --test cloud_aws
```

Everything above runs offline: STS is a local mock server. What no test here
proves is a live account: the IAM providers, the trust policies, the webhook
and the SigV4 call are configuration or SDK behaviour this chapter describes.

## GCP

The GCP adapter is `GcpStsClient` in `axess::workload::outbound::cloud_sts::gcp`
(feature `gcp-wif`), with `GcpServiceAccountImpersonator` for the second hop.
It differs from AWS in two ways. The exchange is two calls: Google's STS
exchanges the token (RFC 8693) for a federated access token, which most APIs
refuse, so a service normally impersonates a service account with it. And the
trust lives on a workload identity pool provider (an attribute mapping and a
condition on the provider) rather than on a role's trust policy, with the
token's audience being the provider's full resource name, built for you by
`WorkloadIdentityPoolProvider`. Everything else in this chapter carries over,
and [Cloud STS exchange](cloud-sts.md) has the configuration.
