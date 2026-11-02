# Walkthrough: a pipeline to a service to Key Vault, on Azure

This chapter follows one request from a GitLab job to a secret in Azure Key
Vault, with the configuration on both sides of every hop and the error each
wrong setting produces. It adds no code of its own: the service is
`examples/workload-identity/tests/cloud_azure.rs`, which compiles and runs
under `cargo test`, and the pieces it uses are the
GitLab recipe (module `gitlab` of the workload-identity example, see [Inbound: federation](federation.md)) and
the Azure adapter described in [Cloud STS exchange](cloud-sts.md).

```text
 GitLab job                Rust service on AKS               Azure AD            Key Vault
     │  1. ID token (aud=axess-platform)                          │                   │
     ├──────────────────────────►│                                │                   │
     │                           │ 2. verify the caller           │                   │
     │                           │    (WorkloadResolver)          │                   │
     │                           │ 3. projected pod token ───────►│                   │
     │                           │    client_credentials          │                   │
     │                           │◄─────── access token ──────────┤                   │
     │                           │ 4. GET /secrets/db-password ──────────────────────►│
     │◄──────── the secret ──────┤◄─────────────────────────────────────────────────  │
```

Two identities are in play and the chapter keeps them apart. The **caller** is
the pipeline; the service checks who it is and decides whether to answer. The
**service** has an identity of its own, the Azure managed identity bound to its
Kubernetes service account; that identity, not the caller's, reads the secret.
The caller's token is never forwarded to Azure.

| Hop | Token | Issuer | Audience | Verified by |
| --- | --- | --- | --- | --- |
| 1, 2 | GitLab ID token | the GitLab instance | `axess-platform` | the service, with axess |
| 3 | AKS projected service-account token | the cluster's OIDC issuer | `api://AzureADTokenExchange` | Azure AD, against the federated credential |
| 4 | Azure AD access token | Azure AD | `https://vault.azure.net` | Key Vault |

The adapter needs the `azure-fic` feature (`cloud-sts` turns on all three
clouds). The example crate enables it for the tests.

## Step 1: the job gets an ID token

GitLab issues the job an OIDC token when the job declares `id_tokens`. The
audience is yours to choose; pick the one the service is configured for.

```yaml
deploy:
  stage: deploy
  id_tokens:
    AXESS_TOKEN:
      aud: axess-platform
  script:
    - >
      curl --fail --silent
      --header "Authorization: Bearer ${AXESS_TOKEN}"
      https://ledger.example.com/secret
```

For a self-managed GitLab inside Azure, the token's `iss` is that instance's
URL (for example `https://gitlab.example.com`), and the service must be able to
reach `<iss>/.well-known/openid-configuration` and its `jwks_uri` to fetch the
signing keys. A private GitLab behind a firewall that the service cannot reach
produces a verification failure on every call; the fix is network, not
configuration.

## Step 2: the service verifies the caller

The recipe block, then the service. The recipe keys the caller on GitLab's
numeric `project_id` and `namespace_id`, never on the mutable paths, and
requires a protected ref and the `production` environment. The first block is
the part that changes with the pipeline's issuer; the second does not.

```rust,ignore
{{#include ../../examples/workload-identity/tests/cloud_azure.rs:inbound_recipe}}
```

```rust,ignore
{{#include ../../examples/workload-identity/tests/cloud_azure.rs:service}}
```

Read the handler in the order it works. It refuses a request without a bearer
token, then resolves the token through `WorkloadResolver`, which checks the
signature against the issuer's keys, the issuer, the audience, the expiry and
the allowlist; a token that fails any of them gets a 401 and never reaches
Azure. Only then does it exchange its own identity. The exchange reads the
projected token from `AZURE_FEDERATED_TOKEN_FILE` on every call, because the
kubelet rotates the file, and asks Azure AD for a token whose scope is
`https://vault.azure.net/.default`. The Key Vault read is a plain bearer
request; Key Vault is not an axess concern.

A failed exchange is logged with Azure's error and answered with a generic 502.
The caller learns that the service could not reach its backend, not which
Azure setting is wrong; the log has the rest.

## Step 3: Azure and Kubernetes configuration

Enable the cluster's OIDC issuer and the workload identity webhook, create the
managed identity, and bind it to the service account with a federated
credential:

```sh
az aks update -g rg -n aks --enable-oidc-issuer --enable-workload-identity
ISSUER=$(az aks show -g rg -n aks --query oidcIssuerProfile.issuerUrl -o tsv)

az identity create -g rg -n ledger-id
CLIENT_ID=$(az identity show -g rg -n ledger-id --query clientId -o tsv)

az identity federated-credential create \
  --name ledger-aks --identity-name ledger-id --resource-group rg \
  --issuer "$ISSUER" \
  --subject system:serviceaccount:payments:ledger \
  --audiences api://AzureADTokenExchange
```

The three values Azure compares are the issuer, the subject and the audience;
they must equal the projected token's `iss`, `sub` and `aud` exactly, with the
trailing slash on the issuer included. Give the identity the right to read the
secret (the vault must use Azure RBAC for this to apply):

```sh
az role assignment create \
  --assignee-object-id "$(az identity show -g rg -n ledger-id --query principalId -o tsv)" \
  --assignee-principal-type ServicePrincipal \
  --role "Key Vault Secrets User" \
  --scope "$(az keyvault show -n ledger-kv --query id -o tsv)"
```

Then the Kubernetes side. The service account carries the identity's client id;
the pod opts in with a label, and the webhook mounts the token and sets
`AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and `AZURE_FEDERATED_TOKEN_FILE`:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ledger
  namespace: payments
  annotations:
    azure.workload.identity/client-id: "<CLIENT_ID>"
---
apiVersion: v1
kind: Pod
metadata:
  name: ledger
  namespace: payments
  labels:
    azure.workload.identity/use: "true"
spec:
  serviceAccountName: ledger
  containers:
    - name: ledger
      image: registry.example.com/ledger:1
```

The service builds its Azure client from those variables (`fic_from_env` in
the code above); a pod without the label has none of them and the service
should refuse to start rather than run without its identity. The adapter's
default token endpoint is the public cloud's; for a sovereign cloud, set
`with_token_endpoint` to the cloud's login host.

## What each wrong setting produces

Each row is a test in `cloud_azure.rs` that reproduces it against a mock Azure
AD holding the federated credential above. The mock compares the assertion's
`iss`, `sub` and `aud` to the credential and answers with the error Azure
documents for the mismatch. It does not verify signatures, and it was written
from Microsoft's documentation, not recorded from a live tenant: the numeric
codes are the stable part, and the description wording around them may differ.

| Misconfiguration | Test | The adapter returns | Fix |
| --- | --- | --- | --- |
| The federated credential's subject is another service account (or the pod runs under a different one) | `credential_subject_not_the_service_account_is_70021` | `AzureFicError::AzureError`, HTTP 401, `invalid_client`, code 70021 ("No matching federated identity record found for presented assertion") | Make `--subject` equal `system:serviceaccount:<namespace>:<name>` |
| The pod's token audience is not the credential's (a custom `aud` on the projected volume) | `credential_audience_not_the_exchange_audience_is_700212` | HTTP 401, `invalid_client`, code 700212 | Use `api://AzureADTokenExchange` on both sides, or let the webhook mount the volume |
| The credential names another cluster's issuer, or omits the trailing slash | `credential_issuer_not_the_cluster_issuer_is_700211` | HTTP 401, `invalid_client`, code 700211 | Copy `oidcIssuerProfile.issuerUrl` verbatim |
| The scope lacks `/.default` | `scope_without_default_suffix_is_70011` | HTTP 400, `invalid_scope`, code 70011 | Use `https://vault.azure.net/.default` |

The first row also drives the whole service and asserts the 502 and that
Key Vault saw no read. Two more cases belong to the service rather than to
Azure. A pipeline token with the wrong audience is refused with a 401 before
any exchange (`pipeline_token_for_another_audience_never_reaches_azure`). A
token that exchanges fine but whose identity lacks the Key Vault role
produces a 403 from Key Vault itself, which the service reports as a 502; that
one is not reproduced here because it is Key Vault's answer, not the STS
adapter's.

## Running it

```sh
cargo test -p axess-example-workload-identity --test cloud_azure
```

Everything above runs offline: Azure AD and Key Vault are local mock servers.
What no test here proves is a live tenant: the federated credential, the
webhook and Key Vault authorisation are configuration this chapter describes
and the mocks stand in for.
