//! Kubernetes service-account projected-token recipe.
//!
//! Wires axess's generic
//! [`WorkloadResolver`](axess_factors::federation::workload::WorkloadResolver)
//! against the `kubernetes.io.{namespace,serviceaccount.name}` claim
//! shape that the kubelet projects into service-account tokens.
//! Verifies tokens signed by the cluster's API server and synthesises
//! a SPIFFE-shape workload id from those claims.
//!
//! # Wire-up
//!
//! ```ignore
//! use axess_example_workload_identity::kubernetes::{
//!     k8s_sa_mapper_pinned, K8sCustomClaims, SaUidPins,
//! };
//! use axess_factors::federation::workload::WorkloadResolver;
//! use axess_factors::jwt::verifier::JwtVerifier;
//! use axess_identity::{Issuer, TrustDomain};
//! use std::sync::Arc;
//!
//! // Startup wiring:
//! let verifier = Arc::new(
//!     JwtVerifier::new(cluster_jwks_handle)
//!         .with_issuer("https://kubernetes.default.svc.cluster.local")
//!         .with_audience("axess-platform"),
//! );
//! let trust_domain = TrustDomain::new("cluster.local").unwrap();
//! // The service accounts you trust, each with the UID the cluster gave it
//! // (`kubectl get sa worker -n payments -o jsonpath='{.metadata.uid}'`).
//! // A token for any other account, or for a recreated one, is refused.
//! let pins = SaUidPins::new().pin("payments", "worker", "5f6e1c0a-...");
//!
//! // Per-request:
//! let resolver = WorkloadResolver::<K8sCustomClaims, _, _>::new(
//!     verifier.clone(),
//!     trust_domain.clone(),
//!     |namespace| tenants.get(namespace).copied(), // None refuses the token
//!     Issuer::custom("kubernetes").unwrap(),
//!     bearer_token,
//!     k8s_sa_mapper_pinned(pins),
//! );
//! let principal = resolver.resolve().await?;
//! ```
//!
//! # Pin the service-account UID
//!
//! A service account is named by `(namespace, name)`, and a name can be
//! deleted and created again by anyone who may create service accounts in
//! that namespace; the new account's tokens then carry the name you
//! trusted. The `uid` claim does not survive that: a recreated account gets
//! a new UID. The wire-up above therefore uses [`k8s_sa_mapper_pinned`] with
//! [`SaUidPins`], which refuses a token whose UID is missing or not the one
//! registered for its `(namespace, name)`. [`k8s_sa_mapper`] records the UID
//! as the `sa_uid` attribute but does not require it; see its warning.
//!
//! # SPIFFE path shape
//!
//! Recipe synthesises `spiffe://<trust_domain>/<sa_name>/<namespace>`
//! so the service-account name serves as the SPIFFE `service_name`
//! and the namespace as the `tenant_slug`. Adjust the mapper's body
//! if you prefer the other order or want to encode `pod.name` /
//! `pod.uid` as additional path segments.

use std::collections::{BTreeMap, HashMap};

use axess_factors::federation::workload::WorkloadMapping;
use axess_factors::jwt::verifier::VerifiedClaims;
use axess_identity::IdentityError;
use serde::Deserialize;

/// Inner service-account block of the `kubernetes.io` claim namespace.
#[derive(Debug, Deserialize)]
pub struct K8sServiceAccountClaim {
    /// Service-account name (e.g. `worker`).
    pub name: String,
    /// Service-account UID. Optional because some clusters' API
    /// servers omit it; preserved on attributes for audit attribution
    /// when present.
    #[serde(default)]
    pub uid: Option<String>,
}

/// Optional pod block of the `kubernetes.io` claim namespace.
#[derive(Debug, Deserialize)]
pub struct K8sPodClaim {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub uid: Option<String>,
}

/// The `kubernetes.io` custom-claim namespace as projected by the
/// kubelet into the service-account token.
#[derive(Debug, Deserialize)]
pub struct K8sNamespacedClaims {
    pub namespace: String,
    pub serviceaccount: K8sServiceAccountClaim,
    #[serde(default)]
    pub pod: Option<K8sPodClaim>,
}

/// Top-level custom-claim shape: only the `kubernetes.io` namespace.
/// Everything else is in `VerifiedClaims`'s registered fields.
#[derive(Debug, Deserialize)]
pub struct K8sCustomClaims {
    #[serde(rename = "kubernetes.io")]
    pub kubernetes_io: K8sNamespacedClaims,
}

/// The service-account UIDs a deployment trusts, keyed by
/// `(namespace, service-account name)`.
#[derive(Debug, Clone, Default)]
pub struct SaUidPins(HashMap<(String, String), String>);

impl SaUidPins {
    /// An empty set, which refuses every token.
    pub fn new() -> Self {
        Self::default()
    }

    /// Trust the service account `name` in `namespace` only with this UID.
    pub fn pin(
        mut self,
        namespace: impl Into<String>,
        name: impl Into<String>,
        uid: impl Into<String>,
    ) -> Self {
        self.0.insert((namespace.into(), name.into()), uid.into());
        self
    }

    /// `Ok` when the account is pinned and the token's UID is the pinned one;
    /// otherwise the error names the claim that decided the refusal.
    fn check(&self, namespace: &str, name: &str, uid: Option<&str>) -> Result<(), IdentityError> {
        let Some(pinned) = self.0.get(&(namespace.to_string(), name.to_string())) else {
            return Err(IdentityError::InvalidComponent(format!(
                "Kubernetes claim `kubernetes.io.namespace` ({namespace}) with \
                 `kubernetes.io.serviceaccount.name` ({name}) is not a pinned service account"
            )));
        };
        match uid {
            Some(u) if u == pinned => Ok(()),
            _ => Err(IdentityError::InvalidComponent(format!(
                "Kubernetes claim `kubernetes.io.serviceaccount.uid` ({}) is not the UID pinned \
                 for {namespace}/{name}",
                uid.unwrap_or("absent")
            ))),
        }
    }
}

/// Like [`k8s_sa_mapper`], but refuses a token whose service-account UID is
/// absent or differs from the one pinned for its `(namespace, name)`, and
/// every account that is not pinned at all. The error names the claim that
/// decided it (`kubernetes.io.namespace` and `serviceaccount.name` for an
/// unpinned account, `kubernetes.io.serviceaccount.uid` for a UID mismatch).
pub fn k8s_sa_mapper_pinned(
    pins: SaUidPins,
) -> impl Fn(&VerifiedClaims<K8sCustomClaims>) -> Result<WorkloadMapping, IdentityError> + Send + Sync
{
    let inner = k8s_sa_mapper();
    move |claims| {
        let ns = &claims.custom.kubernetes_io;
        pins.check(
            &ns.namespace,
            &ns.serviceaccount.name,
            ns.serviceaccount.uid.as_deref(),
        )?;
        inner(claims)
    }
}

/// Build the claim-mapping closure for [`WorkloadResolver`](axess_factors::federation::workload::WorkloadResolver).
///
/// The resolver builds the `WorkloadId` itself, under the trust domain it
/// pins, from the service name and tenant slug this mapper returns.
///
/// # Warning: the account is trusted by name
///
/// This mapper does not look at the service-account UID. Anyone who may
/// create service accounts in a namespace can delete a trusted account and
/// create another under the same `(namespace, name)`, and its tokens are
/// accepted as the original's. Use [`k8s_sa_mapper_pinned`] unless the
/// cluster's RBAC already guarantees nobody can do that, and then only with
/// the namespace's own audit trail as the check.
pub fn k8s_sa_mapper()
-> impl Fn(&VerifiedClaims<K8sCustomClaims>) -> Result<WorkloadMapping, IdentityError> + Send + Sync
{
    move |claims| {
        let ns = &claims.custom.kubernetes_io;

        let mut attributes = BTreeMap::new();
        if let Some(uid) = &ns.serviceaccount.uid {
            attributes.insert("sa_uid".to_string(), serde_json::Value::String(uid.clone()));
        }
        if let Some(pod) = &ns.pod {
            if let Some(name) = &pod.name {
                attributes.insert(
                    "pod_name".to_string(),
                    serde_json::Value::String(name.clone()),
                );
            }
            if let Some(uid) = &pod.uid {
                attributes.insert(
                    "pod_uid".to_string(),
                    serde_json::Value::String(uid.clone()),
                );
            }
        }

        Ok(WorkloadMapping {
            service_name: ns.serviceaccount.name.clone(),
            tenant_slug: ns.namespace.clone(),
            attributes,
        })
    }
}
