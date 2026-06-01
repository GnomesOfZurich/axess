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
//!     k8s_sa_mapper, K8sCustomClaims,
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
//!
//! // Per-request:
//! let resolver = WorkloadResolver::<K8sCustomClaims, _, _>::new(
//!     verifier.clone(),
//!     trust_domain.clone(),
//!     tenant_id,                          // adopter looked up from namespace
//!     Issuer::custom("kubernetes").unwrap(),
//!     bearer_token,
//!     k8s_sa_mapper(trust_domain),
//! );
//! let principal = resolver.resolve().await?;
//! ```
//!
//! # SPIFFE path shape
//!
//! Recipe synthesises `spiffe://<trust_domain>/<sa_name>/<namespace>`
//! so the service-account name serves as the SPIFFE `service_name`
//! and the namespace as the `tenant_slug`. Adjust the mapper's body
//! if you prefer the other order or want to encode `pod.name` /
//! `pod.uid` as additional path segments.

use std::collections::BTreeMap;

use axess_factors::federation::workload::WorkloadMapping;
use axess_factors::jwt::verifier::VerifiedClaims;
use axess_identity::{IdentityError, TrustDomain, WorkloadId};
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

/// Build the claim-mapping closure for [`WorkloadResolver`](axess_factors::federation::workload::WorkloadResolver).
///
/// Captures the `trust_domain` so the synthesised `WorkloadId` lives
/// under the SPIFFE trust domain the resolver pins.
pub fn k8s_sa_mapper(
    trust_domain: TrustDomain,
) -> impl Fn(&VerifiedClaims<K8sCustomClaims>) -> Result<WorkloadMapping, IdentityError> + Send + Sync
{
    move |claims| {
        let ns = &claims.custom.kubernetes_io;

        let workload_id = WorkloadId::build(&trust_domain, &ns.serviceaccount.name, &ns.namespace)?;

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
            workload_id,
            service_name: ns.serviceaccount.name.clone(),
            tenant_slug: ns.namespace.clone(),
            attributes,
        })
    }
}
