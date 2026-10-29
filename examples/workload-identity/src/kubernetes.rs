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
//! # Pin the service-account UID
//!
//! A service account is named by `(namespace, name)`, and a name can be
//! deleted and created again by anyone who may create service accounts in
//! that namespace; the new account's tokens then carry the name you
//! trusted. The `uid` claim does not survive that: a recreated account gets
//! a new UID. [`k8s_sa_mapper`] records the UID as the `sa_uid` attribute
//! but does not require it. Use [`k8s_sa_mapper_pinned`] with
//! [`SaUidPins`] to refuse a token whose UID is missing or not the one
//! registered for its `(namespace, name)`.
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

    fn admits(&self, namespace: &str, name: &str, uid: Option<&str>) -> bool {
        let pinned = self.0.get(&(namespace.to_string(), name.to_string()));
        matches!((pinned, uid), (Some(p), Some(u)) if p == u)
    }
}

/// Like [`k8s_sa_mapper`], but refuses a token whose service-account UID is
/// absent or differs from the one pinned for its `(namespace, name)`, and
/// every account that is not pinned at all.
pub fn k8s_sa_mapper_pinned(
    trust_domain: TrustDomain,
    pins: SaUidPins,
) -> impl Fn(&VerifiedClaims<K8sCustomClaims>) -> Result<WorkloadMapping, IdentityError> + Send + Sync
{
    let inner = k8s_sa_mapper(trust_domain);
    move |claims| {
        let ns = &claims.custom.kubernetes_io;
        if !pins.admits(
            &ns.namespace,
            &ns.serviceaccount.name,
            ns.serviceaccount.uid.as_deref(),
        ) {
            return Err(IdentityError::NotAuthenticated);
        }
        inner(claims)
    }
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
