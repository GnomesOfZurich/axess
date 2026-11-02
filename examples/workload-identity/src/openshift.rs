//! OpenShift bound service-account tokens, on the [`kubernetes`](crate::kubernetes) recipe.
//!
//! OpenShift is Kubernetes here: the token is the same bound service-account
//! token with the same `kubernetes.io` claim block, so the mapper, the claim
//! structs and [`SaUidPins`](crate::kubernetes::SaUidPins) are the
//! Kubernetes ones. What differs is the issuer and the audience.
//!
//! - Issuer: an OpenShift 4 cluster signs with the issuer in its
//!   `Authentication` resource (`oc get authentication cluster -o
//!   jsonpath='{.spec.serviceAccountIssuer}'`). Unless an administrator set
//!   one, that is [`DEFAULT_ISSUER`], the same string for every default
//!   cluster, so the issuer separates no clusters: the JWKS you fetch
//!   (`oc get --raw /openid/v1/jwks`) and the audience do. A cluster
//!   with a custom or cloud-STS issuer (ROSA, workload identity on Azure Red
//!   Hat OpenShift) publishes its keys at that URL instead.
//! - Audience: a pod's default token is for [`DEFAULT_AUDIENCE`], the API
//!   server. Never verify that: any pod on the cluster holds such a token. Ask
//!   for your own audience in the pod spec (a `projected` volume with a
//!   `serviceAccountToken` source and `audience: axess-platform`) and pin it
//!   on the verifier.
//!
//! ```ignore
//! let verifier = Arc::new(
//!     JwtVerifier::new(cluster_jwks_handle)
//!         .with_issuer(axess_example_workload_identity::openshift::DEFAULT_ISSUER)
//!         .with_audience("axess-platform"),
//! );
//! // then k8s_sa_mapper_pinned(trust_domain, pins) as in the kubernetes module
//! ```

/// The service-account issuer of a default OpenShift 4 cluster.
pub const DEFAULT_ISSUER: &str = "https://kubernetes.default.svc";

/// The audience of a pod's default token: the API server. Do not accept it.
pub const DEFAULT_AUDIENCE: &str = "https://kubernetes.default.svc";
