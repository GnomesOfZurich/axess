//! Amazon EKS service-account tokens, on the [`kubernetes`](crate::kubernetes) recipe.
//!
//! EKS is Kubernetes here: the token is the bound service-account token with
//! the same `kubernetes.io` claim block, so the mapper, the claim structs and
//! [`SaUidPins`](crate::kubernetes::SaUidPins) are the Kubernetes ones. What
//! differs is the issuer and the audience.
//!
//! - Issuer: every EKS cluster has its own public OIDC issuer,
//!   `https://oidc.eks.<region>.amazonaws.com/id/<cluster id>` (see
//!   [`issuer`]; `aws eks describe-cluster --name <c> --query
//!   cluster.identity.oidc.issuer` prints it). The keys are at
//!   `<issuer>/keys`. The cluster id makes the issuer unique, so unlike a
//!   default OpenShift cluster the issuer alone names the cluster.
//! - Audience: the IAM roles for service accounts webhook projects a token for
//!   [`IRSA_AUDIENCE`], the AWS STS audience. Keep that token for STS. To call
//!   your own service, project a second token with your own audience (a
//!   `projected` volume with a `serviceAccountToken` source and `audience:
//!   axess-platform`) and pin that on the verifier.
//!
//! ```ignore
//! let verifier = Arc::new(
//!     JwtVerifier::new(cluster_jwks_handle)
//!         .with_issuer(axess_example_workload_identity::eks::issuer("eu-west-1", "ABCDEF0123456789"))
//!         .with_audience("axess-platform"),
//! );
//! // then k8s_sa_mapper_pinned(trust_domain, pins) as in the kubernetes module
//! ```

/// The audience of the token the IRSA webhook projects, meant for AWS STS.
pub const IRSA_AUDIENCE: &str = "sts.amazonaws.com";

/// The OIDC issuer URL of an EKS cluster in `region` with this cluster id.
pub fn issuer(region: &str, cluster_id: &str) -> String {
    format!("https://oidc.eks.{region}.amazonaws.com/id/{cluster_id}")
}
