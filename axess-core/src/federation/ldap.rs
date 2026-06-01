//! Orchestrator-side LDAP code: `HealthCheck` impl for
//! [`LdapProviderConfig`]. The verifier itself, the configuration
//! struct, and the mock implementation live in [`axess_factors::ldap`].

use crate::health::{HealthCheck, HealthStatus};
use axess_factors::ldap::LdapProviderConfig;

impl HealthCheck for LdapProviderConfig {
    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthStatus> + Send + '_>> {
        Box::pin(async {
            // Attempt a TCP connection to verify the LDAP server is reachable.
            // This does not authenticate; it only checks connectivity.
            match tokio::time::timeout(
                self.connection_timeout,
                ldap3::LdapConnAsync::new(&self.url),
            )
            .await
            {
                Ok(Ok((conn, mut ldap))) => {
                    tokio::spawn(async move { conn.drive().await });
                    if let Err(err) = ldap.unbind().await {
                        tracing::trace!(
                            target: "axess::federation::ldap",
                            ?err,
                            "ldap unbind on health-check teardown failed",
                        );
                    }
                    HealthStatus::Healthy
                }
                Ok(Err(e)) => HealthStatus::Unhealthy(format!("LDAP connection failed: {e}")),
                Err(_) => HealthStatus::Unhealthy(format!(
                    "LDAP connection timeout ({}s)",
                    self.connection_timeout.as_secs()
                )),
            }
        })
    }
}
