//! The tenant half of a login: resolve the tenant a request names and admit
//! the request against its status and IP policy; split out of `login` so
//! the login flow itself stays readable.

use crate::authn::error::AuthnError;
use crate::authn::event::AuthFailureReason;
use crate::authn::service::outcomes::LoginOutcome;
use crate::authn::store::{FactorStore, IdentityStore};
use crate::authn::types::Tenant;
use std::ops::ControlFlow;

impl<I, F> crate::authn::service::RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Resolve the tenant a login names and admit the request against it.
    ///
    /// Breaks with [`LoginOutcome::InvalidCredentials`] for an unknown
    /// tenant, an invalid tenant row, a tenant whose status bars logins and
    /// a request the tenant IP policy refuses. Every one of those goes
    /// through [`reject_pre_user`](Self::reject_pre_user) so their store
    /// calls and audit rows are indistinguishable from one another.
    pub(super) async fn admit_tenant(
        &self,
        identifier: &str,
        tenant_identifier: &str,
    ) -> Result<ControlFlow<LoginOutcome, Tenant>, AuthnError<I::Error>> {
        // 1. Find tenant. An unknown tenant is a credential failure like
        // any other, not a distinct error: returning `NotActive` here made
        // tenant existence observable, because that variant maps to 403
        // "account not active" while a wrong password yields
        // `InvalidCredentials`. An attacker could separate "no such tenant"
        // from "wrong password" on the status code alone, which is the
        // enumeration the identifier path below is careful to prevent.
        //
        // Response shape alone is not enough: bailing out here would skip
        // the user lookup entirely and answer measurably sooner, so the
        // same dummy store queries run against a throwaway tenant id to
        // keep the timing of an unknown tenant in line with a known one.
        let tenant = match self
            .inner
            .identity
            .find_tenant(tenant_identifier)
            .await
            .map_err(AuthnError::Store)?
        {
            Some(t) => t,
            None => {
                // Unattributed: there is no tenant and so no user to name.
                // Emitting anyway is what keeps the audit failure mode from
                // becoming an enumeration oracle, because an audit-store
                // outage must fail this path exactly as it fails a known
                // user's wrong password. It also closes a SOC blind spot: a
                // credential-stuffing run against identifiers that do not
                // exist used to leave no audit row at all.
                return self
                    .reject_pre_user(identifier, None, AuthFailureReason::UnknownTenant, false)
                    .await
                    .map(ControlFlow::Break);
            }
        };

        self.admit_resolved_tenant(identifier, tenant).await
    }

    /// Admit a login for the tenant with this id, for the entry points that
    /// do not start at [`begin_login`](Self::begin_login) (the passkey
    /// login, an OAuth callback): the same tenant row check, status check
    /// and IP policy, with the same refusals and audit rows.
    ///
    /// `identifier` is the user's identifier, only used to run the dummy
    /// lookups a refusal makes. Breaks with
    /// [`LoginOutcome::InvalidCredentials`] on any refusal, a tenant that
    /// cannot be loaded included (fail closed).
    #[cfg(any(feature = "fido2", feature = "oauth"))]
    pub(crate) async fn admit_tenant_by_id(
        &self,
        identifier: &str,
        tenant_id: &crate::authn::ids::TenantId,
    ) -> Result<ControlFlow<LoginOutcome, Tenant>, AuthnError<I::Error>> {
        let tenant = self
            .inner
            .identity
            .get_tenant(tenant_id)
            .await
            .map_err(AuthnError::Store)?;
        let Some(tenant) = tenant else {
            return self
                .reject_pre_user(identifier, None, AuthFailureReason::UnknownTenant, false)
                .await
                .map(ControlFlow::Break);
        };
        self.admit_resolved_tenant(identifier, tenant).await
    }

    /// The checks every login runs against a tenant once it is loaded.
    async fn admit_resolved_tenant(
        &self,
        identifier: &str,
        tenant: Tenant,
    ) -> Result<ControlFlow<LoginOutcome, Tenant>, AuthnError<I::Error>> {
        if let Err(e) = tenant.validate() {
            tracing::error!(error = %e, "IdentityStore returned invalid Tenant");
            return self
                .reject_pre_user(identifier, None, AuthFailureReason::InvalidTenantRow, false)
                .await
                .map(ControlFlow::Break);
        }

        // 1a. Enforce tenant-level status. A Suspended or Terminated
        // tenant rejects all logins before we reveal anything
        // user-specific; this is the operator lever for "lock everyone
        // out of tenant X" (see `docs/identity/tenancy.md`).
        //
        // The caller sees the same `InvalidCredentials` as for an unknown
        // tenant, after the same dummy user lookup. A distinct answer here
        // (it was `NotActive`, a 403) let anyone probing tenant slugs tell
        // a suspended tenant from a missing one, and either from a live
        // one. The audit row carries the real reason.
        if !tenant
            .status
            .clone()
            .effective_at(self.inner.clock.now())
            .allows_login()
        {
            tracing::warn!(
                tenant = %tenant.id,
                status = ?tenant.status,
                "login rejected: tenant status does not allow login"
            );
            return self
                .reject_pre_user(
                    identifier,
                    Some(&tenant.id),
                    AuthFailureReason::NotActive,
                    false,
                )
                .await
                .map(ControlFlow::Break);
        }

        if let ControlFlow::Break(outcome) =
            self.enforce_tenant_ip_policy(identifier, &tenant).await?
        {
            return Ok(ControlFlow::Break(outcome));
        }
        Ok(ControlFlow::Continue(tenant))
    }

    /// Enforce the tenant IP policy against the address of this request.
    ///
    /// Breaks with [`LoginOutcome::InvalidCredentials`] when the address is
    /// barred, or when the policy restricts and no address was resolved.
    async fn enforce_tenant_ip_policy(
        &self,
        identifier: &str,
        tenant: &Tenant,
    ) -> Result<ControlFlow<LoginOutcome>, AuthnError<I::Error>> {
        // 1b. Enforce the tenant IP policy against the address this handle
        // was derived with. Until 0.7.0 the address was a parameter and the
        // check ran only `if let Some(ip)`, so a caller passing `None`
        // skipped the policy entirely: an allowlist a caller could switch
        // off by omitting an argument, and 51 of the 52 call sites in this
        // repository omitted it. The address now comes from the client-IP
        // layer by way of the audit context, which the caller does not
        // choose.
        let policy = self
            .inner
            .identity
            .ip_policy_for_tenant(&tenant.id)
            .await
            .map_err(AuthnError::Store)?;
        // Both refusals are answered by `reject_pre_user`, exactly as an
        // unknown identifier is, so a request from a barred address makes the
        // same store calls, in the same order, as one from a permitted
        // address naming a user who does not exist.
        match self.audit.ip_address {
            Some(ip) if !policy.is_allowed(ip) => {
                tracing::warn!(
                    tenant = %tenant.id,
                    client_ip = %ip,
                    "login rejected by tenant IP policy"
                );
                return self
                    .reject_pre_user(
                        identifier,
                        Some(&tenant.id),
                        AuthFailureReason::IpPolicy,
                        true,
                    )
                    .await
                    .map(ControlFlow::Break);
            }
            // A policy that restricts, and no address to test against it:
            // the only safe reading is that it is not satisfied. An empty
            // policy permits everything, so an unknown address is no less
            // compliant with it than a known one, and those deployments are
            // unaffected.
            //
            // `ip_source` separates the two ways to get here. `Unknown`
            // means `client_ip::layer` is not installed, which is a
            // deployment fault and the likely cause. Any other source means
            // the transport genuinely has no address to offer.
            None if policy.restricts() => {
                tracing::error!(
                    tenant = %tenant.id,
                    ip_source = self.audit.ip_source.as_str(),
                    "tenant has an IP policy and this request has no resolved \
                     client address, so the policy cannot be satisfied; install \
                     axess::client_ip::layer on the router"
                );
                return self
                    .reject_pre_user(
                        identifier,
                        Some(&tenant.id),
                        AuthFailureReason::IpPolicy,
                        true,
                    )
                    .await
                    .map(ControlFlow::Break);
            }
            _ => {}
        }
        Ok(ControlFlow::Continue(()))
    }
}
