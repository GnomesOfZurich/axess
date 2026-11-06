//! Turning verified OIDC claims into a local user: find the user the
//! identity is linked to, or create one just in time when the tenant's policy
//! allows it.
//!
//! This is the step `complete_oauth_login` leaves to the application, because
//! only the application knows what a user is. The rules the example follows:
//!
//! - The link is `(issuer, subject)`. The issuer is read from the verified ID
//!   token, never from configuration or the request.
//! - The e-mail address is never looked at to find a user. It is not stored
//!   either: a real user table adds a column and treats it as unverified data
//!   unless `email_verified` said otherwise.
//! - A tenant that does not provision just in time refuses an identity it has
//!   no link for. A linked identity always signs in.

use crate::identities::FederatedIdentities;
use axess::authn::{EntityState, IdentityAdmin, TenantId, User, UserId};
use axess::federation::oauth::OAuthClaims;
use axess::{Clock, SecureRng};
use std::sync::Arc;

/// Whether a tenant creates users on the first login of an unknown identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provisioning {
    /// Create the local user on first sight.
    JustInTime,
    /// Create no one: only identities linked beforehand sign in (an invited
    /// user, an administrator's import).
    LinkedOnly,
}

impl Provisioning {
    /// [`from_setting`](Self::from_setting) over the result of reading the
    /// environment variable: a value that is not valid Unicode is an error,
    /// never read as unset.
    pub fn from_env(value: Result<String, std::env::VarError>) -> Result<Self, String> {
        match value {
            Ok(v) => Self::from_setting(Some(&v)),
            Err(std::env::VarError::NotPresent) => Self::from_setting(None),
            // Given but unreadable is not "unset": that would turn on
            // creating users on a setting the operator meant to restrict.
            Err(e @ std::env::VarError::NotUnicode(_)) => {
                Err(format!("OAUTH_PROVISIONING is not text: {e}"))
            }
        }
    }

    /// Reads the `OAUTH_PROVISIONING` setting: `just-in-time` or
    /// `linked-only`, and linked-only when it is not set: creating users on
    /// first login needs an explicit `just-in-time`, because with a public
    /// IdP such as Google it lets anyone with an account there sign up. Any
    /// other value is an error, so a typo cannot turn on creating users.
    pub fn from_setting(value: Option<&str>) -> Result<Self, String> {
        match value {
            None | Some("linked-only") => Ok(Self::LinkedOnly),
            Some("just-in-time") => Ok(Self::JustInTime),
            Some(other) => Err(format!(
                "OAUTH_PROVISIONING must be `just-in-time` or `linked-only`, not {other:?}"
            )),
        }
    }
}

/// What one tenant allows when an unknown identity arrives.
#[derive(Clone, Debug)]
pub struct TenantPolicy {
    /// The tenant the users are created in. The login is begun for this
    /// tenant, so a user from any other tenant is refused at completion.
    pub tenant: TenantId,
    /// Whether to create users on first login.
    pub provisioning: Provisioning,
    /// Refuse to create a user whose provider did not say the address is
    /// verified. The address is not stored by this example; the switch is
    /// here to show where a policy that does store it would stop.
    pub require_verified_email: bool,
}

/// Why claims could not be turned into a local user.
#[derive(Debug)]
pub enum ResolveError {
    /// The verified ID token carried no `iss`; there is nothing to link on.
    NoIssuer,
    /// The identity is not linked and the tenant does not create users.
    NotProvisioned,
    /// The tenant requires a verified address and the provider did not vouch
    /// for one.
    UnverifiedEmail,
    /// The identity is linked to a user the identity store no longer has.
    LinkedUserMissing(UserId),
    /// The user record the claims would produce is not valid.
    Invalid(String),
    /// The identity store failed.
    Store(String),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoIssuer => f.write_str("the ID token carries no issuer"),
            Self::NotProvisioned => f.write_str("the identity is not linked to a user"),
            Self::UnverifiedEmail => f.write_str("the provider did not verify an e-mail address"),
            Self::LinkedUserMissing(id) => write!(f, "the linked user {id} no longer exists"),
            Self::Invalid(why) => write!(f, "the user record is invalid: {why}"),
            Self::Store(why) => write!(f, "the identity store failed: {why}"),
        }
    }
}

impl std::error::Error for ResolveError {}

/// The local user for a login, and whether this login created it.
#[derive(Debug)]
pub enum Resolution {
    /// The identity was linked already.
    Found(User),
    /// The identity was new; the user was created and linked.
    Created(User),
}

impl Resolution {
    /// The user, either way.
    pub fn user(&self) -> &User {
        match self {
            Self::Found(u) | Self::Created(u) => u,
        }
    }

    /// Whether this login created the user.
    pub fn created(&self) -> bool {
        matches!(self, Self::Created(_))
    }
}

/// The issuer of a verified ID token: the `iss` claim.
///
/// `OAuthClaims::provider` is the name the application gave the registration,
/// which is not an identity: two registrations can name one issuer, and a
/// renamed registration must not orphan its users.
pub fn issuer_of(claims: &OAuthClaims) -> Option<&str> {
    claims
        .additional_claims
        .get("iss")
        .and_then(|v| v.as_str())
        .filter(|iss| !iss.is_empty())
}

/// Finds or creates local users for federated logins.
pub struct Provisioner<I, T> {
    identity: I,
    identities: Arc<T>,
    policy: TenantPolicy,
    clock: Arc<dyn Clock>,
    rng: Arc<dyn SecureRng>,
    // One resolution at a time: two first logins of one identity must not
    // each create a user. A database-backed table gets the same guarantee
    // from its unique key instead; without the gate, `create_and_link` signs
    // the loser in as the winner's user and removes the one it created.
    gate: tokio::sync::Mutex<()>,
}

impl<I, T> Provisioner<I, T>
where
    I: IdentityAdmin,
    T: FederatedIdentities,
{
    /// A provisioner over an identity store and a federated-identity table.
    pub fn new(
        identity: I,
        identities: Arc<T>,
        policy: TenantPolicy,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn SecureRng>,
    ) -> Self {
        Self {
            identity,
            identities,
            policy,
            clock,
            rng,
            gate: tokio::sync::Mutex::new(()),
        }
    }

    /// The tenant policy in force.
    pub fn policy(&self) -> &TenantPolicy {
        &self.policy
    }

    /// The local user for verified claims: the linked one, else a new one if
    /// the tenant's policy provisions just in time.
    pub async fn resolve(&self, claims: &OAuthClaims) -> Result<Resolution, ResolveError> {
        let issuer = issuer_of(claims).ok_or(ResolveError::NoIssuer)?;
        let _one_at_a_time = self.gate.lock().await;

        if let Some(id) = self.identities.find(issuer, &claims.subject).await {
            return match self.identity.get_user(&id).await {
                Ok(Some(user)) => Ok(Resolution::Found(user)),
                Ok(None) => Err(ResolveError::LinkedUserMissing(id)),
                Err(e) => Err(ResolveError::Store(e.to_string())),
            };
        }

        if self.policy.provisioning == Provisioning::LinkedOnly {
            return Err(ResolveError::NotProvisioned);
        }
        if self.policy.require_verified_email && claims.email_verified != Some(true) {
            return Err(ResolveError::UnverifiedEmail);
        }

        let name = claims
            .name
            .as_deref()
            .or(claims.email.as_deref())
            .unwrap_or(&claims.subject);
        self.create_and_link(issuer, &claims.subject, name)
            .await
            .map(Resolution::Created)
    }

    /// Create a user for an outside identity and link them, without waiting for
    /// a login: how an administrator invites someone into a tenant that
    /// creates no one on first login. Fails if the identity is linked already.
    pub async fn invite(
        &self,
        issuer: &str,
        subject: &str,
        display_name: &str,
    ) -> Result<User, ResolveError> {
        let _one_at_a_time = self.gate.lock().await;
        if self.identities.find(issuer, subject).await.is_some() {
            return Err(ResolveError::Invalid(
                "the identity is linked already".into(),
            ));
        }
        self.create_and_link(issuer, subject, display_name).await
    }

    async fn create_and_link(
        &self,
        issuer: &str,
        subject: &str,
        display_name: &str,
    ) -> Result<User, ResolveError> {
        let user = User::new(
            UserId::new(&self.rng).to_string(),
            self.policy.tenant.to_string(),
            // A login identifier that cannot collide with another issuer's:
            // the e-mail address could, and is not the link.
            format!("{issuer}#{subject}"),
            display_name,
            EntityState::Active,
            UserId::system(),
            self.clock.now(),
        )
        .map_err(ResolveError::Invalid)?;
        self.identity
            .create_user(user.clone())
            .await
            .map_err(|e| ResolveError::Store(e.to_string()))?;
        // The table answers with the user the identity is linked to: ours, or
        // the one a concurrent login linked first. Sign in as that one, and
        // do not leave the user this call created behind, linked to no one.
        let linked = self
            .identities
            .link_if_absent(issuer, subject, user.id)
            .await;
        if linked == user.id {
            return Ok(user);
        }
        self.identity
            .delete_user(&user.id)
            .await
            .map_err(|e| ResolveError::Store(e.to_string()))?;
        match self.identity.get_user(&linked).await {
            Ok(Some(winner)) => Ok(winner),
            Ok(None) => Err(ResolveError::LinkedUserMissing(linked)),
            Err(e) => Err(ResolveError::Store(e.to_string())),
        }
    }
}
