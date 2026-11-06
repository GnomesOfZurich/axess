//! The stored shape of an [`AuthState`] as it is read, with the readers of the
//! earlier plain-list shapes, so a session written by an earlier release still
//! loads.

use super::*;

/// Read `Authenticating::remaining` as steps, accepting the earlier shape
/// (a list of factor kinds) as required steps, so a session written by an
/// earlier release mid-login still loads after an upgrade.
fn deserialize_remaining_steps<'de, D>(deserializer: D) -> Result<Vec<FactorStep>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StepOrKind {
        Step(FactorStep),
        Kind(FactorKind),
    }
    let items = Vec::<StepOrKind>::deserialize(deserializer)?;
    Ok(items
        .into_iter()
        .map(|item| match item {
            StepOrKind::Step(step) => step,
            StepOrKind::Kind(kind) => FactorStep::Required(kind),
        })
        .collect())
}

/// The time a factor read from the earlier plain-list shape carries until the
/// state it sits in stamps it (see the `Deserialize` impl of [`AuthState`]).
const LEGACY_FACTOR_TIME: DateTime<Utc> = DateTime::<Utc>::MIN_UTC;

/// Read a list of completed factors, accepting the earlier shape (a list of
/// factor kinds with no times) and marking its entries for stamping.
fn deserialize_completed<'de, D>(
    deserializer: D,
) -> Result<Vec<(FactorKind, DateTime<Utc>)>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Entry {
        Timed((FactorKind, DateTime<Utc>)),
        Kind(FactorKind),
    }
    let items = Vec::<Entry>::deserialize(deserializer)?;
    Ok(items
        .into_iter()
        .map(|item| match item {
            Entry::Timed(entry) => entry,
            Entry::Kind(kind) => (kind, LEGACY_FACTOR_TIME),
        })
        .collect())
}

/// The stored shape of an [`AuthState`] as it is read: the current fields,
/// and the factor lists also as the earlier plain list of kinds. The
/// conversion stamps an `Authenticated` state's plain list with its
/// `authn_time`, and an `Authenticating` state's (which has no time of its
/// own) with the Unix epoch.
#[derive(Deserialize)]
#[serde(tag = "kind")]
pub(super) enum AuthStateWire {
    Guest,
    Identifying {
        user_id: UserId,
        tenant_id: TenantId,
    },
    Authenticating {
        user_id: UserId,
        tenant_id: TenantId,
        method_name: Arc<str>,
        #[serde(deserialize_with = "deserialize_remaining_steps")]
        remaining: Vec<FactorStep>,
        #[serde(default, deserialize_with = "deserialize_completed")]
        completed: Vec<(FactorKind, DateTime<Utc>)>,
        attempt_count: u32,
        last_attempt: Option<DateTime<Utc>>,
        #[serde(default)]
        ldap_groups: Option<Vec<String>>,
        #[serde(default)]
        impersonator: Option<Impersonation>,
    },
    Authenticated {
        user_id: UserId,
        tenant_id: TenantId,
        authn_time: DateTime<Utc>,
        #[serde(default, deserialize_with = "deserialize_completed")]
        factors_completed: Vec<(FactorKind, DateTime<Utc>)>,
        #[serde(default)]
        impersonator: Option<Impersonation>,
        #[serde(default)]
        ldap_groups: Option<Vec<String>>,
    },
    PendingWorkflow {
        user_id: UserId,
        tenant_id: TenantId,
        workflow: WorkflowState,
    },
}

impl From<AuthStateWire> for AuthState {
    fn from(wire: AuthStateWire) -> Self {
        match wire {
            AuthStateWire::Guest => AuthState::Guest,
            AuthStateWire::Identifying { user_id, tenant_id } => {
                AuthState::Identifying { user_id, tenant_id }
            }
            AuthStateWire::Authenticating {
                user_id,
                tenant_id,
                method_name,
                remaining,
                mut completed,
                attempt_count,
                last_attempt,
                ldap_groups,
                impersonator,
            } => {
                stamp_legacy(&mut completed, DateTime::<Utc>::UNIX_EPOCH);
                AuthState::Authenticating {
                    user_id,
                    tenant_id,
                    method_name,
                    remaining,
                    completed,
                    attempt_count,
                    last_attempt,
                    ldap_groups,
                    impersonator,
                }
            }
            AuthStateWire::Authenticated {
                user_id,
                tenant_id,
                authn_time,
                mut factors_completed,
                impersonator,
                ldap_groups,
            } => {
                stamp_legacy(&mut factors_completed, authn_time);
                AuthState::Authenticated {
                    user_id,
                    tenant_id,
                    authn_time,
                    factors_completed,
                    impersonator,
                    ldap_groups,
                }
            }
            AuthStateWire::PendingWorkflow {
                user_id,
                tenant_id,
                workflow,
            } => AuthState::PendingWorkflow {
                user_id,
                tenant_id,
                workflow,
            },
        }
    }
}

fn stamp_legacy(factors: &mut [(FactorKind, DateTime<Utc>)], time: DateTime<Utc>) {
    for (_, at) in factors {
        if *at == LEGACY_FACTOR_TIME {
            *at = time;
        }
    }
}
