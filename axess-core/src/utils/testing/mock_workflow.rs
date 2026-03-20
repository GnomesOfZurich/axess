use crate::authn::{
    backend::AuthnBackend,
    methods::{
        factor::{Kind, Operation},
        form::Action,
    },
    types::SessionState,
    workflows::{StepKind, WorkflowState, WorkflowStep},
};
use chrono::Utc;
use serde_json::Value as JsonValue;
use std::collections::HashMap;

// WIP: used once the registration workflow is wired into session handling.
#[allow(dead_code)]
pub fn example_workflow_state<B: AuthnBackend>(
    _state: SessionState<B>,
    email_metadata: HashMap<String, JsonValue>,
    totp_metadata: HashMap<String, JsonValue>,
) -> WorkflowState {
    let now = Utc::now();
    let workflow_steps: Vec<WorkflowStep> = vec![
        WorkflowStep {
            kind: StepKind::FactorAction(Operation::new(Kind::EmailOtp, Action::Verify)),
            description: "Verify your email address".into(),
            completed: false,
            completed_at: None,
            metadata: Some(email_metadata),
        },
        WorkflowStep {
            kind: StepKind::FactorAction(Operation::new(Kind::Totp, Action::Setup)),
            description: "Set up your TOTP authenticator".into(),
            completed: false,
            completed_at: None,
            metadata: Some(totp_metadata),
        },
        WorkflowStep {
            kind: StepKind::Custom("kyc_review".into()),
            description: "Await KYC/Compliance approval".into(),
            completed: false,
            completed_at: None,
            metadata: None,
        },
    ];

    WorkflowState {
        steps: workflow_steps,
        current_step: 0,
        initiated_at: now,
        last_updated: now,
        blocking: false,
    }
}
