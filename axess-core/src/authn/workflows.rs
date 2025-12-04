use crate::authn::{errors::WorkflowError, methods::factor::AuthFactorKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    hash::Hash,
};

pub trait Workflow:
    Clone
    + Display
    + Debug
    + Eq
    + PartialEq
    + Hash
    + Send
    + Sync
    + Serialize
    + for<'de> Deserialize<'de>
{
    /// Advances the workflow to the next step or state, if possible.
    fn advance(&mut self) -> Result<(), WorkflowError>;

    /// Returns a stable string or enum describing the current workflow step/state.
    fn current_step(&self) -> String;

    /// Returns true if the workflow is currently blocking authentication or access.
    fn is_blocking(&self) -> bool;

    /// Returns true if the workflow is complete and no longer blocking.
    fn is_complete(&self) -> bool;

    /// Optionally, returns a description or reason for blocking.
    fn blocking_reason(&self) -> Option<String>;
}

/// Describes the kind of step in a workflow.
/// Can be a factor verification, setup, or a custom business step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkflowStepKind {
    /// Verify a factor (e.g., email, TOTP, password).
    FactorVerify(AuthFactorKind),
    /// Setup a factor (e.g., provision TOTP).
    FactorSetup(AuthFactorKind),
    /// Custom business logic (e.g., KYC, admin approval).
    Custom(String),
}

/// Represents a single actionable step in a workflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowStep {
    /// The kind of step (factor verify, setup, or custom).
    pub kind: WorkflowStepKind,
    /// Human-readable description for UI/audit.
    pub description: String,
    /// Whether this step is completed.
    pub completed: bool,
    /// Optional timestamp of completion.
    pub completed_at: Option<DateTime<Utc>>,
    /// Optional metadata for extensibility.
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// Represents a user action or event that can advance a workflow.
/// This is passed to the workflow engine to drive transitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkflowAction {
    /// Submitted a factor form (setup, verify, change).
    FactorForm {
        kind: AuthFactorKind,
        form_kind: crate::authn::methods::form::FactorFormKind,
        fields: HashMap<String, serde_json::Value>,
    },
    /// Custom action (e.g., admin approval, document upload).
    Custom {
        name: String,
        data: HashMap<String, serde_json::Value>,
    },
}

/// Tracks the progress and blocking status of a multi-step workflow.
/// Used by `AuthState::PendingWorkflow` and `AuthState::PendingActivation`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowState {
    /// List of steps in the workflow.
    pub steps: Vec<WorkflowStep>,
    /// Index of the current step.
    pub current_step: usize,
    /// When the workflow started.
    pub started_at: DateTime<Utc>,
    /// When the workflow was last updated.
    pub last_updated: DateTime<Utc>,
    /// Whether the workflow is currently blocking access.
    pub blocking: bool,
}

impl WorkflowState {
    /// Returns the current step, if any.
    pub fn current_step(&self) -> Option<&WorkflowStep> {
        self.steps.get(self.current_step)
    }

    /// Returns true if all steps are completed.
    pub fn is_complete(&self) -> bool {
        self.steps.iter().all(|step| step.completed)
    }

    /// Advances the workflow based on an action.
    /// Returns Ok if the step was completed, Err otherwise.
    pub fn advance(
        &mut self,
        action: &WorkflowAction,
    ) -> Result<(), crate::authn::errors::WorkflowError> {
        if let Some(step) = self.steps.get_mut(self.current_step) {
            match (&step.kind, action) {
                (
                    WorkflowStepKind::FactorVerify(kind),
                    WorkflowAction::FactorForm { kind: k, .. },
                )
                | (
                    WorkflowStepKind::FactorSetup(kind),
                    WorkflowAction::FactorForm { kind: k, .. },
                ) if kind == k => {
                    // Here you could add more logic to validate the form_kind, fields, etc.
                    step.completed = true;
                    step.completed_at = Some(Utc::now());
                    self.current_step += 1;
                    self.last_updated = Utc::now();
                    if self.current_step >= self.steps.len() {
                        self.blocking = false;
                    }
                    Ok(())
                }
                (WorkflowStepKind::Custom(expected), WorkflowAction::Custom { name, .. })
                    if expected == name =>
                {
                    step.completed = true;
                    step.completed_at = Some(Utc::now());
                    self.current_step += 1;
                    self.last_updated = Utc::now();
                    if self.current_step >= self.steps.len() {
                        self.blocking = false;
                    }
                    Ok(())
                }
                _ => Err(crate::authn::errors::WorkflowError::InvalidTransition),
            }
        } else {
            Err(crate::authn::errors::WorkflowError::Incomplete)
        }
    }

    /// Returns a human-readable reason for blocking, if any.
    pub fn blocking_reason(&self) -> Option<String> {
        if self.blocking {
            self.current_step()
                .map(|step| format!("Workflow step '{}' is not complete", step.description))
        } else {
            None
        }
    }
}
