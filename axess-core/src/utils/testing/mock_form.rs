//! Dummy `FactorForm` implementations for exercising session and backend flows
//! in unit tests without relying on real credentials.

use crate::authn::{
    errors::FormError,
    methods::{
        factor::Kind,
        form::{Action, FactorForm, Flow, FormField, FormFieldValue},
    },
};
use serde_json::Value as JsonValue;
use std::collections::HashMap;

#[derive(Default, Debug, serde::Deserialize, serde::Serialize)]
pub struct DummyOkForm;

impl FactorForm for DummyOkForm {
    fn flow(&self) -> Flow {
        Flow::Knowledge
    }

    fn kind(&self) -> Kind {
        Kind::Password
    }

    fn action(&self) -> Action {
        Action::Verify
    }

    fn validate_form(&self) -> Result<&Self, FormError> {
        Ok(self)
    }

    fn credential(&self) -> Option<&str> {
        Some("dummy")
    }

    fn fields(&self) -> HashMap<FormField, FormFieldValue> {
        HashMap::new()
    }

    fn verify_against_config(
        &self,
        _config: &HashMap<String, JsonValue>,
    ) -> Result<&Self, FormError> {
        Ok(self)
    }
}

#[derive(Default, Debug, serde::Deserialize, serde::Serialize)]
pub struct DummyFailingForm;

impl FactorForm for DummyFailingForm {
    fn flow(&self) -> Flow {
        Flow::Knowledge
    }

    fn kind(&self) -> Kind {
        Kind::Password
    }

    fn action(&self) -> Action {
        Action::Verify
    }

    fn validate_form(&self) -> Result<&Self, FormError> {
        Ok(self)
    }

    fn credential(&self) -> Option<&str> {
        Some("dummy")
    }

    fn fields(&self) -> HashMap<FormField, FormFieldValue> {
        HashMap::new()
    }

    fn verify_against_config(
        &self,
        _config: &HashMap<String, JsonValue>,
    ) -> Result<&Self, FormError> {
        Err(FormError::ValidationFailed("boom".into()))
    }
}
