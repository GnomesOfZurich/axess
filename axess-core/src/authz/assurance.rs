//! Authentication assurance in the Cedar context, and the refusal that names
//! the step-up a policy needs.
//!
//! [`AssuranceContext`] turns a session's record
//! ([`AuthSession::assurance`](crate::session::extractor::AuthSession::assurance))
//! into the `context.assurance` attribute; [`ASSURANCE_SCHEMA_FRAGMENT`] is
//! its schema, [`AssuranceContextProvider`] puts it in a `require_authz!`
//! gate's context, and [`AuthzRefusal`] is the answer a gate gives when only
//! the assurance is short. The design, the attribute table and the one-rule
//! example are in `docs/authorization/assurance.md`.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use cedar_policy::{Context, EvalResult, RestrictedExpression};
use chrono::{DateTime, Utc};

use super::context::RequestContextProvider;
use super::error::AuthzError;
use crate::authn::assurance::{CredentialBinding, FactorAssurance, StepUp};
use crate::authn::factor::FactorKind;

/// The context attribute that carries the assurance record.
pub const ASSURANCE_ATTRIBUTE: &str = "assurance";

/// The policy annotation that names the step-up which satisfies a rule:
/// `@step_up("passkey")`.
pub const STEP_UP_ANNOTATION: &str = "step_up";

/// The Cedar common types of the `assurance` attribute, as JSON for a
/// namespace's `commonTypes`: `AxessFactorAssurance` (one factor's proof) and
/// `AxessAssurance` (one optional `AxessFactorAssurance` per factor kind).
/// Declare the attribute in an action's context as
/// `"assurance": { "type": "AxessAssurance" }`, or add both types with
/// [`merge_assurance_schema`].
pub const ASSURANCE_SCHEMA_FRAGMENT: &str = r#"{
  "AxessFactorAssurance": {
    "type": "Record",
    "attributes": {
      "user_verified": { "type": "Boolean" },
      "credential": { "type": "String" },
      "attested": { "type": "Boolean" },
      "trust_anchor": { "type": "String", "required": false },
      "age_seconds": { "type": "Long" }
    }
  },
  "AxessAssurance": {
    "type": "Record",
    "attributes": {
      "password": { "type": "AxessFactorAssurance", "required": false },
      "totp": { "type": "AxessFactorAssurance", "required": false },
      "hotp": { "type": "AxessFactorAssurance", "required": false },
      "email_otp": { "type": "AxessFactorAssurance", "required": false },
      "fido2": { "type": "AxessFactorAssurance", "required": false },
      "ldap_bind": { "type": "AxessFactorAssurance", "required": false },
      "recovery_code": { "type": "AxessFactorAssurance", "required": false },
      "federated": { "type": "AxessFactorAssurance", "required": false }
    }
  }
}"#;

/// Add the [`ASSURANCE_SCHEMA_FRAGMENT`] types to `namespace`'s
/// `commonTypes` in a parsed JSON schema.
///
/// # Errors
///
/// [`AuthzError::SchemaParse`] when the schema has no such namespace, its
/// `commonTypes` is not an object, or it already defines one of the two
/// types differently.
pub fn merge_assurance_schema(
    schema: &mut serde_json::Value,
    namespace: &str,
) -> Result<(), AuthzError> {
    let fragment: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(ASSURANCE_SCHEMA_FRAGMENT)
            .map_err(|e| AuthzError::SchemaParse(e.to_string()))?;
    let space = schema
        .get_mut(namespace)
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| AuthzError::SchemaParse(format!("no namespace {namespace:?}")))?;
    let common = space
        .entry("commonTypes")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .ok_or_else(|| AuthzError::SchemaParse("commonTypes is not an object".into()))?;
    for (name, definition) in fragment {
        match common.get(&name) {
            Some(existing) if *existing != definition => {
                return Err(AuthzError::SchemaParse(format!(
                    "commonTypes already defines {name} differently"
                )));
            }
            _ => {
                common.insert(name, definition);
            }
        }
    }
    Ok(())
}

/// The attribute of `context.assurance` a factor kind's proof appears under.
pub fn assurance_attribute(kind: &FactorKind) -> &'static str {
    match kind {
        FactorKind::Password => "password",
        FactorKind::Totp => "totp",
        FactorKind::Hotp => "hotp",
        FactorKind::EmailOtp => "email_otp",
        FactorKind::Fido2 => "fido2",
        FactorKind::LdapBind => "ldap_bind",
        FactorKind::RecoveryCode => "recovery_code",
        FactorKind::Federated(_) => "federated",
    }
}

/// One factor's proof as a policy sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactorEvidence {
    /// `user_verified`.
    pub user_verified: bool,
    /// `credential`: `"device_bound"`, `"synced"` or `"not_applicable"`.
    pub credential: CredentialBinding,
    /// `trust_anchor`, when an attested ceremony verified one; `attested` is
    /// whether it is present.
    pub trust_anchor: Option<String>,
    /// `age_seconds`: whole seconds from the proof to the request.
    pub age_seconds: i64,
}

/// The `context.assurance` record of one request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AssuranceContext {
    factors: BTreeMap<&'static str, FactorEvidence>,
}

impl AssuranceContext {
    /// The record of a session's proofs as of `now`, the caller's clock
    /// reading. A proof dated after `now` is left out (a clock that went
    /// backwards proves nothing fresh). An empty session record gives an
    /// empty record, which satisfies no policy that asks for a factor.
    pub fn from_session(record: &[FactorAssurance], now: DateTime<Utc>) -> Self {
        let mut context = Self::default();
        for proof in record {
            context.insert(proof, now);
        }
        context
    }

    /// The evidence under `attribute` (`"fido2"`, `"password"`, ...).
    pub fn factor(&self, attribute: &str) -> Option<&FactorEvidence> {
        self.factors.get(attribute)
    }

    /// The record with `proof` as the latest of its kind, as of `now`.
    pub fn with_proof(mut self, proof: &FactorAssurance, now: DateTime<Utc>) -> Self {
        self.insert(proof, now);
        self
    }

    fn insert(&mut self, proof: &FactorAssurance, now: DateTime<Utc>) {
        let age = now.signed_duration_since(proof.at).num_seconds();
        if proof.at > now {
            return;
        }
        let attribute = assurance_attribute(&proof.kind);
        let evidence = FactorEvidence {
            user_verified: proof.user_verified,
            credential: proof.credential,
            trust_anchor: proof.trust_anchor.as_deref().map(str::to_string),
            age_seconds: age,
        };
        // Two federated providers share one attribute: the latest holds it.
        match self.factors.get(attribute) {
            Some(held) if held.age_seconds < evidence.age_seconds => {}
            _ => {
                self.factors.insert(attribute, evidence);
            }
        }
    }

    /// The Cedar value of the `assurance` attribute.
    ///
    /// # Errors
    ///
    /// [`AuthzError::Context`] if Cedar refuses the record, which it does
    /// only for a duplicate key and so never here.
    pub fn to_expression(&self) -> Result<RestrictedExpression, AuthzError> {
        let factors = self.factors.iter().map(|(attribute, evidence)| {
            let mut fields = vec![
                (
                    "user_verified".to_string(),
                    RestrictedExpression::new_bool(evidence.user_verified),
                ),
                (
                    "credential".to_string(),
                    RestrictedExpression::new_string(evidence.credential.as_str().to_string()),
                ),
                (
                    "attested".to_string(),
                    RestrictedExpression::new_bool(evidence.trust_anchor.is_some()),
                ),
                (
                    "age_seconds".to_string(),
                    RestrictedExpression::new_long(evidence.age_seconds),
                ),
            ];
            if let Some(anchor) = &evidence.trust_anchor {
                fields.push((
                    "trust_anchor".to_string(),
                    RestrictedExpression::new_string(anchor.clone()),
                ));
            }
            RestrictedExpression::new_record(fields)
                .map(|record| ((*attribute).to_string(), record))
        });
        let factors = factors
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AuthzError::Context(e.to_string()))?;
        RestrictedExpression::new_record(factors).map_err(|e| AuthzError::Context(e.to_string()))
    }

    /// A context of this record alone.
    ///
    /// # Errors
    ///
    /// As [`to_expression`](Self::to_expression).
    pub fn to_context(&self) -> Result<Context, AuthzError> {
        Context::from_pairs([(ASSURANCE_ATTRIBUTE.to_string(), self.to_expression()?)])
            .map_err(|e| AuthzError::Context(e.to_string()))
    }

    /// The record a request's context carries, read back; `None` when the
    /// context has no `assurance` attribute or it is not this shape.
    pub(crate) fn from_context(context: &Context) -> Option<Self> {
        let EvalResult::Record(record) = context.get(ASSURANCE_ATTRIBUTE)? else {
            return None;
        };
        let mut factors = BTreeMap::new();
        for (attribute, value) in record.iter() {
            let attribute = known_attribute(attribute)?;
            factors.insert(attribute, evidence_of(value)?);
        }
        Some(Self { factors })
    }
}

fn known_attribute(name: &str) -> Option<&'static str> {
    [
        "password",
        "totp",
        "hotp",
        "email_otp",
        "fido2",
        "ldap_bind",
        "recovery_code",
        "federated",
    ]
    .into_iter()
    .find(|known| *known == name)
}

fn evidence_of(value: &EvalResult) -> Option<FactorEvidence> {
    let EvalResult::Record(record) = value else {
        return None;
    };
    let user_verified = match record.get("user_verified")? {
        EvalResult::Bool(b) => *b,
        _ => return None,
    };
    let credential = match record.get("credential")? {
        EvalResult::String(s) if s == "device_bound" => CredentialBinding::DeviceBound,
        EvalResult::String(s) if s == "synced" => CredentialBinding::Synced,
        EvalResult::String(s) if s == "not_applicable" => CredentialBinding::NotApplicable,
        _ => return None,
    };
    let age_seconds = match record.get("age_seconds")? {
        EvalResult::Long(n) => *n,
        _ => return None,
    };
    let trust_anchor = match record.get("trust_anchor") {
        Some(EvalResult::String(s)) => Some(s.clone()),
        None => None,
        Some(_) => return None,
    };
    Some(FactorEvidence {
        user_verified,
        credential,
        trust_anchor,
        age_seconds,
    })
}

/// `context` with its `assurance` attribute replaced by `assurance`, every
/// other attribute kept.
pub(crate) fn replace_assurance(
    context: Context,
    assurance: &AssuranceContext,
) -> Result<Context, AuthzError> {
    let replacement = assurance.to_expression()?;
    let pairs = context
        .into_iter()
        .filter(|(name, _)| name != ASSURANCE_ATTRIBUTE)
        .chain(std::iter::once((
            ASSURANCE_ATTRIBUTE.to_string(),
            replacement,
        )));
    Context::from_pairs(pairs).map_err(|e| AuthzError::Context(e.to_string()))
}

// ── AssuranceContextProvider ─────────────────────────────────────────────────

/// A [`RequestContextProvider`] that puts the session's assurance, as of the
/// injected clock, in the context as `assurance`, and nothing else.
///
/// Install it as `Arc<dyn RequestContextProvider>` beside the policy store
/// for gates whose policies read only `context.assurance`; a provider of
/// your own that also emits other attributes adds
/// [`AssuranceContext::to_expression`] beside them, or builds
/// [`StandardRequestContext::with_assurance`](super::context::StandardRequestContext::with_assurance).
pub struct AssuranceContextProvider {
    clock: Arc<dyn axess_clock::Clock>,
}

impl AssuranceContextProvider {
    /// A provider reading `clock` for the age of each proof.
    pub fn new(clock: Arc<dyn axess_clock::Clock>) -> Self {
        Self { clock }
    }
}

impl RequestContextProvider for AssuranceContextProvider {
    fn context_for<'a>(
        &'a self,
        session: &'a crate::session::AuthSession,
        _: &'a axum::http::request::Parts,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Context, AuthzError>> + Send + 'a>>
    {
        Box::pin(async move {
            AssuranceContext::from_session(&session.assurance().await, self.clock.now())
                .to_context()
        })
    }
}

// ── AuthzRefusal ─────────────────────────────────────────────────────────────

/// Why an authorization check refused: a denial, or a shortfall a step-up
/// would cure.
///
/// Converts to a 403 response: `{"error": "Access denied"}` for
/// [`Denied`](Self::Denied), `{"error": "step_up_required", "step_up":
/// "<name>"}` for [`StepUpRequired`](Self::StepUpRequired). The body names
/// the step-up and nothing of the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzRefusal {
    /// The policies deny, and no step-up the policy set names would permit.
    Denied,
    /// The policies would permit after this step-up: begin it with
    /// `RequestAuthnService::begin_step_up_for` and ask again.
    StepUpRequired(StepUp),
}

impl IntoResponse for AuthzRefusal {
    fn into_response(self) -> Response {
        match self {
            Self::Denied => super::error::AuthzDenied.into_response(),
            Self::StepUpRequired(step_up) => (
                StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({
                    "error": "step_up_required",
                    "step_up": step_up.to_string(),
                })),
            )
                .into_response(),
        }
    }
}

#[cfg(test)]
mod assurance_context_tests;
