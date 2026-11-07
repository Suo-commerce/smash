//! Typed HTTP discovery, paired controls, and scalar-only observation evidence.

use crate::http::client::{HttpClient, HttpDisposition, WireOutcome};
use crate::http::policy::{
    HttpPolicyError, HttpTargetPolicy, OperationEffect, PlannedHttpCall, ResponseFieldKind,
    ResponseValue,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use smash_core::lifecycle::AttemptState;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Instant;

pub const M3_CAMPAIGN_VERSION: u32 = 1;
pub const HTTP_ORACLE_VERSION: &str = "http-scalar-differential-v1";
pub const MAX_PLAN_BYTES: u64 = 256 * 1024;

#[derive(Clone, Debug)]
pub struct HttpCampaignError(pub String);
impl fmt::Display for HttpCampaignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for HttpCampaignError {}
impl From<HttpPolicyError> for HttpCampaignError {
    fn from(value: HttpPolicyError) -> Self {
        Self(value.0)
    }
}
impl From<serde_json::Error> for HttpCampaignError {
    fn from(_: serde_json::Error) -> Self {
        Self("HTTP evidence serialization failed".into())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HttpPlannedCall {
    pub call: PlannedHttpCall,
    /// Exact fixed-control expectation. Every schema field must be pinned.
    pub expected: BTreeMap<String, ResponseValue>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EffectContract {
    pub before_case: usize,
    pub mutation_case: usize,
    pub after_case: usize,
    pub unknown_case: usize,
    pub correlation_field: String,
    pub effect_field: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HttpCampaignPolicy {
    pub schema_version: u32,
    pub run_id: String,
    pub target: HttpTargetPolicy,
    /// A separately admitted loopback origin for the fixed control.
    pub fixed_origin: String,
    pub calls: Vec<HttpPlannedCall>,
    pub effect: Option<EffectContract>,
}

impl HttpCampaignPolicy {
    pub fn validate(&self) -> Result<(), HttpCampaignError> {
        self.target.validate()?;
        if self.schema_version != M3_CAMPAIGN_VERSION
            || self.run_id.is_empty()
            || self.run_id.len() > 96
            || !self
                .run_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            || self.calls.is_empty()
            || self.calls.len() > self.target.limits.max_calls as usize
        {
            return Err(HttpCampaignError(
                "unsupported HTTP campaign version, identity, or call count".into(),
            ));
        }
        let mut fixed = self.target.clone();
        fixed.origin.clone_from(&self.fixed_origin);
        fixed.validate()?;
        let mutations = self
            .calls
            .iter()
            .filter(|case| {
                self.target
                    .route(&case.call.route_id)
                    .map(|route| route.effect)
                    == Some(OperationEffect::Mutating)
            })
            .count();
        if mutations > self.target.limits.max_mutations as usize {
            return Err(HttpCampaignError("planned mutation budget exceeded".into()));
        }
        for case in &self.calls {
            let route = self
                .target
                .route(&case.call.route_id)
                .ok_or_else(|| HttpCampaignError("plan selects an unadmitted route".into()))?;
            if case.call.arguments.len() != route.required_fields().len()
                || case.call.arguments.iter().any(|(name, value)| {
                    route.required_fields().get(name).map_or(true, |limit| {
                        value.is_empty() || value.len() > limit.max_utf8_bytes
                    })
                })
            {
                return Err(HttpCampaignError(
                    "planned call fields do not exactly match their admitted bounds".into(),
                ));
            }
            for (name, kind) in &route.response_fields {
                let valid = matches!(
                    (kind, case.expected.get(name)),
                    (ResponseFieldKind::Boolean, Some(ResponseValue::Boolean(_)))
                        | (
                            ResponseFieldKind::NonNegativeInteger,
                            Some(ResponseValue::NonNegativeInteger(_)),
                        )
                );
                if !valid {
                    return Err(HttpCampaignError(
                        "fixed expectation does not exactly pin the route response schema".into(),
                    ));
                }
            }
            if case.expected.len() != route.response_fields.len() {
                return Err(HttpCampaignError(
                    "fixed expectation has extra fields".into(),
                ));
            }
        }
        match (&self.effect, mutations) {
            (None, 0) => {}
            (Some(effect), 1) => self.validate_effect(effect)?,
            _ => {
                return Err(HttpCampaignError(
                    "read-only campaigns omit effects; exactly one mutation requires one effect contract"
                        .into(),
                ))
            }
        }
        Ok(())
    }

    fn validate_effect(&self, effect: &EffectContract) -> Result<(), HttpCampaignError> {
        let indexes = [
            effect.before_case,
            effect.mutation_case,
            effect.after_case,
            effect.unknown_case,
        ];
        let unique = indexes.iter().collect::<BTreeSet<_>>().len() == indexes.len();
        if !unique
            || effect.before_case >= effect.mutation_case
            || effect.mutation_case >= effect.after_case
            || indexes.iter().any(|index| *index >= self.calls.len())
        {
            return Err(HttpCampaignError(
                "effect controls must be distinct and ordered before/mutation/after".into(),
            ));
        }
        let mutation = &self.calls[effect.mutation_case];
        let before = &self.calls[effect.before_case];
        let after = &self.calls[effect.after_case];
        let unknown = &self.calls[effect.unknown_case];
        let Some(mutation_route) = self.target.route(&mutation.call.route_id) else {
            return Err(HttpCampaignError("missing mutation route".into()));
        };
        if mutation_route.effect != OperationEffect::Mutating
            || before.call.route_id != after.call.route_id
            || before.call.route_id != unknown.call.route_id
            || self
                .target
                .route(&before.call.route_id)
                .map(|route| route.effect)
                != Some(OperationEffect::ReadOnly)
            || !before
                .call
                .arguments
                .contains_key(&effect.correlation_field)
            || before.call.arguments != mutation.call.arguments
            || after.call.arguments != mutation.call.arguments
            || unknown.call.arguments.get(&effect.correlation_field)
                == mutation.call.arguments.get(&effect.correlation_field)
            || unknown.call.arguments.iter().any(|(name, value)| {
                name != &effect.correlation_field
                    && mutation.call.arguments.get(name) != Some(value)
            })
        {
            return Err(HttpCampaignError(
                "effect observations are not correlated with one mutation and an isolated unknown control"
                    .into(),
            ));
        }
        let Some(observation_route) = self.target.route(&before.call.route_id) else {
            return Err(HttpCampaignError("missing observation route".into()));
        };
        for (case, expected) in [(before, 0), (after, 1), (unknown, 0)] {
            if observation_route.response_fields.get(&effect.effect_field)
                != Some(&ResponseFieldKind::NonNegativeInteger)
                || case.expected.get(&effect.effect_field)
                    != Some(&ResponseValue::NonNegativeInteger(expected))
            {
                return Err(HttpCampaignError(
                    "effect oracle requires observed before=0, fixed after=1, and unknown=0 integers"
                        .into(),
                ));
            }
        }
        Ok(())
    }

    pub fn sha256(&self) -> Result<String, HttpCampaignError> {
        Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(self)?)))
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HttpControl {
    Observed,
    Broken,
    Fixed,
}
impl HttpControl {
    pub fn label(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Broken => "broken",
            Self::Fixed => "fixed",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttemptDisposition {
    NotDispatched,
    Resolved,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HttpOutcome {
    Denied,
    Malformed,
    Unhandled,
    Timeout,
    Observed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CorrelationEvidence {
    pub run_id: String,
    pub attempt_id: String,
    pub session_id: String,
    pub fixture_namespace: String,
    pub arguments_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HttpObservation {
    pub status: u16,
    pub content_type: Option<String>,
    pub body_sha256: String,
    pub body_length: u64,
    pub fields: BTreeMap<String, ResponseValue>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HttpAttemptEvidence {
    pub sequence: usize,
    pub correlation: CorrelationEvidence,
    pub route_id: String,
    pub method: crate::http::policy::HttpMethod,
    pub effect: OperationEffect,
    pub outcome: HttpOutcome,
    pub disposition: AttemptDisposition,
    pub reason: Option<String>,
    pub observation: Option<HttpObservation>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HttpControlEvidence {
    pub record_version: u32,
    pub control: HttpControl,
    pub target_id: String,
    pub policy_sha256: String,
    pub fixture_namespace: String,
    pub session_id: String,
    pub contained: bool,
    pub cleanup_completed: bool,
    pub calls: Vec<HttpAttemptEvidence>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DifferentialVerdict {
    Reproduced,
    Inconclusive,
    ControlInvalid,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HttpDifferentialAssessment {
    pub oracle_version: String,
    pub verdict: DifferentialVerdict,
    pub reproduced: bool,
    pub effect_observation_required: bool,
    pub limitations: Vec<String>,
}

impl DifferentialVerdict {
    pub fn reproduced(self) -> bool {
        self == Self::Reproduced
    }
}

/// Execute only declared cases with each credential captured immediately before
/// its dispatch. The cleanup callback is a target-provider attestation; callers
/// that do not own fixture teardown must return false, never claim clean exits.
pub fn execute_campaign<F, C>(
    policy: &HttpCampaignPolicy,
    mut credential: F,
    mut cleanup: C,
) -> Result<
    (
        HttpControlEvidence,
        HttpControlEvidence,
        HttpDifferentialAssessment,
    ),
    HttpCampaignError,
>
where
    F: FnMut(&str) -> Option<String>,
    C: FnMut(HttpControl) -> bool,
{
    policy.validate()?;
    execute_paired_with(policy, &mut credential, &mut cleanup)
}

fn execute_paired_with<F, C>(
    policy: &HttpCampaignPolicy,
    credential: &mut F,
    cleanup: &mut C,
) -> Result<
    (
        HttpControlEvidence,
        HttpControlEvidence,
        HttpDifferentialAssessment,
    ),
    HttpCampaignError,
>
where
    F: FnMut(&str) -> Option<String>,
    C: FnMut(HttpControl) -> bool,
{
    let started = Instant::now();
    let mut broken = match execute_control(HttpControl::Broken, policy, credential, started) {
        Ok(record) => record,
        Err(error) => {
            cleanup(HttpControl::Broken);
            cleanup(HttpControl::Fixed);
            return Err(error);
        }
    };
    let mut fixed = match execute_control(HttpControl::Fixed, policy, credential, started) {
        Ok(record) => record,
        Err(error) => {
            cleanup(HttpControl::Broken);
            cleanup(HttpControl::Fixed);
            return Err(error);
        }
    };
    let broken_cleanup = cleanup(HttpControl::Broken);
    let fixed_cleanup = cleanup(HttpControl::Fixed);
    broken.cleanup_completed = broken_cleanup;
    fixed.cleanup_completed = fixed_cleanup;
    let assessment = assess(policy, &broken, &fixed, broken_cleanup, fixed_cleanup);
    Ok((broken, fixed, assessment))
}

pub fn discover<F>(
    policy: &HttpCampaignPolicy,
    credential: &mut F,
) -> Result<HttpControlEvidence, HttpCampaignError>
where
    F: FnMut(&str) -> Option<String>,
{
    policy.validate()?;
    if policy.effect.is_some()
        || policy.calls.iter().any(|case| {
            policy
                .target
                .route(&case.call.route_id)
                .map(|route| route.effect)
                == Some(OperationEffect::Mutating)
        })
    {
        return Err(HttpCampaignError(
            "HTTP discovery admits only explicitly read-only cases".into(),
        ));
    }
    let started = Instant::now();
    execute_control(HttpControl::Observed, policy, credential, started)
}

fn execute_control<F>(
    control: HttpControl,
    policy: &HttpCampaignPolicy,
    credential: &mut F,
    started: Instant,
) -> Result<HttpControlEvidence, HttpCampaignError>
where
    F: FnMut(&str) -> Option<String>,
{
    let mut target = policy.target.clone();
    if control == HttpControl::Fixed {
        target.origin.clone_from(&policy.fixed_origin);
    }
    let client = HttpClient::new(&target)?;
    let fixture_namespace = format!("{}:{}:{}", policy.run_id, target.target_id, control.label());
    let session_id = format!("{fixture_namespace}:session");
    let deadline = std::time::Duration::from_millis(
        u64::from(policy.target.limits.max_calls) * policy.target.limits.timeout_ms,
    );
    let mut calls = Vec::with_capacity(policy.calls.len());
    for (sequence, planned) in policy.calls.iter().enumerate() {
        calls.push(execute_attempt(
            policy,
            &target,
            &client,
            planned,
            sequence,
            &fixture_namespace,
            &session_id,
            credential,
            started,
            deadline,
        )?);
    }
    Ok(HttpControlEvidence {
        record_version: M3_CAMPAIGN_VERSION,
        control,
        target_id: target.target_id,
        policy_sha256: policy.sha256()?,
        fixture_namespace,
        session_id,
        contained: true,
        cleanup_completed: false,
        calls,
    })
}

/// Execute exactly one pre-admitted read for the M4 investigation loop. The
/// caller supplies only a catalog index; no planner-controlled request data
/// crosses this boundary. A fresh client retains M3's no-idle-reuse behavior.
pub fn execute_read_call<F>(
    policy: &HttpCampaignPolicy,
    call_index: usize,
    sequence: usize,
    credential: &mut F,
) -> Result<HttpAttemptEvidence, HttpCampaignError>
where
    F: FnMut(&str) -> Option<String>,
{
    policy.validate()?;
    let planned = policy
        .calls
        .get(call_index)
        .ok_or_else(|| HttpCampaignError("investigation call index is not admitted".into()))?;
    let target = policy.target.clone();
    let route = target
        .route(&planned.call.route_id)
        .ok_or_else(|| HttpCampaignError("selected read route is missing".into()))?;
    if route.effect != OperationEffect::ReadOnly {
        return Err(HttpCampaignError(
            "investigation execution admits only read-only routes".into(),
        ));
    }
    let client = HttpClient::new(&target)?;
    let fixture_namespace = format!("{}:{}:investigation", policy.run_id, target.target_id);
    let session_id = format!("{fixture_namespace}:session");
    execute_attempt(
        policy,
        &target,
        &client,
        planned,
        sequence,
        &fixture_namespace,
        &session_id,
        credential,
        Instant::now(),
        std::time::Duration::from_millis(target.limits.timeout_ms),
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_attempt<F>(
    policy: &HttpCampaignPolicy,
    target: &crate::http::policy::HttpTargetPolicy,
    client: &HttpClient,
    planned: &HttpPlannedCall,
    sequence: usize,
    fixture_namespace: &str,
    session_id: &str,
    credential: &mut F,
    started: Instant,
    deadline: std::time::Duration,
) -> Result<HttpAttemptEvidence, HttpCampaignError>
where
    F: FnMut(&str) -> Option<String>,
{
    let route = target
        .route(&planned.call.route_id)
        .ok_or_else(|| HttpCampaignError("route disappeared during execution".into()))?;
    let attempt_id = format!("{session_id}:attempt-{sequence}");
    let arguments_sha256 = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&planned.call.arguments)?)
    );
    let correlation = CorrelationEvidence {
        run_id: policy.run_id.clone(),
        attempt_id,
        session_id: session_id.to_owned(),
        fixture_namespace: fixture_namespace.to_owned(),
        arguments_sha256,
    };
    let secret = match &route.credential {
        Some(reference) => credential(&reference.environment_variable),
        None => None,
    };
    let exchange = if started.elapsed() > deadline {
        return Err(HttpCampaignError(
            "HTTP campaign wall-clock budget exhausted".into(),
        ));
    } else {
        client.dispatch(&planned.call, secret.as_deref())
    };
    let disposition = match exchange.disposition() {
        HttpDisposition::NotDispatched => AttemptDisposition::NotDispatched,
        HttpDisposition::Resolved => AttemptDisposition::Resolved,
        HttpDisposition::Unresolved => AttemptDisposition::Unresolved,
    };
    let lifecycle = if disposition == AttemptDisposition::NotDispatched {
        AttemptState::Intended
    } else {
        let dispatched = AttemptState::Intended
            .try_advance(AttemptState::Dispatched)
            .map_err(|_| HttpCampaignError("invalid attempt lifecycle".into()))?;
        let terminal = if disposition == AttemptDisposition::Unresolved {
            AttemptState::Unresolved
        } else {
            AttemptState::Resolved
        };
        dispatched
            .try_advance(terminal)
            .map_err(|_| HttpCampaignError("invalid terminal attempt lifecycle".into()))?
    };
    debug_assert_eq!(
        lifecycle.is_safe_as_not_executed(),
        disposition == AttemptDisposition::NotDispatched
    );
    let (outcome, reason, observation) = match exchange.outcome {
        WireOutcome::Denied(failure) => (HttpOutcome::Denied, Some(failure.reason), None),
        WireOutcome::Malformed(failure) => (HttpOutcome::Malformed, Some(failure.reason), None),
        WireOutcome::Unhandled { failure, .. } => {
            (HttpOutcome::Unhandled, Some(failure.reason), None)
        }
        WireOutcome::Timeout => (
            HttpOutcome::Timeout,
            Some("dispatch deadline elapsed; effects may be unresolved".into()),
            None,
        ),
        WireOutcome::Observed(response) => {
            match response
                .parse_json()
                .and_then(|value| scalar_fields(route, value))
            {
                Ok(fields) => (
                    HttpOutcome::Observed,
                    None,
                    Some(HttpObservation {
                        status: response.status,
                        content_type: response.content_type,
                        body_sha256: response.body_sha256,
                        body_length: response.body_length,
                        fields,
                    }),
                ),
                Err(failure) => (HttpOutcome::Malformed, Some(failure.reason), None),
            }
        }
    };
    Ok(HttpAttemptEvidence {
        sequence,
        correlation,
        route_id: planned.call.route_id.clone(),
        method: route.method,
        effect: route.effect,
        outcome,
        disposition,
        reason,
        observation,
    })
}

fn scalar_fields(
    route: &crate::http::policy::RoutePolicy,
    value: serde_json::Value,
) -> Result<BTreeMap<String, ResponseValue>, crate::http::client::ResponseFailure> {
    let invalid = || crate::http::client::ResponseFailure {
        reason: "response does not match its exact scalar route schema".into(),
    };
    let object = value.as_object().ok_or_else(invalid)?;
    if object.len() != route.response_fields.len() {
        return Err(invalid());
    }
    route
        .response_fields
        .iter()
        .map(|(name, kind)| {
            let value = match (kind, object.get(name)) {
                (ResponseFieldKind::Boolean, Some(serde_json::Value::Bool(value))) => {
                    ResponseValue::Boolean(*value)
                }
                (ResponseFieldKind::NonNegativeInteger, Some(value)) => {
                    ResponseValue::NonNegativeInteger(value.as_u64().ok_or_else(invalid)?)
                }
                _ => return Err(invalid()),
            };
            Ok((name.clone(), value))
        })
        .collect()
}

fn arguments_digest(case: &HttpPlannedCall) -> String {
    serde_json::to_vec(&case.call.arguments)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .unwrap_or_default()
}

fn assess(
    policy: &HttpCampaignPolicy,
    broken: &HttpControlEvidence,
    fixed: &HttpControlEvidence,
    broken_cleanup: bool,
    fixed_cleanup: bool,
) -> HttpDifferentialAssessment {
    let valid_identity = |record: &HttpControlEvidence, control| {
        record.record_version == M3_CAMPAIGN_VERSION
            && record.control == control
            && record.contained
            && record.policy_sha256 == policy.sha256().unwrap_or_default()
            && record.calls.len() == policy.calls.len()
            && record.calls.iter().enumerate().all(|(index, call)| {
                call.sequence == index && call.route_id == policy.calls[index].call.route_id
            })
    };
    let complete = |record: &HttpControlEvidence| {
        record.calls.iter().all(|call| {
            call.outcome == HttpOutcome::Observed
                && call.disposition == AttemptDisposition::Resolved
                && call.observation.is_some()
        })
    };
    let fixed_expected = complete(fixed)
        && policy.calls.iter().enumerate().all(|(index, case)| {
            fixed.calls[index]
                .observation
                .as_ref()
                .map(|response| &response.fields)
                == Some(&case.expected)
        });
    let observations_differ = || {
        policy.calls.iter().enumerate().any(|(index, _)| {
            broken
                .calls
                .get(index)
                .and_then(|call| call.observation.as_ref())
                != fixed
                    .calls
                    .get(index)
                    .and_then(|call| call.observation.as_ref())
        })
    };
    let effect_holds = || {
        let Some(effect) = &policy.effect else {
            return observations_differ();
        };
        let Some(before) = broken
            .calls
            .get(effect.before_case)
            .and_then(|call| call.observation.as_ref())
            .and_then(|observation| observation.fields.get(&effect.effect_field))
        else {
            return false;
        };
        let Some(after) = broken
            .calls
            .get(effect.after_case)
            .and_then(|call| call.observation.as_ref())
            .and_then(|observation| observation.fields.get(&effect.effect_field))
        else {
            return false;
        };
        let Some(unknown) = broken
            .calls
            .get(effect.unknown_case)
            .and_then(|call| call.observation.as_ref())
            .and_then(|observation| observation.fields.get(&effect.effect_field))
        else {
            return false;
        };
        let fixed_after = fixed.calls[effect.after_case]
            .observation
            .as_ref()
            .and_then(|observation| observation.fields.get(&effect.effect_field));
        before == &ResponseValue::NonNegativeInteger(0)
            && unknown == &ResponseValue::NonNegativeInteger(0)
            && Some(after) != fixed_after
    };
    let valid = valid_identity(broken, HttpControl::Broken)
        && valid_identity(fixed, HttpControl::Fixed)
        && broken_cleanup
        && fixed_cleanup
        && fixed_expected;
    let verdict = if !valid || !complete(broken) {
        if valid_identity(broken, HttpControl::Broken)
            && valid_identity(fixed, HttpControl::Fixed)
            && complete(fixed)
            && !fixed_expected
        {
            DifferentialVerdict::ControlInvalid
        } else {
            DifferentialVerdict::Inconclusive
        }
    } else if effect_holds() && observations_differ() {
        DifferentialVerdict::Reproduced
    } else {
        DifferentialVerdict::Inconclusive
    };
    HttpDifferentialAssessment {
        oracle_version: HTTP_ORACLE_VERSION.into(),
        reproduced: verdict.reproduced(),
        effect_observation_required: policy.effect.is_some(),
        verdict,
        limitations: vec![
            "Only the admitted scalar route templates and paired disposable-fixture observations were compared.".into(),
            "This establishes no general security, exploitability, production, or unsearched-route conclusion.".into(),
            "Digest and evidence checks are not a signature or an independent authenticity claim.".into(),
        ],
    }
}

/// Strict offline check shared by bundles and reconstructed records. No source,
/// process, target origin, credential, or network access is performed.
pub fn verify_assessment(
    policy: &HttpCampaignPolicy,
    broken: &HttpControlEvidence,
    fixed: &HttpControlEvidence,
    assessment: &HttpDifferentialAssessment,
    broken_cleanup: bool,
    fixed_cleanup: bool,
) -> Result<(), HttpCampaignError> {
    policy.validate()?;
    for (record, control) in [(broken, HttpControl::Broken), (fixed, HttpControl::Fixed)] {
        if record.control != control
            || record.record_version != M3_CAMPAIGN_VERSION
            || !record.contained
            || record.cleanup_completed
                != (broken_cleanup && control == HttpControl::Broken
                    || fixed_cleanup && control == HttpControl::Fixed)
            || record.target_id != policy.target.target_id
            || record.policy_sha256 != policy.sha256()?
            || record.fixture_namespace
                != format!(
                    "{}:{}:{}",
                    policy.run_id,
                    policy.target.target_id,
                    control.label()
                )
            || record.session_id != format!("{}:session", record.fixture_namespace)
            || record.calls.len() != policy.calls.len()
        {
            return Err(HttpCampaignError(
                "HTTP control identity or cleanup mismatch".into(),
            ));
        }
        for (index, call) in record.calls.iter().enumerate() {
            let planned = &policy.calls[index];
            let route = policy
                .target
                .route(&planned.call.route_id)
                .ok_or_else(|| HttpCampaignError("missing route during verification".into()))?;
            let expected_disposition = match call.outcome {
                HttpOutcome::Denied => AttemptDisposition::NotDispatched,
                HttpOutcome::Timeout => AttemptDisposition::Unresolved,
                _ => AttemptDisposition::Resolved,
            };
            let observed = call.outcome == HttpOutcome::Observed;
            if call.sequence != index
                || call.route_id != planned.call.route_id
                || call.method != route.method
                || call.effect != route.effect
                || call.disposition != expected_disposition
                || call.observation.is_some() != observed
                || observed
                    && (call.reason.is_some()
                        || call.observation.as_ref().is_some_and(|response| {
                            response.body_length > policy.target.limits.max_response_bytes
                        }))
                || call.correlation
                    != (CorrelationEvidence {
                        run_id: policy.run_id.clone(),
                        attempt_id: format!("{}:attempt-{index}", record.session_id),
                        session_id: record.session_id.clone(),
                        fixture_namespace: record.fixture_namespace.clone(),
                        arguments_sha256: arguments_digest(planned),
                    })
            {
                return Err(HttpCampaignError(
                    "attempt correlation or disposition mismatch".into(),
                ));
            }
            if let Some(observation) = &call.observation {
                if observation.fields.keys().collect::<Vec<_>>()
                    != route.response_fields.keys().collect::<Vec<_>>()
                    || observation.fields.iter().any(|(name, value)| {
                        !matches!(
                            (route.response_fields.get(name), value),
                            (Some(ResponseFieldKind::Boolean), ResponseValue::Boolean(_))
                                | (
                                    Some(ResponseFieldKind::NonNegativeInteger),
                                    ResponseValue::NonNegativeInteger(_)
                                )
                        )
                    })
                {
                    return Err(HttpCampaignError(
                        "observed scalar response schema mismatch".into(),
                    ));
                }
            }
        }
    }
    if assess(policy, broken, fixed, broken_cleanup, fixed_cleanup) != *assessment {
        return Err(HttpCampaignError(
            "reported HTTP oracle result mismatch".into(),
        ));
    }
    Ok(())
}

/// Execution-free consistency check for one M4 observed-control attempt.
/// Digests identify evidence inside a session; they do not authenticate the
/// original target or prove that a recorded network exchange actually happened.
pub fn verify_read_attempt(
    policy: &HttpCampaignPolicy,
    call_index: usize,
    sequence: usize,
    call: &HttpAttemptEvidence,
) -> Result<(), HttpCampaignError> {
    policy.validate()?;
    let planned = policy
        .calls
        .get(call_index)
        .ok_or_else(|| HttpCampaignError("unadmitted investigation call".into()))?;
    let route = policy
        .target
        .route(&planned.call.route_id)
        .ok_or_else(|| HttpCampaignError("missing investigation route".into()))?;
    if route.effect != OperationEffect::ReadOnly {
        return Err(HttpCampaignError(
            "investigation evidence contains a mutation".into(),
        ));
    }
    let fixture_namespace = format!(
        "{}:{}:investigation",
        policy.run_id, policy.target.target_id
    );
    let session_id = format!("{fixture_namespace}:session");
    let expected_disposition = match call.outcome {
        HttpOutcome::Denied => AttemptDisposition::NotDispatched,
        HttpOutcome::Timeout => AttemptDisposition::Unresolved,
        _ => AttemptDisposition::Resolved,
    };
    let observed = call.outcome == HttpOutcome::Observed;
    if call.sequence != sequence
        || call.route_id != planned.call.route_id
        || call.method != route.method
        || call.effect != OperationEffect::ReadOnly
        || call.disposition != expected_disposition
        || call.observation.is_some() != observed
        || observed
            && (call.reason.is_some()
                || call.observation.as_ref().is_some_and(|response| {
                    response.body_length > policy.target.limits.max_response_bytes
                }))
        || call.correlation
            != (CorrelationEvidence {
                run_id: policy.run_id.clone(),
                attempt_id: format!("{session_id}:attempt-{sequence}"),
                session_id,
                fixture_namespace,
                arguments_sha256: arguments_digest(planned),
            })
    {
        return Err(HttpCampaignError(
            "investigation attempt correlation or disposition mismatch".into(),
        ));
    }
    if let Some(observation) = &call.observation {
        if observation.fields.keys().collect::<Vec<_>>()
            != route.response_fields.keys().collect::<Vec<_>>()
            || observation.fields.iter().any(|(name, value)| {
                !matches!(
                    (route.response_fields.get(name), value),
                    (Some(ResponseFieldKind::Boolean), ResponseValue::Boolean(_))
                        | (
                            Some(ResponseFieldKind::NonNegativeInteger),
                            ResponseValue::NonNegativeInteger(_)
                        )
                )
            })
        {
            return Err(HttpCampaignError(
                "investigation scalar response schema mismatch".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::canonical::parse_no_duplicates;

    #[test]
    fn duplicate_json_keys_are_not_accepted() {
        assert!(parse_no_duplicates(br#"{"ok":true,"ok":false}"#).is_err());
    }
}
