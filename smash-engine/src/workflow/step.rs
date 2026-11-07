//! Apply one admitted process and retain only typed effects and resource evidence.

use super::oracle::{
    DecodingStatus, StateSnapshot, StepRecord, TransitionStatus, WorkflowEvent, WorkflowResult,
};
use super::policy::{hex, AdmittedWorkflowStep, WorkflowPolicy, RESULT_OUTPUT};
use crate::canonical;
use crate::repro::error::ReproError;
use crate::repro::linux::{LinuxRunner, ProcessState};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

pub(crate) struct ExecutedStep {
    pub record: StepRecord,
    pub credential_sha256: String,
}

pub(crate) fn execute_step(
    policy: &WorkflowPolicy,
    admitted: AdmittedWorkflowStep,
    runner: LinuxRunner,
    previous: Option<&StateSnapshot>,
    cancel: &AtomicBool,
) -> Result<ExecutedStep, ReproError> {
    let pre_binding = admitted.binding().clone();
    let run_namespace = admitted.binding().run_namespace.clone();
    let credential_value = admitted
        .job()
        .environment
        .get("SMASH_WORKFLOW_CREDENTIAL")
        .expect("admission fixes credential environment")
        .clone();
    let credential_sha256 = hex(&Sha256::digest(credential_value.as_bytes()));
    let sequence = pre_binding.sequence;
    let operation = pre_binding.operation;
    let index = pre_binding.step_index as usize;
    let (output, binding) =
        runner.execute_workflow(admitted, &[PathBuf::from(RESULT_OUTPUT)], cancel)?;
    if binding != pre_binding || binding.digest()? != pre_binding.digest()? {
        return Err(ReproError::Evidence(
            "one-shot workflow binding changed during execution".into(),
        ));
    }
    let bytes = output
        .declared_outputs
        .get(PathBuf::from(RESULT_OUTPUT).as_path());
    let result = bytes.and_then(|bytes| {
        canonical::parse_no_duplicates(bytes).ok()?;
        serde_json::from_slice::<WorkflowResult>(bytes).ok()
    });
    let resource_observation = result.as_ref().map(|result| result.resources.clone());
    let process = ProcessState::observed(
        &output,
        &policy.limits.to_core(),
        resource_observation.as_ref(),
    );
    let decoding = if output.stdout.is_empty() && result.is_some() {
        DecodingStatus::Valid
    } else {
        DecodingStatus::Invalid
    };
    let transition = if decoding == DecodingStatus::Valid
        && output.stderr.is_empty()
        && result.as_ref().is_some_and(|result| {
            super::oracle::result_well_formed(
                policy,
                binding.run_kind,
                operation,
                index,
                previous,
                result,
            )
        }) {
        TransitionStatus::Valid
    } else {
        TransitionStatus::Invalid
    };
    let mut events = Vec::new();
    if decoding == DecodingStatus::Valid && transition == TransitionStatus::Valid {
        let result = result.as_ref().expect("valid transition has typed result");
        for kind in ["step_started", "step_validated"] {
            events.push(WorkflowEvent {
                sequence,
                kind: kind.into(),
                operation,
                run_namespace: run_namespace.clone(),
                action_status: result.action_status,
                membership_observed: result.membership_observed,
                state_sha256: super::oracle::state_digest(&result.state),
            });
        }
    }
    Ok(ExecutedStep {
        record: StepRecord {
            sequence,
            binding_sha256: binding.digest()?,
            binding,
            events,
            process,
            resource_observation,
            decoding,
            transition,
            result,
            credential_reused: matches!(
                operation,
                super::oracle::WorkflowStep::BeginAcceptance
                    | super::oracle::WorkflowStep::CompleteAcceptance
            ),
        },
        credential_sha256,
    })
}
