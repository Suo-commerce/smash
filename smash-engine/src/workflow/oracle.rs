//! Typed workflow behavior independent of claims, routing, or stored conclusions.

use super::policy::{StepBinding, WorkflowPolicy, REVOKED_INVITE_ORACLE, REVOKED_INVITE_SCENARIO};
use crate::repro::error::ReproError;
use crate::repro::linux::{ProcessState, ResourceObservation};
use serde::{Deserialize, Serialize};
use sha2::Digest;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStep {
    CreateProject,
    CreateInvitation,
    BeginAcceptance,
    RevokeInvitation,
    CompleteAcceptance,
    ObserveMembership,
}

impl WorkflowStep {
    pub fn catalog(functional_control: bool) -> &'static [WorkflowStep] {
        const FULL: &[WorkflowStep] = &[
            WorkflowStep::CreateProject,
            WorkflowStep::CreateInvitation,
            WorkflowStep::BeginAcceptance,
            WorkflowStep::RevokeInvitation,
            WorkflowStep::CompleteAcceptance,
            WorkflowStep::ObserveMembership,
        ];
        const CONTROL: &[WorkflowStep] = &[
            WorkflowStep::CreateProject,
            WorkflowStep::CreateInvitation,
            WorkflowStep::BeginAcceptance,
            WorkflowStep::CompleteAcceptance,
            WorkflowStep::ObserveMembership,
        ];
        if functional_control {
            CONTROL
        } else {
            FULL
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowVariant {
    Broken,
    Fixed,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowRunKind {
    Broken,
    Fixed,
    FunctionalControl,
}
impl WorkflowRunKind {
    pub fn variant(self) -> WorkflowVariant {
        match self {
            WorkflowRunKind::Broken => WorkflowVariant::Broken,
            WorkflowRunKind::Fixed | WorkflowRunKind::FunctionalControl => WorkflowVariant::Fixed,
        }
    }
    pub fn slug(self) -> &'static str {
        match self {
            WorkflowRunKind::Broken => "broken",
            WorkflowRunKind::Fixed => "fixed",
            WorkflowRunKind::FunctionalControl => "control",
        }
    }
    pub fn run_index(self) -> u32 {
        match self {
            Self::Broken => 0,
            Self::Fixed => 1,
            Self::FunctionalControl => 2,
        }
    }
    pub fn file(self) -> &'static str {
        match self {
            WorkflowRunKind::Broken => "broken.json",
            WorkflowRunKind::Fixed => "fixed.json",
            WorkflowRunKind::FunctionalControl => "control.json",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowActionStatus {
    Granted,
    Revoked,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InvitationStatus {
    Pending,
    Revoked,
    Accepted,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceStatus {
    NotStarted,
    Pending,
    Complete,
    Denied,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StateSnapshot {
    pub schema_version: u32,
    pub sequence: u64,
    pub project: String,
    pub owner: String,
    pub guest: String,
    pub invitation: String,
    pub invitation_status: InvitationStatus,
    pub acceptance_status: AcceptanceStatus,
    pub guest_is_member: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowResult {
    pub schema_version: u32,
    pub state: StateSnapshot,
    pub action_status: Option<WorkflowActionStatus>,
    pub membership_observed: bool,
    pub resources: ResourceObservation,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecodingStatus {
    Valid,
    Invalid,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransitionStatus {
    Valid,
    Invalid,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowEvent {
    pub sequence: u64,
    pub kind: String,
    pub operation: WorkflowStep,
    pub run_namespace: String,
    pub action_status: Option<WorkflowActionStatus>,
    pub membership_observed: bool,
    pub state_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StepRecord {
    pub sequence: u64,
    pub binding: StepBinding,
    pub binding_sha256: String,
    pub events: Vec<WorkflowEvent>,
    pub process: ProcessState,
    pub resource_observation: Option<ResourceObservation>,
    pub decoding: DecodingStatus,
    pub transition: TransitionStatus,
    pub result: Option<WorkflowResult>,
    pub credential_reused: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CleanupRecord {
    pub sequence: u64,
    pub complete: bool,
    pub target_root_removed: bool,
    pub error_code: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunRecord {
    pub schema_version: u32,
    pub scenario: String,
    pub oracle: String,
    pub run_kind: WorkflowRunKind,
    pub variant: WorkflowVariant,
    pub run_namespace: String,
    pub policy_sha256: String,
    pub target_root: std::path::PathBuf,
    pub credential_reference: String,
    pub credential_sha256: String,
    pub synthetic_guest: bool,
    pub disposable_private_target: bool,
    pub target_destruction: bool,
    pub error_code: Option<String>,
    pub containment_failures: Vec<String>,
    pub cleanup: CleanupRecord,
    pub steps: Vec<StepRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Assessment {
    pub eligible: bool,
    pub actions_match: bool,
    pub states_match: bool,
    pub membership_matches: bool,
    pub broken_effect: bool,
    pub fixed_effect_prevented: bool,
    pub functional_control_normal: bool,
    pub interpretation: Interpretation,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Interpretation {
    Confirmed,
    NoEffect,
    OperationalFailure,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowConclusion {
    Confirmed,
    NoEffect,
    InterpretationFailed,
    EnvironmentManualReview,
}
impl WorkflowConclusion {
    pub fn slug(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::NoEffect => "no_effect",
            Self::InterpretationFailed => "interpretation_failed",
            Self::EnvironmentManualReview => "environment_manual_review",
        }
    }
}

/// Recompute every semantic and defense-property verdict from the recorded behavior.
pub fn assess(
    policy: &WorkflowPolicy,
    runs: &[RunRecord; 3],
    invocation_id: &str,
) -> Result<Assessment, ReproError> {
    if !super::policy::valid_invocation_id(invocation_id) {
        return Err(ReproError::Evidence(
            "invalid workflow invocation identity".into(),
        ));
    }
    let mut per_run = Vec::new();
    for run in runs {
        if run.schema_version != policy.evidence_schema
            || run.scenario != REVOKED_INVITE_SCENARIO
            || run.oracle != REVOKED_INVITE_ORACLE
            || run.run_namespace
                != super::policy::run_namespace(policy, run.run_kind, invocation_id)
            || run.policy_sha256 != policy.digest()?
            || run.target_root != policy.root(run.run_kind)
            || run.variant != run.run_kind.variant()
            || !run.synthetic_guest
            || !run.disposable_private_target
            || !run.target_destruction
            || !run.cleanup.complete
            || !run.cleanup.target_root_removed
            || run.cleanup.sequence != 1
            || run.cleanup.error_code.is_some()
            || run.credential_reference != policy.credential_reference
            || run.credential_sha256
                != super::policy::credential_digest(policy, run.run_kind, invocation_id)
            || !run.containment_failures.is_empty()
            || run.error_code.is_some()
            || run.steps.len()
                != WorkflowStep::catalog(run.run_kind == WorkflowRunKind::FunctionalControl).len()
        {
            per_run.push((false, false, false, false));
            continue;
        }
        let catalog = WorkflowStep::catalog(run.run_kind == WorkflowRunKind::FunctionalControl);
        let mut states_match = true;
        let mut actions_match = true;
        let mut membership_matches = true;
        let mut eligible = true;
        let mut previous: Option<StateSnapshot> = None;
        for (index, (step, expected_operation)) in run.steps.iter().zip(catalog).enumerate() {
            let valid_step = step.sequence == index as u64 + 1
                && step
                    .result
                    .as_ref()
                    .is_some_and(|result| result.schema_version == policy.evidence_schema)
                && step.binding == policy.expected_binding(run.run_kind, index, invocation_id)?
                && step.binding_sha256 == step.binding.digest()?
                && step.step_cleanup_valid()
                && step.process.state == "exited"
                && step.process.termination == "exit"
                && step.process.exit_code == Some(0)
                && step.process.contained
                && step.process.cleanup_completed
                && step.process.limits_satisfied
                && step.process.containment_failures.is_empty()
                && step.process.stderr_excess_bytes == 0
                && step.decoding == DecodingStatus::Valid
                && step.transition == TransitionStatus::Valid;
            eligible &= valid_step;
            let Some(result) = step.result.as_ref() else {
                eligible = false;
                states_match = false;
                actions_match = false;
                membership_matches = false;
                continue;
            };
            eligible &= resources_valid(policy, run, *expected_operation, step, result)
                && result_well_formed(
                    policy,
                    run.run_kind,
                    *expected_operation,
                    index,
                    previous.as_ref(),
                    result,
                );
            let expected =
                expected_state(policy, run.run_kind, *expected_operation, index as u64 + 1);
            states_match &= result.state == expected
                && previous
                    .as_ref()
                    .map_or(true, |prior| prior.sequence + 1 == result.state.sequence)
                && result.membership_observed == expected.guest_is_member;
            let expected_action = match expected_operation {
                WorkflowStep::CompleteAcceptance | WorkflowStep::ObserveMembership => Some(
                    if run.run_kind == WorkflowRunKind::Broken
                        || run.run_kind == WorkflowRunKind::FunctionalControl
                    {
                        WorkflowActionStatus::Granted
                    } else {
                        WorkflowActionStatus::Revoked
                    },
                ),
                _ => None,
            };
            actions_match &= result.action_status == expected_action;
            membership_matches &= result.membership_observed == expected.guest_is_member;
            let expected_reuse = matches!(
                expected_operation,
                WorkflowStep::BeginAcceptance | WorkflowStep::CompleteAcceptance
            );
            eligible &= step.credential_reused == expected_reuse;
            previous = Some(result.state.clone());
        }
        per_run.push((eligible, actions_match, states_match, membership_matches));
    }
    let eligible = per_run.iter().all(|entry| entry.0);
    let actions_match = per_run.iter().all(|entry| entry.1);
    let states_match = per_run.iter().all(|entry| entry.2);
    let membership_matches = per_run.iter().all(|entry| entry.3);
    let broken = &runs[0];
    let fixed = &runs[1];
    let control = &runs[2];
    let broken_effect = eligible
        && final_result(broken).is_some_and(|result| {
            result.action_status == Some(WorkflowActionStatus::Granted)
                && result.membership_observed
                && result.state.invitation_status == InvitationStatus::Accepted
                && result.state.acceptance_status == AcceptanceStatus::Complete
        });
    let fixed_effect_prevented = eligible
        && final_result(fixed).is_some_and(|result| {
            result.action_status == Some(WorkflowActionStatus::Revoked)
                && !result.membership_observed
                && result.state.invitation_status == InvitationStatus::Revoked
                && result.state.acceptance_status == AcceptanceStatus::Denied
        });
    let functional_control_normal = eligible
        && final_result(control).is_some_and(|result| {
            result.action_status == Some(WorkflowActionStatus::Granted)
                && result.membership_observed
                && result.state.invitation_status == InvitationStatus::Accepted
                && result.state.acceptance_status == AcceptanceStatus::Complete
        });
    let interpretation = if !eligible {
        Interpretation::OperationalFailure
    } else if actions_match
        && states_match
        && membership_matches
        && broken_effect
        && fixed_effect_prevented
        && functional_control_normal
    {
        Interpretation::Confirmed
    } else {
        Interpretation::NoEffect
    };
    Ok(Assessment {
        eligible,
        actions_match,
        states_match,
        membership_matches,
        broken_effect,
        fixed_effect_prevented,
        functional_control_normal,
        interpretation,
    })
}

fn resources_valid(
    policy: &WorkflowPolicy,
    run: &RunRecord,
    operation: WorkflowStep,
    step: &StepRecord,
    result: &WorkflowResult,
) -> bool {
    let observed = &result.resources;
    let limits = &policy.limits;
    run.run_kind == step.binding.run_kind
        && operation == step.binding.operation
        && observed.wall_ms > 0
        && observed.wall_ms <= limits.wall_ms
        && observed.cpu_user_us <= 3_600_000_000
        && observed.cpu_system_us <= 3_600_000_000
        && observed.output_bytes > 0
        && observed.output_bytes <= limits.output_bytes
        && observed
            .max_rss_bytes
            .is_some_and(|rss| rss > 0 && rss <= limits.memory_bytes)
        && observed.memory_limit_bytes == limits.memory_bytes
        && step.resource_observation.as_ref() == Some(observed)
}

impl StepRecord {
    fn step_cleanup_valid(&self) -> bool {
        let Some(result) = self.result.as_ref() else {
            return false;
        };
        self.events.len() == 2
            && self.events[0].kind == "step_started"
            && self.events[1].kind == "step_validated"
            && self.events.iter().all(|event| {
                event.sequence == self.sequence
                    && event.operation == self.binding.operation
                    && event.run_namespace == self.binding.run_namespace
                    && event.action_status == result.action_status
                    && event.membership_observed == result.membership_observed
                    && event.state_sha256 == state_digest(&result.state)
            })
    }
}

pub(crate) fn state_digest(state: &StateSnapshot) -> String {
    let encoded = crate::canonical::canonical_json(
        &serde_json::to_value(state).expect("typed state is serializable"),
    );
    super::policy::hex(&sha2::Sha256::digest(encoded.as_bytes()))
}

/// Validate a typed target transition without deciding the advertised differential.
///
/// In particular, denial by the broken or functional-control fixture and acceptance by
/// the fixed fixture are coherent negative observations. They are `NoEffect`, not malformed
/// evidence or an infrastructure failure. Static identities and state-machine legality still
/// fail closed; only the acceptance outcome is left to the differential assessment below.
pub(crate) fn result_well_formed(
    policy: &WorkflowPolicy,
    kind: WorkflowRunKind,
    operation: WorkflowStep,
    index: usize,
    previous: Option<&StateSnapshot>,
    result: &WorkflowResult,
) -> bool {
    let expected = expected_state(policy, kind, operation, index as u64 + 1);
    let state = &result.state;
    let identities_match = state.project == expected.project
        && state.owner == expected.owner
        && state.guest == expected.guest
        && state.invitation == expected.invitation;
    if result.schema_version != policy.evidence_schema
        || state.schema_version != expected.schema_version
        || state.sequence != expected.sequence
        || !identities_match
        || previous.map_or(operation != WorkflowStep::CreateProject, |prior| {
            prior.sequence + 1 != state.sequence
        })
    {
        return false;
    }
    match operation {
        WorkflowStep::CompleteAcceptance => {
            let Some(prior) = previous else {
                return false;
            };
            if prior.acceptance_status != AcceptanceStatus::Pending {
                return false;
            }
            let accepted = state.invitation_status == InvitationStatus::Accepted
                && state.acceptance_status == AcceptanceStatus::Complete
                && state.guest_is_member
                && result.membership_observed
                && result.action_status == Some(WorkflowActionStatus::Granted);
            let denied = state.invitation_status == prior.invitation_status
                && state.acceptance_status == AcceptanceStatus::Denied
                && !state.guest_is_member
                && !result.membership_observed
                && result.action_status == Some(WorkflowActionStatus::Revoked);
            accepted || denied
        }
        WorkflowStep::ObserveMembership => {
            let Some(prior) = previous else {
                return false;
            };
            state.invitation_status == prior.invitation_status
                && state.acceptance_status == prior.acceptance_status
                && matches!(
                    state.acceptance_status,
                    AcceptanceStatus::Complete | AcceptanceStatus::Denied
                )
                && state.guest_is_member == prior.guest_is_member
                && result.membership_observed == state.guest_is_member
                && result.action_status
                    == Some(if state.guest_is_member {
                        WorkflowActionStatus::Granted
                    } else {
                        WorkflowActionStatus::Revoked
                    })
        }
        _ => {
            state == &expected
                && result.action_status.is_none()
                && result.membership_observed == expected.guest_is_member
        }
    }
}

fn final_result(run: &RunRecord) -> Option<&WorkflowResult> {
    run.steps.last()?.result.as_ref()
}

fn expected_state(
    policy: &WorkflowPolicy,
    kind: WorkflowRunKind,
    operation: WorkflowStep,
    sequence: u64,
) -> StateSnapshot {
    let control = kind == WorkflowRunKind::FunctionalControl;
    let completed = kind != WorkflowRunKind::Fixed
        && matches!(
            operation,
            WorkflowStep::CompleteAcceptance | WorkflowStep::ObserveMembership
        );
    let revoked = !control
        && (operation == WorkflowStep::RevokeInvitation
            || ((kind == WorkflowRunKind::Fixed) && operation == WorkflowStep::CompleteAcceptance)
            || (kind == WorkflowRunKind::Fixed && operation == WorkflowStep::ObserveMembership));
    StateSnapshot {
        schema_version: 1,
        sequence,
        project: policy.identities.project.clone(),
        owner: policy.identities.owner.clone(),
        guest: policy.identities.guest.clone(),
        invitation: policy.identities.invitation.clone(),
        invitation_status: if completed {
            InvitationStatus::Accepted
        } else if revoked {
            InvitationStatus::Revoked
        } else {
            InvitationStatus::Pending
        },
        acceptance_status: if kind == WorkflowRunKind::Fixed
            && matches!(
                operation,
                WorkflowStep::CompleteAcceptance | WorkflowStep::ObserveMembership
            ) {
            AcceptanceStatus::Denied
        } else if operation == WorkflowStep::CreateProject
            || operation == WorkflowStep::CreateInvitation
        {
            AcceptanceStatus::NotStarted
        } else if completed {
            AcceptanceStatus::Complete
        } else {
            AcceptanceStatus::Pending
        },
        guest_is_member: completed,
    }
}
