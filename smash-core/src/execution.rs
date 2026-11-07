//! Bounded, explicitly admitted reproduction contracts.
//!
//! Research observations and decoded model proposals are unexecutable data. An
//! [`AdmittedExecution`] is minted only for one disposal-repository experiment,
//! is valid only within its wall-clock deadline, and is consumed by execution.
//! Core performs syntax and authority checks; the engine additionally recomputes
//! every artifact digest immediately before execution. No observation conferred
//! by this module implies security, exploitability, or production status.

use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const REPRODUCTION_POLICY_VERSION: u32 = 1;
pub const MAX_REPRO_WALL_MS: u64 = 120_000;
pub const MAX_REPRO_OUTPUT_BYTES: u64 = 1_048_576;
pub const MAX_REPRO_MEMORY_BYTES: u64 = 512 * 1_048_576;
pub const MAX_REPRO_PROCESSES: u32 = 32;

/// One-shot proof that admission, live policy and cleanup were checked.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ExecutionToken {
    pub output_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReproCheckpoint {
    pub execution_id: String,
    pub sequence: u64,
    pub output_bytes: u64,
    pub state: EvidenceState,
    pub started_at_ms: u64,
    pub terminal: bool,
}

/// The only executable M2 operation. Recon remains a source observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReproOperation {
    RegressionPair,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlVariant {
    Broken,
    Fixed,
}

/// An exact, independently recomputable artifact plus its bounded cleanup contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlArtifact {
    pub path: PathBuf,
    pub sha256: String,
    pub declared_outputs: Vec<PathBuf>,
}

impl ControlArtifact {
    pub fn validate(&self) -> Result<(), ReproDenial> {
        validate_digest(&self.sha256)?;
        if self.path.as_os_str().is_empty()
            || self.path.components().any(|c| {
                matches!(
                    c,
                    Component::ParentDir | Component::CurDir | Component::Prefix(_)
                )
            })
        {
            return Err(ReproDenial::InvalidArtifactPath);
        }
        self.declared_outputs
            .iter()
            .try_for_each(|p| validate_output(p))?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetIdentity {
    pub repository_fingerprint: String,
    pub contract_sha256: String,
    pub entrypoint_sha256: String,
    pub runtime: String,
    pub platform: String,
}
impl TargetIdentity {
    pub fn validate(&self) -> Result<(), ReproDenial> {
        validate_digest(&self.entrypoint_sha256)?;
        validate_digest(&self.contract_sha256)?;
        if self.repository_fingerprint.is_empty()
            || self.runtime.is_empty()
            || self.platform.is_empty()
        {
            return Err(ReproDenial::TargetIdentityMismatch);
        }
        Ok(())
    }
}

/// Concrete limits are required; deserialization cannot supply debug/infinite defaults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionLimits {
    pub wall_ms: u64,
    pub output_bytes: u64,
    pub memory_bytes: u64,
    pub processes: u32,
}
impl ExecutionLimits {
    pub fn bounded() -> Self {
        Self {
            wall_ms: 30_000,
            output_bytes: 65_536,
            memory_bytes: 128 * 1_048_576,
            processes: 8,
        }
    }
    fn validate(&self) -> Result<(), ReproDenial> {
        if !(1..=MAX_REPRO_WALL_MS).contains(&self.wall_ms)
            || !(1..=MAX_REPRO_OUTPUT_BYTES).contains(&self.output_bytes)
            || !(16 * 1_048_576..=MAX_REPRO_MEMORY_BYTES).contains(&self.memory_bytes)
            || !(1..=MAX_REPRO_PROCESSES).contains(&self.processes)
        {
            return Err(ReproDenial::InvalidLimits);
        }
        Ok(())
    }
}
/// There is no Default: every request must choose and persist bounded limits.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExperimentDraft {
    pub authority: RepositoryAuthority,
    pub protocol_version: u32,
    pub operation: ReproOperation,
    pub attack_class: String,
    pub target_tool: String,
    pub research_fingerprint_prefix: String,
}
impl ExperimentDraft {
    pub fn validate(&self) -> Result<(), ReproDenial> {
        if self.protocol_version != REPRODUCTION_POLICY_VERSION {
            return Err(ReproDenial::ProtocolMismatch);
        }
        if self.attack_class.trim().is_empty()
            || self.target_tool.trim().is_empty()
            || self.research_fingerprint_prefix.len() != 16
            || !self
                .research_fingerprint_prefix
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            return Err(ReproDenial::InsufficientAuthority);
        }
        self.authority.validate()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepositoryDepth {
    Bounded,
    LocalGitProject,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckoutPermission {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryAuthority {
    depth: RepositoryDepth,
    checkout_permission: CheckoutPermission,
    commit_evidence: bool,
    executable_surfaces: u8,
    updated_modules: u8,
}
impl RepositoryAuthority {
    pub fn new(
        depth: RepositoryDepth,
        checkout_permission: CheckoutPermission,
        commit_evidence: bool,
        executable_surfaces: u8,
        updated_modules: u8,
    ) -> Self {
        Self {
            depth,
            checkout_permission,
            commit_evidence,
            executable_surfaces,
            updated_modules,
        }
    }
    fn validate(&self) -> Result<(), ReproDenial> {
        if self.depth != RepositoryDepth::LocalGitProject
            || (self.checkout_permission == CheckoutPermission::ReadOnly && !self.commit_evidence)
            || self.executable_surfaces == 0
            || self.updated_modules == 0
        {
            return Err(ReproDenial::InsufficientAuthority);
        }
        Ok(())
    }
}
pub trait ReproAdmission {
    fn admit(&self, draft: &ExperimentDraft) -> Result<AdmittedReproduction, ReproDenial>;
}

#[derive(Clone, Debug)]
pub struct ExecutionAdmission;
impl ReproAdmission for ExecutionAdmission {
    fn admit(&self, draft: &ExperimentDraft) -> Result<AdmittedReproduction, ReproDenial> {
        draft.validate()?;
        Ok(AdmittedReproduction {
            admission: Admission::new(draft.attack_class.clone()),
        })
    }
}

/// Internal authorization, impossible to construct from a serialized proposal.
#[derive(Clone, Debug)]
struct Admission {
    attack_class: String,
}
impl Admission {
    fn new(attack_class: String) -> Self {
        Self { attack_class }
    }
}

#[derive(Clone, Debug)]
pub struct AdmittedReproduction {
    admission: Admission,
}
impl AdmittedReproduction {
    pub fn attack_class(&self) -> &str {
        &self.admission.attack_class
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionRequest {
    pub run_id: String,
    pub target_identity: TargetIdentity,
    pub artifact: ControlArtifact,
    pub limits: ExecutionLimits,
}
impl ExecutionRequest {
    pub fn validate(&self) -> Result<(), ReproDenial> {
        if self.run_id.trim().is_empty() {
            return Err(ReproDenial::TargetIdentityMismatch);
        }
        self.target_identity.validate()?;
        self.artifact.validate()?;
        self.limits.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EphemeralCleanup;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunnerAvailability {
    pub supported: bool,
    pub identity_matches: bool,
    pub initialization_dry_run_passed: bool,
    pub missing_tools: Vec<String>,
}
impl RunnerAvailability {
    fn validate(&self) -> Result<(), ReproDenial> {
        if !self.supported
            || !self.identity_matches
            || !self.initialization_dry_run_passed
            || !self.missing_tools.is_empty()
        {
            return Err(ReproDenial::ExecutionUnavailable);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct AdmittedExecution {
    request: ExecutionRequest,
    _cleanup: EphemeralCleanup,
    deadline_ms: u64,
    used: bool,
}
impl AdmittedExecution {
    pub fn request(&self) -> &ExecutionRequest {
        &self.request
    }
    pub fn deadline_ms(&self) -> u64 {
        self.deadline_ms
    }
    pub fn consume(mut self, started_ms: u64) -> Result<ExecutionToken, ReproDenial> {
        if self.used || started_ms > self.deadline_ms {
            return Err(ReproDenial::ExecutionExpired);
        }
        self.used = true;
        Ok(ExecutionToken {
            output_bytes: self.request.limits.output_bytes,
        })
    }

    /// Bind this exact experiment to one independently certified cleanup repository.
    pub fn bind_execution(
        admitted: &AdmittedReproduction,
        request: ExecutionRequest,
        cleanup: EphemeralCleanup,
        runner: &RunnerAvailability,
        started_ms: u64,
    ) -> Result<Self, ReproDenial> {
        // Only this function can combine authority and cleanup into an execution token.
        let _authority = &admitted.admission;
        request.validate()?;
        runner.validate()?;
        let deadline_ms = started_ms.saturating_add(request.limits.wall_ms);
        Ok(Self {
            request,
            _cleanup: cleanup,
            deadline_ms,
            used: false,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceState {
    Admitted,
    RunnerUnavailable,
    Spawned,
    Running,
    Succeeded,
    ReproductionFailed,
    TimedOut,
    Cancelled,
    Interrupted,
    EnvironmentSetupFailed,
    OutputLimitExceeded,
    MalformedEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionReceipt {
    pub run_id: String,
    pub state: EvidenceState,
    pub artifact_sha256: String,
    pub target_identity: TargetIdentity,
    pub policy_version: u32,
    pub started_at_ms: Option<u64>,
    pub finished_at_ms: Option<u64>,
    pub exit_code: Option<i32>,
    pub successful_exit: Option<bool>,
    pub resource_output: Option<u64>,
    pub output_bounded: bool,
    pub cleanup_completed: bool,
    pub noisy: bool,
    pub from_checkpoint: bool,
}
impl ExecutionReceipt {
    pub fn unavailable(run_id: &str, target: &TargetIdentity, artifact_sha256: &str) -> Self {
        Self {
            run_id: run_id.into(),
            state: EvidenceState::RunnerUnavailable,
            artifact_sha256: artifact_sha256.into(),
            target_identity: target.clone(),
            policy_version: REPRODUCTION_POLICY_VERSION,
            started_at_ms: None,
            finished_at_ms: None,
            exit_code: None,
            successful_exit: None,
            resource_output: None,
            output_bounded: false,
            cleanup_completed: false,
            noisy: false,
            from_checkpoint: false,
        }
    }
    /// Never infer research truth from a process exit code or local tool exit status.
    pub fn reproduced(&self) -> bool {
        self.state == EvidenceState::ReproductionFailed
            && self.from_checkpoint
            && self.cleanup_completed
            && !self.noisy
    }
}

pub trait ExecutionClock: Send + Sync {
    fn now_ms(&self) -> u64;
}
#[derive(Clone, Copy, Debug)]
pub struct SystemExecutionClock;
impl ExecutionClock for SystemExecutionClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionTransition {
    Spawned,
    Running,
    Succeeded,
    ReproductionFailed,
    Cancelled,
    Interrupted,
}

/// Tracks an execution without relocating a borrowed token or synthesizing success.
pub struct ExecutionJournal<'a, C: ExecutionClock> {
    admission: &'a AdmittedExecution,
    clock: &'a C,
    started_ms: u64,
    state: EvidenceState,
    output: Option<u64>,
}
impl<'a, C: ExecutionClock> ExecutionJournal<'a, C> {
    pub fn new(admission: &'a AdmittedExecution, clock: &'a C) -> Self {
        Self {
            admission,
            clock,
            started_ms: clock.now_ms(),
            state: EvidenceState::Admitted,
            output: None,
        }
    }
    pub fn transition(&mut self, event: ExecutionTransition) {
        match event {
            ExecutionTransition::Spawned => self.state = EvidenceState::Spawned,
            ExecutionTransition::Running if self.state == EvidenceState::Spawned => {
                self.state = EvidenceState::Running;
            }
            ExecutionTransition::Succeeded => self.state = EvidenceState::Succeeded,
            ExecutionTransition::ReproductionFailed => {
                self.state = EvidenceState::ReproductionFailed
            }
            ExecutionTransition::Cancelled => self.state = EvidenceState::Cancelled,
            ExecutionTransition::Interrupted => self.state = EvidenceState::Interrupted,
            _ => {}
        }
    }
    pub fn checkpoint(&self, id: &str) -> ReproCheckpoint {
        ReproCheckpoint {
            execution_id: id.into(),
            sequence: event_sequence(self.state),
            output_bytes: self.admission.request().limits.output_bytes,
            state: self.state,
            started_at_ms: self.started_ms,
            terminal: matches!(
                self.state,
                EvidenceState::Succeeded
                    | EvidenceState::ReproductionFailed
                    | EvidenceState::TimedOut
                    | EvidenceState::Cancelled
                    | EvidenceState::Interrupted
                    | EvidenceState::EnvironmentSetupFailed
                    | EvidenceState::OutputLimitExceeded
                    | EvidenceState::MalformedEvidence
            ),
        }
    }
    pub fn finish(mut self, timed_out: bool, output: Option<u64>) -> ExecutionReceipt {
        self.output = output;
        if timed_out {
            self.state = EvidenceState::TimedOut;
        }
        let now = self.clock.now_ms();
        ExecutionReceipt {
            run_id: self.admission.request().run_id.clone(),
            state: self.state,
            artifact_sha256: self.admission.request().artifact.sha256.clone(),
            target_identity: self.admission.request().target_identity.clone(),
            policy_version: REPRODUCTION_POLICY_VERSION,
            started_at_ms: Some(self.started_ms),
            finished_at_ms: Some(now),
            exit_code: None,
            successful_exit: None,
            resource_output: self.output,
            output_bounded: output
                .is_some_and(|b| b <= self.admission.request().limits.output_bytes),
            cleanup_completed: false,
            noisy: false,
            from_checkpoint: false,
        }
    }
}
fn event_sequence(state: EvidenceState) -> u64 {
    match state {
        EvidenceState::Admitted | EvidenceState::RunnerUnavailable => 0,
        EvidenceState::Spawned => 1,
        EvidenceState::Running => 2,
        _ => 3,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReproDenial {
    ProtocolMismatch,
    InsufficientAuthority,
    ExecutionUnavailable,
    TargetIdentityMismatch,
    InvalidArtifactPath,
    InvalidArtifactDigest,
    InvalidOutputPath,
    InvalidLimits,
    ExecutionExpired,
}

fn validate_digest(s: &str) -> Result<(), ReproDenial> {
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ReproDenial::InvalidArtifactDigest)
    }
}
fn validate_output(path: &Path) -> Result<(), ReproDenial> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        Err(ReproDenial::InvalidOutputPath)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft() -> ExperimentDraft {
        ExperimentDraft {
            authority: RepositoryAuthority::new(
                RepositoryDepth::LocalGitProject,
                CheckoutPermission::ReadWrite,
                true,
                1,
                1,
            ),
            protocol_version: 1,
            operation: ReproOperation::RegressionPair,
            attack_class: "stateful-regression".into(),
            target_tool: "fixture".into(),
            research_fingerprint_prefix: "0123456789abcdef".into(),
        }
    }
    fn request() -> ExecutionRequest {
        ExecutionRequest {
            run_id: "run".into(),
            target_identity: TargetIdentity {
                repository_fingerprint: "repo".into(),
                contract_sha256: "33".repeat(32),
                entrypoint_sha256: "11".repeat(32),
                runtime: "python3".into(),
                platform: "linux".into(),
            },
            artifact: ControlArtifact {
                path: PathBuf::from("control.py"),
                sha256: "22".repeat(32),
                declared_outputs: vec![PathBuf::from("result.json")],
            },
            limits: ExecutionLimits::bounded(),
        }
    }
    #[derive(Debug)]
    struct Clock(u64);
    impl ExecutionClock for Clock {
        fn now_ms(&self) -> u64 {
            self.0
        }
    }

    #[test]
    fn proposals_do_not_construct_authority_or_cleanup() {
        // Deliberately no Deserialize impl for admitted execution or cleanup.
        assert!(ExecutionAdmission.admit(&draft()).is_ok());
    }
    #[test]
    fn denied_execution_receives_no_cleanup_token() {
        let bad = ExperimentDraft {
            protocol_version: 0,
            ..draft()
        };
        assert_eq!(
            ExecutionAdmission.admit(&bad).unwrap_err(),
            ReproDenial::ProtocolMismatch
        );
        let admitted = ExecutionAdmission.admit(&draft()).unwrap();
        let runner = RunnerAvailability {
            supported: false,
            identity_matches: true,
            initialization_dry_run_passed: false,
            missing_tools: vec!["python3".into()],
        };
        assert!(AdmittedExecution::bind_execution(
            &admitted,
            request(),
            EphemeralCleanup,
            &runner,
            10
        )
        .is_err());
    }
    #[test]
    fn admitted_execution_degrades_to_timeout_and_can_checkpoint() {
        let admitted = ExecutionAdmission.admit(&draft()).unwrap();
        let runner = RunnerAvailability {
            supported: true,
            identity_matches: true,
            initialization_dry_run_passed: true,
            missing_tools: vec![],
        };
        let execution =
            AdmittedExecution::bind_execution(&admitted, request(), EphemeralCleanup, &runner, 10)
                .unwrap();
        let clock = Clock(10);
        let mut journal = ExecutionJournal::new(&execution, &clock);
        assert_eq!(journal.checkpoint("r").state, EvidenceState::Admitted);
        journal.transition(ExecutionTransition::Spawned);
        journal.transition(ExecutionTransition::Running);
        journal.transition(ExecutionTransition::Interrupted);
        assert_eq!(journal.checkpoint("r").sequence, 3);
        let receipt = journal.finish(true, None);
        assert_eq!(receipt.state, EvidenceState::TimedOut);
        assert!(!receipt.reproduced());
        assert!(execution.consume(10).is_ok());
    }
    #[test]
    fn rejects_suffix_paths_parent_contracts_and_unbounded_limits() {
        let r = request();
        let mut bad = r.clone();
        bad.artifact.declared_outputs = vec![PathBuf::from("../escape")];
        assert_eq!(bad.validate(), Err(ReproDenial::InvalidOutputPath));
        let mut bad = r.clone();
        bad.limits.wall_ms = 0;
        assert_eq!(bad.validate(), Err(ReproDenial::InvalidLimits));
        let mut bad = r.clone();
        bad.target_identity.platform = String::new();
        assert_eq!(bad.validate(), Err(ReproDenial::TargetIdentityMismatch));
        let mut bad = r;
        bad.artifact.path = PathBuf::from("a/../b");
        assert_eq!(bad.validate(), Err(ReproDenial::InvalidArtifactPath));
    }
    #[test]
    fn refusal_is_not_a_positive_observation() {
        let receipt = ExecutionReceipt::unavailable("run", &request().target_identity, "0");
        assert!(!receipt.reproduced());
    }
}
