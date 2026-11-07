//! Bounded, execution-free reproduction bundles.
//!
//! The original repository and artifact are not read by verification. Exact copies
//! are hashed inside the bundle, then the same versioned oracle is applied to the
//! saved observations. A self-consistent bundle is evidence from its producer,
//! not a substitute for an external trust or signing authority.

use crate::repro::error::ReproError;
use crate::repro::linux::{LinuxExecutionEnd, LinuxOutput};
use crate::repro::oracle::ControlVariantWire;
use crate::repro::oracle::{
    evaluate_control, evaluate_pair, ScopedRegression, AUTHENTICATED_RETRY_ORACLE_VERSION,
};
use crate::repro::policy::BoundedLimits;
use crate::repro::policy::{
    admit_artifact, contract_digest, policy_digest, source_digest, ControlRun, ExactSourceFile,
    ReproductionArtifact, ReproductionPolicy, ReproductionRun, M2_POLICY_VERSION,
    MAX_FIXTURE_FILES,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use smash_core::execution::*;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const BUNDLE_VERSION: u32 = 1;
const MAX_STATE_BYTES: u64 = 8 * 1_048_576;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OutputRecord {
    pub end: LinuxExecutionEndRecord,
    pub resource_output: u64,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub declared_outputs: BTreeMap<PathBuf, Vec<u8>>,
    pub cleanup_completed: bool,
    pub contained: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinuxExecutionEndRecord {
    pub state: StateRecord,
    pub exit_code: Option<i32>,
    pub successful_exit: Option<bool>,
    pub unresolved: bool,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum StateRecord {
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
impl From<EvidenceState> for StateRecord {
    fn from(state: EvidenceState) -> Self {
        match state {
            EvidenceState::Admitted => Self::Admitted,
            EvidenceState::RunnerUnavailable => Self::RunnerUnavailable,
            EvidenceState::Spawned => Self::Spawned,
            EvidenceState::Running => Self::Running,
            EvidenceState::Succeeded => Self::Succeeded,
            EvidenceState::ReproductionFailed => Self::ReproductionFailed,
            EvidenceState::TimedOut => Self::TimedOut,
            EvidenceState::Cancelled => Self::Cancelled,
            EvidenceState::Interrupted => Self::Interrupted,
            EvidenceState::EnvironmentSetupFailed => Self::EnvironmentSetupFailed,
            EvidenceState::OutputLimitExceeded => Self::OutputLimitExceeded,
            EvidenceState::MalformedEvidence => Self::MalformedEvidence,
        }
    }
}
impl StateRecord {
    fn core(self) -> EvidenceState {
        match self {
            Self::Admitted => EvidenceState::Admitted,
            Self::RunnerUnavailable => EvidenceState::RunnerUnavailable,
            Self::Spawned => EvidenceState::Spawned,
            Self::Running => EvidenceState::Running,
            Self::Succeeded => EvidenceState::Succeeded,
            Self::ReproductionFailed => EvidenceState::ReproductionFailed,
            Self::TimedOut => EvidenceState::TimedOut,
            Self::Cancelled => EvidenceState::Cancelled,
            Self::Interrupted => EvidenceState::Interrupted,
            Self::EnvironmentSetupFailed => EvidenceState::EnvironmentSetupFailed,
            Self::OutputLimitExceeded => EvidenceState::OutputLimitExceeded,
            Self::MalformedEvidence => EvidenceState::MalformedEvidence,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TargetRecord {
    pub repository_fingerprint: String,
    pub contract_sha256: String,
    pub entrypoint_sha256: String,
    pub runtime: String,
    pub platform: String,
}
impl TargetRecord {
    fn core(&self) -> TargetIdentity {
        TargetIdentity {
            repository_fingerprint: self.repository_fingerprint.clone(),
            contract_sha256: self.contract_sha256.clone(),
            entrypoint_sha256: self.entrypoint_sha256.clone(),
            runtime: self.runtime.clone(),
            platform: self.platform.clone(),
        }
    }
}
impl From<TargetIdentity> for TargetRecord {
    fn from(identity: TargetIdentity) -> Self {
        Self {
            repository_fingerprint: identity.repository_fingerprint,
            contract_sha256: identity.contract_sha256,
            entrypoint_sha256: identity.entrypoint_sha256,
            runtime: identity.runtime,
            platform: identity.platform,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRecord {
    pub path: PathBuf,
    pub sha256: String,
    pub declared_outputs: Vec<PathBuf>,
}
impl ArtifactRecord {
    fn core(&self) -> ControlArtifact {
        ControlArtifact {
            path: self.path.clone(),
            sha256: self.sha256.clone(),
            declared_outputs: self.declared_outputs.clone(),
        }
    }
}
impl From<ControlArtifact> for ArtifactRecord {
    fn from(artifact: ControlArtifact) -> Self {
        Self {
            path: artifact.path,
            sha256: artifact.sha256,
            declared_outputs: artifact.declared_outputs,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckpointRecord {
    pub execution_id: String,
    pub sequence: u64,
    pub output_bytes: u64,
    pub state: StateRecord,
    pub started_at_ms: u64,
    pub terminal: bool,
}
impl From<ReproCheckpoint> for CheckpointRecord {
    fn from(checkpoint: ReproCheckpoint) -> Self {
        Self {
            execution_id: checkpoint.execution_id,
            sequence: checkpoint.sequence,
            output_bytes: checkpoint.output_bytes,
            state: checkpoint.state.into(),
            started_at_ms: checkpoint.started_at_ms,
            terminal: checkpoint.terminal,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReceiptRecord {
    pub run_id: String,
    pub state: StateRecord,
    pub artifact_sha256: String,
    pub target_identity: TargetRecord,
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
impl ReceiptRecord {
    fn core(&self) -> ExecutionReceipt {
        ExecutionReceipt {
            run_id: self.run_id.clone(),
            state: self.state.core(),
            artifact_sha256: self.artifact_sha256.clone(),
            target_identity: self.target_identity.core(),
            policy_version: self.policy_version,
            started_at_ms: self.started_at_ms,
            finished_at_ms: self.finished_at_ms,
            exit_code: self.exit_code,
            successful_exit: self.successful_exit,
            resource_output: self.resource_output,
            output_bounded: self.output_bounded,
            cleanup_completed: self.cleanup_completed,
            noisy: self.noisy,
            from_checkpoint: self.from_checkpoint,
        }
    }
}
impl From<ExecutionReceipt> for ReceiptRecord {
    fn from(receipt: ExecutionReceipt) -> Self {
        Self {
            run_id: receipt.run_id,
            state: receipt.state.into(),
            artifact_sha256: receipt.artifact_sha256,
            target_identity: receipt.target_identity.into(),
            policy_version: receipt.policy_version,
            started_at_ms: receipt.started_at_ms,
            finished_at_ms: receipt.finished_at_ms,
            exit_code: receipt.exit_code,
            successful_exit: receipt.successful_exit,
            resource_output: receipt.resource_output,
            output_bounded: receipt.output_bounded,
            cleanup_completed: receipt.cleanup_completed,
            noisy: receipt.noisy,
            from_checkpoint: receipt.from_checkpoint,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlRecord {
    pub variant: ControlVariantWire,
    pub identity: TargetRecord,
    pub artifact: ArtifactRecord,
    pub receipt: ReceiptRecord,
    pub limits: BoundedLimits,
    pub output: OutputRecord,
    pub checkpoints: Vec<CheckpointRecord>,
    pub sources: Vec<ExactSourceFile>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReproductionBundle {
    pub bundle_version: u32,
    pub policy_version: u32,
    pub run_id: String,
    pub policy: ReproductionPolicy,
    pub artifact_sha256: String,
    pub broken: ControlRecord,
    pub fixed: ControlRecord,
    pub assessment: ScopedRegression,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResumeDecision {
    CompletedWithoutReplay,
    FreshAttemptRequired,
    RefuseMismatch,
    RefuseUnresolved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedBundle {
    pub reproduced: bool,
    pub resume: ResumeDecision,
}
impl ReproductionBundle {
    /// Evaluate only supplied records. This function performs no I/O or execution.
    pub fn verified(&self, artifact_bytes: &[u8]) -> Result<VerifiedBundle, ReproError> {
        if self.bundle_version != BUNDLE_VERSION
            || self.policy_version != M2_POLICY_VERSION
            || self.policy.protocol_version != M2_POLICY_VERSION
            || !self.policy.unsafe_seeding
            || !self.policy.build_under_test
            || !self.policy.privileged_containment
            || self.policy.target_tool != crate::repro::policy::AUTHENTICATED_REPRO_TOOL
            || self.policy.entrypoint != crate::repro::policy::AUTHENTICATED_REPRO_ENTRYPOINT
            || self.policy.broken_root == self.policy.fixed_root
            || self.policy.run_id != self.run_id
            || self.broken.variant != ControlVariantWire::Broken
            || self.fixed.variant != ControlVariantWire::Fixed
        {
            return Err(ReproError::Policy(
                "unsupported or incomplete reproduction bundle".into(),
            ));
        }
        let sha = hex(&Sha256::digest(artifact_bytes));
        if sha != self.artifact_sha256
            || sha != self.broken.artifact.sha256
            || sha != self.fixed.artifact.sha256
            || self.broken.artifact != self.fixed.artifact
        {
            return Err(ReproError::Policy(
                "bundle artifact identity mismatch".into(),
            ));
        }
        // Parsing enforces the exact typed action; no fields are used as argv or code.
        let typed: serde_json::Value = serde_json::from_slice(artifact_bytes)?;
        if typed.get("action").and_then(serde_json::Value::as_str)
            != Some("retry_after_authenticated_refresh")
        {
            return Err(ReproError::Policy("unsupported bundle artifact".into()));
        }
        let first = self.verify_control(&self.broken)?;
        let second = self.verify_control(&self.fixed)?;
        let assessed = evaluate_pair(
            evaluate_control(
                ControlVariant::Broken,
                &self.broken.artifact.core(),
                &self.broken.receipt.core(),
                &first,
            ),
            evaluate_control(
                ControlVariant::Fixed,
                &self.fixed.artifact.core(),
                &self.fixed.receipt.core(),
                &second,
            ),
        );
        if assessed != self.assessment {
            return Err(ReproError::Policy(
                "reported oracle assessment does not match evidence".into(),
            ));
        }
        let fresh = [&self.broken, &self.fixed].iter().any(|record| {
            !record.output.end.unresolved
                && record.output.cleanup_completed
                && matches!(
                    record.output.end.state,
                    StateRecord::Cancelled | StateRecord::TimedOut | StateRecord::Interrupted
                )
        });
        let unresolved = [&self.broken, &self.fixed]
            .iter()
            .any(|record| record.output.end.unresolved || !record.output.cleanup_completed);
        let resume = if unresolved {
            ResumeDecision::RefuseUnresolved
        } else if fresh {
            ResumeDecision::FreshAttemptRequired
        } else {
            ResumeDecision::CompletedWithoutReplay
        };
        Ok(VerifiedBundle {
            reproduced: assessed.reproduced(),
            resume,
        })
    }

    fn verify_control(&self, record: &ControlRecord) -> Result<LinuxOutput, ReproError> {
        let limits = record.limits.to_core();
        let request = ExecutionRequest {
            run_id: self.run_id.clone(),
            target_identity: record.identity.core(),
            artifact: record.artifact.core(),
            limits,
        };
        request.validate()?;
        if request.limits != self.policy.limits.to_core()
            || record.receipt.run_id != self.run_id
            || record.receipt.policy_version != REPRODUCTION_POLICY_VERSION
            || record.receipt.target_identity != record.identity
            || record.receipt.artifact_sha256 != self.artifact_sha256
            || record.receipt.state != record.output.end.state
            || record.receipt.exit_code != record.output.end.exit_code
            || record.receipt.successful_exit != record.output.end.successful_exit
            || record.receipt.resource_output != Some(record.output.resource_output)
            || record.receipt.cleanup_completed != record.output.cleanup_completed
            || record.receipt.output_bounded
                != (record.output.resource_output <= record.limits.output_bytes)
            || !record.receipt.from_checkpoint
        {
            return Err(ReproError::Policy(
                "control receipt or limits mismatch".into(),
            ));
        }
        if record.sources.len() > MAX_FIXTURE_FILES
            || record
                .sources
                .iter()
                .map(|file| file.bytes.len() as u64)
                .sum::<u64>()
                > 1_048_576
            || source_digest(&record.sources)? != record.identity.repository_fingerprint
        {
            return Err(ReproError::Policy(
                "source snapshot identity mismatch".into(),
            ));
        }
        let entrypoint = record
            .sources
            .iter()
            .find(|source| source.relative == Path::new(&self.policy.entrypoint))
            .ok_or_else(|| ReproError::Policy("bundle entrypoint missing".into()))?;
        if hex(&Sha256::digest(&entrypoint.bytes)) != record.identity.entrypoint_sha256
            || entrypoint.bytes != crate::repro::policy::M2_FIXTURE_ENTRYPOINT
        {
            return Err(ReproError::Policy(
                "bundle entrypoint identity mismatch".into(),
            ));
        }
        let runner = record
            .identity
            .platform
            .strip_prefix("linux:")
            .and_then(|value| value.strip_suffix(&format!(":{AUTHENTICATED_RETRY_ORACLE_VERSION}")))
            .ok_or_else(|| ReproError::Policy("runner or oracle identity missing".into()))?;
        if contract_digest(
            hex(&Sha256::digest(serde_json::to_vec(&serde_json::to_value(
                &self.policy,
            )?)?))
            .as_bytes(),
            &record.identity.repository_fingerprint,
            &record.identity.entrypoint_sha256,
            runner,
        ) != record.identity.contract_sha256
        {
            return Err(ReproError::Policy("contract identity mismatch".into()));
        }
        verify_journal(record)?;
        Ok(record.output.to_output())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "record_type", rename_all = "snake_case")]
pub enum JournalLine {
    Header {
        schema_version: u32,
        run_id: String,
        policy_sha256: String,
    },
    Checkpoint {
        checkpoint: CheckpointRecord,
    },
}

/// Write a new bundle by renaming a fully serialized private staging directory.
pub fn persist_bundle(
    root: &Path,
    policy: &ReproductionPolicy,
    artifact: &ReproductionArtifact,
    run: ReproductionRun,
) -> Result<ReproductionBundle, ReproError> {
    persist_bundle_with_journal(root, policy, artifact, run, None)
}
pub fn persist_bundle_with_journal(
    root: &Path,
    policy: &ReproductionPolicy,
    artifact: &ReproductionArtifact,
    run: ReproductionRun,
    journal: Option<&[u8]>,
) -> Result<ReproductionBundle, ReproError> {
    if run.error.is_some() {
        return Err(ReproError::Policy(
            "cannot persist an errored assessment as complete".into(),
        ));
    }
    let broken = run
        .broken
        .ok_or_else(|| ReproError::Policy("broken control absent".into()))?;
    let fixed = run
        .fixed
        .ok_or_else(|| ReproError::Policy("fixed control absent".into()))?;
    let convert = |control: ControlRun| ControlRecord {
        variant: control.variant.into(),
        identity: control.identity.into(),
        artifact: control.artifact.into(),
        receipt: control.receipt.into(),
        limits: policy.limits.clone(),
        output: OutputRecord::from(control.output),
        checkpoints: control.checkpoints.into_iter().map(Into::into).collect(),
        sources: control.sources,
    };
    let bundle = ReproductionBundle {
        bundle_version: BUNDLE_VERSION,
        policy_version: M2_POLICY_VERSION,
        run_id: policy.run_id.clone(),
        policy: policy.clone(),
        artifact_sha256: artifact.sha256.clone(),
        broken: convert(broken),
        fixed: convert(fixed),
        assessment: run.assessment,
    };
    let stage = crate::repro::policy::tempfile_private("m2-bundle-write")?;
    let result = (|| {
        write_json(&stage.join("manifest.json"), &bundle)?;
        write_json(&stage.join("policy.json"), policy)?;
        // Dynamic serde values are not supported by serde_json::from_slice with arbitrary
        // bytes; the fixed artifact parser below still enforces the trusted schema.
        fs::write(stage.join("artifact.json"), &artifact.bytes)?;
        if let Some(journal) = journal {
            fs::write(stage.join("journal.jsonl"), journal)?;
            verify_attached_journal(&bundle, journal)?;
        }
        bundle.verified(&artifact.bytes)?;
        if root.exists() {
            return Err(ReproError::Policy(
                "bundle destination already exists".into(),
            ));
        }
        if let Some(parent) = root.parent() {
            if !parent.as_os_str().is_empty() && !parent.is_dir() {
                return Err(ReproError::Policy(
                    "bundle parent is not a directory".into(),
                ));
            }
        }
        fs::rename(&stage, root)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(stage);
    }
    result.map(|()| bundle)
}

/// Verification reads only the explicit bundle directory. Original paths in the
/// archived policy are opaque strings and are never opened here.
pub fn verify_bundle(root: &Path) -> Result<VerifiedBundle, ReproError> {
    let meta = fs::symlink_metadata(root)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(ReproError::Policy(
            "bundle root must be a real directory".into(),
        ));
    }
    let bundle: ReproductionBundle = read_bound(&root.join("manifest.json"), MAX_STATE_BYTES)
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))?;
    let policy: ReproductionPolicy = read_bound(&root.join("policy.json"), MAX_STATE_BYTES)
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))?;
    if policy_digest(&policy)? != policy_digest(&bundle.policy)? {
        return Err(ReproError::Policy(
            "manifest policy and archived policy differ".into(),
        ));
    }
    let artifact = read_bound(&root.join("artifact.json"), 65_537)?;
    // This also verifies protocol, action, expected state, and the exact four-key form.
    let admitted = admit_artifact(&bundle.policy, &root.join("artifact.json"))?;
    if admitted.bytes != artifact {
        return Err(ReproError::Policy(
            "artifact bytes changed while reading".into(),
        ));
    }
    let journal = root.join("journal.jsonl");
    if journal.exists() {
        let bytes = read_bound(&journal, 1_048_576)?;
        verify_attached_journal(&bundle, &bytes)?;
    }
    bundle.verified(&artifact)
}
fn verify_attached_journal(bundle: &ReproductionBundle, bytes: &[u8]) -> Result<(), ReproError> {
    use std::io::{BufRead, BufReader};
    if !bytes.ends_with(b"\n") {
        return Err(ReproError::Policy("incomplete live journal line".into()));
    }
    let mut events = Vec::new();
    for (index, line) in BufReader::new(bytes).lines().enumerate() {
        if index > 512 {
            return Err(ReproError::Policy("too many journal events".into()));
        }
        let line = line?;
        match serde_json::from_str(&line)
            .map_err(|error| ReproError::Evidence(error.to_string()))?
        {
            JournalLine::Header {
                schema_version,
                run_id,
                policy_sha256,
            } if index == 0
                && schema_version == 1
                && run_id == bundle.run_id
                && policy_sha256 == policy_digest(&bundle.policy)? => {}
            JournalLine::Header { .. } => {
                return Err(ReproError::Policy("invalid journal header".into()))
            }
            JournalLine::Checkpoint { checkpoint } if index > 0 => events.push(checkpoint),
            JournalLine::Checkpoint { .. } => {
                return Err(ReproError::Policy("journal header missing".into()))
            }
        }
    }
    let expected = bundle
        .broken
        .checkpoints
        .iter()
        .chain(&bundle.fixed.checkpoints);
    if events.len() != bundle.broken.checkpoints.len() + bundle.fixed.checkpoints.len()
        || !events
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual == expected)
    {
        return Err(ReproError::Policy(
            "live journal differs from completed controls".into(),
        ));
    }
    Ok(())
}

/// Never replays a completed, failed, or unresolved control. The caller must hash
/// current inputs before choosing a separately admitted fresh attempt.
pub fn resume_bundle(
    root: &Path,
    policy: &ReproductionPolicy,
    artifact_sha256: &str,
    broken_repository: &str,
    fixed_repository: &str,
) -> Result<ResumeDecision, ReproError> {
    let bundle: ReproductionBundle = read_bound(&root.join("manifest.json"), MAX_STATE_BYTES)
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))?;
    let verified = verify_bundle(root)?;
    if verified.resume == ResumeDecision::RefuseUnresolved {
        return Ok(ResumeDecision::RefuseUnresolved);
    }
    if policy.run_id != bundle.run_id
        || policy_digest(policy)? != policy_digest(&bundle.policy)?
        || artifact_sha256 != bundle.artifact_sha256
        || broken_repository != bundle.broken.identity.repository_fingerprint
        || fixed_repository != bundle.fixed.identity.repository_fingerprint
    {
        return Ok(ResumeDecision::RefuseMismatch);
    }
    if verified.reproduced {
        Ok(ResumeDecision::CompletedWithoutReplay)
    } else {
        Ok(ResumeDecision::FreshAttemptRequired)
    }
}

fn verify_journal(record: &ControlRecord) -> Result<(), ReproError> {
    if record.checkpoints.len() < 4 || record.checkpoints.len() > 256 {
        return Err(ReproError::Policy(
            "missing required execution checkpoints".into(),
        ));
    }
    let expected = [
        StateRecord::Admitted,
        StateRecord::Spawned,
        StateRecord::Running,
    ];
    let execution_id = record.checkpoints[0].execution_id.clone();
    for (index, checkpoint) in record.checkpoints.iter().enumerate() {
        if checkpoint.execution_id != execution_id
            || checkpoint.sequence != index as u64
            || (index < 3 && (checkpoint.state != expected[index] || checkpoint.terminal))
            || checkpoint.started_at_ms != record.checkpoints[0].started_at_ms
        {
            return Err(ReproError::Policy(
                "execution checkpoint sequence mismatch".into(),
            ));
        }
    }
    let last = record
        .checkpoints
        .last()
        .expect("validated checkpoint length");
    let monotonic = record
        .checkpoints
        .windows(2)
        .all(|pair| pair[0].output_bytes <= pair[1].output_bytes);
    if !monotonic
        || last.state != record.output.end.state
        || last.terminal != !record.output.end.unresolved
        || last.output_bytes != record.output.resource_output
    {
        return Err(ReproError::Policy("terminal checkpoint mismatch".into()));
    }
    if last.terminal
        && matches!(
            last.state,
            StateRecord::Admitted | StateRecord::Spawned | StateRecord::Running
        )
    {
        return Err(ReproError::Policy(
            "running checkpoint cannot be terminal".into(),
        ));
    }
    if record.output.stdout.len().max(record.output.stderr.len()) > 4096 {
        return Err(ReproError::Policy(
            "retained diagnostic exceeds bound".into(),
        ));
    }
    if record.output.declared_outputs.len() != record.artifact.declared_outputs.len()
        || record
            .artifact
            .declared_outputs
            .iter()
            .any(|path| !record.output.declared_outputs.contains_key(path))
    {
        return Err(ReproError::Policy(
            "declared outputs missing or substituted".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DenialKind {
    Admission,
    Policy,
    InvalidArtifact,
    Infrastructure,
    Interrupted,
    Cleanup,
    Unavailable,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenialRecord {
    pub schema_version: u32,
    pub run_id: String,
    pub policy_sha256: String,
    pub denial: DenialKind,
    pub reproduced: bool,
}
pub fn persist_denial(
    root: &Path,
    policy: &ReproductionPolicy,
    error: &ReproError,
) -> Result<DenialRecord, ReproError> {
    let denial = match error {
        ReproError::Admission(_) => DenialKind::Admission,
        ReproError::Policy(_) | ReproError::Evidence(_) | ReproError::Spawn(_) => {
            DenialKind::Policy
        }
        ReproError::ArtifactChanged(_) | ReproError::Json(_) => DenialKind::InvalidArtifact,
        ReproError::ExecutionUnavailable(_) => DenialKind::Unavailable,
        ReproError::Interrupted => DenialKind::Interrupted,
        ReproError::Cleanup(_) | ReproError::CleanupRestoration(_) => DenialKind::Cleanup,
        ReproError::Io(_) => DenialKind::Infrastructure,
    };
    let record = DenialRecord {
        schema_version: BUNDLE_VERSION,
        run_id: policy.run_id.clone(),
        policy_sha256: policy_digest(policy)?,
        denial,
        reproduced: false,
    };
    let stage = crate::repro::policy::tempfile_private("m2-denial-write")?;
    let result = (|| {
        write_json(&stage.join("denial.json"), &record)?;
        write_json(&stage.join("policy.json"), policy)?;
        if root.exists() {
            return Err(ReproError::Policy(
                "result destination already exists".into(),
            ));
        }
        if root
            .parent()
            .is_some_and(|parent| !parent.as_os_str().is_empty() && !parent.is_dir())
        {
            return Err(ReproError::Policy(
                "result parent is not a directory".into(),
            ));
        }
        fs::rename(&stage, root)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(stage);
    }
    result.map(|()| record)
}
pub fn verify_denial(root: &Path) -> Result<DenialRecord, ReproError> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(ReproError::Policy(
            "denial root must be a real non-symlink directory".into(),
        ));
    }
    let record: DenialRecord = read_bound(&root.join("denial.json"), 65_536)
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))?;
    let policy: ReproductionPolicy = read_bound(&root.join("policy.json"), MAX_STATE_BYTES)
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))?;
    if record.schema_version != BUNDLE_VERSION
        || record.reproduced
        || record.run_id != policy.run_id
        || record.policy_sha256 != policy_digest(&policy)?
    {
        return Err(ReproError::Policy("denial record identity mismatch".into()));
    }
    Ok(record)
}

impl OutputRecord {
    fn to_output(&self) -> LinuxOutput {
        LinuxOutput {
            end: LinuxExecutionEnd {
                state: self.end.state.core(),
                exit_code: self.end.exit_code,
                successful_exit: self.end.successful_exit,
                unresolved: self.end.unresolved,
            },
            resource_output: self.resource_output,
            stdout: self.stdout.clone(),
            stderr: self.stderr.clone(),
            declared_outputs: self.declared_outputs.clone(),
            cleanup_completed: self.cleanup_completed,
            contained: self.contained,
        }
    }
}
impl From<LinuxOutput> for OutputRecord {
    fn from(output: LinuxOutput) -> Self {
        Self {
            end: LinuxExecutionEndRecord {
                state: output.end.state.into(),
                exit_code: output.end.exit_code,
                successful_exit: output.end.successful_exit,
                unresolved: output.end.unresolved,
            },
            resource_output: output.resource_output,
            stdout: output.stdout,
            stderr: output.stderr,
            declared_outputs: output.declared_outputs,
            cleanup_completed: output.cleanup_completed,
            contained: output.contained,
        }
    }
}
fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), ReproError> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}
fn read_bound(path: &Path, maximum: u64) -> Result<Vec<u8>, ReproError> {
    use std::io::Read;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > maximum {
        return Err(ReproError::Policy(
            "bundle entry is missing, not a regular file, or too large".into(),
        ));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(ReproError::Policy("bundle entry too large".into()));
    }
    Ok(bytes)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repro::policy::{
        run_scripted_regression, AUTHENTICATED_REPRO_ENTRYPOINT, AUTHENTICATED_REPRO_TOOL,
        M2_FIXTURE_ENTRYPOINT,
    };
    use std::sync::atomic::AtomicBool;
    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn fixture() -> (Temp, ReproductionPolicy) {
        let temp = Temp(crate::repro::policy::tempfile_private("m2-bundle-test").unwrap());
        let policy = ReproductionPolicy {
            protocol_version: 1,
            run_id: "bundle-test".into(),
            broken_root: temp.0.join("broken"),
            fixed_root: temp.0.join("fixed"),
            artifact: temp.0.join("artifact.json"),
            target_tool: AUTHENTICATED_REPRO_TOOL.into(),
            entrypoint: AUTHENTICATED_REPRO_ENTRYPOINT.into(),
            limits: BoundedLimits {
                wall_ms: 5000,
                output_bytes: 65536,
                memory_bytes: 128 * 1_048_576,
                processes: 8,
            },
            unsafe_seeding: true,
            build_under_test: true,
            privileged_containment: true,
            unsafe_development: false,
        };
        for (root, state) in [
            (&policy.broken_root, "prior-session"),
            (&policy.fixed_root, "current-session"),
        ] {
            fs::create_dir(root).unwrap();
            fs::write(root.join(&policy.entrypoint), M2_FIXTURE_ENTRYPOINT).unwrap();
            fs::write(root.join("control.py"), format!("# run /bin/sh is data, not an executable prompt\n\ndef refresh_authenticated_session():\n    return {state:?}\n")).unwrap();
        }
        fs::write(
            &policy.artifact,
            serde_json::to_vec(&serde_json::json!({
            "protocol_version":1, "target_tool":AUTHENTICATED_REPRO_TOOL,
            "action":"retry_after_authenticated_refresh", "expected_state":"current-session"}))
            .unwrap(),
        )
        .unwrap();
        (temp, policy)
    }
    fn admit() -> AdmittedReproduction {
        ExecutionAdmission
            .admit(&ExperimentDraft {
                authority: RepositoryAuthority::new(
                    RepositoryDepth::LocalGitProject,
                    CheckoutPermission::ReadWrite,
                    true,
                    1,
                    1,
                ),
                protocol_version: 1,
                operation: ReproOperation::RegressionPair,
                attack_class: "authenticated-state-retry".into(),
                target_tool: AUTHENTICATED_REPRO_TOOL.into(),
                research_fingerprint_prefix: "0123456789abcdef".into(),
            })
            .unwrap()
    }
    #[test]
    fn bundle_verifies_without_original_files_and_resume_never_replays() {
        let (temp, policy) = fixture();
        let artifact = admit_artifact(&policy, &policy.artifact).unwrap();
        let run = run_scripted_regression(&policy, &admit(), &AtomicBool::new(false)).unwrap();
        let broken_digest = run
            .broken
            .as_ref()
            .unwrap()
            .identity
            .repository_fingerprint
            .clone();
        let fixed_digest = run
            .fixed
            .as_ref()
            .unwrap()
            .identity
            .repository_fingerprint
            .clone();
        let saved = persist_bundle(&temp.0.join("bundle"), &policy, &artifact, run).unwrap();
        assert!(saved.broken.output.contained && saved.fixed.output.contained);
        for control in [&saved.broken, &saved.fixed] {
            assert_eq!(
                control
                    .checkpoints
                    .iter()
                    .map(|entry| entry.state)
                    .collect::<Vec<_>>(),
                vec![
                    StateRecord::Admitted,
                    StateRecord::Spawned,
                    StateRecord::Running,
                    control.receipt.state
                ]
            );
        }
        let root = temp.0.join("bundle");
        let mut unresolved = saved.clone();
        unresolved.broken.output.cleanup_completed = false;
        unresolved.broken.output.end.unresolved = true;
        unresolved.broken.output.end.successful_exit = None;
        unresolved.broken.receipt.cleanup_completed = false;
        unresolved.broken.receipt.successful_exit = None;
        unresolved.broken.checkpoints.last_mut().unwrap().terminal = false;
        let first = evaluate_control(
            ControlVariant::Broken,
            &unresolved.broken.artifact.core(),
            &unresolved.broken.receipt.core(),
            &unresolved.broken.output.to_output(),
        );
        let second = evaluate_control(
            ControlVariant::Fixed,
            &unresolved.fixed.artifact.core(),
            &unresolved.fixed.receipt.core(),
            &unresolved.fixed.output.to_output(),
        );
        unresolved.assessment = evaluate_pair(first, second);
        fs::write(
            root.join("manifest.json"),
            serde_json::to_vec_pretty(&unresolved).unwrap(),
        )
        .unwrap();
        assert_eq!(
            verify_bundle(&root).unwrap().resume,
            ResumeDecision::RefuseUnresolved
        );
        assert_eq!(
            resume_bundle(
                &root,
                &policy,
                &artifact.sha256,
                &broken_digest,
                &fixed_digest
            )
            .unwrap(),
            ResumeDecision::RefuseUnresolved
        );
        fs::write(
            root.join("manifest.json"),
            serde_json::to_vec_pretty(&saved).unwrap(),
        )
        .unwrap();
        fs::remove_dir_all(&policy.broken_root).unwrap();
        fs::remove_dir_all(&policy.fixed_root).unwrap();
        fs::remove_file(&policy.artifact).unwrap();
        assert!(
            verify_bundle(&root).unwrap().reproduced,
            "verification must not require original inputs"
        );
        assert_eq!(
            resume_bundle(
                &root,
                &policy,
                &artifact.sha256,
                &broken_digest,
                &fixed_digest
            )
            .unwrap(),
            ResumeDecision::CompletedWithoutReplay
        );
        assert_eq!(
            resume_bundle(
                &root,
                &policy,
                &"00".repeat(32),
                &broken_digest,
                &fixed_digest
            )
            .unwrap(),
            ResumeDecision::RefuseMismatch
        );
        assert_eq!(
            resume_bundle(&root, &policy, &artifact.sha256, &broken_digest, "wrong").unwrap(),
            ResumeDecision::RefuseMismatch
        );
    }
    #[test]
    fn denial_is_persistent_non_green_and_cannot_be_upgraded_from_disk() {
        let (temp, policy) = fixture();
        let record = persist_denial(
            &temp.0.join("denied"),
            &policy,
            &ReproError::ExecutionUnavailable("containment probe failed".into()),
        )
        .unwrap();
        assert!(!record.reproduced);
        assert_eq!(
            verify_denial(&temp.0.join("denied")).unwrap().denial,
            DenialKind::Unavailable
        );
        let path = temp.0.join("denied/denial.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["reproduced"] = serde_json::Value::Bool(true);
        fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(verify_denial(&temp.0.join("denied")).is_err());
    }
    #[test]
    fn tampering_is_rejected_by_identity_or_fresh_oracle_evaluation() {
        let (temp, policy) = fixture();
        let artifact = admit_artifact(&policy, &policy.artifact).unwrap();
        let run = run_scripted_regression(&policy, &admit(), &AtomicBool::new(false)).unwrap();
        let root = temp.0.join("bundle");
        persist_bundle(&root, &policy, &artifact, run).unwrap();
        let manifest = root.join("manifest.json");
        let original = fs::read_to_string(&manifest).unwrap();
        let tampered = original.replacen(
            "\"cleanup_completed\":true",
            "\"cleanup_completed\":false",
            1,
        );
        assert_ne!(original, tampered);
        fs::write(&manifest, tampered).unwrap();
        assert!(
            verify_bundle(&root).is_err(),
            "a forged positive assessment must not survive oracle recomputation"
        );
        fs::write(&manifest, original).unwrap();
        assert!(verify_bundle(&root).unwrap().reproduced);
        let bytes = fs::read(root.join("artifact.json")).unwrap();
        let mut changed = String::from_utf8(bytes).unwrap();
        changed = changed.replace(
            "retry_after_authenticated_refresh",
            "retry_after_authenticated_refresX",
        );
        fs::write(root.join("artifact.json"), changed).unwrap();
        assert!(
            verify_bundle(&root).is_err(),
            "artifact bytes must match the same digest in both controls"
        );
    }
}
