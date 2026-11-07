//! Append-only M5 evidence. Verification never reopens any target root or driver.

use super::oracle::{assess, Assessment, RunRecord, WorkflowConclusion, WorkflowRunKind};
use super::policy::WorkflowPolicy;
use crate::repro::error::ReproError;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(test)]
static TEST_CANCEL_DURING_TERMINAL: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_CANCEL_BEFORE_RENAME: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_CANCEL_AFTER_RENAME: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_CANCEL_AFTER_COMMIT: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_HALT_BEFORE_RENAME: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_HALT_AFTER_RENAME: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_HALT_BEFORE_COMMIT: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_HALT_AFTER_COMMIT: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_FAIL_PARENT_SYNC: AtomicBool = AtomicBool::new(false);
const MAX_EVIDENCE_FILE_BYTES: u64 = 8 * 1_048_576;
const MAX_JOURNAL_RECORDS: usize = 128;
const EVIDENCE_FILES: &[&str] = &[
    "policy.json",
    "state.json",
    "broken.json",
    "fixed.json",
    "control.json",
    "journal.jsonl",
    "manifest.json",
];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum JournalRecord {
    BundleCreated {
        run_id: String,
        invocation_id: String,
    },
    RunStarted {
        run_kind: WorkflowRunKind,
        step_index: usize,
    },
    StepAdmitted {
        run_kind: WorkflowRunKind,
        step_index: usize,
    },
    StepValidated {
        run_kind: WorkflowRunKind,
        step_index: usize,
    },
    CleanupStarted {
        run_kind: WorkflowRunKind,
    },
    CleanupComplete {
        run_kind: WorkflowRunKind,
    },
    RunCompleted {
        run_kind: WorkflowRunKind,
    },
    Error {
        code: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowState {
    pub schema_version: u32,
    pub run_id: String,
    pub invocation_id: String,
    pub policy_sha256: String,
    pub phase: String,
    pub run_kind: Option<WorkflowRunKind>,
    pub next_step: usize,
}

impl WorkflowState {
    pub fn started(policy: &WorkflowPolicy, invocation_id: &str) -> Result<Self, ReproError> {
        if !super::policy::valid_invocation_id(invocation_id) {
            return Err(ReproError::Evidence(
                "invalid workflow invocation identity".into(),
            ));
        }
        Ok(Self {
            schema_version: policy.evidence_schema,
            run_id: policy.run_id.clone(),
            invocation_id: invocation_id.into(),
            policy_sha256: policy.digest()?,
            phase: "created".into(),
            run_kind: None,
            next_step: 0,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunSummary {
    pub run_kind: WorkflowRunKind,
    pub final_effect_observed: bool,
    pub effect_prevented: bool,
    pub complete: bool,
    pub error_code: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowManifest {
    pub bundle_version: u32,
    pub schema_version: u32,
    pub scenario: String,
    pub oracle: String,
    pub run_id: String,
    pub invocation_id: String,
    pub policy_sha256: String,
    pub runner_version: String,
    pub conclusion: WorkflowConclusion,
    pub assessment: Assessment,
    pub runs: Vec<RunSummary>,
    pub source_digests: BTreeMap<String, String>,
    pub evidence_sha256: BTreeMap<String, String>,
}

pub struct Workspace {
    directory: PathBuf,
    publication: PathBuf,
    invocation_id: String,
    journal: File,
}
impl Workspace {
    pub fn create(
        directory: &Path,
        policy: &WorkflowPolicy,
        invocation_id: &str,
    ) -> Result<Self, ReproError> {
        for path in [
            directory,
            directory.parent().unwrap_or_else(|| Path::new(".")),
        ] {
            match fs::symlink_metadata(path) {
                Ok(metadata) if path == directory || metadata.is_dir() => {
                    if path == directory {
                        return Err(ReproError::Policy("workflow bundle already exists".into()));
                    }
                    if metadata.file_type().is_symlink() {
                        return Err(ReproError::Policy(
                            "workflow output parent must be real".into(),
                        ));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && path == directory => {
                }
                Err(error) => return Err(error.into()),
                _ => {
                    return Err(ReproError::Policy(
                        "invalid workflow output directory".into(),
                    ));
                }
            }
        }
        let parent = directory
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .ok_or_else(|| ReproError::Policy("workflow output needs a real parent".into()))?;
        let name = directory
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty() && !name.contains('/'))
            .ok_or_else(|| ReproError::Policy("workflow output needs a UTF-8 filename".into()))?;
        if !super::policy::valid_invocation_id(invocation_id) {
            return Err(ReproError::Evidence("invalid invocation identity".into()));
        }
        if pending_invocation(name).is_some() {
            return Err(ReproError::Policy(
                "workflow output uses the reserved private-pending namespace".into(),
            ));
        }
        let pending = parent.join(format!(".{name}.pending-{invocation_id}"));
        if fs::symlink_metadata(&pending).is_ok() {
            return Err(ReproError::Policy(
                "workflow pending namespace already exists".into(),
            ));
        }
        fs::DirBuilder::new().mode(0o700).create(&pending)?;
        let publication = directory.to_path_buf();
        let directory = &pending;
        let result = (|| {
            let journal_path = directory.join("journal.jsonl");
            private_write(&journal_path, b"")?;
            let journal = open_append(&journal_path)?;
            let workspace = Self {
                directory: directory.to_path_buf(),
                publication,
                invocation_id: invocation_id.into(),
                journal,
            };
            workspace.append(&JournalRecord::BundleCreated {
                run_id: policy.run_id.clone(),
                invocation_id: invocation_id.into(),
            })?;
            workspace.write_json(Path::new("policy.json"), policy)?;
            workspace.write_state(&WorkflowState::started(policy, invocation_id)?)?;
            Ok(workspace)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(directory);
        }
        result
    }

    pub fn append(&self, record: &JournalRecord) -> Result<(), ReproError> {
        let mut line = serde_json::to_vec(record)?;
        line.push(b'\n');
        (&self.journal).write_all(&line)?;
        self.journal.sync_data()?;
        Ok(())
    }

    pub fn write_state(&self, state: &WorkflowState) -> Result<(), ReproError> {
        atomic_write(&self.directory.join("state.json"), &encode(state)?)
    }

    pub fn write_run(&self, run: &RunRecord) -> Result<(), ReproError> {
        self.write_json(Path::new(run.run_kind.file()), run)
    }

    pub fn finish(
        self,
        policy: &WorkflowPolicy,
        runs: &[RunRecord; 3],
        cancel: &AtomicBool,
    ) -> Result<WorkflowManifest, ReproError> {
        if cancel.load(Ordering::SeqCst) {
            return Err(ReproError::Interrupted);
        }
        let invocation_id = self.invocation_id.clone();
        #[cfg(test)]
        if TEST_CANCEL_DURING_TERMINAL.swap(false, Ordering::SeqCst) {
            cancel.store(true, Ordering::SeqCst);
        }
        if cancel.load(Ordering::SeqCst) {
            return Err(ReproError::Interrupted);
        }
        let assessment = assess(policy, runs, &invocation_id)?;
        let conclusion = match assessment.interpretation {
            super::oracle::Interpretation::Confirmed => WorkflowConclusion::Confirmed,
            super::oracle::Interpretation::NoEffect => WorkflowConclusion::NoEffect,
            super::oracle::Interpretation::OperationalFailure => {
                WorkflowConclusion::EnvironmentManualReview
            }
        };
        let runner_version = crate::repro::linux::LinuxRunner::contained()?.version();
        let mut evidence_sha256 = BTreeMap::new();
        for name in &EVIDENCE_FILES[..EVIDENCE_FILES.len() - 1] {
            evidence_sha256.insert(
                (*name).into(),
                super::policy::hex(&Sha256::digest(fs::read(self.directory.join(name))?)),
            );
        }
        if cancel.load(Ordering::SeqCst) {
            return Err(ReproError::Interrupted);
        }
        let manifest = WorkflowManifest {
            bundle_version: 1,
            schema_version: policy.evidence_schema,
            scenario: policy.scenario.clone(),
            oracle: policy.oracle.clone(),
            run_id: policy.run_id.clone(),
            invocation_id,
            policy_sha256: policy.digest()?,
            runner_version,
            conclusion,
            assessment: assessment.clone(),
            runs: run_summaries(runs, &assessment),
            source_digests: BTreeMap::from([(
                super::policy::REVOKED_INVITE_DRIVER_NAME.into(),
                super::policy::REVOKED_INVITE_DRIVER_SHA256.into(),
            )]),
            evidence_sha256,
        };
        self.journal.sync_data()?;
        sync_directory(&self.directory)?;
        #[cfg(test)]
        if TEST_HALT_BEFORE_COMMIT.swap(false, Ordering::SeqCst) {
            panic!("test halt before private terminal manifest write");
        }
        let staged = private_write(
            &self.directory.join("manifest.json"),
            encode(&manifest)?.as_bytes(),
        )
        .and_then(|()| sync_directory(&self.directory))
        .and_then(|()| verify_staged(&self.directory).map(|_| ()));
        if let Err(error) = staged {
            return Err(self.abort_publication(error));
        }
        #[cfg(test)]
        if TEST_CANCEL_BEFORE_RENAME.swap(false, Ordering::SeqCst) {
            cancel.store(true, Ordering::SeqCst);
        }
        if cancel.load(Ordering::SeqCst) {
            return Err(self.withdraw_terminal());
        }
        #[cfg(test)]
        if TEST_HALT_BEFORE_RENAME.swap(false, Ordering::SeqCst) {
            panic!("test halt before terminal directory rename");
        }
        // The complete, internally verified directory crosses the publication
        // boundary with one no-replace rename. Private pending evidence never
        // verifies green through the public entry point.
        let published = rustix::fs::renameat_with(
            rustix::fs::CWD,
            &self.directory,
            rustix::fs::CWD,
            &self.publication,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|error| {
            ReproError::Evidence(format!("terminal bundle publication failed: {error}"))
        });
        if let Err(error) = published {
            return Err(self.abort_publication(error));
        }
        #[cfg(test)]
        if TEST_CANCEL_AFTER_RENAME.swap(false, Ordering::SeqCst) {
            cancel.store(true, Ordering::SeqCst);
        }
        #[cfg(test)]
        if TEST_HALT_AFTER_RENAME.swap(false, Ordering::SeqCst) {
            panic!("test halt after terminal directory rename");
        }
        let parent_sync = sync_directory(
            self.publication
                .parent()
                .expect("validated publication parent"),
        );
        #[cfg(test)]
        let parent_sync = if TEST_FAIL_PARENT_SYNC.swap(false, Ordering::SeqCst) {
            Err(ReproError::Evidence(
                "injected terminal parent sync failure".into(),
            ))
        } else {
            parent_sync
        };
        if let Err(error) = parent_sync {
            return Err(ReproError::Cleanup(format!(
                "terminal bundle is committed and remains green, but its parent-directory \
                 durability is unresolved: {error}"
            )));
        }
        // Nothing fallible or cancellation-sensitive follows the commit. In
        // particular, a later signal cannot retract visible committed evidence.
        #[cfg(test)]
        if TEST_HALT_AFTER_COMMIT.swap(false, Ordering::SeqCst) {
            panic!("test halt after terminal directory commit");
        }
        #[cfg(test)]
        if TEST_CANCEL_AFTER_COMMIT.swap(false, Ordering::SeqCst) {
            cancel.store(true, Ordering::SeqCst);
        }
        Ok(manifest)
    }

    fn abort_publication(&self, cause: ReproError) -> ReproError {
        match self.withdraw_terminal() {
            ReproError::Interrupted => cause,
            ReproError::Cleanup(withdrawal) => ReproError::Cleanup(format!(
                "{cause}; terminal pre-commit withdrawal failed: {withdrawal}"
            )),
            other => ReproError::Cleanup(format!(
                "{cause}; terminal pre-commit withdrawal failed: {other}"
            )),
        }
    }

    /// Before the directory commit, cancellation or an operational error leaves
    /// only non-green pending evidence. There is no withdrawal path after commit.
    fn withdraw_terminal(&self) -> ReproError {
        let current = &self.directory;
        let mut failures = Vec::new();
        match read_json::<WorkflowState>(&current.join("state.json")) {
            Ok(mut state) => {
                state.phase = "interrupted".into();
                match encode(&state) {
                    Ok(encoded) => {
                        if let Err(error) = atomic_write(&current.join("state.json"), &encoded) {
                            failures.push(format!("interrupt state: {error}"));
                        }
                    }
                    Err(error) => failures.push(format!("encode interrupt state: {error}")),
                }
            }
            Err(error) => failures.push(format!("read terminal state: {error}")),
        }
        match fs::remove_file(current.join("manifest.json")) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => failures.push(format!("withdraw manifest: {error}")),
        }
        if let Err(error) = sync_directory(current) {
            failures.push(format!("sync withdrawal: {error}"));
        }
        if failures.is_empty() {
            ReproError::Interrupted
        } else {
            ReproError::Cleanup(format!(
                "terminal cancellation withdrawal failed: {}",
                failures.join("; ")
            ))
        }
    }

    fn write_json<T: Serialize>(&self, relative: &Path, value: &T) -> Result<(), ReproError> {
        if relative.components().count() != 1
            || !matches!(relative.components().next(), Some(Component::Normal(_)))
        {
            return Err(ReproError::Evidence("unsafe evidence path".into()));
        }
        atomic_write(&self.directory.join(relative), &encode(value)?)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowVerification {
    pub bundle_version: u32,
    pub conclusion: WorkflowConclusion,
    pub assessment: Option<Assessment>,
    pub run_id: String,
    pub diagnostic: String,
}

pub fn verify(directory: &Path) -> Result<WorkflowVerification, ReproError> {
    verify_impl(directory, false)
}

/// Used only by publication while the directory is still private. Public
/// verification deliberately rejects this namespace, even if a copied or
/// crashed pending directory contains a complete manifest.
fn verify_staged(directory: &Path) -> Result<WorkflowVerification, ReproError> {
    verify_impl(directory, true)
}

fn verify_impl(directory: &Path, staged: bool) -> Result<WorkflowVerification, ReproError> {
    let directory = verification_directory(directory)?;
    let policy_path = directory.join("policy.json");
    let policy_bytes = super::policy::bounded_source_read(&policy_path, MAX_EVIDENCE_FILE_BYTES)
        .map_err(|_| {
            ReproError::Evidence("workflow policy must be a bounded regular file".into())
        })?;
    crate::canonical::parse_no_duplicates(&policy_bytes)
        .map_err(|error| ReproError::Evidence(error.to_string()))?;
    let policy: WorkflowPolicy = serde_json::from_slice(&policy_bytes)?;
    policy.validate_shape(true)?;
    if policy_bytes != encode(&policy)?.as_bytes() {
        return Err(ReproError::Evidence(
            "workflow policy encoding is not canonical".into(),
        ));
    }
    let state: WorkflowState = match read_json(&directory.join("state.json")) {
        Ok(state) => state,
        Err(error) => {
            return interrupted(policy.run_id, format!("invalid persisted state: {error}"));
        }
    };
    if state.run_id != policy.run_id
        || !super::policy::valid_invocation_id(&state.invocation_id)
        || state.policy_sha256 != policy.digest()?
        || state.schema_version != policy.evidence_schema
    {
        return Err(ReproError::Evidence(
            "persisted state identity mismatch".into(),
        ));
    }
    let journal = read_journal(&directory.join("journal.jsonl"))
        .map_err(|error| ReproError::Evidence(format!("invalid workflow journal: {error}")))?;
    if journal.first()
        != Some(&JournalRecord::BundleCreated {
            run_id: policy.run_id.clone(),
            invocation_id: state.invocation_id.clone(),
        })
    {
        return Err(ReproError::Evidence(
            "journal did not create this run".into(),
        ));
    }
    if !staged
        && directory
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(pending_invocation)
            == Some(state.invocation_id.as_str())
    {
        return interrupted(
            policy.run_id,
            "private pending evidence is not a published terminal result".into(),
        );
    }
    let manifest_path = directory.join("manifest.json");
    if !manifest_path.exists() {
        return interrupted(
            policy.run_id,
            "run did not produce a complete manifest".into(),
        );
    }
    let manifest: WorkflowManifest = read_json(&manifest_path)?;
    if state.phase != "complete"
        || state.run_kind.is_some()
        || state.next_step != 0
        || journal
            .iter()
            .any(|record| matches!(record, JournalRecord::Error { .. }))
    {
        return interrupted(
            policy.run_id,
            "journal or state records an incomplete run".into(),
        );
    }
    if manifest.bundle_version != 1
        || manifest.schema_version != policy.evidence_schema
        || manifest.run_id != policy.run_id
        || manifest.invocation_id != state.invocation_id
        || manifest.policy_sha256 != policy.digest()?
        || manifest.scenario != policy.scenario
        || manifest.oracle != policy.oracle
        || !crate::repro::linux::LinuxRunner::valid_evidence_version(&manifest.runner_version)
        || manifest.source_digests.len() != 1
        || manifest
            .source_digests
            .get(super::policy::REVOKED_INVITE_DRIVER_NAME)
            != Some(&super::policy::REVOKED_INVITE_DRIVER_SHA256.into())
    {
        return Err(ReproError::Evidence(
            "workflow manifest identity mismatch".into(),
        ));
    }
    let expected = EVIDENCE_FILES
        .iter()
        .map(|name| (*name).into())
        .collect::<BTreeSet<String>>();
    let mut entries = BTreeSet::new();
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !expected.contains(&name) || !entries.insert(name) {
            return Err(ReproError::Evidence(
                "workflow bundle file set mismatch".into(),
            ));
        }
        let file_type = entry.file_type()?;
        if !file_type.is_file() || file_type.is_symlink() {
            return Err(ReproError::Evidence(
                "unexpected evidence entry type".into(),
            ));
        }
    }
    if entries != expected || manifest.evidence_sha256.len() != EVIDENCE_FILES.len() - 1 {
        return Err(ReproError::Evidence(
            "workflow bundle file set mismatch".into(),
        ));
    }
    for (name, expected_digest) in &manifest.evidence_sha256 {
        if !expected.contains(name)
            || super::policy::hex(&Sha256::digest(bounded_read(&directory.join(name))?))
                != *expected_digest
        {
            return Err(ReproError::Evidence(
                "workflow evidence digest mismatch".into(),
            ));
        }
    }
    let runs = [
        read_json::<RunRecord>(&directory.join("broken.json"))?,
        read_json::<RunRecord>(&directory.join("fixed.json"))?,
        read_json::<RunRecord>(&directory.join("control.json"))?,
    ];
    if runs.iter().enumerate().any(|(index, run)| {
        run.run_kind
            != [
                WorkflowRunKind::Broken,
                WorkflowRunKind::Fixed,
                WorkflowRunKind::FunctionalControl,
            ][index]
    }) {
        return Err(ReproError::Evidence(
            "workflow variant order mismatch".into(),
        ));
    }
    validate_journal(&journal, &policy, &runs, &state.invocation_id)?;
    let assessment = assess(&policy, &runs, &state.invocation_id)?;
    if assessment != manifest.assessment {
        return Err(ReproError::Evidence(
            "stored assessment differs from decoded behavior".into(),
        ));
    }
    let expected = run_summaries(&runs, &assessment);
    if manifest.runs != expected {
        return Err(ReproError::Evidence(
            "run summary differs from typed behavior".into(),
        ));
    }
    if manifest.runs.iter().map(|run| run.run_kind).ne([
        WorkflowRunKind::Broken,
        WorkflowRunKind::Fixed,
        WorkflowRunKind::FunctionalControl,
    ]) {
        return Err(ReproError::Evidence(
            "run summaries are not uniquely ordered".into(),
        ));
    }
    let expected_conclusion = match assessment.interpretation {
        super::oracle::Interpretation::Confirmed => WorkflowConclusion::Confirmed,
        super::oracle::Interpretation::NoEffect => WorkflowConclusion::NoEffect,
        super::oracle::Interpretation::OperationalFailure => {
            WorkflowConclusion::EnvironmentManualReview
        }
    };
    if manifest.conclusion != expected_conclusion || manifest.runs.len() != 3 {
        return Err(ReproError::Evidence(
            "stored conclusion differs from typed behavior".into(),
        ));
    }
    Ok(WorkflowVerification {
        bundle_version: 1,
        conclusion: expected_conclusion,
        assessment: Some(assessment),
        run_id: policy.run_id,
        diagnostic: "typed effects independently recomputed; no target reaccess".into(),
    })
}

fn run_summaries(runs: &[RunRecord; 3], assessment: &Assessment) -> Vec<RunSummary> {
    runs.iter()
        .map(|run| RunSummary {
            run_kind: run.run_kind,
            final_effect_observed: match run.run_kind {
                WorkflowRunKind::Broken => assessment.broken_effect,
                WorkflowRunKind::FunctionalControl => assessment.functional_control_normal,
                WorkflowRunKind::Fixed => false,
            },
            effect_prevented: run.run_kind == WorkflowRunKind::Fixed
                && assessment.fixed_effect_prevented,
            complete: assessment.eligible
                && run.cleanup.complete
                && run.cleanup.target_root_removed
                && run.error_code.is_none()
                && run.containment_failures.is_empty(),
            error_code: run.error_code.clone(),
        })
        .collect()
}

fn validate_journal(
    journal: &[JournalRecord],
    policy: &WorkflowPolicy,
    runs: &[RunRecord; 3],
    invocation_id: &str,
) -> Result<(), ReproError> {
    use JournalRecord::*;
    let mut expected = vec![BundleCreated {
        run_id: policy.run_id.clone(),
        invocation_id: invocation_id.into(),
    }];
    for run in runs {
        expected.push(RunStarted {
            run_kind: run.run_kind,
            step_index: 0,
        });
        for (index, step) in run.steps.iter().enumerate() {
            expected.push(StepAdmitted {
                run_kind: run.run_kind,
                step_index: index,
            });
            if matches!(step.decoding, super::oracle::DecodingStatus::Valid)
                && matches!(step.transition, super::oracle::TransitionStatus::Valid)
            {
                expected.push(StepValidated {
                    run_kind: run.run_kind,
                    step_index: index,
                });
            }
        }
        expected.push(CleanupStarted {
            run_kind: run.run_kind,
        });
        expected.push(CleanupComplete {
            run_kind: run.run_kind,
        });
        expected.push(RunCompleted {
            run_kind: run.run_kind,
        });
    }
    if journal != expected {
        return Err(ReproError::Evidence(
            "journal sequence does not match typed step effects".into(),
        ));
    }
    Ok(())
}

fn encode<T: Serialize>(value: &T) -> Result<String, ReproError> {
    Ok(crate::canonical::canonical_json(&serde_json::to_value(
        value,
    )?))
}

fn read_journal(path: &Path) -> Result<Vec<JournalRecord>, ReproError> {
    let bytes = bounded_read(path)?;
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err(ReproError::Evidence("unterminated journal record".into()));
    }
    let mut records = Vec::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        crate::canonical::parse_no_duplicates(line)
            .map_err(|error| ReproError::Evidence(error.to_string()))?;
        records.push(serde_json::from_slice(line)?);
        if records.len() > MAX_JOURNAL_RECORDS {
            return Err(ReproError::Evidence("workflow journal is too large".into()));
        }
    }
    Ok(records)
}

fn pending_invocation(name: &str) -> Option<&str> {
    let (base, invocation) = name.strip_prefix('.')?.rsplit_once(".pending-")?;
    (!base.is_empty() && super::policy::valid_invocation_id(invocation)).then_some(invocation)
}

fn verification_directory(path: &Path) -> Result<PathBuf, ReproError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(ReproError::Evidence(
            "bundle must be a real directory".into(),
        ));
    }
    Ok(fs::canonicalize(path)?)
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, ReproError> {
    let bytes = bounded_read(path)?;
    crate::canonical::parse_no_duplicates(&bytes)
        .map_err(|error| ReproError::Evidence(error.to_string()))?;
    serde_json::from_slice(&bytes).map_err(Into::into)
}

fn bounded_read(path: &Path) -> Result<Vec<u8>, ReproError> {
    super::policy::bounded_source_read(path, MAX_EVIDENCE_FILE_BYTES)
        .map_err(|_| ReproError::Evidence("missing, non-regular, or oversized evidence".into()))
}

fn private_write(path: &Path, bytes: &[u8]) -> Result<(), ReproError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_data()?;
    Ok(())
}
fn open_append(path: &Path) -> Result<File, ReproError> {
    OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(Into::into)
}
fn atomic_write(path: &Path, value: &str) -> Result<(), ReproError> {
    let parent = path
        .parent()
        .ok_or_else(|| ReproError::Evidence("missing evidence parent".into()))?;
    let temporary = parent.join(format!(
        ".{}.new",
        path.file_name().unwrap().to_string_lossy()
    ));
    let _ = fs::remove_file(&temporary);
    private_write(&temporary, value.as_bytes())?;
    fs::rename(&temporary, path)?;
    sync_directory(parent)
}
fn sync_directory(path: &Path) -> Result<(), ReproError> {
    File::open(path)?.sync_data()?;
    Ok(())
}

fn interrupted(
    run_id: impl Into<String>,
    diagnostic: String,
) -> Result<WorkflowVerification, ReproError> {
    Ok(WorkflowVerification {
        bundle_version: 1,
        conclusion: WorkflowConclusion::InterpretationFailed,
        assessment: None,
        run_id: run_id.into(),
        diagnostic,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::oracle::{Interpretation, WorkflowVariant};
    use crate::workflow::{REVOKED_INVITE_ORACLE, REVOKED_INVITE_SCENARIO};

    static TERMINAL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn terminal_test_guard() -> std::sync::MutexGuard<'static, ()> {
        TERMINAL_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn no_effect_runs() -> [RunRecord; 3] {
        let run = |run_kind| RunRecord {
            schema_version: 1,
            scenario: REVOKED_INVITE_SCENARIO.into(),
            oracle: REVOKED_INVITE_ORACLE.into(),
            run_kind,
            variant: match run_kind {
                WorkflowRunKind::Broken => WorkflowVariant::Broken,
                WorkflowRunKind::Fixed | WorkflowRunKind::FunctionalControl => {
                    WorkflowVariant::Fixed
                }
            },
            run_namespace: run_kind.slug().into(),
            policy_sha256: "00".repeat(32),
            target_root: PathBuf::from(format!(
                "/tmp/opencode/smash-m5-target-{}",
                run_kind.slug()
            )),
            credential_reference: "synthetic-guest".into(),
            credential_sha256: "11".repeat(32),
            synthetic_guest: true,
            disposable_private_target: true,
            target_destruction: true,
            error_code: None,
            containment_failures: Vec::new(),
            cleanup: super::super::oracle::CleanupRecord {
                sequence: 1,
                complete: true,
                target_root_removed: true,
                error_code: None,
            },
            steps: Vec::new(),
        };
        [
            run(WorkflowRunKind::Broken),
            run(WorkflowRunKind::Fixed),
            run(WorkflowRunKind::FunctionalControl),
        ]
    }

    #[test]
    fn shared_no_effect_summary_preserves_the_normal_functional_control() {
        let runs = no_effect_runs();
        let assessment = Assessment {
            eligible: true,
            actions_match: false,
            states_match: false,
            membership_matches: false,
            broken_effect: false,
            fixed_effect_prevented: true,
            functional_control_normal: true,
            interpretation: Interpretation::NoEffect,
        };
        // Both Workspace::finish and verify call this same summary function.
        let summaries = run_summaries(&runs, &assessment);
        assert!(!summaries[0].final_effect_observed);
        assert!(summaries[1].effect_prevented);
        assert!(summaries[2].final_effect_observed);
        assert!(summaries.iter().all(|summary| summary.complete));
    }

    fn terminal_case(label: &str) -> (PathBuf, PathBuf, Workspace, WorkflowPolicy, [RunRecord; 3]) {
        use crate::repro::policy::BoundedLimits;
        use crate::workflow::policy::{WorkflowDriver, WorkflowIdentities};
        use crate::workflow::{REVOKED_INVITE_DRIVER_SHA256, SYNTHETIC_GUEST_CREDENTIAL_REFERENCE};

        let root = PathBuf::from(format!(
            "/tmp/opencode/smash-m5-terminal-{label}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let driver = WorkflowDriver {
            path: PathBuf::from("/tmp/opencode/revoked_invite.py"),
            sha256: REVOKED_INVITE_DRIVER_SHA256.into(),
        };
        let policy = WorkflowPolicy {
            protocol_version: 1,
            run_id: format!("m5-terminal-{label}"),
            scenario: REVOKED_INVITE_SCENARIO.into(),
            oracle: REVOKED_INVITE_ORACLE.into(),
            provider: "linux-landlock-seccomp".into(),
            evidence_schema: 1,
            broken_driver: driver.clone(),
            fixed_driver: driver,
            broken_root: PathBuf::from(format!(
                "/tmp/opencode/smash-m5-target-cancel-{label}-broken-{}",
                std::process::id()
            )),
            fixed_root: PathBuf::from(format!(
                "/tmp/opencode/smash-m5-target-cancel-{label}-fixed-{}",
                std::process::id()
            )),
            control_root: PathBuf::from(format!(
                "/tmp/opencode/smash-m5-target-cancel-{label}-control-{}",
                std::process::id()
            )),
            identities: WorkflowIdentities {
                project: "project".into(),
                owner: "owner".into(),
                guest: "guest".into(),
                invitation: "invitation".into(),
            },
            credential_reference: SYNTHETIC_GUEST_CREDENTIAL_REFERENCE.into(),
            limits: BoundedLimits {
                wall_ms: 5_000,
                output_bytes: 65_536,
                memory_bytes: 128 * 1_048_576,
                processes: 1,
            },
            synthetic_guests: true,
            disposable_targets: true,
            target_destruction: true,
            network: "none".into(),
            unsafe_development: false,
        };
        let bundle = root.join("bundle");
        let workspace = Workspace::create(&bundle, &policy, &"ab".repeat(16)).unwrap();
        let runs = no_effect_runs();
        for run in &runs {
            workspace.write_run(run).unwrap();
            workspace
                .append(&JournalRecord::RunStarted {
                    run_kind: run.run_kind,
                    step_index: 0,
                })
                .unwrap();
            workspace
                .append(&JournalRecord::CleanupStarted {
                    run_kind: run.run_kind,
                })
                .unwrap();
            workspace
                .append(&JournalRecord::CleanupComplete {
                    run_kind: run.run_kind,
                })
                .unwrap();
            workspace
                .append(&JournalRecord::RunCompleted {
                    run_kind: run.run_kind,
                })
                .unwrap();
        }
        let mut final_state = WorkflowState::started(&policy, &"ab".repeat(16)).unwrap();
        final_state.phase = "complete".into();
        workspace.write_state(&final_state).unwrap();
        (root, bundle, workspace, policy, runs)
    }

    #[test]
    fn terminal_cancellation_never_leaves_a_green_manifest() {
        let _guard = terminal_test_guard();
        for (label, trigger) in [
            ("during", &TEST_CANCEL_DURING_TERMINAL),
            ("before-rename", &TEST_CANCEL_BEFORE_RENAME),
        ] {
            let (root, bundle, workspace, policy, runs) = terminal_case(label);
            let pending = workspace.directory.clone();
            let cancel = AtomicBool::new(false);
            trigger.store(true, Ordering::SeqCst);
            let result = workspace.finish(&policy, &runs, &cancel);
            assert!(
                matches!(result, Err(ReproError::Interrupted)),
                "{label}: {result:?}"
            );
            assert!(!bundle.exists(), "{label}");
            assert!(!pending.join("manifest.json").exists(), "{label}");
            assert_eq!(
                verify(&pending).unwrap().conclusion,
                WorkflowConclusion::InterpretationFailed,
                "{label}"
            );
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn terminal_directory_rename_is_the_cancellation_linearization_point() {
        let _guard = terminal_test_guard();
        for (label, trigger) in [
            ("after-rename-cancel", &TEST_CANCEL_AFTER_RENAME),
            ("after-commit-cancel", &TEST_CANCEL_AFTER_COMMIT),
        ] {
            let (root, bundle, workspace, policy, runs) = terminal_case(label);
            let cancel = AtomicBool::new(false);
            trigger.store(true, Ordering::SeqCst);
            let manifest = workspace.finish(&policy, &runs, &cancel).unwrap();
            assert!(cancel.load(Ordering::SeqCst));
            assert_eq!(
                manifest.conclusion,
                WorkflowConclusion::EnvironmentManualReview
            );
            let verified = verify(&bundle).unwrap();
            assert_eq!(
                verified.conclusion,
                WorkflowConclusion::EnvironmentManualReview
            );
            assert!(verified.assessment.is_some());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn fatal_halts_expose_green_evidence_only_after_the_commit() {
        let _guard = terminal_test_guard();
        for (label, trigger, committed, staged_manifest) in [
            ("halt-before-commit", &TEST_HALT_BEFORE_COMMIT, false, false),
            ("halt-before-rename", &TEST_HALT_BEFORE_RENAME, false, true),
            ("halt-after-rename", &TEST_HALT_AFTER_RENAME, true, true),
            ("halt-after-commit", &TEST_HALT_AFTER_COMMIT, true, true),
        ] {
            let (root, bundle, workspace, policy, runs) = terminal_case(label);
            let pending = workspace.directory.clone();
            trigger.store(true, Ordering::SeqCst);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                workspace.finish(&policy, &runs, &AtomicBool::new(false))
            }));
            assert!(result.is_err(), "{label} did not reach its halt point");
            assert_eq!(bundle.exists(), committed, "{label}");
            if committed {
                let verified = verify(&bundle).unwrap();
                assert_eq!(
                    verified.conclusion,
                    WorkflowConclusion::EnvironmentManualReview,
                    "{label}"
                );
                assert!(verified.assessment.is_some(), "{label}");
            } else {
                assert_eq!(pending.join("manifest.json").exists(), staged_manifest);
                if staged_manifest {
                    let staged = verify_staged(&pending).unwrap();
                    assert_eq!(
                        staged.conclusion,
                        WorkflowConclusion::EnvironmentManualReview
                    );
                }
                assert_eq!(
                    verify(&pending).unwrap().conclusion,
                    WorkflowConclusion::InterpretationFailed,
                    "{label}"
                );
            }
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn terminal_publication_failures_cannot_create_or_overwrite_green_evidence() {
        let _guard = terminal_test_guard();
        let (root, bundle, workspace, policy, runs) = terminal_case("collision");
        let pending = workspace.directory.clone();
        fs::create_dir(&bundle).unwrap();
        fs::write(bundle.join("keep"), b"existing output").unwrap();
        assert!(workspace
            .finish(&policy, &runs, &AtomicBool::new(false))
            .is_err());
        assert_eq!(fs::read(bundle.join("keep")).unwrap(), b"existing output");
        assert!(!pending.join("manifest.json").exists());
        assert_eq!(
            verify(&pending).unwrap().conclusion,
            WorkflowConclusion::InterpretationFailed
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn post_commit_sync_failure_is_explicit_without_rolling_back_green_evidence() {
        let _guard = terminal_test_guard();
        let (root, bundle, workspace, policy, runs) = terminal_case("parent-sync-failure");
        TEST_FAIL_PARENT_SYNC.store(true, Ordering::SeqCst);
        let result = workspace.finish(&policy, &runs, &AtomicBool::new(false));
        assert!(matches!(result, Err(ReproError::Cleanup(_))), "{result:?}");
        assert!(bundle.exists());
        assert_eq!(
            verify(&bundle).unwrap().conclusion,
            WorkflowConclusion::EnvironmentManualReview
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn public_output_cannot_use_the_reserved_pending_namespace() {
        let _guard = terminal_test_guard();
        let (root, _bundle, workspace, policy, _runs) = terminal_case("reserved-name");
        drop(workspace);
        let reserved = root.join(format!(".other.pending-{}", "ab".repeat(16)));
        assert!(Workspace::create(&reserved, &policy, &"cd".repeat(16)).is_err());
        assert!(!reserved.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn offline_verification_rejects_an_eighth_bundle_entry() {
        let _guard = terminal_test_guard();
        let (root, bundle, workspace, policy, runs) = terminal_case("eighth-entry");
        workspace
            .finish(&policy, &runs, &AtomicBool::new(false))
            .unwrap();
        fs::write(bundle.join("unexpected.json"), b"{}").unwrap();
        let error = verify(&bundle).unwrap_err();
        assert!(
            matches!(&error, ReproError::Evidence(message) if message == "workflow bundle file set mismatch"),
            "{error:?}"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
