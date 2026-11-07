//! M5-only policy and one-shot step authority. No M2 proposal can mint these tokens.

use super::oracle::{WorkflowRunKind, WorkflowStep};
use crate::repro::error::ReproError;
use crate::repro::linux::LinuxJob;
use crate::repro::policy::BoundedLimits;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use smash_core::execution::{
    ExecutionLimits, MAX_REPRO_MEMORY_BYTES, MAX_REPRO_OUTPUT_BYTES, MAX_REPRO_PROCESSES,
    MAX_REPRO_WALL_MS,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const WORKFLOW_POLICY_VERSION: u32 = 1;
pub const REVOKED_INVITE_SCENARIO: &str = "revoked-invite-acceptance-v1";
pub const REVOKED_INVITE_ORACLE: &str = "revoked-invite-differential-v1";
pub const WORKFLOW_EVIDENCE_SCHEMA: u32 = 1;
pub const REVOKED_INVITE_DRIVER_NAME: &str = "revoked_invite.py";
pub const REVOKED_INVITE_DRIVER_SHA256: &str =
    "de6054ffb6abc4e93e56482c16a90e1ee611173ac1d62900e9a04d2398ff24a8";
pub const SYNTHETIC_GUEST_CREDENTIAL_REFERENCE: &str = "synthetic-guest";
pub(crate) const RESULT_OUTPUT: &str = "result.json";
const MAX_POLICY_BYTES: usize = 65_536;
const MAX_DRIVER_BYTES: u64 = 65_536;
const MAX_WORKFLOW_WALL_MS: u64 = 10_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowDriver {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowIdentities {
    pub project: String,
    pub owner: String,
    pub guest: String,
    pub invitation: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowPolicy {
    pub protocol_version: u32,
    pub run_id: String,
    pub scenario: String,
    pub oracle: String,
    pub provider: String,
    pub evidence_schema: u32,
    pub broken_driver: WorkflowDriver,
    pub fixed_driver: WorkflowDriver,
    pub broken_root: PathBuf,
    pub fixed_root: PathBuf,
    pub control_root: PathBuf,
    pub identities: WorkflowIdentities,
    pub credential_reference: String,
    pub limits: BoundedLimits,
    pub synthetic_guests: bool,
    pub disposable_targets: bool,
    pub target_destruction: bool,
    pub network: String,
    pub unsafe_development: bool,
}

impl WorkflowPolicy {
    /// Validate only this closed catalog. Policy text is never argv or authority.
    pub fn review(&self, execute_fixture_workflow: bool) -> Result<WorkflowAdmission, ReproError> {
        self.validate_shape(execute_fixture_workflow)?;
        let driver = checked_driver(&self.broken_driver)?;
        if checked_driver(&self.fixed_driver)? != driver {
            return Err(ReproError::Policy(
                "broken and fixed variants require the pinned shared driver".into(),
            ));
        }
        let mut random = [0_u8; 16];
        let count = rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())
            .map_err(|error| ReproError::ExecutionUnavailable(format!("getrandom: {error}")))?;
        if count != random.len() {
            return Err(ReproError::ExecutionUnavailable(
                "short invocation nonce".into(),
            ));
        }
        Ok(WorkflowAdmission {
            policy_sha256: self.digest()?,
            invocation_id: hex(&random),
            driver,
            used_runs: 0,
        })
    }

    pub(crate) fn validate_shape(&self, execute_fixture_workflow: bool) -> Result<(), ReproError> {
        let identities = [
            &self.identities.project,
            &self.identities.owner,
            &self.identities.guest,
            &self.identities.invitation,
        ];
        let distinct = identities.iter().collect::<BTreeSet<_>>().len() == identities.len();
        if !execute_fixture_workflow
            || self.protocol_version != WORKFLOW_POLICY_VERSION
            || self.scenario != REVOKED_INVITE_SCENARIO
            || self.oracle != REVOKED_INVITE_ORACLE
            || self.provider != "linux-landlock-seccomp"
            || self.evidence_schema != WORKFLOW_EVIDENCE_SCHEMA
            || self.credential_reference != SYNTHETIC_GUEST_CREDENTIAL_REFERENCE
            || !self.synthetic_guests
            || !self.disposable_targets
            || !self.target_destruction
            || self.network != "none"
            || self.unsafe_development
            || !valid_symbol(&self.run_id)
            || identities.iter().any(|value| !valid_symbol(value))
            || !distinct
            || self.broken_driver.sha256 != REVOKED_INVITE_DRIVER_SHA256
            || self.fixed_driver.sha256 != REVOKED_INVITE_DRIVER_SHA256
            || self
                .broken_driver
                .path
                .file_name()
                .and_then(|name| name.to_str())
                != Some(REVOKED_INVITE_DRIVER_NAME)
            || self
                .fixed_driver
                .path
                .file_name()
                .and_then(|name| name.to_str())
                != Some(REVOKED_INVITE_DRIVER_NAME)
            || self.broken_root == self.fixed_root
            || self.broken_root == self.control_root
            || self.fixed_root == self.control_root
        {
            return Err(ReproError::Policy(
                "M5 requires the pinned contained synthetic revoked-invite scenario".into(),
            ));
        }
        self.limits.validate()?;
        for root in [&self.broken_root, &self.fixed_root, &self.control_root] {
            validate_disposable_name(root)?;
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ReproError> {
        Ok(hex(&Sha256::digest(serde_json::to_vec(self)?)))
    }

    pub fn root(&self, kind: WorkflowRunKind) -> &Path {
        match kind {
            WorkflowRunKind::Broken => &self.broken_root,
            WorkflowRunKind::Fixed => &self.fixed_root,
            WorkflowRunKind::FunctionalControl => &self.control_root,
        }
    }

    /// Offline verification derives every input independently. Comparing only
    /// the recorded digest would let a forged binding cover different bytes.
    pub(crate) fn expected_binding(
        &self,
        kind: WorkflowRunKind,
        index: usize,
        invocation_id: &str,
    ) -> Result<StepBinding, ReproError> {
        let operation = WorkflowStep::catalog(kind == WorkflowRunKind::FunctionalControl)
            .get(index)
            .copied()
            .ok_or_else(|| ReproError::Evidence("step index exceeds closed catalog".into()))?;
        let root = self.root(kind);
        let driver = self.driver(kind).path.clone();
        let variant = match kind.variant() {
            super::oracle::WorkflowVariant::Broken => "broken",
            super::oracle::WorkflowVariant::Fixed => "fixed",
        };
        let operation_name = serde_json::to_value(operation)?
            .as_str()
            .expect("typed workflow operation")
            .to_owned();
        let argv = vec![
            "/usr/bin/python3".into(),
            "-I".into(),
            "-B".into(),
            "-S".into(),
            driver.to_string_lossy().into_owned(),
            "--state".into(),
            root.join("state.json").to_string_lossy().into_owned(),
            "--project".into(),
            self.identities.project.clone(),
            "--owner".into(),
            self.identities.owner.clone(),
            "--guest".into(),
            self.identities.guest.clone(),
            "--invitation".into(),
            self.identities.invitation.clone(),
            "--operation".into(),
            operation_name,
            "--variant".into(),
            variant.into(),
            "--output".into(),
            RESULT_OUTPUT.into(),
            "--credential-reference".into(),
            self.credential_reference.clone(),
            "--memory-limit-bytes".into(),
            self.limits.memory_bytes.to_string(),
        ];
        Ok(StepBinding {
            schema_version: WORKFLOW_EVIDENCE_SCHEMA,
            scenario: self.scenario.clone(),
            oracle: self.oracle.clone(),
            policy_sha256: self.digest()?,
            run_namespace: run_namespace(self, kind, invocation_id),
            run_kind: kind,
            variant: kind.variant(),
            step_index: index as u32,
            operation,
            driver_path: driver,
            driver_sha256: REVOKED_INVITE_DRIVER_SHA256.into(),
            target_root: root.to_path_buf(),
            argv,
            credential_reference: self.credential_reference.clone(),
            declared_output: PathBuf::from(RESULT_OUTPUT),
            limits: self.limits.clone(),
            sequence: index as u64 + 1,
        })
    }

    fn driver(&self, kind: WorkflowRunKind) -> &WorkflowDriver {
        match kind {
            WorkflowRunKind::Broken => &self.broken_driver,
            WorkflowRunKind::Fixed | WorkflowRunKind::FunctionalControl => &self.fixed_driver,
        }
    }
}

pub(crate) fn run_namespace(
    policy: &WorkflowPolicy,
    kind: WorkflowRunKind,
    invocation_id: &str,
) -> String {
    format!("{}:{invocation_id}:{}", policy.run_id, kind.slug())
}

pub(crate) fn valid_invocation_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn synthetic_credential(namespace: &str, reference: &str) -> String {
    format!("synthetic-only:{namespace}:{reference}")
}

pub(crate) fn credential_digest(
    policy: &WorkflowPolicy,
    kind: WorkflowRunKind,
    invocation_id: &str,
) -> String {
    let credential = synthetic_credential(
        &run_namespace(policy, kind, invocation_id),
        &policy.credential_reference,
    );
    hex(&Sha256::digest(credential.as_bytes()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReviewedDriver {
    path: PathBuf,
    bytes: Vec<u8>,
}

trait ValidateWorkflowLimits {
    fn validate(&self) -> Result<(), ReproError>;
}
impl ValidateWorkflowLimits for BoundedLimits {
    fn validate(&self) -> Result<(), ReproError> {
        if !(1..=MAX_WORKFLOW_WALL_MS.min(MAX_REPRO_WALL_MS)).contains(&self.wall_ms)
            || !(1..=65_536.min(MAX_REPRO_OUTPUT_BYTES)).contains(&self.output_bytes)
            || !(16 * 1_048_576..=(128 * 1_048_576).min(MAX_REPRO_MEMORY_BYTES))
                .contains(&self.memory_bytes)
            || self.processes != 1
            || MAX_REPRO_PROCESSES < 1
        {
            return Err(ReproError::Policy("invalid M5 resource limits".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct WorkflowAdmission {
    policy_sha256: String,
    invocation_id: String,
    driver: ReviewedDriver,
    used_runs: u8,
}

impl WorkflowAdmission {
    pub fn invocation_id(&self) -> &str {
        &self.invocation_id
    }

    pub(crate) fn begin_run(
        &mut self,
        policy: &WorkflowPolicy,
        kind: WorkflowRunKind,
        provisioned_root: &PinnedTargetRoot,
    ) -> Result<WorkflowRunAdmission, ReproError> {
        if self.policy_sha256 != policy.digest()?
            || checked_driver(policy.driver(kind))? != self.driver
        {
            return Err(ReproError::Policy(
                "M5 policy or driver changed after review".into(),
            ));
        }
        let bit = 1_u8 << kind.run_index();
        if self.used_runs & bit != 0 || self.used_runs.count_ones() >= 3 {
            return Err(ReproError::Policy(
                "workflow run authority was already consumed".into(),
            ));
        }
        provisioned_root.verify_current()?;
        if fs::read_dir(&provisioned_root.path)?.next().is_some() {
            return Err(ReproError::Policy(
                "a fresh workflow namespace must not contain prior target state".into(),
            ));
        }
        self.used_runs |= bit;
        Ok(WorkflowRunAdmission {
            policy: policy.clone(),
            policy_sha256: self.policy_sha256.clone(),
            invocation_id: self.invocation_id.clone(),
            kind,
            root: provisioned_root.try_clone()?,
            driver: self.driver.clone(),
            next_step: 0,
        })
    }
}

pub struct WorkflowRunAdmission {
    policy: WorkflowPolicy,
    policy_sha256: String,
    invocation_id: String,
    kind: WorkflowRunKind,
    root: PinnedTargetRoot,
    driver: ReviewedDriver,
    next_step: usize,
}

impl WorkflowRunAdmission {
    pub(crate) fn target_root(&self) -> &PinnedTargetRoot {
        &self.root
    }

    pub fn admit_step(&mut self, stage: &Path) -> Result<AdmittedWorkflowStep, ReproError> {
        if stage != Path::new(RESULT_OUTPUT) {
            return Err(ReproError::Policy(
                "M5 permits only the symbolic typed result output".into(),
            ));
        }
        self.root.verify_current()?;
        let steps = WorkflowStep::catalog(self.kind == WorkflowRunKind::FunctionalControl);
        let operation = *steps.get(self.next_step).ok_or_else(|| {
            ReproError::Policy("workflow step sequence is already complete".into())
        })?;
        let index = self.next_step;
        self.next_step += 1;
        let run_namespace = run_namespace(&self.policy, self.kind, &self.invocation_id);
        let credential_value =
            synthetic_credential(&run_namespace, &self.policy.credential_reference);
        let operation_name = serde_json::to_value(operation)?
            .as_str()
            .expect("typed workflow operation")
            .to_owned();
        let variant = match self.kind.variant() {
            super::oracle::WorkflowVariant::Broken => "broken",
            super::oracle::WorkflowVariant::Fixed => "fixed",
        };
        let argv = vec![
            PathBuf::from("/usr/bin/python3"),
            PathBuf::from("-I"),
            PathBuf::from("-B"),
            PathBuf::from("-S"),
            self.driver.path.clone(),
            PathBuf::from("--state"),
            self.root.path.join("state.json"),
            PathBuf::from("--project"),
            PathBuf::from(&self.policy.identities.project),
            PathBuf::from("--owner"),
            PathBuf::from(&self.policy.identities.owner),
            PathBuf::from("--guest"),
            PathBuf::from(&self.policy.identities.guest),
            PathBuf::from("--invitation"),
            PathBuf::from(&self.policy.identities.invitation),
            PathBuf::from("--operation"),
            PathBuf::from(operation_name),
            PathBuf::from("--variant"),
            PathBuf::from(variant),
            PathBuf::from("--output"),
            PathBuf::from(RESULT_OUTPUT),
            PathBuf::from("--credential-reference"),
            PathBuf::from(&self.policy.credential_reference),
            PathBuf::from("--memory-limit-bytes"),
            PathBuf::from(self.policy.limits.memory_bytes.to_string()),
        ];
        let mut environment = BTreeMap::new();
        environment.insert("SMASH_WORKFLOW_CREDENTIAL".into(), credential_value);
        environment.insert(
            "SMASH_ATTEMPT_ID".into(),
            format!("{run_namespace}:step-{index}"),
        );
        let job = LinuxJob {
            argv,
            read_roots: vec![
                PathBuf::from("/usr"),
                PathBuf::from("/lib"),
                PathBuf::from("/lib64"),
            ],
            read_files: vec![self.driver.path.clone()],
            write_roots: vec![self.root.path.clone()],
            output_root: stage.to_path_buf(),
            environment,
            limits: self.policy.limits.to_core(),
        };
        let binding = StepBinding {
            schema_version: WORKFLOW_EVIDENCE_SCHEMA,
            scenario: self.policy.scenario.clone(),
            oracle: self.policy.oracle.clone(),
            policy_sha256: self.policy_sha256.clone(),
            run_namespace: run_namespace.clone(),
            run_kind: self.kind,
            variant: self.kind.variant(),
            step_index: index as u32,
            operation,
            driver_path: self.driver.path.clone(),
            driver_sha256: REVOKED_INVITE_DRIVER_SHA256.into(),
            target_root: self.root.path.clone(),
            argv: job
                .argv
                .iter()
                .map(|part| part.to_string_lossy().into_owned())
                .collect(),
            credential_reference: self.policy.credential_reference.clone(),
            declared_output: PathBuf::from(RESULT_OUTPUT),
            limits: job.limits.clone().into(),
            sequence: index as u64 + 1,
        };
        Ok(AdmittedWorkflowStep {
            binding,
            job,
            target_root: self.root.try_clone()?,
            driver_bytes: self.driver.bytes.clone(),
            created: Instant::now(),
            valid_for: Duration::from_millis(self.policy.limits.wall_ms),
            used: false,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StepBinding {
    pub schema_version: u32,
    pub scenario: String,
    pub oracle: String,
    pub policy_sha256: String,
    pub run_namespace: String,
    pub run_kind: WorkflowRunKind,
    pub variant: super::oracle::WorkflowVariant,
    pub step_index: u32,
    pub operation: WorkflowStep,
    pub driver_path: PathBuf,
    pub driver_sha256: String,
    pub target_root: PathBuf,
    pub argv: Vec<String>,
    pub credential_reference: String,
    pub declared_output: PathBuf,
    pub limits: BoundedLimits,
    pub sequence: u64,
}

impl StepBinding {
    pub fn digest(&self) -> Result<String, ReproError> {
        Ok(hex(&Sha256::digest(serde_json::to_vec(self)?)))
    }
}

/// Unserializable, non-cloneable authority for exactly one typed external process.
pub struct AdmittedWorkflowStep {
    binding: StepBinding,
    job: LinuxJob,
    target_root: PinnedTargetRoot,
    pub(crate) driver_bytes: Vec<u8>,
    created: Instant,
    valid_for: Duration,
    used: bool,
}

impl AdmittedWorkflowStep {
    pub fn binding(&self) -> &StepBinding {
        &self.binding
    }
    pub(crate) fn job(&self) -> &LinuxJob {
        &self.job
    }
    pub(crate) fn pinned_target_root(&self) -> Result<PinnedTargetRoot, ReproError> {
        self.target_root.try_clone()
    }
    pub(crate) fn consume(
        mut self,
        job: &LinuxJob,
        declared_outputs: &[PathBuf],
    ) -> Result<StepBinding, ReproError> {
        if self.used
            || self.created.elapsed() >= self.valid_for
            || self.job != *job
            || declared_outputs != [PathBuf::from(RESULT_OUTPUT)]
        {
            return Err(ReproError::Policy(
                "M5 admitted-step binding, sequence, or deadline mismatch".into(),
            ));
        }
        self.used = true;
        Ok(self.binding)
    }
}

pub fn read_policy(path: &Path) -> Result<WorkflowPolicy, ReproError> {
    let bytes = bounded_source_read(path, MAX_POLICY_BYTES as u64)?;
    crate::canonical::parse_no_duplicates(&bytes)
        .map_err(|error| ReproError::Policy(error.to_string()))?;
    serde_json::from_slice(&bytes).map_err(Into::into)
}

pub(crate) fn bounded_source_read(path: &Path, maximum: u64) -> Result<Vec<u8>, ReproError> {
    let before = fs::symlink_metadata(path)?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    let opened = file.metadata()?;
    let current = fs::symlink_metadata(path)?;
    if !before.is_file()
        || before.file_type().is_symlink()
        || !opened.is_file()
        || (opened.dev(), opened.ino()) != (before.dev(), before.ino())
        || (opened.dev(), opened.ino()) != (current.dev(), current.ino())
        || before.len() > maximum
    {
        return Err(ReproError::Policy(
            "source changed while being reviewed".into(),
        ));
    }
    let mut bytes = Vec::new();
    file.by_ref().take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum || file.metadata()?.len() != bytes.len() as u64 {
        return Err(ReproError::Policy(
            "source exceeds its bounded identity".into(),
        ));
    }
    Ok(bytes)
}

fn checked_driver(driver: &WorkflowDriver) -> Result<ReviewedDriver, ReproError> {
    if driver.sha256 != REVOKED_INVITE_DRIVER_SHA256
        || !driver.path.is_absolute()
        || driver.path.file_name().and_then(|name| name.to_str())
            != Some(REVOKED_INVITE_DRIVER_NAME)
    {
        return Err(ReproError::Policy("unrecognized workflow driver".into()));
    }
    let metadata = fs::symlink_metadata(&driver.path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ReproError::Policy(
            "workflow driver must be a regular non-symlink file".into(),
        ));
    }
    let path = fs::canonicalize(&driver.path)?;
    let bytes = bounded_source_read(&path, MAX_DRIVER_BYTES)?;
    if path != driver.path || hex(&Sha256::digest(&bytes)) != driver.sha256 {
        return Err(ReproError::Policy(
            "workflow driver path or source digest mismatch".into(),
        ));
    }
    Ok(ReviewedDriver { path, bytes })
}

#[derive(Debug)]
pub(crate) struct PinnedTargetRoot {
    path: PathBuf,
    directory: File,
    parent: File,
}

impl PinnedTargetRoot {
    pub(crate) fn descriptor(&self) -> &File {
        &self.directory
    }
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn try_clone(&self) -> Result<Self, ReproError> {
        Ok(Self {
            path: self.path.clone(),
            directory: self.directory.try_clone()?,
            parent: self.parent.try_clone()?,
        })
    }
    pub(crate) fn is_destroyed(&self) -> Result<bool, ReproError> {
        let path_absent = match fs::symlink_metadata(&self.path) {
            Ok(_) => false,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(error) => return Err(error.into()),
        };
        // Removing a different directory at the recycled pathname would make a
        // path-only check look successful while this reviewed inode survived.
        Ok(path_absent && self.directory.metadata()?.nlink() == 0)
    }
    pub(crate) fn destroy_current_with_hook(
        &self,
        before_claim: impl FnOnce() -> Result<(), ReproError>,
    ) -> Result<(), ReproError> {
        const MAX_TARGET_DEPTH: usize = 32;
        self.verify_current()?;
        before_claim()?;
        let cleanup_parent = private_cleanup_namespace(&self.parent)?;
        let name = self.path.file_name().expect("validated target filename");
        let claim_name = cleanup_claim_name(name.to_string_lossy().as_ref())?;
        // Claim into a mode-0700 parent retained for the service lifetime. Even if
        // its shared-parent pathname is displaced, actors cannot replace entries
        // through this descriptor, and the final rmdir is consequently inode-safe.
        rustix::fs::renameat_with(
            &self.parent,
            name,
            &cleanup_parent,
            &claim_name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|error| ReproError::Cleanup(format!("claim reviewed target root: {error}")))?;
        let restore = |error: ReproError| {
            match rustix::fs::renameat_with(
            &cleanup_parent,
            &claim_name,
            &self.parent,
            name,
            rustix::fs::RenameFlags::NOREPLACE,
        ) {
            Ok(()) => error,
            Err(restoration) => ReproError::CleanupRestoration(format!(
                "{error}; restoration failed: {restoration}; unreviewed inode retained in {PRIVATE_CLEANUP_NAMESPACE}/{claim_name}"
            )),
        }
        };
        let claimed = rustix::fs::openat(
            &cleanup_parent,
            &claim_name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        );
        let claimed = match claimed {
            Ok(claimed) => File::from(claimed),
            Err(error) => {
                return Err(restore(ReproError::Cleanup(format!(
                    "open claimed target root: {error}"
                ))));
            }
        };
        let reviewed_identity = self.directory.metadata().map_err(|error| {
            restore(ReproError::Cleanup(format!(
                "read reviewed target identity: {error}"
            )))
        })?;
        let claimed_identity = claimed.metadata().map_err(|error| {
            restore(ReproError::Cleanup(format!(
                "read claimed target identity: {error}"
            )))
        })?;
        if (claimed_identity.dev(), claimed_identity.ino())
            != (reviewed_identity.dev(), reviewed_identity.ino())
        {
            return Err(restore(ReproError::Evidence(
                "reviewed target identity changed during cleanup claim".into(),
            )));
        }
        let mut entries = 0_usize;
        remove_target_contents(&claimed, MAX_TARGET_DEPTH, &mut entries).map_err(restore)?;
        rustix::fs::unlinkat(&cleanup_parent, &claim_name, rustix::fs::AtFlags::REMOVEDIR)
            .map_err(|error| {
                restore(ReproError::Cleanup(format!(
                    "remove claimed target root from private cleanup namespace: {error}"
                )))
            })?;
        if self.is_destroyed()? {
            Ok(())
        } else {
            Err(ReproError::Cleanup(
                "the reviewed target inode survived cleanup or its path was replaced".into(),
            ))
        }
    }
    pub(crate) fn verify_current(&self) -> Result<(), ReproError> {
        let opened = self.directory.metadata()?;
        let current = fs::symlink_metadata(&self.path).map_err(|error| {
            ReproError::Evidence(format!(
                "reviewed workflow target path disappeared: {error}"
            ))
        })?;
        if !opened.is_dir()
            || !current.is_dir()
            || current.file_type().is_symlink()
            || current.permissions().mode() & 0o777 != 0o700
            || current.uid() != rustix::process::getuid().as_raw()
            || (current.dev(), current.ino()) != (opened.dev(), opened.ino())
        {
            return Err(ReproError::Evidence(
                "workflow target identity changed after admission".into(),
            ));
        }
        Ok(())
    }
}

const PRIVATE_CLEANUP_NAMESPACE: &str = ".smash-m5-private-cleanup-v1";

fn private_cleanup_namespace(parent: &File) -> Result<File, ReproError> {
    match rustix::fs::mkdirat(
        parent,
        PRIVATE_CLEANUP_NAMESPACE,
        rustix::fs::Mode::from_raw_mode(0o700),
    ) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(error) => {
            return Err(ReproError::Cleanup(format!(
                "create private cleanup namespace: {error}"
            )));
        }
    }
    let directory = File::from(
        rustix::fs::openat(
            parent,
            PRIVATE_CLEANUP_NAMESPACE,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| ReproError::Cleanup(format!("open private cleanup namespace: {error}")))?,
    );
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(ReproError::Cleanup(
            "private cleanup namespace is not an owned mode-0700 directory".into(),
        ));
    }
    Ok(directory)
}

fn cleanup_claim_name(target_name: &str) -> Result<String, ReproError> {
    let mut random = [0_u8; 16];
    let count = rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())
        .map_err(|error| ReproError::Cleanup(format!("cleanup claim nonce: {error}")))?;
    if count != random.len() {
        return Err(ReproError::Cleanup("short cleanup claim nonce".into()));
    }
    Ok(format!(".{target_name}.cleanup-{}", hex(&random)))
}

/// Move an unpinned, possibly replaced creation-failure path out of the public
/// target namespace without deleting an inode whose provenance is uncertain.
pub(crate) fn quarantine_unpinned_target(root: &Path) -> Result<PathBuf, ReproError> {
    validate_disposable_name(root)?;
    let parent = File::open(root.parent().expect("validated target parent"))?;
    let cleanup_parent = private_cleanup_namespace(&parent)?;
    let name = root.file_name().expect("validated target filename");
    let claim_name = cleanup_claim_name(name.to_string_lossy().as_ref())?;
    rustix::fs::renameat_with(
        parent,
        name,
        cleanup_parent,
        &claim_name,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| ReproError::Cleanup(format!("quarantine unpinned target: {error}")))?;
    Ok(Path::new("/tmp/opencode")
        .join(PRIVATE_CLEANUP_NAMESPACE)
        .join(claim_name))
}

/// Delete through pinned directory descriptors, never through a pathname that
/// a displaced target or a target-created symlink can redirect.
fn remove_target_contents(
    directory: &File,
    remaining_depth: usize,
    entries: &mut usize,
) -> Result<(), ReproError> {
    const MAX_TARGET_ENTRIES: usize = 4_096;

    let Some(remaining_depth) = remaining_depth.checked_sub(1) else {
        return Err(ReproError::Cleanup("workflow target is too deep".into()));
    };
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(directory)
        .map_err(|error| ReproError::Cleanup(format!("read reviewed target: {error}")))?
    {
        let name = entry
            .map(|entry| entry.file_name().to_owned())
            .map_err(|error| ReproError::Cleanup(format!("read reviewed target: {error}")))?;
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        *entries = entries
            .checked_add(1)
            .ok_or_else(|| ReproError::Cleanup("workflow target entry counter overflow".into()))?;
        if *entries > MAX_TARGET_ENTRIES {
            return Err(ReproError::Cleanup(
                "workflow target contains too many entries".into(),
            ));
        }
        names.push(name);
    }
    for name in names {
        match rustix::fs::openat(
            directory,
            &name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ) {
            Ok(child) => {
                remove_target_contents(&File::from(child), remaining_depth, entries)?;
                rustix::fs::unlinkat(directory, &name, rustix::fs::AtFlags::REMOVEDIR).map_err(
                    |error| {
                        ReproError::Cleanup(format!("remove reviewed target directory: {error}"))
                    },
                )?;
            }
            Err(rustix::io::Errno::NOTDIR | rustix::io::Errno::LOOP) => {
                rustix::fs::unlinkat(directory, &name, rustix::fs::AtFlags::empty()).map_err(
                    |error| ReproError::Cleanup(format!("remove reviewed target entry: {error}")),
                )?;
            }
            Err(rustix::io::Errno::NOENT) => {}
            Err(error) => {
                return Err(ReproError::Cleanup(format!(
                    "open reviewed target entry: {error}"
                )));
            }
        }
    }
    Ok(())
}

pub(crate) fn checked_target_root(root: &Path) -> Result<PinnedTargetRoot, ReproError> {
    validate_disposable_name(root)?;
    let parent = fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::DIRECTORY).bits() as i32)
        .open(root.parent().expect("validated target parent"))?;
    let before = fs::symlink_metadata(root)?;
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::DIRECTORY).bits() as i32)
        .open(root)?;
    let opened = directory.metadata()?;
    let current = fs::symlink_metadata(root)?;
    if !before.is_dir()
        || before.file_type().is_symlink()
        || !opened.is_dir()
        || !current.is_dir()
        || current.file_type().is_symlink()
        || opened.permissions().mode() & 0o777 != 0o700
        || current.permissions().mode() & 0o777 != 0o700
        || opened.uid() != rustix::process::getuid().as_raw()
        || current.uid() != opened.uid()
        || (opened.dev(), opened.ino()) != (before.dev(), before.ino())
        || (opened.dev(), opened.ino()) != (current.dev(), current.ino())
        || fs::canonicalize(root)? != root
    {
        return Err(ReproError::Policy(
            "workflow target root must be an owned private real directory".into(),
        ));
    }
    Ok(PinnedTargetRoot {
        path: root.to_path_buf(),
        directory,
        parent,
    })
}

fn validate_disposable_name(root: &Path) -> Result<(), ReproError> {
    let valid = root.parent() == Some(Path::new("/tmp/opencode"))
        && root
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.starts_with("smash-m5-target-")
                    && name.len() <= 160
                    && name.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                    })
            });
    if valid {
        Ok(())
    } else {
        Err(ReproError::Policy(
            "workflow target roots must be fresh private /tmp/opencode/smash-m5-target-* directories"
                .into(),
        ))
    }
}

fn valid_symbol(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl From<ExecutionLimits> for BoundedLimits {
    fn from(value: ExecutionLimits) -> Self {
        Self {
            wall_ms: value.wall_ms,
            output_bytes: value.output_bytes,
            memory_bytes: value.memory_bytes,
            processes: value.processes,
        }
    }
}

#[allow(dead_code)]
fn fixed_environment_type(_: BTreeMap<String, String>) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> WorkflowPolicy {
        let driver = WorkflowDriver {
            path: PathBuf::from("/tmp/opencode/revoked_invite.py"),
            sha256: REVOKED_INVITE_DRIVER_SHA256.into(),
        };
        WorkflowPolicy {
            protocol_version: 1,
            run_id: "m5-policy-test".into(),
            scenario: REVOKED_INVITE_SCENARIO.into(),
            oracle: REVOKED_INVITE_ORACLE.into(),
            provider: "linux-landlock-seccomp".into(),
            evidence_schema: 1,
            broken_driver: driver.clone(),
            fixed_driver: driver,
            broken_root: PathBuf::from("/tmp/opencode/smash-m5-target-broken-test"),
            fixed_root: PathBuf::from("/tmp/opencode/smash-m5-target-fixed-test"),
            control_root: PathBuf::from("/tmp/opencode/smash-m5-target-control-test"),
            identities: WorkflowIdentities {
                project: "project".into(),
                owner: "owner".into(),
                guest: "guest".into(),
                invitation: "invitation".into(),
            },
            credential_reference: SYNTHETIC_GUEST_CREDENTIAL_REFERENCE.into(),
            limits: BoundedLimits {
                wall_ms: 5000,
                output_bytes: 65_536,
                memory_bytes: 128 * 1_048_576,
                processes: 1,
            },
            synthetic_guests: true,
            disposable_targets: true,
            target_destruction: true,
            network: "none".into(),
            unsafe_development: false,
        }
    }

    #[test]
    fn unsupported_authority_and_execution_text_fail_before_any_input_is_opened() {
        let valid = policy();
        for changed in [
            WorkflowPolicy {
                scenario: "os.system('id')".into(),
                ..valid.clone()
            },
            WorkflowPolicy {
                oracle: "caller-selected".into(),
                ..valid.clone()
            },
            WorkflowPolicy {
                credential_reference: "actual-secret-value".into(),
                ..valid.clone()
            },
            WorkflowPolicy {
                unsafe_development: true,
                ..valid.clone()
            },
            WorkflowPolicy {
                network: "loopback".into(),
                ..valid.clone()
            },
            WorkflowPolicy {
                fixed_root: PathBuf::from("/etc"),
                ..valid.clone()
            },
        ] {
            assert!(changed.review(true).is_err());
        }
        assert!(valid.review(false).is_err());
    }

    #[test]
    fn symbolic_fields_and_limits_are_bounded() {
        let mut changed = policy();
        changed.identities.guest = "x".repeat(97);
        assert!(changed.review(true).is_err());
        let mut changed = policy();
        changed.limits.wall_ms = 0;
        assert!(changed.review(true).is_err());
        let mut changed = policy();
        changed.identities.guest = changed.identities.owner.clone();
        assert!(changed.review(true).is_err());
    }

    #[test]
    fn duplicate_and_unknown_policy_fields_are_rejected() {
        assert!(read_policy(Path::new("/definitely/not/opened")).is_err());
        let duplicate = br#"{"protocol_version":1,"protocol_version":1}"#;
        assert!(crate::canonical::parse_no_duplicates(duplicate).is_err());
        assert!(serde_json::from_slice::<WorkflowPolicy>(
            br#"{"protocol_version":1,"argv":["sh"]}"#
        )
        .is_err());
    }

    #[test]
    fn one_shot_steps_bind_the_exact_job_deadline_output_and_closed_sequence() {
        let root = PathBuf::from(format!(
            "/tmp/opencode/smash-m5-token-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let result = (|| {
            let driver = root.join(REVOKED_INVITE_DRIVER_NAME);
            fs::copy(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../smash-capstone/fixtures/revoked_invite.py"),
                &driver,
            )?;
            let mut policy = policy();
            policy.broken_driver.path = driver.clone();
            policy.fixed_driver.path = driver;
            for path in [
                &policy.broken_root,
                &policy.fixed_root,
                &policy.control_root,
            ] {
                fs::create_dir(path)?;
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            }
            let broken_root = checked_target_root(&policy.broken_root)?;
            let fixed_root = checked_target_root(&policy.fixed_root)?;
            let mut admission = policy.review(true)?;
            let other_invocation = policy.review(true)?;
            assert_ne!(admission.invocation_id(), other_invocation.invocation_id());
            let mut run = admission.begin_run(&policy, WorkflowRunKind::Broken, &broken_root)?;
            assert!(run.admit_step(Path::new("../host-output")).is_err());
            let first = run.admit_step(Path::new(RESULT_OUTPUT))?;
            assert_eq!(first.binding().sequence, 1);
            assert!(first
                .binding()
                .run_namespace
                .contains(admission.invocation_id()));
            let mut wrong = first.job().clone();
            wrong.argv.push(PathBuf::from("--caller-selected"));
            assert!(first
                .consume(&wrong, &[PathBuf::from(RESULT_OUTPUT)])
                .is_err());
            assert!(fs::read_dir(&policy.broken_root)?.next().is_none());
            let pinned = root.join("pinned-target");
            let replacement = root.join("replacement-target");
            fs::rename(&policy.broken_root, &pinned)?;
            fs::create_dir(&replacement)?;
            fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700))?;
            std::os::unix::fs::symlink(&replacement, &policy.broken_root)?;
            assert!(run.admit_step(Path::new(RESULT_OUTPUT)).is_err());
            fs::remove_file(&policy.broken_root)?;
            fs::rename(&pinned, &policy.broken_root)?;

            for expected in 2..=6 {
                let step = run.admit_step(Path::new(RESULT_OUTPUT))?;
                assert_eq!(step.binding().sequence, expected);
                assert_eq!(
                    step.binding().step_index + 1,
                    u32::try_from(expected).unwrap()
                );
                let job = step.job().clone();
                let binding = step.consume(&job, &[PathBuf::from(RESULT_OUTPUT)])?;
                assert_eq!(binding.sequence, expected);
                assert!(fs::read_dir(&policy.broken_root)?.next().is_none());
            }
            assert!(run.admit_step(Path::new(RESULT_OUTPUT)).is_err());
            assert!(admission
                .begin_run(&policy, WorkflowRunKind::Broken, &broken_root)
                .is_err());

            let mut fixed = admission.begin_run(&policy, WorkflowRunKind::Fixed, &fixed_root)?;
            let admitted = fixed.admit_step(Path::new(RESULT_OUTPUT))?;
            let job = admitted.job().clone();
            assert_eq!(
                admitted
                    .consume(&job, &[PathBuf::from(RESULT_OUTPUT)])?
                    .sequence,
                1
            );
            let mut expired = fixed.admit_step(Path::new(RESULT_OUTPUT))?;
            let job = expired.job().clone();
            expired.created = Instant::now() - expired.valid_for;
            assert!(expired
                .consume(&job, &[PathBuf::from(RESULT_OUTPUT)])
                .is_err());
            let mut zero = fixed.admit_step(Path::new(RESULT_OUTPUT))?;
            let job = zero.job().clone();
            zero.valid_for = Duration::ZERO;
            assert!(zero.consume(&job, &[PathBuf::from(RESULT_OUTPUT)]).is_err());
            let mut used = fixed.admit_step(Path::new(RESULT_OUTPUT))?;
            let job = used.job().clone();
            used.used = true;
            assert!(used.consume(&job, &[PathBuf::from(RESULT_OUTPUT)]).is_err());
            Ok::<(), ReproError>(())
        })();
        for path in [
            "/tmp/opencode/smash-m5-target-broken-test",
            "/tmp/opencode/smash-m5-target-fixed-test",
            "/tmp/opencode/smash-m5-target-control-test",
        ] {
            let _ = fs::remove_dir_all(path);
        }
        let _ = fs::remove_dir_all(root);
        result.unwrap();
    }

    #[test]
    fn failed_creation_pinning_quarantines_without_deleting_an_uncertain_inode() {
        let root = PathBuf::from(format!(
            "/tmp/opencode/smash-m5-target-quarantine-test-{}",
            std::process::id()
        ));
        let displaced = PathBuf::from(format!(
            "/tmp/opencode/smash-m5-quarantine-original-{}",
            std::process::id()
        ));
        for path in [&root, &displaced] {
            let _ = fs::remove_dir_all(path);
        }
        fs::create_dir(&root).unwrap();
        fs::write(root.join("original"), b"original").unwrap();
        fs::rename(&root, &displaced).unwrap();
        fs::create_dir(&root).unwrap();
        fs::write(root.join("replacement"), b"replacement").unwrap();

        let claimed = quarantine_unpinned_target(&root).unwrap();
        assert!(!root.exists());
        assert_eq!(
            fs::read(claimed.join("replacement")).unwrap(),
            b"replacement"
        );
        assert_eq!(fs::read(displaced.join("original")).unwrap(), b"original");
        fs::remove_dir_all(claimed).unwrap();
        fs::remove_dir_all(displaced).unwrap();
    }

    #[test]
    fn cleanup_stops_at_the_global_entry_budget_before_deleting() {
        let root = PathBuf::from(format!(
            "/tmp/opencode/smash-m5-cleanup-entry-limit-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        for index in 0..=4_096 {
            fs::write(root.join(format!("entry-{index}")), b"").unwrap();
        }

        let directory = File::open(&root).unwrap();
        let mut entries = 0;
        let error = remove_target_contents(&directory, 32, &mut entries).unwrap_err();
        assert!(
            matches!(&error, ReproError::Cleanup(message) if message == "workflow target contains too many entries"),
            "{error:?}"
        );
        assert_eq!(entries, 4_097);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 4_097);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn nested_siblings_share_the_global_enumeration_budget() {
        let root = PathBuf::from(format!(
            "/tmp/opencode/smash-m5-cleanup-nested-entry-limit-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let mut current = root.clone();
        for depth in 0..32 {
            for sibling in 0..140 {
                fs::write(current.join(format!("sibling-{depth}-{sibling}")), b"").unwrap();
            }
            let next = current.join("next");
            fs::create_dir(&next).unwrap();
            current = next;
        }

        let directory = File::open(&root).unwrap();
        let mut entries = 0;
        let error = remove_target_contents(&directory, 32, &mut entries).unwrap_err();
        assert!(
            matches!(&error, ReproError::Cleanup(message) if message == "workflow target contains too many entries"),
            "{error:?}"
        );
        assert_eq!(entries, 4_097);
        assert!(root.join("sibling-0-0").exists());
        fs::remove_dir_all(root).unwrap();
    }
}
