//! Freshly admitted variants, typed effects, guaranteed cleanup, durable evidence.

use super::oracle::{CleanupRecord, DecodingStatus, RunRecord, TransitionStatus, WorkflowRunKind};
use super::persist::{JournalRecord, WorkflowManifest, WorkflowState, Workspace};
use super::policy::{read_policy, PinnedTargetRoot, WorkflowPolicy};
use super::step::execute_step;
use crate::repro::error::ReproError;
use crate::repro::linux::LinuxRunner;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
#[cfg(test)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(test)]
static CANCEL_BEFORE_PUBLICATION: AtomicBool = AtomicBool::new(false);

pub fn run_from_path(
    policy_path: &Path,
    bundle: &Path,
    execute_fixture_workflow: bool,
    cancel: &AtomicBool,
) -> Result<WorkflowManifest, ReproError> {
    let policy = read_policy(policy_path)?;
    run(policy, bundle, execute_fixture_workflow, cancel)
}

pub fn run(
    policy: WorkflowPolicy,
    bundle: &Path,
    execute_fixture_workflow: bool,
    cancel: &AtomicBool,
) -> Result<WorkflowManifest, ReproError> {
    // Reject execution strings/authority before reading driver bytes or touching targets.
    policy.validate_shape(execute_fixture_workflow)?;
    let mut admission = policy.review(execute_fixture_workflow)?;
    if cancel.load(Ordering::SeqCst) {
        return Err(ReproError::Interrupted);
    }
    let roots = TargetRoots {
        paths: provision_roots(&policy)?,
    };
    let workspace = Workspace::create(bundle, &policy, admission.invocation_id())?;
    let mut records = Vec::new();
    for kind in [
        WorkflowRunKind::Broken,
        WorkflowRunKind::Fixed,
        WorkflowRunKind::FunctionalControl,
    ] {
        match execute_run(
            &workspace,
            &mut admission,
            &policy,
            kind,
            roots.root(kind),
            cancel,
        ) {
            Ok(record) => {
                if let Err(error) = workspace.write_run(&record) {
                    let _ = workspace.append(&JournalRecord::Error {
                        code: error_code(&error).into(),
                    });
                    return Err(error);
                }
                workspace.append(&JournalRecord::RunCompleted { run_kind: kind })?;
                records.push(record);
            }
            Err(error) => {
                let _ = workspace.append(&JournalRecord::Error {
                    code: error_code(&error).into(),
                });
                return Err(error);
            }
        }
    }
    let runs: [RunRecord; 3] = records.try_into().map_err(|_| {
        ReproError::Evidence("workflow did not produce exactly three variant records".into())
    })?;
    if cancel.load(Ordering::SeqCst) {
        return Err(ReproError::Interrupted);
    }
    #[cfg(test)]
    if CANCEL_BEFORE_PUBLICATION.swap(false, Ordering::SeqCst) {
        cancel.store(true, Ordering::SeqCst);
    }
    let mut final_state = WorkflowState::started(&policy, admission.invocation_id())?;
    final_state.phase = "complete".into();
    workspace.write_state(&final_state)?;
    let result = workspace.finish(&policy, &runs, cancel);
    if result.is_ok() {
        roots.release();
    }
    result
}

fn execute_run(
    workspace: &Workspace,
    admission: &mut super::policy::WorkflowAdmission,
    policy: &WorkflowPolicy,
    kind: WorkflowRunKind,
    provisioned_root: &PinnedTargetRoot,
    cancel: &AtomicBool,
) -> Result<RunRecord, ReproError> {
    let run_namespace = super::policy::run_namespace(policy, kind, admission.invocation_id());
    if cancel.load(Ordering::SeqCst) {
        return Err(ReproError::Interrupted);
    }
    // A removed directory is never reopened as a new step namespace: each run admission
    // requires a fresh still-empty root before the first token is minted.
    let mut run_admission = Some(admission.begin_run(policy, kind, provisioned_root)?);
    workspace.append(&JournalRecord::RunStarted {
        run_kind: kind,
        step_index: 0,
    })?;
    let mut state = WorkflowState::started(policy, admission.invocation_id())?;
    state.phase = "running".into();
    state.run_kind = Some(kind);
    workspace.write_state(&state)?;
    let catalog = super::oracle::WorkflowStep::catalog(kind == WorkflowRunKind::FunctionalControl);
    let mut steps = Vec::new();
    let mut credential_sha256 = None;
    let mut error = None;
    let mut stop = false;
    for (index, _operation) in catalog.iter().enumerate() {
        if stop {
            break;
        }
        state.next_step = index;
        workspace.write_state(&state)?;
        let admitted = run_admission
            .as_mut()
            .expect("active run has live admission")
            .admit_step(Path::new("result.json"))?;
        workspace.append(&JournalRecord::StepAdmitted {
            run_kind: kind,
            step_index: index,
        })?;
        let runner = LinuxRunner::contained()?;
        match execute_step(
            policy,
            admitted,
            runner,
            steps.last().and_then(|step: &super::oracle::StepRecord| {
                step.result.as_ref().map(|result| &result.state)
            }),
            cancel,
        ) {
            Ok(executed) => {
                if credential_sha256
                    .as_ref()
                    .is_some_and(|hash| *hash != executed.credential_sha256)
                {
                    error = Some("credential_identity_changed".into());
                } else {
                    credential_sha256 = Some(executed.credential_sha256);
                }
                let valid = executed.record.decoding == DecodingStatus::Valid
                    && executed.record.transition == TransitionStatus::Valid;
                if valid {
                    workspace.append(&JournalRecord::StepValidated {
                        run_kind: kind,
                        step_index: index,
                    })?;
                } else {
                    error = Some("invalid_step_evidence".into());
                }
                if !executed.record.process.containment_failures.is_empty()
                    || executed.record.process.state != "exited"
                    || executed.record.process.exit_code != Some(0)
                {
                    error = Some("process_or_containment_failure".into());
                }
                if !executed.record.process.limits_satisfied
                    || executed.record.resource_observation.is_none()
                {
                    error = Some("resource_observation_failure".into());
                }
                steps.push(executed.record);
                stop = !valid || error.is_some();
            }
            Err(cause) => {
                error = Some(error_code(&cause).into());
                stop = true;
            }
        }
        if cancel.load(Ordering::SeqCst) {
            return Err(ReproError::Interrupted);
        }
    }
    workspace.append(&JournalRecord::CleanupStarted { run_kind: kind })?;
    state.phase = "cleaning_up".into();
    workspace.write_state(&state)?;
    let cleanup = cleanup_root(
        run_admission
            .as_ref()
            .expect("active run retains its pinned target")
            .target_root(),
    )?;
    if !cleanup.complete {
        error = Some("target_cleanup_failed".into());
    }
    let target_cleanup_started = true;
    workspace.append(&JournalRecord::CleanupComplete { run_kind: kind })?;
    state.phase = "run_recorded".into();
    state.next_step = steps.len();
    workspace.write_state(&state)?;
    let mut containment_failures = steps
        .iter()
        .flat_map(|step| step.process.containment_failures.clone())
        .collect::<Vec<_>>();
    if !target_cleanup_started || !cleanup.complete {
        containment_failures.push("target_cleanup".into());
    }
    containment_failures.sort();
    containment_failures.dedup();
    Ok(RunRecord {
        schema_version: policy.evidence_schema,
        scenario: policy.scenario.clone(),
        oracle: policy.oracle.clone(),
        run_kind: kind,
        variant: kind.variant(),
        run_namespace,
        policy_sha256: policy.digest()?,
        target_root: policy.root(kind).to_path_buf(),
        credential_reference: policy.credential_reference.clone(),
        credential_sha256: credential_sha256.unwrap_or_default(),
        synthetic_guest: true,
        disposable_private_target: true,
        target_destruction: true,
        error_code: error,
        containment_failures,
        cleanup,
        steps,
    })
}

fn cleanup_root(root: &PinnedTargetRoot) -> Result<CleanupRecord, ReproError> {
    cleanup_root_with_hook(root, || Ok(()))
}

fn cleanup_root_with_hook(
    root: &PinnedTargetRoot,
    before_claim: impl FnOnce() -> Result<(), ReproError>,
) -> Result<CleanupRecord, ReproError> {
    let failure = |error_code: &str| {
        Ok(CleanupRecord {
            sequence: 1,
            complete: false,
            target_root_removed: root.is_destroyed().unwrap_or(false),
            error_code: Some(error_code.into()),
        })
    };
    match fs::symlink_metadata(root.path()) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            match root.destroy_current_with_hook(before_claim) {
                Ok(()) => Ok(CleanupRecord {
                    sequence: 1,
                    complete: true,
                    target_root_removed: true,
                    error_code: None,
                }),
                Err(ReproError::CleanupRestoration(_)) => {
                    failure("target_cleanup_restoration_failed")
                }
                Err(ReproError::Evidence(_)) => failure("target_path_replaced"),
                Err(_) if root.verify_current().is_err() => {
                    failure("target_cleanup_identity_or_path_failed")
                }
                Err(_) => failure("remove_target_failed"),
            }
        }
        Ok(_) => failure("target_path_replaced"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            failure("target_missing_before_cleanup")
        }
        Err(error) => Err(error.into()),
    }
}

struct TargetRoots {
    paths: Vec<PinnedTargetRoot>,
}
impl TargetRoots {
    fn root(&self, kind: WorkflowRunKind) -> &PinnedTargetRoot {
        &self.paths[kind.run_index() as usize]
    }
    fn cleanup(&mut self) {
        cleanup_roots(&std::mem::take(&mut self.paths));
    }
    fn release(mut self) {
        self.paths.clear();
    }
}
impl Drop for TargetRoots {
    fn drop(&mut self) {
        self.cleanup();
    }
}

fn provision_roots(policy: &WorkflowPolicy) -> Result<Vec<PinnedTargetRoot>, ReproError> {
    let mut roots = Vec::new();
    for kind in [
        WorkflowRunKind::Broken,
        WorkflowRunKind::Fixed,
        WorkflowRunKind::FunctionalControl,
    ] {
        let path = policy.root(kind).to_path_buf();
        let mut builder = fs::DirBuilder::new();
        if builder.mode(0o700).create(&path).is_err() {
            cleanup_roots(&roots);
            return Err(ReproError::Policy(
                "workflow target namespaces must be newly allocatable private directories".into(),
            ));
        }
        match super::policy::checked_target_root(&path) {
            Ok(root) => roots.push(root),
            Err(error) => {
                // This path was created, but could not be pinned. Never recursively
                // delete it: a replacement must survive. Quarantine is non-destructive
                // and the error retains both the admission and disposition causes.
                let disposition = super::policy::quarantine_unpinned_target(&path);
                cleanup_roots(&roots);
                return Err(match disposition {
                    Ok(claimed) => ReproError::Cleanup(format!(
                        "{error}; unpinned target retained at {}",
                        claimed.display()
                    )),
                    Err(disposition) => ReproError::CleanupRestoration(format!(
                        "{error}; unpinned target quarantine failed: {disposition}"
                    )),
                });
            }
        }
    }
    Ok(roots)
}
fn cleanup_roots(roots: &[PinnedTargetRoot]) {
    for root in roots {
        let _ = cleanup_root(root);
    }
}

fn error_code(error: &ReproError) -> &'static str {
    match error {
        ReproError::Io(_) => "io_error",
        ReproError::Json(_) => "json_error",
        ReproError::ExecutionUnavailable(_) => "execution_unavailable",
        ReproError::Policy(_) => "policy_denied",
        ReproError::Evidence(_) => "evidence_invalid",
        ReproError::Spawn(_) => "spawn_failed",
        ReproError::Cleanup(_) | ReproError::CleanupRestoration(_) => "cleanup_failed",
        ReproError::Admission(_) => "execution_denied",
        ReproError::ArtifactChanged(_) => "driver_changed",
        ReproError::Interrupted => "interrupted",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_proves_destruction_of_the_reviewed_target_inode() {
        let root = PathBuf::from(format!(
            "/tmp/opencode/smash-m5-target-cleanup-pinned-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.join("state.json"), b"target state").unwrap();
        let pinned = super::super::policy::checked_target_root(&root).unwrap();
        let cleanup = cleanup_root(&pinned).unwrap();
        assert!(cleanup.complete);
        assert!(cleanup.target_root_removed);
        assert!(pinned.is_destroyed().unwrap());
        assert!(!root.exists());
    }

    #[test]
    fn replacement_during_cleanup_claim_is_restored_and_never_deleted() {
        let root = PathBuf::from(format!(
            "/tmp/opencode/smash-m5-target-cleanup-raced-{}",
            std::process::id()
        ));
        let displaced = PathBuf::from(format!(
            "/tmp/opencode/smash-m5-target-cleanup-raced-displaced-{}",
            std::process::id()
        ));
        for path in [&root, &displaced] {
            let _ = fs::remove_dir_all(path);
        }
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.join("original"), b"reviewed inode").unwrap();
        let pinned = super::super::policy::checked_target_root(&root).unwrap();

        let cleanup = cleanup_root_with_hook(&pinned, || {
            // This point is after verify_current and immediately before the atomic
            // claim. The former verify-then-rmdir implementation deleted this
            // replacement while detecting only afterwards that the original lived.
            fs::rename(&root, &displaced)?;
            fs::create_dir(&root)?;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
            fs::write(root.join("replacement"), b"different inode")?;
            Ok(())
        })
        .unwrap();
        assert!(!cleanup.complete);
        assert!(!cleanup.target_root_removed);
        assert_eq!(cleanup.error_code.as_deref(), Some("target_path_replaced"));
        assert_eq!(
            fs::read(displaced.join("original")).unwrap(),
            b"reviewed inode"
        );
        assert_eq!(
            fs::read(root.join("replacement")).unwrap(),
            b"different inode"
        );
        assert!(!pinned.is_destroyed().unwrap());
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(displaced).unwrap();
    }

    #[test]
    fn cleanup_failure_restores_the_reviewed_root_and_reports_the_real_class() {
        let root = PathBuf::from(format!(
            "/tmp/opencode/smash-m5-target-cleanup-restored-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for index in 0..=4_096 {
            fs::write(root.join(format!("entry-{index}")), b"").unwrap();
        }
        let pinned = super::super::policy::checked_target_root(&root).unwrap();
        let cleanup = cleanup_root(&pinned).unwrap();

        assert!(!cleanup.complete);
        assert!(!cleanup.target_root_removed);
        assert_eq!(cleanup.error_code.as_deref(), Some("remove_target_failed"));
        pinned.verify_current().unwrap();
        assert_eq!(fs::read_dir(&root).unwrap().count(), 4_097);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replaced_target_is_not_deleted_or_reported_as_cleaned_up() {
        let root = PathBuf::from(format!(
            "/tmp/opencode/smash-m5-target-cleanup-replaced-{}",
            std::process::id()
        ));
        let displaced = PathBuf::from(format!(
            "/tmp/opencode/smash-m5-target-cleanup-displaced-{}",
            std::process::id()
        ));
        for path in [&root, &displaced] {
            let _ = fs::remove_dir_all(path);
        }
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.join("original"), b"reviewed inode").unwrap();
        let pinned = super::super::policy::checked_target_root(&root).unwrap();
        fs::rename(&root, &displaced).unwrap();
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.join("replacement"), b"different inode").unwrap();

        let cleanup = cleanup_root(&pinned).unwrap();
        assert!(!cleanup.complete);
        assert!(!cleanup.target_root_removed);
        assert_eq!(cleanup.error_code.as_deref(), Some("target_path_replaced"));
        assert!(!pinned.is_destroyed().unwrap());
        assert_eq!(
            fs::read(displaced.join("original")).unwrap(),
            b"reviewed inode"
        );
        assert_eq!(
            fs::read(root.join("replacement")).unwrap(),
            b"different inode"
        );
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(displaced).unwrap();
    }
}
